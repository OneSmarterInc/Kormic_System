import time
from typing import List, Dict, Any, Optional
from kormic.interfaces.registry import RegistryReader
from kormic.models.verify import ProofToken, VerificationResult
from kormic.models.pedigree import BirthRecord, HistoryLink
from kormic.verify.cache import TrustCache
from kormic.crypto.algorithms import MLDSASigner
from kormic.utils.serialize import canonical_json, sha256_hex
from kormic.utils.exceptions import VerificationError, PedigreeIntegrityError
import os

class Verifier:
    """
    Verification Engine implementing FAST and FULL pedigree checks.
    Satisfies Section 5.3, 5.4 & 7.
    """
    def __init__(self, registry: RegistryReader, cache: Optional[TrustCache] = None, legacy_single_tier: bool = False):
        self._registry = registry
        self._cache = cache
        self.legacy_single_tier = legacy_single_tier
        # Challenge nonce -> first_seen_ts (to prevent memory leak)
        # Note: In a distributed environment, this is currently per-replica scope.
        # Replays across replicas are bounded by the 5-minute freshness window.
        self._spent_challenges = {}

    def _verify_single_birth(self, agent_code: str, birth_data: Dict[str, Any]) -> VerificationResult:
        """Helper to authenticate a single birth record (DAIN or BAIN)."""
        epoch_n = birth_data.get("epoch_number")
        sig_hex = birth_data.get("signature", "")
        sig_bytes = bytes.fromhex(sig_hex) if sig_hex else b""

        # 1. Check registry for epoch revocation
        if self._registry.is_epoch_revoked(epoch_n):
            return VerificationResult("REVOKED", f"Epoch {epoch_n} has been revoked", agent_code, epoch_n)

        # 2. Check registry for explicit revocation
        if self._registry.is_agent_revoked(agent_code):
            return VerificationResult("REVOKED", f"Identity {agent_code} has been explicitly revoked", agent_code, epoch_n)

        # 3. Authenticate origin signature (incorporates cached trust bypass check)
        is_authentic = False
        if self._cache and self._cache.check(agent_code, sig_bytes):
            is_authentic = True
        else:
            pub_key = self._registry.get_epoch_public_key(epoch_n)
            if not pub_key:
                return VerificationResult("ESCALATE", f"Epoch certificate not found locally for epoch {epoch_n}", agent_code, epoch_n)

            sig_alg = birth_data.get("sig_alg")
            if not sig_alg:
                return VerificationResult("HALT_HARD", "Missing sig_alg field. Hard cutover enforced.", agent_code, epoch_n)
                
            from kormic.crypto.agility import require_allowed_algorithm
            try:
                require_allowed_algorithm(sig_alg)
            except ValueError as e:
                return VerificationResult("HALT_HARD", str(e), agent_code, epoch_n)

            # Reconstruct payload
            payload_dict = {
                "identity": birth_data.get("identity"),
                "created_at": birth_data.get("created_at"),
                "guardrails": birth_data.get("guardrails"),
                "epoch_number": birth_data.get("epoch_number"),
                "sig_alg": sig_alg,
                "fmt_ver": birth_data.get("fmt_ver"),
                "agent_pub_key": birth_data.get("agent_pub_key", "")
            }
            
            if payload_dict["fmt_ver"] is None:
                return VerificationResult("HALT_HARD", "Missing fmt_ver field. Hard cutover enforced.", agent_code, epoch_n)
            if self.legacy_single_tier and "derived_from" not in birth_data:
                pass # Legacy births were signed without this key
            else:
                payload_dict["derived_from"] = birth_data.get("derived_from")
                payload_dict["vendor_pub_key"] = birth_data.get("vendor_pub_key")
                payload_dict["artifact_digest"] = birth_data.get("artifact_digest")
                if birth_data.get("read_scopes") is not None:
                    payload_dict["read_scopes"] = birth_data.get("read_scopes")
                if birth_data.get("allowed_egress") is not None:
                    payload_dict["allowed_egress"] = birth_data.get("allowed_egress")

            serialized_payload = canonical_json(payload_dict)
            is_authentic = MLDSASigner.verify(sig_alg, pub_key, serialized_payload.encode('utf-8'), sig_bytes)
            
            if is_authentic and self._cache:
                self._cache.put(agent_code, sig_bytes)

        if not is_authentic:
            return VerificationResult("HALT_HARD", "Invalid birth signature. Cryptographic origin authentication failed.", agent_code, epoch_n)

        return VerificationResult("PASS", "Authentic", agent_code, epoch_n)

    def generate_challenge(self) -> str:
        """Issue a fresh, single-use nonce for challenge-response."""
        return os.urandom(16).hex()

    def verify_fast(self, token: ProofToken, mode: str = "deployment") -> VerificationResult:
        """
        FAST Verification (O(1)).
        Validates birth signature and compares running head without walking the history.
        Satisfies Section 3, 5.3, and Phase 5 Two-Tier Identity.
        """
        agent_code = token.agent_code
        birth_data = token.birth_record
        epoch_n = birth_data.get("epoch_number")
        
        # 1. Phase 5 Two-Tier Check
        derived_from = birth_data.get("derived_from")
        
        # If it is a deployment, enforce BAIN checks
        if agent_code.startswith("KMC.DPL.") or (agent_code.startswith("KMC.") and not agent_code.startswith("KMC.BLD.") and derived_from):
            if not derived_from:
                if not self.legacy_single_tier:
                    return VerificationResult("HALT_HARD", "Deployment birth record missing 'derived_from' and legacy single-tier mode is off.", agent_code, epoch_n)
            else:
                if not token.parent_birth_record:
                    return VerificationResult("HALT_HARD", "Parent BAIN record not provided in token.", agent_code, epoch_n)
                
                if token.parent_birth_record.get("identity") != derived_from:
                    return VerificationResult("HALT_HARD", "DAIN derived_from does not match provided BAIN identity.", agent_code, epoch_n)
                
                # Check BAIN (Recall implicit fail happens here because _verify_single_birth checks revocation)
                bain_res = self._verify_single_birth(derived_from, token.parent_birth_record)
                if bain_res.status != "PASS":
                    return bain_res
        
        # 2. Check the presented identity
        primary_res = self._verify_single_birth(agent_code, birth_data)
        if primary_res.status != "PASS":
            return primary_res
            
        if mode == "build_only":
            return VerificationResult("PASS", "Build identity verified successfully. Head and history skipped.", agent_code, epoch_n, verified_scope="build")

        # 5. [GAP 1 FIX] FAST MUST authenticate the head via proof-of-possession. FAIL CLOSED.
        agent_pub_key_hex = birth_data.get("agent_pub_key", "")
        if agent_pub_key_hex:
            # The birth seals an agent key, so the presenter MUST prove possession
            if not token.challenge or not token.signature:
                return VerificationResult(
                    status="HALT_HARD",
                    reason="Head not authenticated: proof token carries no challenge/signature.",
                    agent_code=agent_code, epoch_number=epoch_n)
                    
            try:
                from kormic.crypto.agility import require_allowed_algorithm
                require_allowed_algorithm(token.sig_alg)
                if token.fmt_ver is None:
                    raise ValueError("Missing fmt_ver field. Hard cutover enforced.")
            except ValueError as e:
                return VerificationResult(
                    status="HALT_HARD",
                    reason=f"Token crypto-agility rejected: {e}",
                    agent_code=agent_code, epoch_number=epoch_n)
            
            # Anti-Replay and Clock Skew (GAP 3): Strict ±30s tolerance
            now = time.time()
            skew = now - token.freshness_timestamp
            
            # If the token is more than 30 seconds in the future (skew < -30) or past TTL
            if skew < -30 or skew > 300: # 5 minute TTL, but strictly bounds future tokens
                return VerificationResult(
                    status="HALT_HARD",
                    reason=f"Token freshness out of bounds (Clock Skew/Expiry). Skew: {skew:.2f}s",
                    agent_code=agent_code, epoch_number=epoch_n)
            
            # Purge anything older than the freshness window so this can't grow unbounded
            self._spent_challenges = {c: t for c, t in self._spent_challenges.items() if now - t <= 300}
            
            is_spent = False
            if token.challenge in self._spent_challenges:
                is_spent = True
            elif hasattr(self._registry, 'spent_nonces') and token.challenge in self._registry.spent_nonces:
                is_spent = True
                
            if is_spent:
                return VerificationResult(
                    status="HALT_HARD",
                    reason="Replay Attack Detected: Challenge nonce has already been used.",
                    agent_code=agent_code, epoch_number=epoch_n)
            
            try:
                agent_pub_bytes = bytes.fromhex(agent_pub_key_hex)
                sig_bytes_agent = bytes.fromhex(token.signature)
            except ValueError:
                return VerificationResult(
                    status="HALT_HARD",
                    reason="Head not authenticated: malformed agent key or signature.",
                    agent_code=agent_code, epoch_number=epoch_n)

            # Bind the head into the structured signed payload
            bound_payload = token.challenge_payload()
            if not MLDSASigner.verify(token.sig_alg, agent_pub_bytes, bound_payload, sig_bytes_agent):
                return VerificationResult(
                    status="HALT_HARD",
                    reason="Invalid FAST challenge signature. Agent cryptographic authentication failed.",
                    agent_code=agent_code, epoch_number=epoch_n)
            
            # Record challenge as spent locally and promote to global authority
            self._spent_challenges[token.challenge] = now
            if hasattr(self._registry, 'spend_nonce'):
                self._registry.spend_nonce(token.challenge)

        # 6. Success
        return VerificationResult(
            status="PASS",
            reason="FAST verification passed. Origin authentic, running head recorded.",
            agent_code=agent_code,
            epoch_number=epoch_n
        )

    def verify_full(self, token: ProofToken, history_links: List[HistoryLink]) -> VerificationResult:
        """
        FULL Verification (O(N)).
        Walks every single history link verifying linkages, previous hashes, and recalculating head.
        Satisfies Section 3 & 5.1.
        """
        # First execute FAST verification to assert origin authenticity & revocation status
        fast_res = self.verify_fast(token)
        if fast_res.status != "PASS":
            return fast_res

        agent_code = token.agent_code
        birth_data = token.birth_record

        # Recompute base birth hash anchor
        payload_dict = {
            "identity": birth_data.get("identity"),
            "created_at": birth_data.get("created_at"),
            "guardrails": birth_data.get("guardrails"),
            "epoch_number": birth_data.get("epoch_number"),
            "sig_alg": birth_data.get("sig_alg"),
            "fmt_ver": birth_data.get("fmt_ver"),
            "agent_pub_key": birth_data.get("agent_pub_key", "")
        }
        if self.legacy_single_tier and "derived_from" not in birth_data:
            pass # Legacy births were signed without this key
        else:
            payload_dict["derived_from"] = birth_data.get("derived_from")
            payload_dict["vendor_pub_key"] = birth_data.get("vendor_pub_key")
            payload_dict["artifact_digest"] = birth_data.get("artifact_digest")
            if birth_data.get("read_scopes") is not None:
                payload_dict["read_scopes"] = birth_data.get("read_scopes")
            if birth_data.get("allowed_egress") is not None:
                payload_dict["allowed_egress"] = birth_data.get("allowed_egress")
            
        birth_hash = sha256_hex(canonical_json(payload_dict))

        # Check history length match with token expectation
        if len(history_links) != token.history_length:
            return VerificationResult(
                status="HALT_HARD",
                reason=f"History length mismatch. Token expected: {token.history_length}, actual links provided: {len(history_links)}",
                agent_code=agent_code
            )

        # Walk the chain confirming linkages and hashes
        expected_prev_hash = birth_hash
        calculated_head = sha256_hex(birth_hash)

        for idx, link in enumerate(history_links):
            seq = idx + 1
            
            # Assert sequential sequencing
            if link.seq != seq:
                return VerificationResult(
                    status="HALT_HARD",
                    reason=f"Integrity violation: Out-of-order sequence at item {seq}. Found seq: {link.seq}",
                    agent_code=agent_code
                )

            # Confirm linkage alignment
            if link.prev_hash != expected_prev_hash:
                return VerificationResult(
                    status="HALT_HARD",
                    reason=f"Integrity violation: Hash linkage broken at sequence {seq}. Expected prev_hash: {expected_prev_hash}, found: {link.prev_hash}",
                    agent_code=agent_code
                )

            # Recompute link payload verification hash
            link_payload = {
                "seq": link.seq,
                "event": link.event,
                "timestamp": link.timestamp,
                "prev_hash": link.prev_hash
            }
            recomputed_hash = sha256_hex(canonical_json(link_payload))
            if link.this_hash != recomputed_hash:
                return VerificationResult(
                    status="HALT_HARD",
                    reason=f"Integrity violation: Altered event data detected at sequence {seq}.",
                    agent_code=agent_code
                )

            # Update running expectation variables
            expected_prev_hash = link.this_hash
            
            # Recalculate O(1) running head iteration
            event_payload = {
                "seq": link.seq,
                "event": link.event,
                "timestamp": link.timestamp
            }
            calculated_head = sha256_hex(calculated_head + canonical_json(event_payload))

        # Finally check head matches the token's current head
        if calculated_head != token.current_head:
            return VerificationResult(
                status="HALT_HARD",
                reason="Integrity violation: Recalculated history head hash does not match token head.",
                agent_code=agent_code
            )

        return VerificationResult(
            status="PASS",
            reason="FULL verification passed. Complete history integrity successfully validated.",
            agent_code=agent_code,
            epoch_number=birth_data.get("epoch_number")
        )
