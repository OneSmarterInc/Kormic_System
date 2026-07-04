import time
from typing import List, Dict, Any, Optional
from kormic.interfaces.registry import RegistryReader
from kormic.models.verify import ProofToken, VerificationResult
from kormic.models.pedigree import BirthRecord, HistoryLink
from kormic.verify.cache import TrustCache
from kormic.crypto.algorithms import MLDSASigner
from kormic.utils.serialize import canonical_json, sha256_hex
from kormic.utils.exceptions import VerificationError, PedigreeIntegrityError

class Verifier:
    """
    Verification Engine implementing FAST and FULL pedigree checks.
    Satisfies Section 5.3, 5.4 & 7.
    """
    def __init__(self, registry: RegistryReader, cache: Optional[TrustCache] = None):
        self._registry = registry
        self._cache = cache

    def verify_fast(self, token: ProofToken) -> VerificationResult:
        """
        FAST Verification (O(1)).
        Validates birth signature and compares running head without walking the history.
        Satisfies Section 3 & 5.3.
        """
        agent_code = token.agent_code
        birth_data = token.birth_record
        
        # 1. Parse details
        epoch_n = birth_data.get("epoch_number")
        sig_hex = birth_data.get("signature", "")
        sig_bytes = bytes.fromhex(sig_hex) if sig_hex else b""

        # 2. Check registry for epoch revocation status
        if self._registry.is_epoch_revoked(epoch_n):
            return VerificationResult(
                status="REVOKED",
                reason=f"Epoch {epoch_n} has been revoked",
                agent_code=agent_code,
                epoch_number=epoch_n
            )

        # 3. Check registry for agent-specific revocation
        if self._registry.is_agent_revoked(agent_code):
            return VerificationResult(
                status="REVOKED",
                reason=f"Agent {agent_code} has been explicitly revoked",
                agent_code=agent_code,
                epoch_number=epoch_n
            )

        # 4. Authenticate origin signature (incorporates cached trust bypass check)
        is_authentic = False
        if self._cache and self._cache.check(agent_code, sig_bytes):
            is_authentic = True
        else:
            # Fetch epoch public key from registry
            pub_key = self._registry.get_epoch_public_key(epoch_n)
            if not pub_key:
                # If replica is lagging or registry is missing certificate, escalate
                return VerificationResult(
                    status="ESCALATE",
                    reason=f"Epoch certificate not found locally for epoch {epoch_n}",
                    agent_code=agent_code,
                    epoch_number=epoch_n
                )

            # Reconstruct birth payload used for signing
            payload_dict = {
                "identity": birth_data.get("identity"),
                "created_at": birth_data.get("created_at"),
                "guardrails": birth_data.get("guardrails"),
                "epoch_number": birth_data.get("epoch_number"),
                "sig_alg": birth_data.get("sig_alg")
            }
            serialized_payload = canonical_json(payload_dict)
            
            # Verify PQ signature
            is_authentic = MLDSASigner.verify(pub_key, serialized_payload.encode('utf-8'), sig_bytes)
            
            if is_authentic and self._cache:
                self._cache.put(agent_code, sig_bytes)

        if not is_authentic:
            return VerificationResult(
                status="HALT_HARD",
                reason="Invalid birth signature. Cryptographic origin authentication failed.",
                agent_code=agent_code,
                epoch_number=epoch_n
            )

        # 5. Success
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
            "sig_alg": birth_data.get("sig_alg")
        }
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
