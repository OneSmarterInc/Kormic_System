from dataclasses import dataclass
from typing import Optional, Dict, Any
from .authority import Authority
from kormic.models.verify import ProofToken

@dataclass
class Verdict:
    """
    A clean, simple dataclass that hides the complex Kormic engine from the receiver.
    """
    ok: bool
    status: str
    reason: str
    may_reach: Optional[Dict[str, Any]] = None
    rung: Optional[str] = None

from kormic.runtime.detection import DetectionSink, DetectionEvent
import time

class ReceiverClient:
    """
    The Receiver Client used by APIs and Databases to validate an agent's access token.
    """
    def __init__(self, authority: Authority, detection_sink: DetectionSink = None, enforcement_mode: str = "enforced"):
        self.authority = authority
        self.detection_sink = detection_sink
        self.enforcement_mode = enforcement_mode

    def new_challenge(self) -> str:
        """Generates a nonce for Interactive challenge-response handshake."""
        return self.authority.issue_challenge()

    def _emit_detection(self, token: ProofToken, kind: str, target: str, reason: str):
        if self.detection_sink:
            ev = DetectionEvent(
                event_kind=kind,
                identity=token.agent_code,
                action_target=target,
                reason=reason,
                mode=self.enforcement_mode,
                timestamp=time.time()
            )
            self.detection_sink.emit(ev)

    def validate(self, token: ProofToken, action_type: str = "write", resource: Optional[str] = None) -> Verdict:
        """
        Validates the token against the Kormic verifier and enforces scope containment.
        """
        verifier = self.authority.get_verifier()
        result = verifier.verify_fast(token)

        if result.status == "PASS":
            birth = token.birth_record
            manifest = birth.get('guardrails', {})
            read_scopes = birth.get('read_scopes', [])
            
            if action_type == "read":
                if not read_scopes:
                    reason = "Agent has no read_scopes defined."
                    self._emit_detection(token, "out_of_scope_read", resource or "any", reason)
                    if self.enforcement_mode == "enforced":
                        return Verdict(ok=False, status="HALT_HARD", reason=reason)
                elif resource and resource not in read_scopes:
                    reason = f"Agent not authorized to read resource: {resource}"
                    self._emit_detection(token, "out_of_scope_read", resource, reason)
                    if self.enforcement_mode == "enforced":
                        return Verdict(ok=False, status="HALT_HARD", reason=reason)
            
            rung = "accountable" # Real implementation checks identity verification depth
            
            return Verdict(
                ok=True,
                status=result.status,
                reason=result.reason,
                may_reach=manifest,
                rung=rung
            )
        else:
            return Verdict(
                ok=False,
                status=result.status,
                reason=result.reason
            )

    def verify_artifact(self, artifact_bytes: bytes, token: ProofToken, artifact_signature: str) -> Verdict:
        """
        Phase 6 Part D: Receiver-Side Artifact Verification.
        Verifies the Build AIN, the digest binding, and the vendor enrollment.
        """
        verifier = self.authority.get_verifier()
        failed = False
        fail_reason = ""
        fail_status = ""
        
        # 1. Verify the Build AIN itself using the verifier's build path
        res = verifier.verify_fast(token, mode="build_only")
        if res.status != "PASS":
            self._emit_detection(token, "artifact_ain_invalid", "artifact", res.reason)
            failed = True
            fail_reason = res.reason
            fail_status = res.status
                
        birth = token.birth_record
        expected_digest = birth.get("artifact_digest")
        if not failed and not expected_digest:
            reason = "Build AIN does not seal an artifact_digest."
            self._emit_detection(token, "artifact_digest_missing", "artifact", reason)
            failed = True
            fail_reason = reason
            fail_status = "HALT_HARD"
            
        # 2. Compute digest and check binding
        if not failed:
            from kormic.utils.serialize import hash_hex
            hash_alg = birth.get("hash_alg", "SHA-256")
            actual_digest = hash_hex(hash_alg, artifact_bytes)
            
            if actual_digest != expected_digest:
                reason = f"Artifact digest mismatch. Expected {expected_digest}, computed {actual_digest}"
                self._emit_detection(token, "artifact_digest_mismatch", "artifact", reason)
                failed = True
                fail_reason = reason
                fail_status = "HALT_HARD"
                
        # 3. Verify vendor enrollment
        if not failed:
            identity_parts = token.agent_code.split('.')
            entity_ref = identity_parts[2] if len(identity_parts) > 2 else ""
            instance_num = identity_parts[3] if len(identity_parts) > 3 else ""
            
            registry_reader = getattr(verifier, '_registry', None)
            if not registry_reader:
                return Verdict(ok=False, status="HALT_HARD", reason="No registry available for vendor check")
                
            enrolled_vendor = registry_reader.get_enrolled_vendor(entity_ref)
            if not enrolled_vendor:
                reason = f"Vendor '{entity_ref}' not enrolled."
                self._emit_detection(token, "vendor_not_enrolled", "artifact", reason)
                failed = True
                fail_reason = reason
                fail_status = "HALT_HARD"
            else:
                vendor_pub_key = birth.get("vendor_pub_key")
                if enrolled_vendor.get('public_key') != vendor_pub_key:
                    reason = "Vendor public key mismatch against registry."
                    self._emit_detection(token, "vendor_key_mismatch", "artifact", reason)
                    failed = True
                    fail_reason = reason
                    fail_status = "HALT_HARD"
                else:
                    vendor_alg = enrolled_vendor.get('sig_alg')
                    from kormic.crypto.agility import require_allowed_algorithm
                    try:
                        require_allowed_algorithm(vendor_alg)
                        payload = (entity_ref + instance_num + expected_digest).encode('utf-8')
                        from kormic.crypto.algorithms import MLDSASigner
                        try:
                            sig_bytes = bytes.fromhex(artifact_signature)
                            pub_bytes = bytes.fromhex(vendor_pub_key)
                            if not MLDSASigner.verify(vendor_alg, pub_bytes, payload, sig_bytes):
                                reason = "Artifact signature verification failed."
                                self._emit_detection(token, "artifact_signature_invalid", "artifact", reason)
                                failed = True
                                fail_reason = reason
                                fail_status = "HALT_HARD"
                        except Exception as e:
                            reason = f"Invalid artifact binding: {str(e)}"
                            self._emit_detection(token, "artifact_signature_invalid", "artifact", reason)
                            failed = True
                            fail_reason = reason
                            fail_status = "HALT_HARD"
                    except ValueError as e:
                        self._emit_detection(token, "vendor_crypto_rejected", "artifact", str(e))
                        failed = True
                        fail_reason = str(e)
                        fail_status = "HALT_HARD"

        # 4. Verify Approval Assertion (Piece 3)
        if not failed:
            approval_data = birth.get("approval_assertion")
            if not approval_data:
                reason = "Build AIN is missing an approval_assertion."
                self._emit_detection(token, "approval_assertion_missing", "artifact", reason)
                failed = True
                fail_reason = reason
                fail_status = "HALT_HARD"
            else:
                from kormic.models.approval import DelegationAssertion
                from kormic.verify.approval import verify_delegation_assertion
                try:
                    assertion = DelegationAssertion.from_dict(approval_data)
                    # For a build, the action is usually "release" and target is the artifact digest
                    verify_delegation_assertion(assertion, registry_reader, "release", expected_digest)
                except Exception as e:
                    reason = f"Approval assertion verification failed: {str(e)}"
                    self._emit_detection(token, "approval_assertion_invalid", "artifact", reason)
                    failed = True
                    fail_reason = reason
                    fail_status = "HALT_HARD"

        if failed:
            if self.enforcement_mode == "enforced":
                return Verdict(ok=False, status=fail_status, reason=fail_reason)
            else:
                # Advisory mode bypasses the failure
                return Verdict(ok=True, status="ADVISORY_BYPASS", reason=fail_reason)

        return Verdict(ok=True, status="PASS", reason="Artifact verified successfully.")
