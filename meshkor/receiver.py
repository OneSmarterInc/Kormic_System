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
