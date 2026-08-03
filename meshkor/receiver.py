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

class ReceiverClient:
    """
    The Receiver Client used by APIs and Databases to validate an agent's access token.
    """
    def __init__(self, authority: Authority):
        self.authority = authority

    def new_challenge(self) -> str:
        """Generates a nonce for Interactive challenge-response handshake."""
        return self.authority.issue_challenge()

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
                    return Verdict(ok=False, status="HALT_HARD", reason="Agent has no read_scopes defined.")
                if resource and resource not in read_scopes:
                    return Verdict(ok=False, status="HALT_HARD", reason=f"Agent not authorized to read resource: {resource}")
            
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
