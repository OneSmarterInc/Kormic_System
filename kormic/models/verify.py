from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass(frozen=True)
class ProofToken:
    """
    Single-pass asynchronous self-contained verification token.
    Satisfies Section 4.2 & 5.4.
    """
    agent_code: str
    birth_record: Dict[str, Any]      # Serialized BirthRecord dictionary
    current_head: str                 # 64-char running head summary hash
    history_length: int               # Number of links currently in history
    freshness_timestamp: float        # Prevents reply/replay attacks
    authority_reference: str          # Contextual signing domain details
    challenge: str = ""               # Optional, used for Challenge-Response in Phase 3
    signature: str = ""               # Hex signature of the challenge
    parent_birth_record: Optional[Dict[str, Any]] = None # Serialized parent BAIN if this is a DAIN
    sig_alg: str = None
    fmt_ver: int = None

    def challenge_payload(self) -> bytes:
        import json
        return json.dumps({
            "current_head": self.current_head,
            "challenge": self.challenge,
            "sig_alg": self.sig_alg,
            "fmt_ver": self.fmt_ver
        }, sort_keys=True).encode('utf-8')

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_code": self.agent_code,
            "birth_record": self.birth_record,
            "current_head": self.current_head,
            "history_length": self.history_length,
            "freshness_timestamp": self.freshness_timestamp,
            "authority_reference": self.authority_reference,
            "challenge": self.challenge,
            "signature": self.signature,
            "parent_birth_record": self.parent_birth_record,
            "sig_alg": self.sig_alg,
            "fmt_ver": self.fmt_ver
        }

@dataclass(frozen=True)
class TrustTicket:
    """
    Verification cache ticket issued for validated agent origins.
    Satisfies Section 4.1 & 5.4.
    """
    agent_code: str
    birth_signature: str              # Hex representation of signature used as cache key sanity check
    expires_at: float

@dataclass(frozen=True)
class VerificationResult:
    """
    Represents the output verdict of verification processes.
    Satisfies Section 7 (Verdicts and human escalation).
    """
    status: str                       # 'PASS' | 'HALT_HARD' | 'REVOKED' | 'ESCALATE'
    reason: str
    agent_code: str
    epoch_number: Optional[int] = None
    verified_scope: str = "full"      # 'full' | 'build'
