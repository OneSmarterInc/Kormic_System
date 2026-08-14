import json
from dataclasses import dataclass
from typing import Dict, Any

@dataclass(frozen=True)
class DelegationAssertion:
    """
    A single-use, time-bounded delegation assertion from an enrolled principal.
    Authorizes a consequential action over a specific target.
    """
    principal_ref: str
    action: str
    target: str
    expiry: float
    nonce: str
    signature: str = ""
    sig_alg: str = "ML-DSA-87"
    fmt_ver: int = 1

    def signable_payload(self) -> bytes:
        return json.dumps({
            "principal_ref": self.principal_ref,
            "action": self.action,
            "target": self.target,
            "expiry": self.expiry,
            "nonce": self.nonce,
            "sig_alg": self.sig_alg,
            "fmt_ver": self.fmt_ver
        }, sort_keys=True).encode('utf-8')

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_ref": self.principal_ref,
            "action": self.action,
            "target": self.target,
            "expiry": self.expiry,
            "nonce": self.nonce,
            "signature": self.signature,
            "sig_alg": self.sig_alg,
            "fmt_ver": self.fmt_ver
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DelegationAssertion':
        return cls(**data)
