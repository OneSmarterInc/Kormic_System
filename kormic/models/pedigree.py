from dataclasses import dataclass, field
from typing import List, Dict, Any
from kormic.models.identity import Identity

@dataclass(frozen=True)
class BirthRecord:
    identity: Identity
    created_at: float
    guardrails: Dict[str, Any]
    epoch_number: int
    sig_alg: str
    signature: bytes
    agent_pub_key: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Converts the BirthRecord to a serializable dictionary matching Section 5.1 payload requirements."""
        return {
            "identity": self.identity.to_string(),
            "created_at": self.created_at,
            "guardrails": self.guardrails,
            "epoch_number": self.epoch_number,
            "sig_alg": self.sig_alg,
            "agent_pub_key": self.agent_pub_key,
            "signature": self.signature.hex()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BirthRecord":
        return cls(
            identity=Identity.from_string(data["identity"]),
            created_at=data["created_at"],
            guardrails=data["guardrails"],
            epoch_number=data["epoch_number"],
            sig_alg=data["sig_alg"],
            agent_pub_key=data.get("agent_pub_key", ""),
            signature=bytes.fromhex(data["signature"])
        )

    def to_payload_dict(self) -> Dict[str, Any]:
        """Returns the raw birth payload dictionary used for signing and hashing validation (excludes signature)."""
        return {
            "identity": self.identity.to_string(),
            "created_at": self.created_at,
            "guardrails": self.guardrails,
            "epoch_number": self.epoch_number,
            "sig_alg": self.sig_alg,
            "agent_pub_key": self.agent_pub_key
        }

@dataclass(frozen=True)
class HistoryLink:
    seq: int
    event: str
    timestamp: float
    prev_hash: str
    this_hash: str

    def to_dict(self) -> Dict[str, Any]:
        """Serializes history link representation to dictionary format."""
        return {
            "seq": self.seq,
            "event": self.event,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "this_hash": self.this_hash
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HistoryLink":
        return cls(
            seq=data["seq"],
            event=data["event"],
            timestamp=data["timestamp"],
            prev_hash=data["prev_hash"],
            this_hash=data["this_hash"]
        )

    def to_payload_dict(self) -> Dict[str, Any]:
        """Payload dict used for calculating this_hash link (excluding this_hash itself)."""
        return {
            "seq": self.seq,
            "event": self.event,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash
        }

@dataclass(frozen=True)
class Pedigree:
    birth_record: BirthRecord
    history: List[HistoryLink] = field(default_factory=list)
    running_head: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the entire Pedigree to a nested dictionary representation."""
        return {
            "birth_record": self.birth_record.to_dict(),
            "history": [link.to_dict() for link in self.history],
            "running_head": self.running_head
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Pedigree":
        return cls(
            birth_record=BirthRecord.from_dict(data["birth_record"]),
            history=[HistoryLink.from_dict(link_data) for link_data in data.get("history", [])],
            running_head=data.get("running_head", "")
        )
