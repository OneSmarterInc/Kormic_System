from typing import Protocol, Optional

class RecordStore(Protocol):
    """
    Capability interface for storage.
    Satisfies Section 4.1. Maps to hot object storage + cold backup/twin storage.
    """
    def put(self, agent_code: str, pedigree: dict) -> None:
        """Stores a serialized pedigree record associated with an agent_code."""
        ...

    def get(self, agent_code: str) -> Optional[dict]:
        """Retrieves a pedigree record for an agent_code. Returns None if not found."""
        ...

    def put_twin(self, agent_code: str, sealed_blob: bytes) -> None:
        """Stores the encrypted/sealed recovery twin backup for the agent."""
        ...

    def get_twin(self, agent_code: str) -> Optional[bytes]:
        """Retrieves the encrypted twin backup. Returns None if not found."""
        ...

    def put_salt(self, agent_code: str, salt: str) -> None:
        """Stores a deployment-specific salt associated with an agent_code."""
        ...

    def get_salt(self, agent_code: str) -> Optional[str]:
        """Retrieves the salt for an agent_code. Returns None if not found."""
        ...

    def enroll_vendor(self, entity_ref: str, public_key: str) -> None:
        """Enrolls a vendor's public key in the registry."""
        ...

    def get_enrolled_vendor(self, entity_ref: str) -> Optional[str]:
        """Retrieves a vendor's enrolled public key. Returns None if not found."""
        ...
