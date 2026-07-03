from typing import Protocol, List, Dict, Any

class Share(Protocol):
    """Placeholder interface representing a Shamir secret share key slice."""
    @property
    def share_index(self) -> int:
        ...

    @property
    def share_data(self) -> bytes:
        ...

class KeyCustody(Protocol):
    """
    Capability interface for cryptography and secure key operations.
    Satisfies Section 4.3. Interface remains identical for software (Phase 1) and hardware/HSM (Phase 3).
    """
    def sign_birth(self, epoch_n: int, payload: bytes) -> bytes:
        """Signs the birth record payload using the designated epoch private key."""
        ...

    def epoch_public(self, epoch_n: int) -> bytes:
        """Returns the public verification key for the specified epoch."""
        ...

    def wrap_twin_key(self, key: bytes) -> List[Share]:
        """Performs a threshold split of a twin encryption key."""
        ...

    def unwrap_twin_key(self, shares: List[Share]) -> bytes:
        """Reconstructs the twin encryption key from the provided threshold shares quorum."""
        ...
