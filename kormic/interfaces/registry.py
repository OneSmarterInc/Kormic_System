from typing import Protocol, Optional

class RegistryReader(Protocol):
    """
    Registry Reader capability abstraction.
    Supports querying valid epochs, revoked epochs/agents, and epoch public certificates.
    Allows Phase 1 and 2 to query local or replicated states seamlessly.
    """
    def is_epoch_revoked(self, epoch_n: int) -> bool:
        """Queries if an epoch certificate/signing key is revoked."""
        ...

    def is_agent_revoked(self, agent_code: str) -> bool:
        """Queries if a specific agent code/id is on the revocation list."""
        ...

    def get_epoch_certificate(self, epoch_n: int) -> Optional[bytes]:
        """Gets the signed epoch verification public key certificate."""
        ...

    def get_epoch_public_key(self, epoch_n: int) -> Optional[bytes]:
        """Gets the epoch verification public key."""
        ...

    def spend_nonce(self, nonce: str) -> None:
        """Promotes a spent nonce to the global authority to prevent multi-region replay attacks."""
        ...
