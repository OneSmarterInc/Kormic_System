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
    
    PRODUCTION INVARIANT: Root capability (sign_root, generate_epoch_key) without a threshold 
    policy is impossible in production. Hardware backends must inherit and enforce this rule.

    
    Operations are explicitly classified into two tiers:
    - Routine: `sign_birth`. Happens constantly, per agent enrollment. Single-party.
    - Root: `sign_root`, `generate_epoch_key`. Rare, catastrophic if abused. Threshold-gated.
    """
    def sign_birth(self, epoch_n: int, payload: bytes) -> bytes:
        """[Routine] Signs the birth record payload using the designated epoch private key."""
        ...

    def sign_root(self, payload: bytes, challenge_nonce: str = None) -> bytes:
        """[Root] Signs a payload using the master root private key (e.g., for registry snapshots)."""
        ...

    def get_root_public_key(self) -> bytes:
        """Returns the master root public verification key."""
        ...

    def generate_epoch_key(self, epoch_n: int, challenge_nonce: str = None) -> None:
        """[Root] Generates a new epoch keypair and certifies it with the root key."""
        ...

    def get_epoch_certificate(self, epoch_n: int) -> bytes:
        """Retrieves root-signed certificate for epoch verification key validation."""
        ...

    def verify_epoch_certificate(self, epoch_n: int, public_key: bytes) -> bool:
        """Verifies if the public key for an epoch is certified by the Root key."""
        ...

    def revoke_epoch(self, epoch_n: int) -> None:
        """Revokes an epoch, rendering keys and agents registered under it invalid."""
        ...

    def is_epoch_revoked(self, epoch_n: int) -> bool:
        """Returns whether an epoch is revoked."""
        ...

    def get_all_epoch_public_keys(self) -> Dict[int, bytes]:
        """Returns all epoch public keys."""
        ...

    def get_revoked_epochs(self) -> set:
        """Returns the set of all revoked epochs."""
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
