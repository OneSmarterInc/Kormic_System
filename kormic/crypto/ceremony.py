import logging
from typing import List, Callable, Any
from kormic.interfaces.keys import Share

class ThresholdCeremony:
    """
    Implements Phase 3 Threshold Key Ceremony for existential actions.
    (Self-Destruct is fundamentally impossible in this architecture).
    """
    def __init__(self, n: int = 5, standard_quorum: int = 3):
        self.n = n
        self.k = standard_quorum
        self.logger = logging.getLogger("Ceremony")

    def authorize_create(self, shares: List[Share], create_func: Callable, *args, **kwargs) -> Any:
        self._verify_quorum(shares, required=self.k, action="CREATE_AGENT")
        return create_func(*args, **kwargs)

    def authorize_restore(self, shares: List[Share], restore_func: Callable, *args, **kwargs) -> Any:
        self._verify_quorum(shares, required=self.k, action="RESTORE_AGENT")
        return restore_func(*args, **kwargs)

    def authorize_destroy(self, shares: List[Share], destroy_func: Callable, *args, **kwargs) -> Any:
        self._verify_quorum(shares, required=self.k, action="DESTROY_AGENT_SINGLE")
        return destroy_func(*args, **kwargs)

    def authorize_catastrophic_destroy(self, shares: List[Share], destroy_func: Callable, *args, **kwargs) -> Any:
        # Catastrophic actions require MAXIMUM quorum (n of n)
        self._verify_quorum(shares, required=self.n, action="DESTROY_ALL_AGENTS_CATASTROPHIC")
        return destroy_func(*args, **kwargs)

    def _verify_quorum(self, shares: List[Share], required: int, action: str):
        provided = len(shares)
        if provided < required:
            self.logger.error(f"CEREMONY FAILED [{action}]: Provided {provided}/{self.n} shares. Required: {required}")
            raise PermissionError(f"Quorum not met for existential action: {action}. Provided {provided} shares, requires {required}.")
        
        # Cryptographically validate shares using Shamir Secret Sharing
        try:
            from kormic.crypto.software import SoftwareKeyCustody
            # If shares are invalid, unwrap will throw an error
            SoftwareKeyCustody().unwrap_twin_key(shares[:required])
        except Exception as e:
            self.logger.error(f"CEREMONY FAILED [{action}]: Cryptographic validation of Shamir shares failed.")
            raise PermissionError(f"Threshold quorum failed. Invalid or corrupted shares: {e}")

        self.logger.warning(f"CEREMONY SUCCESS [{action}]: Threshold quorum cryptographically verified ({provided}/{self.n} shares).")
