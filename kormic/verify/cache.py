import time
from typing import Dict, Optional
from kormic.models.verify import TrustTicket

class TrustCache:
    """
    In-memory trust verification cache.
    Satisfies Section 4.1 & 5.4 (TTL enforcement, zero security bypass).
    """
    def __init__(self, ttl_seconds: int = 60):
        self._cache: Dict[str, TrustTicket] = {}
        self._ttl_seconds = ttl_seconds

    def _get_cache_key(self, agent_code: str, birth_signature: bytes) -> str:
        """Constructs a deterministic key using agent code and birth signature hex."""
        return f"{agent_code}:{birth_signature.hex()}"

    def put(self, agent_code: str, birth_signature: bytes) -> None:
        """Stores validation ticket in cache with absolute expiration timestamp."""
        now = time.time()
        expires_at = now + self._ttl_seconds
        ticket = TrustTicket(
            agent_code=agent_code,
            birth_signature=birth_signature.hex(),
            expires_at=expires_at
        )
        key = self._get_cache_key(agent_code, birth_signature)
        self._cache[key] = ticket

    def check(self, agent_code: str, birth_signature: bytes) -> bool:
        """
        Validates cached ticket. Returns True if valid cache hit, False on miss or expiry.
        Checks matching signature to prevent different agents from bypassing using same ID.
        """
        key = self._get_cache_key(agent_code, birth_signature)
        ticket = self._cache.get(key)
        if not ticket:
            return False

        # Expiry validation
        if time.time() > ticket.expires_at:
            del self._cache[key]  # Clean expired item
            return False

        # Signature validation to guarantee ticket integrity
        return ticket.birth_signature == birth_signature.hex()

    def invalidate(self, agent_code: str, birth_signature: bytes) -> None:
        """Invalidates a single cached entry (e.g. on revocation detection)."""
        key = self._get_cache_key(agent_code, birth_signature)
        if key in self._cache:
            del self._cache[key]
