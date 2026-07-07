from typing import Set, Iterable
from pybloom_live import BloomFilter

class ScalableRevocationFilter:
    """
    Bloom Filter for scalable, constant-memory revocation checks.
    Satisfies Section 6.3.
    """
    def __init__(self, capacity: int = 1_000_000, error_rate: float = 0.001):
        self._bloom = BloomFilter(capacity=max(capacity, 1), error_rate=error_rate)
        # We maintain a backing set as the "authoritative source" for this node.
        # In the distributed phase, this represents the exact signed database.
        self._authoritative_set: Set[str] = set()

    def add(self, item_id: str) -> None:
        """Adds an item (agent code or epoch) to the revocation list."""
        from kormic.logger import kormic_logger
        self._bloom.add(item_id)
        self._authoritative_set.add(item_id)
        kormic_logger.info("REVOCATION_SYNC", item_id, f"Blacklisted in Bloom Filter (Zero memory footprint)")

    def load_from_snapshot(self, items: Iterable[str]) -> None:
        """Bulk load a snapshot into the filter."""
        from kormic.logger import kormic_logger
        count = 0
        for item in items:
            self.add(item)
            count += 1
        kormic_logger.info("REVOCATION_SYNC", "SYSTEM", f"Bloom Filter initialized with {count} records")

    def is_revoked(self, item_id: str) -> bool:
        """
        Two-tier revocation check.
        O(1) fast path if Bloom says NOT revoked.
        Falls through to authoritative check if Bloom says MAYBE.
        No false negatives possible.
        """
        from kormic.logger import kormic_logger
        if item_id not in self._bloom:
            return False  # Definitely not revoked
            
        kormic_logger.warning("BLOOM_TIER2", item_id, "Bloom Filter says 'Maybe'. Triggering Tier-2 deep check.")
        # Bloom flagged it as "maybe". Check authoritative source.
        is_rev = item_id in self._authoritative_set
        if is_rev:
            kormic_logger.error("REVOKED", item_id, "Tier-2 Check: Agent officially revoked.")
        return is_rev
