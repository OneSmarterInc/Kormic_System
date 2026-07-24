import json
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

from kormic.interfaces.registry import RegistryReader
from kormic.crypto.algorithms import MLDSASigner
from kormic.utils.bloom import ScalableRevocationFilter


@dataclass
class RegistrySnapshot:
    """A signed snapshot of the registry state. Distributed to Regional Replicas."""
    version: int
    issued_at: float
    epochs: Dict[str, str]  # epoch_n (str) -> public_key_hex
    revoked_epochs: List[int]
    revoked_agents: List[str]
    spent_nonces: List[str]
    checkpoint_indices: Dict[str, int]
    root_sig_hex: str = ""

    def payload(self) -> bytes:
        return json.dumps({
            "version": self.version,
            "issued_at": self.issued_at,
            "epochs": self.epochs,
            "revoked_epochs": sorted(self.revoked_epochs),
            "revoked_agents": sorted(self.revoked_agents),
            "spent_nonces": sorted(self.spent_nonces),
            "checkpoint_indices": self.checkpoint_indices
        }, sort_keys=True).encode('utf-8')


class CentralRegistryAuthority:
    """
    The authoritative source. Gathers valid keys and revocations, and signs them
    into versioned snapshots for distribution.
    """
    def __init__(self, key_custody):
        self.key_custody = key_custody
        self.version = 0
        self.revoked_agents = set()
        self.spent_nonces: Dict[str, float] = {}
        self.checkpoint_indices = {}

    def _purge_old_nonces(self):
        now = time.time()
        self.spent_nonces = {n: t for n, t in self.spent_nonces.items() if now - t <= 300}

    def spend_nonce(self, nonce: str) -> None:
        self.spent_nonces[nonce] = time.time()
        self._purge_old_nonces()
        # Routine verification no longer bumps the global snapshot version

    def update_checkpoint(self, agent_code: str, index: int) -> None:
        if index > self.checkpoint_indices.get(agent_code, 0):
            self.checkpoint_indices[agent_code] = index
            self.version += 1

    def revoke_agent(self, agent_code: str) -> None:
        self.revoked_agents.add(agent_code)
        self.version += 1

    def revoke_epoch(self, epoch_n: int) -> None:
        self.key_custody.revoke_epoch(epoch_n)
        self.version += 1

    def snapshot(self) -> RegistrySnapshot:
        self._purge_old_nonces()
        # Collect all active and revoked epochs from key custody
        epochs_dict = {}
        for epoch_n, (_, pub) in self.key_custody._epoch_keys.items():
            epochs_dict[str(epoch_n)] = pub.hex()

        revoked_epochs = list(self.key_custody._revoked_epochs)

        snap = RegistrySnapshot(
            version=self.version,
            issued_at=time.time(),
            epochs=epochs_dict,
            revoked_epochs=revoked_epochs,
            revoked_agents=list(self.revoked_agents),
            spent_nonces=list(self.spent_nonces.keys()),
            checkpoint_indices=self.checkpoint_indices.copy()
        )
        # Sign the payload using the root private key
        root_priv = self.key_custody._root_priv
        snap.root_sig_hex = MLDSASigner.sign(root_priv, snap.payload()).hex()
        
        from kormic.logger import kormic_logger
        kormic_logger.info("SNAPSHOT_GENERATE", "CENTRAL", f"Signed Global Snapshot v{snap.version} (Contains {len(self.revoked_agents)} revocations, {len(self.spent_nonces)} nonces)")
        
        return snap


class RegionalReplicaRegistry(RegistryReader):
    """
    Regional Replica. Verifiers read THIS locally. Pulls signed snapshots from
    the Central Authority. Uses a local Bloom Filter for O(1) revocation checks.
    """
    def __init__(self, region: str, root_pub_key: bytes, central_sync=None, local_only: bool = False):
        self.region = region
        self.root_pub_key = root_pub_key
        self.central_sync = central_sync
        self.snapshot: Optional[RegistrySnapshot] = None
        self.last_sync: float = 0.0
        self.revoked_filter = ScalableRevocationFilter()
        self.spent_nonces = set()
        self.checkpoint_indices = {}
        
        if self.central_sync is None and not local_only:
            raise ValueError("central_sync is required for cross-replica replay protection. Pass local_only=True to explicitly opt-out for testing.")
            
        if local_only and self.central_sync is None:
            from kormic.logger import kormic_logger
            kormic_logger.warning("REPLICA_INIT", f"REPLICA:{self.region}", "DANGER: central_sync is None. Replay protection is running in LOCAL-ONLY mode. Cross-replica replays are possible!")

    def spend_nonce(self, nonce: str) -> None:
        """Saves locally and pushes upstream to central authority if connected."""
        self.spent_nonces.add(nonce)
        if self.central_sync:
            self.central_sync.spend_nonce(nonce)

    def apply_snapshot(self, snap: RegistrySnapshot) -> bool:
        """
        Applies a snapshot. Accepts same version if strictly newer timestamp to sync nonces.
        """
        from kormic.logger import kormic_logger
        
        # 1. Verify Signature
        if not MLDSASigner.verify(self.root_pub_key, snap.payload(), bytes.fromhex(snap.root_sig_hex)):
            kormic_logger.error("SNAPSHOT_PULL", f"REPLICA:{self.region}", "Snapshot rejected: Invalid Root Signature (Forgery detected!)")
            return False
            
        # 2. Check Version and Freshness
        if self.snapshot:
            if snap.version < self.snapshot.version:
                kormic_logger.warning("SNAPSHOT_PULL", f"REPLICA:{self.region}", f"Snapshot rejected: Version {snap.version} is older than current {self.snapshot.version}")
                return False
            elif snap.version == self.snapshot.version:
                if snap.issued_at <= self.snapshot.issued_at:
                    return False
                # Fast-path for non-version-bumping updates (nonces).
                # UNION, never replace: because a spend no longer bumps the version,
                # snapshot issued_at ordering doesn't track nonce causality, so a
                # snapshot generated before a spend but delivered after it would wipe
                # that spend and reopen the replay window. Union can't grow unbounded
                # because central purges on the 300s freshness rule and the freshness
                # gate rejects anything older than that before the spent-check runs.
                self.spent_nonces |= set(snap.spent_nonces)
                self.checkpoint_indices = snap.checkpoint_indices
                self.snapshot = snap
                self.last_sync = time.time()
                return True
            
        # 3. Apply Full Snapshot (Version Bumped)
        self.snapshot = snap
        self.last_sync = time.time()
        
        # 4. Rebuild Bloom Filter Locally
        self.revoked_filter = ScalableRevocationFilter()
        self.revoked_filter.load_from_snapshot(snap.revoked_agents)
        for epoch in snap.revoked_epochs:
            self.revoked_filter.add(f"EPOCH:{epoch}")
            
        self.spent_nonces = set(snap.spent_nonces)
        self.checkpoint_indices = snap.checkpoint_indices
            
        kormic_logger.info("SNAPSHOT_PULL", f"REPLICA:{self.region}", f"Snapshot v{snap.version} received. Local Bloom Filter updated.")
        return True

    def staleness(self) -> float:
        return time.time() - self.last_sync

    def is_epoch_revoked(self, epoch_n: int) -> bool:
        if not self.snapshot:
            return False
        return self.revoked_filter.is_revoked(f"EPOCH:{epoch_n}")

    def is_agent_revoked(self, agent_code: str) -> bool:
        if not self.snapshot:
            return False
        return self.revoked_filter.is_revoked(agent_code)

    def get_epoch_public_key(self, epoch_n: int) -> Optional[bytes]:
        if not self.snapshot:
            return None
        pub_hex = self.snapshot.epochs.get(str(epoch_n))
        if pub_hex:
            return bytes.fromhex(pub_hex)
        return None

    def get_epoch_certificate(self, epoch_n: int) -> Optional[bytes]:
        # Snapshots don't carry the certificates in this minimal model, they just carry the trusted public keys
        # The snapshot signature itself acts as the certificate of trust for the whole set of keys.
        return None
