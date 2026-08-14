import json
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

from kormic.interfaces.registry import RegistryReader
from kormic.crypto.algorithms import MLDSASigner
from kormic.utils.bloom import ScalableRevocationFilter

# How long a spent nonce must be remembered. It only needs to outlive the token
# freshness window: verify_fast rejects any token older than this on skew BEFORE it
# consults the spent set, so a nonce purged at this age can never be usefully replayed.
# Central and every replica must agree on this number, hence one constant.
NONCE_TTL_SECONDS = 300


class VendorStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    ROTATED = "ROTATED"

@dataclass
class VendorEnrollment:
    entity_ref: str
    public_key: str
    status: str
    enrolled_at: float
    enrolled_by: str
    identity_proof_ref: str
    sig_alg: str
    fmt_ver: int
    version: int

@dataclass
class PrincipalEnrollment:
    principal_ref: str
    public_key: str
    status: str
    enrolled_at: float
    enrolled_by: str
    identity_proof_ref: str
    sig_alg: str
    fmt_ver: int
    version: int

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
    vendors: Dict[str, dict]  # entity_ref -> VendorEnrollment dict
    principals: Dict[str, dict] = None # principal_ref -> PrincipalEnrollment dict
    sig_alg: str = None
    fmt_ver: int = None
    root_sig_hex: str = ""

    def payload(self) -> bytes:
        d = {
            "version": self.version,
            "issued_at": self.issued_at,
            "epochs": self.epochs,
            "revoked_epochs": sorted(self.revoked_epochs),
            "revoked_agents": sorted(self.revoked_agents),
            "spent_nonces": sorted(self.spent_nonces),
            "checkpoint_indices": self.checkpoint_indices,
            "vendors": self.vendors,
            "sig_alg": self.sig_alg,
            "fmt_ver": self.fmt_ver
        }
        if self.principals is not None:
            d["principals"] = self.principals
        return json.dumps(d, sort_keys=True).encode('utf-8')


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
        self.vendors: Dict[str, VendorEnrollment] = {}

    def _purge_old_nonces(self):
        now = time.time()
        self.spent_nonces = {
            n: t for n, t in self.spent_nonces.items() if now - t <= NONCE_TTL_SECONDS
        }

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

    def enroll_vendor(self, entity_ref: str, public_key: str, possession_proof: str, identity_proof_ref: str, challenge_nonce: str) -> None:
        if not identity_proof_ref:
            raise ValueError("identity_proof_ref is required.")
        if challenge_nonce in self.spent_nonces:
            raise ValueError("challenge nonce already used.")
        if entity_ref in self.vendors:
            raise ValueError(f"Vendor '{entity_ref}' has already been bound.")
            
        signed = f"{challenge_nonce}:{entity_ref}".encode("utf-8")
        try:
            sig_bytes = bytes.fromhex(possession_proof)
            pub_bytes = bytes.fromhex(public_key)
            sig_alg = getattr(self.key_custody, "sig_alg", "ML-DSA-87")
            if not MLDSASigner.verify(sig_alg, pub_bytes, signed, sig_bytes):
                raise ValueError("Proof of possession failed.")
        except Exception as e:
            raise ValueError(f"Invalid proof of possession: {str(e)}")

        # Mark the challenge nonce as spent so it can't be reused for possession proofs
        self.spend_nonce(challenge_nonce)

        self.version += 1
        self.vendors[entity_ref] = VendorEnrollment(
            entity_ref=entity_ref,
            public_key=public_key,
            status=VendorStatus.ACTIVE,
            enrolled_at=time.time(),
            enrolled_by="central_authority",
            identity_proof_ref=identity_proof_ref,
            sig_alg=getattr(self.key_custody, "sig_alg", "ML-DSA-87"),
            fmt_ver=1,
            version=self.version
        )

    def revoke_vendor(self, entity_ref: str) -> None:
        if entity_ref not in self.vendors:
            raise ValueError(f"Vendor '{entity_ref}' not found.")
        self.vendors[entity_ref].status = VendorStatus.REVOKED
        self.version += 1

    def enroll_principal(self, principal_ref: str, public_key: str, possession_proof: str, identity_proof_ref: str, challenge_nonce: str) -> None:
        if not identity_proof_ref:
            raise ValueError("identity_proof_ref is required.")
        if challenge_nonce in self.spent_nonces:
            raise ValueError("challenge nonce already used.")
        if principal_ref in getattr(self, 'principals', {}):
            raise ValueError(f"Principal '{principal_ref}' has already been bound.")
            
        signed = f"{challenge_nonce}:{principal_ref}".encode("utf-8")
        try:
            sig_bytes = bytes.fromhex(possession_proof)
            pub_bytes = bytes.fromhex(public_key)
            sig_alg = getattr(self.key_custody, "sig_alg", "ML-DSA-87")
            if not MLDSASigner.verify(sig_alg, pub_bytes, signed, sig_bytes):
                raise ValueError("Proof of possession failed.")
        except Exception as e:
            raise ValueError(f"Invalid proof of possession: {str(e)}")

        self.spend_nonce(challenge_nonce)

        self.version += 1
        if not hasattr(self, 'principals'):
            self.principals = {}
        self.principals[principal_ref] = PrincipalEnrollment(
            principal_ref=principal_ref,
            public_key=public_key,
            status=VendorStatus.ACTIVE,
            enrolled_at=time.time(),
            enrolled_by="central_authority",
            identity_proof_ref=identity_proof_ref,
            sig_alg=getattr(self.key_custody, "sig_alg", "ML-DSA-87"),
            fmt_ver=1,
            version=self.version
        )

    def revoke_principal(self, principal_ref: str) -> None:
        if not hasattr(self, 'principals') or principal_ref not in self.principals:
            raise ValueError(f"Principal '{principal_ref}' not found.")
        self.principals[principal_ref].status = VendorStatus.REVOKED
        self.version += 1

    def rotate_vendor_key(self, *args, **kwargs):
        raise NotImplementedError("rotate_vendor_key is stubbed out for this round.")

    def snapshot(self) -> RegistrySnapshot:
        self._purge_old_nonces()
        # Collect all active and revoked epochs from key custody
        epochs_dict = {}
        for epoch_n, pub in self.key_custody.get_all_epoch_public_keys().items():
            epochs_dict[str(epoch_n)] = pub.hex()

        revoked_epochs = list(self.key_custody.get_revoked_epochs())

        snap = RegistrySnapshot(
            version=self.version,
            issued_at=time.time(),
            epochs=epochs_dict,
            revoked_epochs=revoked_epochs,
            revoked_agents=list(self.revoked_agents),
            spent_nonces=list(self.spent_nonces.keys()),
            checkpoint_indices=self.checkpoint_indices.copy(),
            vendors={k: asdict(v) for k, v in self.vendors.items()},
            principals={k: asdict(v) for k, v in getattr(self, 'principals', {}).items()},
            sig_alg=getattr(self.key_custody, "sig_alg", "ML-DSA-87"),
            fmt_ver=1
        )
        # Sign the payload using the root private key via the custody interface
        snap.root_sig_hex = self.key_custody.sign_root(snap.payload()).hex()
        
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
        # nonce -> time it was observed as spent. Mirrors CentralRegistryAuthority so the
        # set can actually expire; a plain set could only ever grow, because merging from
        # snapshots never removes anything. Membership tests (`nonce in spent_nonces`)
        # behave identically on a dict, so the verifier is unaffected.
        self.spent_nonces: Dict[str, float] = {}
        self.checkpoint_indices = {}
        
        if self.central_sync is None and not local_only:
            raise ValueError("central_sync is required for cross-replica replay protection. Pass local_only=True to explicitly opt-out for testing.")
            
        if local_only and self.central_sync is None:
            from kormic.logger import kormic_logger
            kormic_logger.warning("REPLICA_INIT", f"REPLICA:{self.region}", "DANGER: central_sync is None. Replay protection is running in LOCAL-ONLY mode. Cross-replica replays are possible!")

    def _purge_old_nonces(self) -> None:
        now = time.time()
        self.spent_nonces = {
            n: t for n, t in self.spent_nonces.items() if now - t <= NONCE_TTL_SECONDS
        }

    def _merge_spent_nonces(self, incoming: List[str], observed_at: float) -> None:
        """
        Merges snapshot nonces into the local set, never replacing it.

        Replacement is the bug this exists to prevent: spends don't bump the snapshot
        version, so snapshot ordering doesn't track nonce causality, and a snapshot cut
        before a local spend but delivered after it would erase that spend and reopen the
        replay window. Both apply_snapshot paths (same-version and version-bump) must go
        through here for that reason.

        Locally-recorded timestamps win over the snapshot's, because a local spend is the
        exact moment; for nonces we learn about from a peer we use the snapshot's issue
        time, which is never earlier than the real spend and so only ever errs toward
        remembering slightly longer.
        """
        for nonce in incoming:
            if nonce not in self.spent_nonces:
                self.spent_nonces[nonce] = observed_at
        self._purge_old_nonces()

    def spend_nonce(self, nonce: str) -> None:
        """Saves locally and pushes upstream to central authority if connected."""
        self.spent_nonces[nonce] = time.time()
        self._purge_old_nonces()
        if self.central_sync:
            self.central_sync.spend_nonce(nonce)

    def apply_snapshot(self, snap: RegistrySnapshot) -> bool:
        """
        Applies a snapshot. Accepts same version if strictly newer timestamp to sync nonces.
        """
        from kormic.logger import kormic_logger
        
        # 1. Verify Crypto-Agility Allowlist
        try:
            from kormic.crypto.agility import require_allowed_algorithm
            require_allowed_algorithm(snap.sig_alg)
            if snap.fmt_ver is None:
                raise ValueError("Missing fmt_ver field.")
        except ValueError as e:
            kormic_logger.error("SNAPSHOT_PULL", f"REPLICA:{self.region}", f"Snapshot crypto-agility rejected: {e}")
            return False

        # 2. Verify Signature
        if not MLDSASigner.verify(snap.sig_alg, self.root_pub_key, snap.payload(), bytes.fromhex(snap.root_sig_hex)):
            kormic_logger.error("SNAPSHOT_PULL", f"REPLICA:{self.region}", "Snapshot rejected: Invalid Root Signature (Forgery detected!)")
            return False
            
        # 3. Check Version and Freshness
        if self.snapshot:
            if snap.version < self.snapshot.version:
                kormic_logger.warning("SNAPSHOT_PULL", f"REPLICA:{self.region}", f"Snapshot rejected: Version {snap.version} is older than current {self.snapshot.version}")
                return False
            elif snap.version == self.snapshot.version:
                if snap.issued_at <= self.snapshot.issued_at:
                    return False
                # Fast-path for non-version-bumping updates (nonces).
                self._merge_spent_nonces(snap.spent_nonces, snap.issued_at)
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
            
        # Merge, never replace — same reasoning as the same-version path above. A
        # revocation bumps the version, so this branch is reachable with a snapshot that
        # was cut before a local spend; replacing here would erase it.
        self._merge_spent_nonces(snap.spent_nonces, snap.issued_at)
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

    def get_enrolled_vendor(self, entity_ref: str) -> Optional[str]:
        if not self.snapshot:
            return None
        vendor_dict = self.snapshot.vendors.get(entity_ref)
        if vendor_dict and vendor_dict.get('status') == VendorStatus.ACTIVE:
            return vendor_dict
        return None

    def get_enrolled_principal(self, principal_ref: str) -> Optional[dict]:
        if not self.snapshot or not self.snapshot.principals:
            return None
        principal_dict = self.snapshot.principals.get(principal_ref)
        if principal_dict and principal_dict.get('status') == VendorStatus.ACTIVE:
            return principal_dict
        return None
