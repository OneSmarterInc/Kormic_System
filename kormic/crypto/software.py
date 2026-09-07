import os
import hashlib
import time
from typing import List, Dict, Tuple, Any
from collections import defaultdict
from kormic.interfaces.keys import KeyCustody, Share
from kormic.crypto.algorithms import MLDSASigner
from Crypto.Protocol.SecretSharing import Shamir
from kormic.utils.exceptions import CryptographicError
from kormic.runtime.detection import DetectionSink, DetectionEvent

# DEV SEAM: This class is currently a dev-grade seam, not a hardened quorum.
# Phase 3 Hardening Requirements:
# 1. Nonce-binding: Approvals must be bound to a fresh, single-use challenge (nonce), 
#    and the operation key must carry this challenge to prevent replay attacks.
# 2. Allowlist checking: The approve path must run the algorithm through the 
#    CryptoAgility allowlist rather than hardcoding it.
class ThresholdPolicy:
    def __init__(self, k: int, n: int, enrolled_holders: Dict[str, Any] = None, detection_sink: DetectionSink = None):
        self.k = k
        self.n = n
        self.enrolled_holders = enrolled_holders or {}
        self.detection_sink = detection_sink
        self.approvals = defaultdict(set) # operation_key -> set of holder_ids
        self.spent_nonces = set()
        
    def approve(self, op_key: str, holder_id: str, signature: bytes, challenge_nonce: str):
        """
        Records an approval. The approval must carry a cryptographic proof that the approver
        holds a genuine share (a signature over the op_key by the holder's key).
        """
        if holder_id not in self.enrolled_holders:
            raise PermissionError(f"Holder {holder_id} is not enrolled in the threshold policy.")
        if not signature:
            raise PermissionError("Unsigned approvals are rejected.")
            
        if challenge_nonce in self.spent_nonces:
            raise PermissionError("Challenge nonce already spent.")
            
        holder_info = self.enrolled_holders[holder_id]
        if isinstance(holder_info, bytes):
            pub_key = holder_info
            sig_alg = "ML-DSA-87"
        else:
            pub_key = holder_info["public_key"]
            sig_alg = holder_info["sig_alg"]
            
        from kormic.crypto.agility import require_allowed_algorithm
        require_allowed_algorithm(sig_alg)
            
        if not MLDSASigner.verify(sig_alg, pub_key, op_key.encode('utf-8'), signature):
            raise PermissionError(f"Invalid signature for holder {holder_id}.")
            
        self.approvals[op_key].add(holder_id)
        
    def check_and_consume(self, op_name: str, op_key: str, challenge_nonce: str) -> bool:
        if challenge_nonce in self.spent_nonces:
            raise PermissionError("Challenge nonce already spent.")
            
        holders = self.approvals.get(op_key, set())
        if len(holders) >= self.k:
            del self.approvals[op_key]
            self.spent_nonces.add(challenge_nonce)
            if self.detection_sink:
                self.detection_sink.emit(DetectionEvent(
                    event_kind="root_operation_success",
                    identity="threshold_quorum",
                    action_target=op_name,
                    reason=f"Operation {op_name} executed with quorum of {len(holders)}",
                    mode="enforced",
                    timestamp=time.time(),
                    severity="info"
                ))
            return True
            
        if self.detection_sink:
            self.detection_sink.emit(DetectionEvent(
                event_kind="root_operation_refused",
                identity="single_party",
                action_target=op_name,
                reason=f"Operation {op_name} refused: has {len(holders)} approvals, needs {self.k}",
                mode="enforced",
                timestamp=time.time(),
                severity="critical"
            ))
        return False

# DEV_KEY_NOT_PRODUCTION

class SoftwareShare:
    """
    Software implementation of a Shamir Secret Share.
    Satisfies Section 4.3 (Share protocol).
    """
    def __init__(self, index: int, data: bytes):
        self._index = index
        self._data = data

    @property
    def share_index(self) -> int:
        return self._index

    @property
    def share_data(self) -> bytes:
        return self._data

class SoftwareKeyCustody(KeyCustody):
    """
    Software implementation of KeyCustody for Phase 1.
    All keys are held in memory. Real HSM/threshold isolation is swapped in Phase 3.
    
    PRODUCTION INVARIANT: `SoftwareKeyCustody` is disabled in production. Future hardware
    backends must explicitly enforce that `threshold_policy` is not None.
    """
    def __init__(self, sig_alg: str = "ML-DSA-87", hash_alg: str = "SHA-256", threshold_policy: ThresholdPolicy = None):
        if os.environ.get("KORMIC_DEPLOYMENT_MODE", "").lower() == "production":
            raise CryptographicError(
                "DEV_KEY_NOT_PRODUCTION: SoftwareKeyCustody cannot be used in production mode. "
                "A real key custody, hardware-backed or threshold, is required."
            )
            
        self.sig_alg = sig_alg
        self.hash_alg = hash_alg
        self.threshold_policy = threshold_policy
        # DEV_KEY_NOT_PRODUCTION
        # Root key pair initialization
        self._root_priv, self._root_pub = MLDSASigner.generate_keypair(self.sig_alg)
        # Holds epoch private/public keys mapping: epoch_num -> (priv, pub)
        self._epoch_keys: Dict[int, Tuple[bytes, bytes]] = {}
        # Certified epoch verification keys (signed certificates)
        self._epoch_certificates: Dict[int, bytes] = {}
        # Revoked epochs set
        self._revoked_epochs = set()

    def generate_epoch_key(self, epoch_n: int, challenge_nonce: str = None) -> None:
        """
        [Root] Generates and signs a certificate for a new epoch using the Root key.
        Satisfies Section 5.5 & 6.
        """
        if self.threshold_policy:
            if not challenge_nonce:
                raise PermissionError("Threshold policy requires a challenge_nonce")
            op_key = f"generate_epoch_key_{epoch_n}:{challenge_nonce}"
            if not self.threshold_policy.check_and_consume("generate_epoch_key", op_key, challenge_nonce):
                raise PermissionError(f"Root operation generate_epoch_key refused: missing threshold quorum")
        
        # DEV_KEY_NOT_PRODUCTION
        priv, pub = MLDSASigner.generate_keypair(self.sig_alg)
        self._epoch_keys[epoch_n] = (priv, pub)
        
        # Certified verification payload: certifies that pub belongs to epoch_n
        cert_payload = f"EPOCH_CERTIFICATE:{epoch_n}:".encode('utf-8') + pub
        epoch_certificate = MLDSASigner.sign(self.sig_alg, self._root_priv, cert_payload)
        self._epoch_certificates[epoch_n] = epoch_certificate

    def get_epoch_certificate(self, epoch_n: int) -> bytes:
        """Retrieves root-signed certificate for epoch verification key validation."""
        if epoch_n not in self._epoch_certificates:
            raise CryptographicError(f"No certificate found for epoch {epoch_n}")
        return self._epoch_certificates[epoch_n]

    def verify_epoch_certificate(self, epoch_n: int, public_key: bytes) -> bool:
        """Verifies if the public key for an epoch is certified by the Root key."""
        if epoch_n not in self._epoch_certificates:
            return False
        cert = self._epoch_certificates[epoch_n]
        cert_payload = f"EPOCH_CERTIFICATE:{epoch_n}:".encode('utf-8') + public_key
        return MLDSASigner.verify(self.sig_alg, self._root_pub, cert_payload, cert)

    def sign_birth(self, epoch_n: int, payload: bytes) -> bytes:
        """Signs birth record payload via epoch private key."""
        # DEV_KEY_NOT_PRODUCTION
        if epoch_n in self._revoked_epochs:
            raise CryptographicError(f"Cannot sign birth record: Epoch {epoch_n} has been revoked.")
        if epoch_n not in self._epoch_keys:
            raise CryptographicError(f"No signing key available for epoch: {epoch_n}")
        
        priv_key = self._epoch_keys[epoch_n][0]
        return MLDSASigner.sign(self.sig_alg, priv_key, payload)

    def epoch_public(self, epoch_n: int) -> bytes:
        """Retrieves public key for verifying signature issued during epoch_n."""
        if epoch_n not in self._epoch_keys:
            raise CryptographicError(f"No key pair registered for epoch: {epoch_n}")
        return self._epoch_keys[epoch_n][1]

    def revoke_epoch(self, epoch_n: int) -> None:
        """Revokes an epoch, rendering keys and agents registered under it invalid."""
        self._revoked_epochs.add(epoch_n)

    def is_epoch_revoked(self, epoch_n: int) -> bool:
        return epoch_n in self._revoked_epochs

    def get_root_public_key(self) -> bytes:
        return self._root_pub

    def sign_root(self, payload: bytes, challenge_nonce: str = None) -> bytes:
        """[Root] Signs a payload using the master root private key (e.g., for registry snapshots)."""
        if self.threshold_policy:
            if not challenge_nonce:
                raise PermissionError("Threshold policy requires a challenge_nonce")
            payload_hash = hashlib.sha256(payload).hexdigest()
            op_key = f"sign_root:{payload_hash}:{challenge_nonce}"
            if not self.threshold_policy.check_and_consume("sign_root", op_key, challenge_nonce):
                raise PermissionError(f"Root operation sign_root refused: missing threshold quorum")
        # DEV_KEY_NOT_PRODUCTION
        return MLDSASigner.sign(self.sig_alg, self._root_priv, payload)

    def get_all_epoch_public_keys(self) -> Dict[int, bytes]:
        return {epoch_n: pub for epoch_n, (_, pub) in self._epoch_keys.items()}

    def get_revoked_epochs(self) -> set:
        return set(self._revoked_epochs)

    # Shamir Secret Sharing polynomial interpolation wrapper (Galois Field GF(256))
    # Satisfies Section 8.3 (k-of-n Shamir threshold split logic)
    
    def wrap_twin_key(self, key: bytes) -> List[Share]:
        # DEV_KEY_NOT_PRODUCTION
        assert len(key) == 32
        lo = Shamir.split(3, 5, key[:16])
        hi = Shamir.split(3, 5, key[16:])
        return [SoftwareShare(idx, l + h) for (idx, l), (_, h) in zip(lo, hi)]

    def unwrap_twin_key(self, shares: List[Share]) -> bytes:
        # DEV_KEY_NOT_PRODUCTION
        if len(shares) < 3:
            raise CryptographicError(f"Quorum not met: need 3, got {len(shares)}")
        lo = Shamir.combine([(s.share_index, s.share_data[:16]) for s in shares])
        hi = Shamir.combine([(s.share_index, s.share_data[16:]) for s in shares])
        return lo + hi
