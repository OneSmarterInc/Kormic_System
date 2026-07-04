import os
from typing import List, Dict, Tuple
from kormic.interfaces.keys import KeyCustody, Share
from kormic.crypto.algorithms import MLDSASigner
from Crypto.Protocol.SecretSharing import Shamir
from kormic.utils.exceptions import CryptographicError

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
    """
    def __init__(self):
        # DEV_KEY_NOT_PRODUCTION
        # Root key pair initialization
        self._root_priv, self._root_pub = MLDSASigner.generate_keypair()
        # Holds epoch private/public keys mapping: epoch_num -> (priv, pub)
        self._epoch_keys: Dict[int, Tuple[bytes, bytes]] = {}
        # Certified epoch verification keys (signed certificates)
        self._epoch_certificates: Dict[int, bytes] = {}
        # Revoked epochs set
        self._revoked_epochs = set()

    def generate_epoch_key(self, epoch_n: int) -> Tuple[bytes, bytes]:
        """
        Generates and signs a certificate for a new epoch using the Root key.
        Satisfies Section 5.5 & 6.
        """
        # DEV_KEY_NOT_PRODUCTION
        priv, pub = MLDSASigner.generate_keypair()
        self._epoch_keys[epoch_n] = (priv, pub)
        
        # Certified verification payload: certifies that pub belongs to epoch_n
        cert_payload = f"EPOCH_CERTIFICATE:{epoch_n}:".encode('utf-8') + pub
        epoch_certificate = MLDSASigner.sign(self._root_priv, cert_payload)
        self._epoch_certificates[epoch_n] = epoch_certificate
        return priv, pub

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
        return MLDSASigner.verify(self._root_pub, cert_payload, cert)

    def sign_birth(self, epoch_n: int, payload: bytes) -> bytes:
        """Signs birth record payload via epoch private key."""
        # DEV_KEY_NOT_PRODUCTION
        if epoch_n in self._revoked_epochs:
            raise CryptographicError(f"Cannot sign birth record: Epoch {epoch_n} has been revoked.")
        if epoch_n not in self._epoch_keys:
            raise CryptographicError(f"No signing key available for epoch: {epoch_n}")
        
        priv_key = self._epoch_keys[epoch_n][0]
        return MLDSASigner.sign(priv_key, payload)

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
