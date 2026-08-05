from typing import Tuple
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

_SUITES = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}

class MLDSASigner:
    """Real ML-DSA (FIPS 204) post-quantum signatures."""
    @staticmethod
    def generate_keypair(sig_alg: str) -> Tuple[bytes, bytes]:
        pk, sk = _SUITES[sig_alg].keygen()
        return sk, pk
    
    @staticmethod
    def sign(sig_alg: str, private_key_bytes: bytes, message: bytes) -> bytes:
        return _SUITES[sig_alg].sign(private_key_bytes, message)
    
    @staticmethod
    def verify(sig_alg: str, public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        suite = _SUITES.get(sig_alg)
        if suite is None:
            return False
        try:
            return suite.verify(public_key_bytes, message, signature)
        except Exception:
            return False
