from typing import Tuple
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

_SUITES = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}

class MLDSASigner:
    """
    Real ML-DSA (FIPS 204) post-quantum signatures.
    
    WARNING: DEV-GRADE ONLY. NOT FOR PRODUCTION.
    This implementation uses dilithium_py, which is a pure-Python reference implementation.
    While correct, it is not constant-time and not side-channel hardened.
    
    For a production deployment, this module must be swapped out for a native, hardened 
    implementation (such as a liboqs binding) that provides:
    1. Constant-time operations
    2. A vetted, cryptographically secure RNG
    3. Fault resistance
    """
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
