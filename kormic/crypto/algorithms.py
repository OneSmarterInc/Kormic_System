from typing import Tuple
from dilithium_py.ml_dsa import ML_DSA_44

class MLDSASigner:
    """Real ML-DSA-44 (FIPS 204) post-quantum signatures."""
    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        pk, sk = ML_DSA_44.keygen()
        return sk, pk                      # (private, public) — matches existing order
    
    @staticmethod
    def sign(private_key_bytes: bytes, message: bytes) -> bytes:
        return ML_DSA_44.sign(private_key_bytes, message)
    
    @staticmethod
    def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return ML_DSA_44.verify(public_key_bytes, message, signature)
        except Exception:
            return False
