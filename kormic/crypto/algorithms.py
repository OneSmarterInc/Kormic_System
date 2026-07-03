import os
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# DEV_KEY_NOT_PRODUCTION
# This module implements a portable post-quantum ML-DSA signature envelope mockup.
# It wraps standard Ed25519 asymmetric signing inside a custom ML-DSA-44 envelope.
# In Phase 3, this file will be swapped to use native liboqs (FIPS 204 ML-DSA-44).

class MLDSASignerMock:
    """
    Mock wrapper representing an ML-DSA-44 signer.
    Uses Ed25519 keys internally and wraps signatures inside an ML-DSA-44 envelope.
    """
    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Generates an asymmetric keypair (private_bytes, public_bytes)."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes_raw()
        public_bytes = private_key.public_key().public_bytes_raw()
        return private_bytes, public_bytes

    @staticmethod
    def sign(private_key_bytes: bytes, message: bytes) -> bytes:
        """Signs a message using the private key."""
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        raw_signature = private_key.sign(message)
        
        envelope_prefix = b"ML-DSA-44-SIG-DEV-MOCK\x00"
        return envelope_prefix + raw_signature

    @staticmethod
    def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        """Verifies signature authenticity against the public key."""
        envelope_prefix = b"ML-DSA-44-SIG-DEV-MOCK\x00"
        if not signature.startswith(envelope_prefix):
            return False
        
        raw_signature = signature[len(envelope_prefix):]
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        
        try:
            public_key.verify(raw_signature, message)
            return True
        except InvalidSignature:
            return False

