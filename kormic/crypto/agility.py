ALLOWED_SIG_ALGS = ["ML-DSA-44", "ML-DSA-87"]
ALLOWED_HASH_ALGS = ["SHA-256"]

def require_allowed_algorithm(sig_alg: str):
    """
    Validates that a cryptographic algorithm is on the hard allowlist.
    Prevents downgrade attacks to broken/legacy primitives.
    """
    if not sig_alg:
        raise ValueError("Missing cryptographic algorithm identifier (sig_alg).")
    if sig_alg not in ALLOWED_SIG_ALGS:
        raise ValueError(f"Algorithm {sig_alg} is not on the ALLOWLIST.")

def require_allowed_hash(hash_alg: str):
    """
    Validates that a hash algorithm is on the hard allowlist.
    Prevents downgrade attacks to broken/legacy primitives like MD5.
    """
    if not hash_alg:
        raise ValueError("Missing hash algorithm identifier (hash_alg).")
    if hash_alg not in ALLOWED_HASH_ALGS:
        raise ValueError(f"Hash Algorithm {hash_alg} is not on the ALLOWLIST.")
