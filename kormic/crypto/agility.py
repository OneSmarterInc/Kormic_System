ALLOWED_SIG_ALGS = ["ML-DSA-44", "ML-DSA-87"]

def require_allowed_algorithm(sig_alg: str):
    """
    Enforces the Crypto-Agility Allowlist.
    Prevents cryptographic downgrade attacks by refusing to process signatures
    whose declared algorithm is not on the explicitly approved list.
    """
    if not sig_alg:
        raise ValueError("Missing sig_alg field. Hard cutover enforced.")
    if sig_alg not in ALLOWED_SIG_ALGS:
        raise ValueError(f"Signature algorithm '{sig_alg}' is not on the allowed list.")
