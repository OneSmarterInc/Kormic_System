import json
import hashlib
from typing import Any
from kormic.crypto.agility import require_allowed_hash

# Hash algorithm registry
_HASH_SUITES = {
    "SHA-256": hashlib.sha256,
    "SHA3-256": hashlib.sha3_256,
    "MD5": hashlib.md5  # For downgrade tests only, not in allowlist
}

def canonical_json(data: Any) -> str:
    """
    Serializes a dictionary, list, or value into a sorted, uniform JSON string.
    Ensures that cryptographic hashes match across different systems and operations.
    """
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def hash_hex(hash_alg: str, data) -> str:
    """
    Helper to return the hex digest of a payload using an agile hash algorithm.
    """
    require_allowed_hash(hash_alg)
    suite = _HASH_SUITES.get(hash_alg)
    if suite is None:
        raise ValueError(f"Hash Algorithm {hash_alg} is not implemented.")
    if isinstance(data, str):
        data = data.encode('utf-8')
    return suite(data).hexdigest()

def sha256_hex(data: str) -> str:
    """Helper to return the SHA256 hex digest of a string payload."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
