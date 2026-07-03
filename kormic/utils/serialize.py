import json
import hashlib
from typing import Any

def canonical_json(data: Any) -> str:
    """
    Serializes a dictionary, list, or value into a sorted, uniform JSON string.
    Ensures that cryptographic hashes match across different systems and operations.
    """
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def sha256_hex(data: str) -> str:
    """Helper to return the SHA256 hex digest of a string payload."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
