import hashlib
import json
from typing import Any, Dict, Union

def canonicalize_payload(data: Union[Dict[str, Any], Any]) -> str:
    """
    Creates a deterministic (canonical) JSON representation of data.
    Keys are sorted alphabetically and separators have no whitespace.
    This guarantees identical byte outputs for identical semantic structures.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True
    )

def calculate_sha256(data: Union[str, bytes]) -> str:
    """
    Calculates SHA-256 cryptographic hash of canonical data.
    Returns hex digest string (64 characters).
    """
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        raise TypeError("Input must be a string or bytes")
        
    return hashlib.sha256(data_bytes).hexdigest()
