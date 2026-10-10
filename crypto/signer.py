import base64
from typing import Union, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .key_manager import KeyManager

def sign_payload(
    canonical_data: Union[str, bytes], 
    private_key: Optional[rsa.RSAPrivateKey] = None
) -> str:
    """
    Cryptographically signs the canonical payload using RSA-2048 with SHA-256 (PKCS#1 v1.5).
    
    Security flow:
    1. canonical_data (bytes)
    2. Hashes with SHA-256 internally during RSA signing
    3. Generates 256-byte digital signature
    4. Base64 encodes signature for standard JSON transport
    
    Returns: Base64-encoded signature string.
    """
    if private_key is None:
        km = KeyManager()
        private_key = km.load_private_key()
        
    if isinstance(canonical_data, str):
        data_bytes = canonical_data.encode('utf-8')
    elif isinstance(canonical_data, bytes):
        data_bytes = canonical_data
    else:
        raise TypeError("canonical_data must be a str or bytes")
        
    # Sign using RSA-PKCS1v15 with SHA-256
    raw_signature = private_key.sign(
        data_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Return Base64 encoded signature
    return base64.b64encode(raw_signature).decode('utf-8')
