import base64
from typing import Union, Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

from .key_manager import KeyManager

def verify_signature(
    canonical_data: Union[str, bytes],
    signature_base64: str,
    public_key: Optional[Union[rsa.RSAPublicKey, str]] = None
) -> Tuple[bool, str]:
    """
    Verifies RSA-SHA256 digital signature of canonical payload data against an RSA public key.
    
    Parameters:
    - canonical_data: The deterministic byte/string representation of signed payload
    - signature_base64: The Base64-encoded digital signature
    - public_key: RSAPublicKey instance or PEM string. If None, uses local authority public key.
    
    Returns:
    - (True, "Signature verified successfully") if valid
    - (False, "<detailed reason>") if verification fails
    """
    if not signature_base64 or not isinstance(signature_base64, str):
        return False, "Missing or invalid signature format"
        
    # Resolve public key
    km = KeyManager()
    if public_key is None:
        pub_key_obj = km.load_public_key()
    elif isinstance(public_key, str):
        try:
            pub_key_obj = km.load_public_key_from_pem(public_key)
        except Exception as e:
            return False, f"Failed to parse public key PEM: {str(e)}"
    elif isinstance(public_key, rsa.RSAPublicKey):
        pub_key_obj = public_key
    else:
        return False, "Unsupported public key object type"

    # Decode base64 signature
    try:
        raw_signature = base64.b64decode(signature_base64.strip())
    except Exception as e:
        return False, f"Base64 decoding failed for signature: {str(e)}"

    # Ensure bytes
    if isinstance(canonical_data, str):
        data_bytes = canonical_data.encode('utf-8')
    elif isinstance(canonical_data, bytes):
        data_bytes = canonical_data
    else:
        return False, "Invalid canonical data format (must be str or bytes)"

    # Cryptographic verification
    try:
        pub_key_obj.verify(
            raw_signature,
            data_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True, "Digital signature is cryptographically valid (RSA-2048 / SHA-256)"
    except InvalidSignature:
        return False, "Signature verification failed: Data payload has been tampered with or signature does not match issuer's public key"
    except Exception as e:
        return False, f"Cryptographic verification error: {str(e)}"
