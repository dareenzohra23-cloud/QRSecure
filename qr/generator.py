import io
import json
import uuid
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple
import qrcode
from qrcode.image.pil import PilImage

from config import Config
from crypto.hashing import canonicalize_payload, calculate_sha256
from crypto.signer import sign_payload
from database.models import generate_next_qr_id, save_qr_code, get_active_authority

def build_signed_payload(
    qr_type: str,
    data_dict: Dict[str, Any],
    expires_at_iso: Optional[str] = None,
    is_one_time: bool = False,
    custom_qr_id: Optional[str] = None
) -> Tuple[Dict[str, Any], str, str, str]:
    """
    Constructs and cryptographically signs a QR payload.
    
    Returns:
    (final_payload_dict, canonical_json_string, sha256_hash, base64_signature)
    """
    qr_id = custom_qr_id if custom_qr_id else generate_next_qr_id()
    
    # Obtain issuer name from authority
    authority = get_active_authority()
    issuer_name = authority['authority_name'] if authority else Config.DEFAULT_AUTHORITY_NAME
    
    now = datetime.now(timezone.utc)
    issued_at = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    if not expires_at_iso:
        # Default validity: 1 year
        expires_at = (now + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%SZ')
    else:
        expires_at = expires_at_iso

    # Assemble canonical structure (excluding the signature itself)
    signing_payload: Dict[str, Any] = {
        "version": "1.0",
        "qr_id": qr_id,
        "issuer": issuer_name,
        "type": qr_type,
        "data": data_dict,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "signature_algorithm": Config.KEY_ALGORITHM
    }

    if is_one_time:
        signing_payload["nonce"] = uuid.uuid4().hex[:16]

    # Step 1: Canonicalize
    canonical_str = canonicalize_payload(signing_payload)

    # Step 2: Compute SHA-256 fingerprint
    payload_hash = calculate_sha256(canonical_str)

    # Step 3: Sign using RSA-2048 private key
    signature = sign_payload(canonical_str)

    # Step 4: Construct final transport payload
    final_payload = dict(signing_payload)
    final_payload["signature"] = signature

    return final_payload, canonical_str, payload_hash, signature

def generate_qr_image_base64(json_str: str) -> str:
    """
    Encodes JSON string into a high-contrast, clean QR code image (PNG),
    returning a base64 Data URI for inline display in HTML.
    """
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=3,
    )
    qr.add_data(json_str)
    qr.make(fit=True)

    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_b64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{img_b64}"

def generate_secure_qr(
    qr_type: str,
    data_dict: Dict[str, Any],
    expires_at_iso: Optional[str] = None,
    is_one_time: bool = False,
    save_to_db: bool = True
) -> Dict[str, Any]:
    """
    End-to-end QR generation pipeline:
    1. Builds signed payload
    2. Generates deterministic QR image
    3. Saves record into SQLite
    4. Returns payload + image + verification metadata
    """
    final_payload, canonical_str, payload_hash, signature = build_signed_payload(
        qr_type=qr_type,
        data_dict=data_dict,
        expires_at_iso=expires_at_iso,
        is_one_time=is_one_time
    )

    json_payload_str = json.dumps(final_payload, indent=2)
    minified_json_str = json.dumps(final_payload, separators=(',', ':'))
    
    # Generate QR image encoding the minified JSON
    qr_image_uri = generate_qr_image_base64(minified_json_str)

    qr_id = final_payload["qr_id"]
    issuer = final_payload["issuer"]
    issued_at = final_payload["issued_at"]
    expires_at = final_payload["expires_at"]

    if save_to_db:
        save_qr_code(
            qr_id=qr_id,
            qr_type=qr_type,
            payload_json=json_payload_str,
            payload_hash=payload_hash,
            signature=signature,
            issuer=issuer,
            issued_at=issued_at,
            expires_at=expires_at,
            status='ACTIVE',
            is_one_time=1 if is_one_time else 0
        )

    return {
        "success": True,
        "qr_id": qr_id,
        "type": qr_type,
        "issuer": issuer,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "is_one_time": is_one_time,
        "signature_algorithm": final_payload["signature_algorithm"],
        "payload_hash": payload_hash,
        "signature": signature,
        "canonical_str": canonical_str,
        "json_payload": json_payload_str,
        "minified_json": minified_json_str,
        "qr_image_uri": qr_image_uri,
        "data": data_dict
    }
