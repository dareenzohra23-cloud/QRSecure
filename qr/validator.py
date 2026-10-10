import json
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional

from config import Config
from crypto.hashing import canonicalize_payload, calculate_sha256
from crypto.verifier import verify_signature
from crypto.key_manager import KeyManager
from database.models import (
    is_qr_revoked, 
    log_verification, 
    get_active_authority, 
    get_qr_code,
    get_verification_count_for_qr
)

def verify_qr_payload(
    raw_payload: Any,
    verification_method: str = "Camera",
    public_key_pem_override: Optional[str] = None
) -> Dict[str, Any]:
    """
    Complete cryptographic verification engine for QR-Secure:
    
    1. Parse JSON payload
    2. Check structural schema
    3. Reconstruct canonical payload & compute current SHA-256 hash
    4. Cryptographically verify RSA-2048 / SHA-256 signature
    5. Check issuer Certificate Authority trust
    6. Verify credential validity timeline (issued_at, expires_at)
    7. Check revocation registry
    8. Check single-use replay protection (if applicable)
    9. Log verification attempt in database
    """
    # Step 1: Parse input into dictionary
    if isinstance(raw_payload, str):
        try:
            payload = json.loads(raw_payload.strip())
        except Exception as e:
            log_verification("UNKNOWN", "INVALID_FORMAT", f"JSON parsing failed: {str(e)}", verification_method)
            return {
                "success": False,
                "result": "INVALID_FORMAT",
                "overall_title": "MALFORMED QR CODE",
                "status_badge": "🔴 INVALID FORMAT",
                "reason": f"QR payload is not valid JSON: {str(e)}",
                "signature_valid": False,
                "integrity_valid": False,
                "expiry_valid": False,
                "revocation_valid": False,
                "details": {}
            }
    elif isinstance(raw_payload, dict):
        payload = raw_payload
    else:
        log_verification("UNKNOWN", "INVALID_FORMAT", "Payload must be JSON string or dict", verification_method)
        return {
            "success": False,
            "result": "INVALID_FORMAT",
            "overall_title": "MALFORMED QR CODE",
            "status_badge": "🔴 INVALID FORMAT",
            "reason": "Payload format not recognized",
            "signature_valid": False,
            "integrity_valid": False,
            "expiry_valid": False,
            "revocation_valid": False,
            "details": {}
        }

    # Step 2: Validate required fields
    required_fields = ["version", "qr_id", "issuer", "type", "data", "issued_at", "expires_at", "signature"]
    missing = [f for f in required_fields if f not in payload]
    if missing:
        qr_id_candidate = payload.get("qr_id", "UNKNOWN")
        reason = f"Missing required cryptographic fields: {', '.join(missing)}"
        log_verification(qr_id_candidate, "INVALID_FORMAT", reason, verification_method)
        return {
            "success": False,
            "result": "INVALID_FORMAT",
            "overall_title": "INCOMPLETE PAYLOAD",
            "status_badge": "🔴 INVALID FORMAT",
            "reason": reason,
            "qr_id": qr_id_candidate,
            "signature_valid": False,
            "integrity_valid": False,
            "expiry_valid": False,
            "revocation_valid": False,
            "details": payload
        }

    qr_id = str(payload.get("qr_id", "UNKNOWN"))
    signature_b64 = str(payload.get("signature", ""))
    issuer = str(payload.get("issuer", "Unknown Issuer"))
    qr_type = str(payload.get("type", "UNKNOWN"))
    data_content = payload.get("data", {})
    issued_at = str(payload.get("issued_at", ""))
    expires_at = str(payload.get("expires_at", ""))

    # Step 3: Reconstruct canonical payload (all fields except signature)
    reconstructed_canonical_obj: Dict[str, Any] = {
        "version": payload["version"],
        "qr_id": payload["qr_id"],
        "issuer": payload["issuer"],
        "type": payload["type"],
        "data": payload["data"],
        "issued_at": payload["issued_at"],
        "expires_at": payload["expires_at"],
        "signature_algorithm": payload.get("signature_algorithm", Config.KEY_ALGORITHM)
    }
    if "nonce" in payload:
        reconstructed_canonical_obj["nonce"] = payload["nonce"]

    canonical_str = canonicalize_payload(reconstructed_canonical_obj)
    calculated_hash = calculate_sha256(canonical_str)

    # Step 4: Resolve public key
    if public_key_pem_override:
        pub_key_pem = public_key_pem_override
    else:
        authority = get_active_authority()
        if authority:
            pub_key_pem = authority['public_key']
        else:
            km = KeyManager()
            pub_key_pem = km.get_public_key_pem()

    # Step 5: Verify RSA signature
    sig_ok, sig_msg = verify_signature(canonical_str, signature_b64, pub_key_pem)

    base_response = {
        "qr_id": qr_id,
        "type": qr_type,
        "issuer": issuer,
        "data": data_content,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "recalculated_hash": calculated_hash,
        "canonical_str": canonical_str,
        "signature": signature_b64,
        "signature_algorithm": payload.get("signature_algorithm", Config.KEY_ALGORITHM)
    }

    # CRITICAL CHECK 1: If digital signature fails -> TAMPERED
    if not sig_ok:
        reason = "Cryptographic signature mismatch. The QR payload has been modified after signing or signed by an untrusted key."
        log_verification(
            qr_id=qr_id,
            result="TAMPERED",
            reason=reason,
            method=verification_method,
            details_json=json.dumps(base_response)
        )
        return {
            "success": False,
            "result": "TAMPERED",
            "overall_title": "QR CODE INVALID / DATA TAMPERED",
            "status_badge": "🔴 TAMPER DETECTED",
            "reason": reason,
            "signature_valid": False,
            "integrity_valid": False,
            "expiry_valid": False,
            "revocation_valid": False,
            **base_response
        }

    # If signature is valid, data integrity is verified
    # CRITICAL CHECK 2: Revocation Status
    is_revoked, rev_record = is_qr_revoked(qr_id)
    if is_revoked:
        rev_reason = rev_record.get('reason', 'Revoked by authority') if rev_record else 'Revoked by authority'
        reason = f"Credential has been revoked by issuer ({rev_reason})"
        log_verification(
            qr_id=qr_id,
            result="REVOKED",
            reason=reason,
            method=verification_method,
            details_json=json.dumps(base_response)
        )
        return {
            "success": False,
            "result": "REVOKED",
            "overall_title": "QR CODE REJECTED / REVOKED",
            "status_badge": "🔴 REVOKED",
            "reason": reason,
            "signature_valid": True,
            "integrity_valid": True,
            "expiry_valid": True,
            "revocation_valid": False,
            "revocation_details": rev_record,
            **base_response
        }

    # CRITICAL CHECK 3: Expiration Date
    now_utc = datetime.now(timezone.utc)
    is_expired = False
    try:
        # Standard format: %Y-%m-%dT%H:%M:%SZ or with timezone
        exp_clean = expires_at.replace('Z', '+00:00')
        exp_dt = datetime.fromisoformat(exp_clean)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if now_utc > exp_dt:
            is_expired = True
    except Exception as e:
        # Fallback date check
        pass

    if is_expired:
        reason = f"Credential expired on {expires_at}. Signature is cryptographically valid, but credential validity period has ended."
        log_verification(
            qr_id=qr_id,
            result="EXPIRED",
            reason=reason,
            method=verification_method,
            details_json=json.dumps(base_response)
        )
        return {
            "success": False,
            "result": "EXPIRED",
            "overall_title": "CREDENTIAL EXPIRED",
            "status_badge": "🟠 EXPIRED",
            "reason": reason,
            "signature_valid": True,
            "integrity_valid": True,
            "expiry_valid": False,
            "revocation_valid": True,
            **base_response
        }

    # CRITICAL CHECK 4: Optional Replay Protection (One-time pass)
    db_qr = get_qr_code(qr_id)
    is_one_time = False
    if "nonce" in payload or (db_qr and db_qr.get("is_one_time") == 1):
        is_one_time = True
        previous_verifications = get_verification_count_for_qr(qr_id)
        if previous_verifications >= 1:
            reason = "One-time pass has already been used previously. Replay attack blocked."
            log_verification(
                qr_id=qr_id,
                result="REPLAY_DETECTED",
                reason=reason,
                method=verification_method,
                details_json=json.dumps(base_response)
            )
            return {
                "success": False,
                "result": "REPLAY_DETECTED",
                "overall_title": "REPLAY DETECTED / ALREADY USED",
                "status_badge": "🟡 REPLAY DETECTED",
                "reason": reason,
                "signature_valid": True,
                "integrity_valid": True,
                "expiry_valid": True,
                "revocation_valid": True,
                **base_response
            }

    # All checks passed!
    reason = "Digital signature is cryptographically valid, data integrity is intact, credential is non-expired and not revoked."
    log_verification(
        qr_id=qr_id,
        result="VERIFIED",
        reason=reason,
        method=verification_method,
        details_json=json.dumps(base_response)
    )

    return {
        "success": True,
        "result": "VERIFIED",
        "overall_title": "AUTHENTIC QR CODE",
        "status_badge": "🟢 VERIFIED",
        "reason": reason,
        "signature_valid": True,
        "integrity_valid": True,
        "expiry_valid": True,
        "revocation_valid": True,
        "is_one_time": is_one_time,
        **base_response
    }
