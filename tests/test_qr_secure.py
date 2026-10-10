import os
import json
import pytest
import copy
from datetime import datetime, timezone, timedelta

from app import create_app
from config import Config
from crypto.hashing import canonicalize_payload, calculate_sha256
from crypto.key_manager import KeyManager
from crypto.signer import sign_payload
from crypto.verifier import verify_signature
from qr.generator import generate_secure_qr, build_signed_payload
from qr.validator import verify_qr_payload
from auth.password import hash_password, verify_password
from database.database import init_db, get_db_connection
from database.models import (
    generate_next_qr_id, 
    save_qr_code, 
    revoke_qr_code, 
    get_qr_code
)

@pytest.fixture(scope="session")
def test_app():
    # Use temporary test database
    test_db = os.path.join(Config.BASE_DIR, 'test_qr_secure.db')
    test_keys_dir = os.path.join(Config.BASE_DIR, 'test_keys')
    
    class TestConfig(Config):
        TESTING = True
        DATABASE_PATH = test_db
        KEYS_DIR = test_keys_dir
        PRIVATE_KEY_PATH = os.path.join(test_keys_dir, 'private_key.pem')
        PUBLIC_KEY_PATH = os.path.join(test_keys_dir, 'public_key.pem')

    app = create_app(TestConfig)
    yield app

    # Cleanup test files
    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except Exception:
            pass
    if os.path.exists(test_keys_dir):
        import shutil
        try:
            shutil.rmtree(test_keys_dir)
        except Exception:
            pass

@pytest.fixture
def client(test_app):
    return test_app.test_client()

# ==========================================
# TEST 1: Correct signature verification
# ==========================================
def test_1_correct_signature_verification(test_app):
    km = KeyManager()
    priv = km.load_private_key()
    pub = km.load_public_key()

    test_data = {"name": "Alice", "usn": "1VTXX001"}
    canon = canonicalize_payload(test_data)
    sig = sign_payload(canon, priv)

    is_valid, reason = verify_signature(canon, sig, pub)
    assert is_valid is True
    assert "cryptographically valid" in reason

# ==========================================
# TEST 2: Incorrect signature rejection
# ==========================================
def test_2_incorrect_signature_rejection(test_app):
    km = KeyManager()
    pub = km.load_public_key()

    test_data = {"name": "Alice", "usn": "1VTXX001"}
    canon = canonicalize_payload(test_data)
    
    # Tampered or bogus base64 signature
    fake_sig = "aW52YWxpZHNpZ25hdHVyZWJvZ3VzZGF0YTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
    is_valid, reason = verify_signature(canon, fake_sig, pub)
    assert is_valid is False

# ==========================================
# TEST 3: Modified payload detection (TAMPER)
# ==========================================
def test_3_modified_payload_detection(test_app):
    with test_app.app_context():
        # Generate valid student QR
        alice_data = {"name": "Alice", "usn": "1VTXX001", "branch": "ISE"}
        res = generate_secure_qr("STUDENT_ID", alice_data, save_to_db=True)
        payload = json.loads(res["json_payload"])

        # Tamper USN to 1VTXX999 while keeping signature
        tampered_payload = copy.deepcopy(payload)
        tampered_payload["data"]["usn"] = "1VTXX999"

        # Verify tampered payload
        ver_result = verify_qr_payload(tampered_payload, verification_method="Test")
        assert ver_result["success"] is False
        assert ver_result["result"] == "TAMPERED"
        assert ver_result["signature_valid"] is False
        assert ver_result["integrity_valid"] is False
        assert "modified after signing" in ver_result["reason"]

# ==========================================
# TEST 4: Expired QR rejection
# ==========================================
def test_4_expired_qr_rejection(test_app):
    with test_app.app_context():
        now = datetime.now(timezone.utc)
        past_time = (now - timedelta(days=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        expired_data = {"name": "Bob", "usn": "1VTXX002"}
        res = generate_secure_qr("STUDENT_ID", expired_data, expires_at_iso=past_time, save_to_db=True)
        payload = json.loads(res["json_payload"])

        ver_result = verify_qr_payload(payload, verification_method="Test")
        assert ver_result["success"] is False
        assert ver_result["result"] == "EXPIRED"
        assert ver_result["signature_valid"] is True  # Signature was valid, but date expired
        assert ver_result["expiry_valid"] is False

# ==========================================
# TEST 5: Revoked QR rejection
# ==========================================
def test_5_revoked_qr_rejection(test_app):
    with test_app.app_context():
        rev_data = {"name": "Charlie", "usn": "1VTXX003"}
        res = generate_secure_qr("STUDENT_ID", rev_data, save_to_db=True)
        qr_id = res["qr_id"]

        # Revoke the QR in registry
        revoke_qr_code(qr_id, "Reported stolen", "admin")

        payload = json.loads(res["json_payload"])
        ver_result = verify_qr_payload(payload, verification_method="Test")
        assert ver_result["success"] is False
        assert ver_result["result"] == "REVOKED"
        assert ver_result["revocation_valid"] is False
        assert "revoked by issuer" in ver_result["reason"]

# ==========================================
# TEST 6: Invalid QR format rejection
# ==========================================
def test_6_invalid_qr_format_rejection(test_app):
    with test_app.app_context():
        # Test malformed non-JSON string
        ver_1 = verify_qr_payload("NOT_A_JSON_STRING", verification_method="Test")
        assert ver_1["result"] == "INVALID_FORMAT"

        # Test incomplete JSON missing signature and fields
        ver_2 = verify_qr_payload({"only_one_field": 123}, verification_method="Test")
        assert ver_2["result"] == "INVALID_FORMAT"
        assert "Missing required cryptographic fields" in ver_2["reason"]

# ==========================================
# TEST 7: Wrong public key rejection
# ==========================================
def test_7_wrong_public_key_rejection(test_app):
    km = KeyManager()
    priv = km.load_private_key()
    
    # Generate an unrelated rogue keypair
    rogue_priv, rogue_pub = km.generate_keypair()
    rogue_pub_pem = km.serialize_public_key(rogue_pub)

    data = {"secret": "confidential_auth"}
    canon = canonicalize_payload(data)
    sig = sign_payload(canon, priv)

    # Verifying legitimate signature with the wrong public key MUST fail
    is_valid, reason = verify_signature(canon, sig, rogue_pub_pem)
    assert is_valid is False
    assert "tampered with or signature does not match" in reason

import uuid

# ==========================================
# TEST 8: Duplicate QR ID rejection
# ==========================================
def test_8_duplicate_qr_id_rejection(test_app):
    with test_app.app_context():
        qr_id = f"QR-TEST-DUPLICATE-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        # Save first
        save_qr_code(
            qr_id=qr_id,
            qr_type="STUDENT_ID",
            payload_json="{}",
            payload_hash="abcd",
            signature="sig1",
            issuer="Authority",
            issued_at=now_str,
            expires_at=now_str
        )

        # Attempt to insert same qr_id again should raise sqlite3.IntegrityError
        with pytest.raises(Exception):
            save_qr_code(
                qr_id=qr_id,
                qr_type="STUDENT_ID",
                payload_json="{}",
                payload_hash="abcd",
                signature="sig2",
                issuer="Authority",
                issued_at=now_str,
                expires_at=now_str
            )

# ==========================================
# TEST 9: Password hashing verification
# ==========================================
def test_9_password_hashing_verification():
    raw_pass = "SecureP@ssw0rd2026!"
    hashed = hash_password(raw_pass)

    assert hashed != raw_pass
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPassword", hashed) is False

# ==========================================
# TEST 10: Unauthorized access rejection
# ==========================================
def test_10_unauthorized_access_rejection(client):
    # Unauthenticated GET on protected admin generate route should redirect to login
    resp = client.get('/generate', follow_redirects=False)
    assert resp.status_code == 302
    assert '/login' in resp.headers.get('Location', '')

    # Unauthenticated API call should return 401 Unauthorized
    api_resp = client.post('/api/qr/generate', json={"type": "STUDENT_ID"})
    assert api_resp.status_code == 401

# ==========================================
# TEST 11: Replay attack detection test
# ==========================================
def test_11_replay_attack_detection(test_app):
    with test_app.app_context():
        # Generate one-time event pass
        event_data = {"name": "Dave", "event": "Concert 2026", "ticket_id": "TKT-101"}
        res = generate_secure_qr("EVENT_PASS", event_data, is_one_time=True, save_to_db=True)
        payload = json.loads(res["json_payload"])

        # Scan 1: Should be VERIFIED
        scan1 = verify_qr_payload(payload, verification_method="Camera")
        assert scan1["result"] == "VERIFIED"

        # Scan 2: Replay attempt! Should be REPLAY_DETECTED
        scan2 = verify_qr_payload(payload, verification_method="Camera")
        assert scan2["result"] == "REPLAY_DETECTED"
        assert "already been used previously" in scan2["reason"]
