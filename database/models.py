import json
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
from .database import get_db_connection
from config import Config

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def generate_next_qr_id() -> str:
    """Generates unique sequential QR ID formatted like QR-2026-00001."""
    conn = get_db_connection()
    year = datetime.now(timezone.utc).year
    prefix = f"QR-{year}-"
    row = conn.execute(
        "SELECT qr_id FROM qr_codes WHERE qr_id LIKE ? ORDER BY id DESC LIMIT 1",
        (f"{prefix}%",)
    ).fetchone()
    conn.close()
    
    if row and row['qr_id'].startswith(prefix):
        try:
            current_num = int(row['qr_id'].replace(prefix, ''))
            next_num = current_num + 1
        except ValueError:
            next_num = 1
    else:
        next_num = 1
        
    return f"{prefix}{next_num:05d}"

def save_qr_code(
    qr_id: str,
    qr_type: str,
    payload_json: str,
    payload_hash: str,
    signature: str,
    issuer: str,
    issued_at: str,
    expires_at: str,
    status: str = 'ACTIVE',
    is_one_time: int = 0
) -> int:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO qr_codes 
        (qr_id, type, payload_json, payload_hash, signature, issuer, issued_at, expires_at, status, is_one_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            qr_id, qr_type, payload_json, payload_hash, signature,
            issuer, issued_at, expires_at, status, is_one_time
        ))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def get_qr_code(qr_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM qr_codes WHERE qr_id = ?", (qr_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_all_qr_codes() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM qr_codes ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_qr_status(qr_id: str, status: str) -> None:
    conn = get_db_connection()
    conn.execute("UPDATE qr_codes SET status = ? WHERE qr_id = ?", (status, qr_id))
    conn.commit()
    conn.close()

def revoke_qr_code(qr_id: str, reason: str, revoked_by: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        INSERT OR REPLACE INTO revocations (qr_id, reason, revoked_by)
        VALUES (?, ?, ?)
        """, (qr_id, reason, revoked_by))
        cursor.execute("UPDATE qr_codes SET status = 'REVOKED' WHERE qr_id = ?", (qr_id,))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        return False
    finally:
        conn.close()

def is_qr_revoked(qr_id: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM revocations WHERE qr_id = ?", (qr_id,)).fetchone()
    conn.close()
    if row:
        return True, dict(row)
    return False, None

def get_all_revocations() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("""
    SELECT r.*, q.type, q.issuer, q.issued_at
    FROM revocations r
    LEFT JOIN qr_codes q ON r.qr_id = q.qr_id
    ORDER BY r.id DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def log_verification(
    qr_id: str,
    result: str,
    reason: str,
    method: str,
    details_json: Optional[str] = None
) -> int:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO verification_logs (qr_id, result, reason, method, details_json)
        VALUES (?, ?, ?, ?, ?)
        """, (qr_id, result, reason, method, details_json or "{}"))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def get_recent_logs(limit: int = 25) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM verification_logs ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_verification_count_for_qr(qr_id: str) -> int:
    """Counts successful previous verifications for replay detection."""
    conn = get_db_connection()
    row = conn.execute(
        "SELECT COUNT(*) FROM verification_logs WHERE qr_id = ? AND result = 'VERIFIED'",
        (qr_id,)
    ).fetchone()
    conn.close()
    return row[0] if row else 0

def get_dashboard_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    
    # Total QR codes
    total_qr = conn.execute("SELECT COUNT(*) FROM qr_codes").fetchone()[0]
    
    # Active
    active_qr = conn.execute("SELECT COUNT(*) FROM qr_codes WHERE status = 'ACTIVE'").fetchone()[0]
    
    # Expired
    now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    expired_qr = conn.execute(
        "SELECT COUNT(*) FROM qr_codes WHERE expires_at < ? AND status != 'REVOKED'",
        (now_iso,)
    ).fetchone()[0]
    
    # Revoked
    revoked_qr = conn.execute("SELECT COUNT(*) FROM revocations").fetchone()[0]
    
    # Tampered attempts
    tampered_attempts = conn.execute(
        "SELECT COUNT(*) FROM verification_logs WHERE result = 'TAMPERED'"
    ).fetchone()[0]
    
    # Logs breakdown
    verified_logs = conn.execute("SELECT COUNT(*) FROM verification_logs WHERE result = 'VERIFIED'").fetchone()[0]
    expired_logs = conn.execute("SELECT COUNT(*) FROM verification_logs WHERE result = 'EXPIRED'").fetchone()[0]
    revoked_logs = conn.execute("SELECT COUNT(*) FROM verification_logs WHERE result = 'REVOKED'").fetchone()[0]
    tampered_logs = conn.execute("SELECT COUNT(*) FROM verification_logs WHERE result = 'TAMPERED'").fetchone()[0]
    replay_logs = conn.execute("SELECT COUNT(*) FROM verification_logs WHERE result = 'REPLAY_DETECTED'").fetchone()[0]
    
    conn.close()
    
    # Dynamic active calculation
    valid_count = max(0, active_qr - expired_qr)
    
    return {
        'total_qr': total_qr,
        'valid_qr': valid_count,
        'expired_qr': expired_qr,
        'revoked_qr': revoked_qr,
        'tampered_attempts': tampered_attempts,
        'verified_logs': verified_logs,
        'expired_logs': expired_logs,
        'revoked_logs': revoked_logs,
        'tampered_logs': tampered_logs,
        'replay_logs': replay_logs
    }

def get_active_authority() -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM authority WHERE status = 'ACTIVE' ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    return dict(row) if row else None

def get_authority_history() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM authority ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def rotate_authority_in_db(new_pub_key: str, new_fingerprint: str) -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Mark old authority as SUPERSEDED
        cursor.execute("UPDATE authority SET status = 'SUPERSEDED' WHERE status = 'ACTIVE'")
        
        now = datetime.now(timezone.utc)
        cert_id = f"CERT-QRSEC-{now.strftime('%Y%m%d%H%M%S')}"
        valid_from = now.strftime('%Y-%m-%dT%H:%M:%SZ')
        valid_until = (now + timedelta(days=365*2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        cursor.execute("""
        INSERT INTO authority 
        (authority_name, certificate_id, public_key, key_algorithm, fingerprint, valid_from, valid_until, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
        """, (
            Config.DEFAULT_AUTHORITY_NAME,
            cert_id,
            new_pub_key,
            Config.KEY_ALGORITHM,
            new_fingerprint,
            valid_from,
            valid_until
        ))
        conn.commit()
        return {
            'certificate_id': cert_id,
            'fingerprint': new_fingerprint,
            'valid_from': valid_from,
            'valid_until': valid_until
        }
    finally:
        conn.close()
