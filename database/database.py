import sqlite3
import os
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash
from config import Config
from crypto.key_manager import KeyManager

def get_db_connection() -> sqlite3.Connection:
    """Returns an SQLite database connection with row access by column name."""
    conn = sqlite3.connect(Config.DATABASE_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db() -> None:
    """Initializes the SQLite schema and seeds default authority and admin/verifier accounts."""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # QR Codes table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS qr_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        qr_id TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        issuer TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        status TEXT NOT NULL,
        is_one_time INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Revocations table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS revocations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        qr_id TEXT NOT NULL UNIQUE,
        reason TEXT NOT NULL,
        revoked_by TEXT NOT NULL,
        revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Verification logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS verification_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        qr_id TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        result TEXT NOT NULL,
        reason TEXT NOT NULL,
        method TEXT NOT NULL,
        details_json TEXT
    );
    """)

    # Authority table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS authority (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        authority_name TEXT NOT NULL,
        certificate_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        key_algorithm TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        valid_from TEXT NOT NULL,
        valid_until TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()

    # Seed initial users if table is empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        admin_hash = generate_password_hash("admin123")
        verifier_hash = generate_password_hash("verifier123")
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", admin_hash, "ADMIN")
        )
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("verifier", verifier_hash, "VERIFIER")
        )
        conn.commit()

    # Seed initial simulated Certificate Authority record if table is empty
    cursor.execute("SELECT COUNT(*) FROM authority WHERE status = 'ACTIVE'")
    if cursor.fetchone()[0] == 0:
        km = KeyManager()
        pub_pem = km.get_public_key_pem()
        fingerprint = km.get_fingerprint()
        
        now = datetime.now(timezone.utc)
        valid_from = now.strftime('%Y-%m-%dT%H:%M:%SZ')
        valid_until = (now + timedelta(days=365*2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        cursor.execute("""
        INSERT INTO authority 
        (authority_name, certificate_id, public_key, key_algorithm, fingerprint, valid_from, valid_until, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
        """, (
            Config.DEFAULT_AUTHORITY_NAME,
            Config.DEFAULT_CERTIFICATE_ID,
            pub_pem,
            Config.KEY_ALGORITHM,
            fingerprint,
            valid_from,
            valid_until
        ))
        conn.commit()

    conn.close()
