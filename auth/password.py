from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(plaintext_password: str) -> str:
    """Securely hashes plaintext password with salted PBKDF2/scrypt."""
    return generate_password_hash(plaintext_password)

def verify_password(plaintext_password: str, hashed_password: str) -> bool:
    """Verifies plaintext password against secure hash."""
    return check_password_hash(hashed_password, plaintext_password)
