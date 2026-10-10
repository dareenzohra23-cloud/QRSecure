import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    BASE_DIR = BASE_DIR
    SECRET_KEY = os.environ.get('SECRET_KEY', 'qr-secure-enterprise-production-key-2026')
    DATABASE_PATH = os.path.join(BASE_DIR, 'qr_secure.db')
    KEYS_DIR = os.path.join(BASE_DIR, 'keys')
    PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, 'private_key.pem')
    PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, 'public_key.pem')
    
    # Authority settings
    DEFAULT_AUTHORITY_NAME = 'QR-Secure Authority'
    DEFAULT_CERTIFICATE_ID = 'CERT-QRSEC-2026-ROOT'
    KEY_ALGORITHM = 'RSA-2048 / SHA-256'
    
    # Session lifetime
    SESSION_PERMANENT = False
