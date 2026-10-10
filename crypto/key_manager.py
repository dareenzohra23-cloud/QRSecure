import os
import hashlib
from datetime import datetime, timezone
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from config import Config

class KeyManager:
    """
    Manages RSA 2048-bit cryptographic key pairs for QR-Secure Authority.
    Ensures safe key generation, PEM serialization, fingerprint calculation, and key rotation.
    NOTE: Private keys are stored server-side only and NEVER exposed to frontend clients.
    """
    
    def __init__(self, keys_dir: str = Config.KEYS_DIR, 
                 private_key_path: str = Config.PRIVATE_KEY_PATH, 
                 public_key_path: str = Config.PUBLIC_KEY_PATH):
        self.keys_dir = keys_dir
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.ensure_keys_exist()

    def ensure_keys_exist(self) -> None:
        """Generates initial key pair if none exists."""
        os.makedirs(self.keys_dir, exist_ok=True)
        if not os.path.exists(self.private_key_path) or not os.path.exists(self.public_key_path):
            self.generate_and_save_keypair()

    def generate_keypair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generates an industry-standard RSA 2048-bit keypair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_private_key(self, private_key: rsa.RSAPrivateKey) -> str:
        """Serializes RSA private key to PKCS#8 PEM format."""
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem_bytes.decode('utf-8')

    def serialize_public_key(self, public_key: rsa.RSAPublicKey) -> str:
        """Serializes RSA public key to SubjectPublicKeyInfo PEM format."""
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode('utf-8')

    def calculate_public_key_fingerprint(self, public_key: rsa.RSAPublicKey) -> str:
        """
        Calculates SHA-256 fingerprint of the public key's DER encoding.
        Format: e.g. SHA256:3F:8A:...
        """
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashlib.sha256(der_bytes).hexdigest().upper()
        formatted = ':'.join(digest[i:i+2] for i in range(0, len(digest), 2))
        return f"SHA256:{formatted}"

    def generate_and_save_keypair(self) -> Tuple[str, str, str]:
        """
        Generates, saves to disk, and returns (private_pem, public_pem, fingerprint).
        """
        os.makedirs(self.keys_dir, exist_ok=True)
        private_key, public_key = self.generate_keypair()
        
        priv_pem = self.serialize_private_key(private_key)
        pub_pem = self.serialize_public_key(public_key)
        fingerprint = self.calculate_public_key_fingerprint(public_key)
        
        with open(self.private_key_path, 'w', encoding='utf-8') as f:
            f.write(priv_pem)
        
        # Set file permissions for private key (owner read/write only: 0600)
        try:
            os.chmod(self.private_key_path, 0o600)
        except Exception:
            pass

        with open(self.public_key_path, 'w', encoding='utf-8') as f:
            f.write(pub_pem)

        return priv_pem, pub_pem, fingerprint

    def load_private_key(self) -> rsa.RSAPrivateKey:
        """Loads active private key from disk."""
        if not os.path.exists(self.private_key_path):
            self.ensure_keys_exist()
        with open(self.private_key_path, 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

    def load_public_key(self) -> rsa.RSAPublicKey:
        """Loads active public key from disk."""
        if not os.path.exists(self.public_key_path):
            self.ensure_keys_exist()
        with open(self.public_key_path, 'rb') as f:
            return serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def load_public_key_from_pem(self, pem_str: str) -> rsa.RSAPublicKey:
        """Parses RSA public key from a PEM string."""
        return serialization.load_pem_public_key(
            pem_str.encode('utf-8') if isinstance(pem_str, str) else pem_str,
            backend=default_backend()
        )

    def get_public_key_pem(self) -> str:
        """Returns active public key PEM string."""
        if not os.path.exists(self.public_key_path):
            self.ensure_keys_exist()
        with open(self.public_key_path, 'r', encoding='utf-8') as f:
            return f.read()

    def get_fingerprint(self) -> str:
        """Returns fingerprint of active public key."""
        return self.calculate_public_key_fingerprint(self.load_public_key())

    def rotate_keys(self) -> Tuple[str, str, str]:
        """
        Archives current keypair and generates a fresh RSA-2048 keypair.
        Returns (new_private_pem, new_public_pem, new_fingerprint).
        """
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        archive_priv = os.path.join(self.keys_dir, f'private_key_archived_{timestamp}.pem')
        archive_pub = os.path.join(self.keys_dir, f'public_key_archived_{timestamp}.pem')
        
        if os.path.exists(self.private_key_path):
            os.rename(self.private_key_path, archive_priv)
        if os.path.exists(self.public_key_path):
            os.rename(self.public_key_path, archive_pub)
            
        return self.generate_and_save_keypair()
