import base64
import os
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class CryptoUtils:
    """Standardized cryptographic utility class for SecureCrypt Vault."""

    @staticmethod
    def b64e(data: bytes) -> str:
        return base64.b64encode(data).decode("utf-8")

    @staticmethod
    def b64d(data: str) -> bytes:
        return base64.b64decode(data.encode("utf-8"))

    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        return os.urandom(length)

    @staticmethod
    def generate_rsa_key_pair(key_size: int = 2048):
        """Generate a new RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

    @staticmethod
    def serialize_private_key(private_key, passphrase=None) -> bytes:
        """Serialize RSA private key to PEM format."""
        encryption = serialization.NoEncryption()
        if passphrase:
            encryption = serialization.BestAvailableEncryption(passphrase.encode())
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    @staticmethod
    def serialize_public_key(public_key) -> bytes:
        """Serialize RSA public key to PEM format."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def load_private_key(data: bytes, passphrase=None):
        """Load RSA private key from PEM bytes."""
        pw = passphrase.encode() if passphrase else None
        return serialization.load_pem_private_key(data, password=pw, backend=default_backend())

    @staticmethod
    def load_public_key(data: bytes):
        """Load RSA public key from PEM bytes."""
        return serialization.load_pem_public_key(data, backend=default_backend())
