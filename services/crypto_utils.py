import base64
import os
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

    @staticmethod
    def serialize_private_key(private_key, passphrase=None) -> bytes:
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
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def load_private_key(data: bytes, passphrase=None):
        pw = passphrase.encode() if passphrase else None
        return serialization.load_pem_private_key(data, password=pw, backend=default_backend())

    @staticmethod
    def load_public_key(data: bytes):
        return serialization.load_pem_public_key(data, backend=default_backend())

    @staticmethod
    def encrypt_aes_gcm(plaintext: bytes, key: bytes, associated_data: bytes = None) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-256-GCM. Returns (nonce, ciphertext)."""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    @staticmethod
    def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, associated_data: bytes = None) -> bytes:
        """Decrypt data using AES-256-GCM."""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
