import base64
import os
from typing import Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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
    def derive_key(passphrase: str, salt: bytes, iterations: int = 600000) -> bytes:
        """Legacy PBKDF2-HMAC-SHA256 key derivation (32 bytes)."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        return kdf.derive(passphrase.encode("utf-8"))

    @staticmethod
    def derive_key_argon2id(
        passphrase: str,
        salt: bytes,
        *,
        length: int = 32,
        iterations: int = 2,
        lanes: int = 4,
        memory_cost: int = 65536,
    ) -> bytes:
        """Argon2id key derivation with fallback to argon2-cffi."""
        try:
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
            kdf = Argon2id(
                salt=salt,
                length=length,
                iterations=max(1, int(iterations)),
                lanes=max(1, int(lanes)),
                memory_cost=max(8192, int(memory_cost)),
            )
            return kdf.derive(passphrase.encode("utf-8"))
        except Exception:
            from argon2.low_level import Type, hash_secret_raw
            return hash_secret_raw(
                secret=passphrase.encode("utf-8"),
                salt=salt,
                time_cost=max(1, int(iterations)),
                memory_cost=max(8192, int(memory_cost)),
                parallelism=max(1, int(lanes)),
                hash_len=max(16, int(length)),
                type=Type.ID,
            )

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
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    @staticmethod
    def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, associated_data: bytes = None) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
