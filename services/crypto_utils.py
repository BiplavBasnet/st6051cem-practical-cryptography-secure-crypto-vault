import base64
import hashlib
import hmac
import os
from typing import Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoUtils:
    """
    Standardized cryptographic utility class for the SecureCrypt Vault.

    - Asymmetric: RSA (OAEP / RSA-PSS)
    - Symmetric: AES-256-GCM (AEAD)
    - Hashing: SHA-256
    - KDF: PBKDF2 and Argon2id (for newer paths)
    """

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
        """
        Argon2id key derivation.

        Uses cryptography Argon2id when available, with fallback to argon2-cffi.
        """
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
            # Fallback path
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
    def hkdf_expand(
        ikm: bytes,
        *,
        info: bytes,
        salt: Optional[bytes] = None,
        length: int = 32,
    ) -> bytes:
        """Derive a context-separated sub-key using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(ikm)

    @staticmethod
        @staticmethod
    def hkdf_expand(
        ikm: bytes,
        *,
        info: bytes,
        salt: Optional[bytes] = None,
        length: int = 32,
    ) -> bytes:
        """Derive a context-separated sub-key using HKDF-SHA256."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(ikm)
