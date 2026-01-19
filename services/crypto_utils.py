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
    def hmac_sha256(key: bytes, data: bytes) -> bytes:
        """Return HMAC-SHA256 digest."""
        h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()

    @staticmethod
    def hmac_sha256_hex(key: bytes, data: bytes) -> str:
        return CryptoUtils.hmac_sha256(key, data).hex()

    @staticmethod
    def hmac_compare(expected_hex: str, key: bytes, data: bytes) -> bool:
        actual = CryptoUtils.hmac_sha256_hex(key, data)
        return hmac.compare_digest(actual, expected_hex)

    @staticmethod
    def b64e(data: bytes) -> str:
        return base64.b64encode(data).decode("utf-8")

    @staticmethod
    def b64d(data: str) -> bytes:
        return base64.b64decode(data.encode("utf-8"))

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

    @staticmethod
    def generate_rsa_key_pair(key_size: int = 2048):
        """Generate a new RSA private key."""
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())

    @staticmethod
    def serialize_private_key(private_key, passphrase=None) -> bytes:
        """Serialize RSA private key to PEM format."""
        encryption_algorithm = serialization.NoEncryption()
        if passphrase:
            encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
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
        pw = passphrase.encode("utf-8") if passphrase else None
        return serialization.load_pem_private_key(data, password=pw, backend=default_backend())

    @staticmethod
    def load_public_key(data: bytes):
        """Load RSA public key from PEM bytes."""
        return serialization.load_pem_public_key(data, backend=default_backend())

    @staticmethod
    def hybrid_encrypt(public_key, plaintext: bytes, associated_data: bytes = None):
        """
        Envelope encryption:
        1) Generate random DEK
        2) Wrap DEK with RSA-OAEP(SHA-256)
        3) Encrypt plaintext with AES-256-GCM (+ optional AAD)
        Returns (enc_dek, nonce, ciphertext)
        """
        dek = os.urandom(32)

        enc_dek = public_key.encrypt(
            dek,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        return enc_dek, nonce, ciphertext

    @staticmethod
    def hybrid_decrypt(private_key, enc_dek: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
        """Decrypt envelope-encrypted payload."""
        dek = private_key.decrypt(
            enc_dek,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

        aesgcm = AESGCM(dek)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)

    @staticmethod
    def sign_data(private_key, data: bytes) -> bytes:
        """Sign data using RSA-PSS(SHA-256)."""
        return private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    @staticmethod
    def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
        """Verify RSA-PSS(SHA-256) signature."""
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    @staticmethod
    def generate_ephemeral_ecdh_keys():
        """Generate X25519 private key for ephemeral ECDH."""
        from cryptography.hazmat.primitives.asymmetric import x25519

        return x25519.X25519PrivateKey.generate()

    @staticmethod
    def derive_shared_secret(private_key, peer_public) -> bytes:
        """Derive shared secret using X25519 ECDH."""
        from cryptography.hazmat.primitives.asymmetric import x25519

        if isinstance(peer_public, x25519.X25519PublicKey):
            peer_public_key = peer_public
        else:
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public)

        return private_key.exchange(peer_public_key)

    @staticmethod
    def validate_input(input_str, field_type="general"):
        """Security validation for user inputs to prevent injection/XSS."""
        import re

        patterns = {
            "username": (r"^[a-zA-Z0-9_\-]{3,30}$", "Username must be 3-30 alphanumeric characters."),
            "email": (r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", "Invalid email format."),
            "service": (r"^[a-zA-Z0-9_\-\. ]{1,50}$", "Service name must be 1-50 safe characters."),
            "general": (r"^[a-zA-Z0-9_\-\. ]*$", "Input contains invalid characters."),
        }
        pattern, msg = patterns.get(field_type, patterns["general"])
        if not input_str:
            return False, "Input cannot be empty."
        if re.match(pattern, input_str):
            return True, "Valid"
        return False, msg

    @staticmethod
    def wipe_sensitive_data(obj):
        """Best-effort wipe for mutable buffers."""
        try:
            if isinstance(obj, bytearray):
                for i in range(len(obj)):
                    obj[i] = 0
                return True
            if isinstance(obj, memoryview) and not obj.readonly:
                obj[:] = b"\x00" * len(obj)
                return True
            return False
        except Exception:
            return False

    @staticmethod
    def hash_file(file_path: str) -> str:
        """Generate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def generate_pki_nonce(length: int = 32):
        return os.urandom(length)
