import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class CryptoUtils:
    """
    Standardized cryptographic utility class for the SecureCrypt Vault.
    Provides robust primitives for RSA, AES, Hashing, and Key Derivation.
    """
    
    @staticmethod
    def generate_salt(length=16):
        return os.urandom(length)

    @staticmethod
    def derive_key(passphrase: str, salt: bytes, iterations=600000) -> bytes:
        """Derive a high-entropy 256-bit key using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode())

    @staticmethod
    def encrypt_aes_gcm(plaintext: bytes, key: bytes, associated_data: bytes = None) -> (bytes, bytes):
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
    def generate_rsa_key_pair(key_size=2048):
        """Generate a new RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

    @staticmethod
    def serialize_private_key(private_key, passphrase=None):
        """Serialize RSA private key to PEM format."""
        encryption_algorithm = serialization.NoEncryption()
        if passphrase:
            encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode())
            
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

    @staticmethod
    def serialize_public_key(public_key):
        """Serialize RSA public key to PEM format."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
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

    @staticmethod
    def hybrid_encrypt(public_key, plaintext: bytes) -> (bytes, bytes, bytes):
        """Asymmetrically encrypt a random DEK, then use it to encrypt data."""
        dek = os.urandom(32)
        
        # 1. Encrypt DEK with RSA Public Key
        enc_dek = public_key.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 2. Encrypt Data with DEK
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return enc_dek, nonce, ciphertext

    @staticmethod
    def hybrid_decrypt(private_key, enc_dek: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """Decrypt DEK with RSA Private Key, then use it to decrypt data."""
        # 1. Decrypt DEK
        dek = private_key.decrypt(
            enc_dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 2. Decrypt Data
        aesgcm = AESGCM(dek)
        return aesgcm.decrypt(nonce, ciphertext, None)

    @staticmethod
    def hash_file(file_path: str) -> str:
        """Generate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def generate_pki_nonce(length=32):
        return os.urandom(length)

# Forensic Integrity: 831b9547 verified at 2026-02-13 15:07:59
