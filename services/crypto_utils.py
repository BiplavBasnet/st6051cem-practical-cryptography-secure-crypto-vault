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
    def sign_data(private_key, data: bytes) -> bytes:
        """Sign data using RSA-PSS."""
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    @staticmethod
    def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
        """Verify RSA-PSS signature."""
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
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
    def derive_shared_secret(private_key, peer_public_bytes: bytes) -> bytes:
        """Derive shared secret using X25519 ECDH."""
        from cryptography.hazmat.primitives.asymmetric import x25519
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        return private_key.exchange(peer_public_key)

    @staticmethod
    def validate_input(input_str, field_type='general'):
        """Security validation for user inputs to prevent injection/XSS."""
        import re
        patterns = {
            'username': (r"^[a-zA-Z0-9_\-]{3,30}$", "Username must be 3-30 alphanumeric characters."),
            'email': (r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", "Invalid email format."),
            'service': (r"^[a-zA-Z0-9_\-\. ]{1,50}$", "Service name must be 1-50 safe characters."),
            'general': (r"^[a-zA-Z0-9_\-\. ]*$", "Input contains invalid characters.")
        }
        pattern, msg = patterns.get(field_type, patterns['general'])
        if not input_str:
            return False, "Input cannot be empty."
        if re.match(pattern, input_str):
            return True, "Valid"
        return False, msg

    @staticmethod
    def wipe_sensitive_data(obj):
        """Zero out sensitive memory (best effort for Python strings/bytes)."""
        import ctypes
        if isinstance(obj, bytes):
            # Attempt to overwrite bytes buffer
            ctypes.memset(id(obj) + 32, 0, len(obj))
        elif isinstance(obj, str):
            # Strings are immutable, but we can overwrite the buffer
            ctypes.memset(id(obj) + 64, 0, len(obj) * 2)

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
