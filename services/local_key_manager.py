import os
import json
import base64
import secrets
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

class LocalKeyManager:
    """
    Manages local protection of private keys using dual passphrases.
    Private keys are encrypted at-rest and never stored in plain text.
    """
    
    @staticmethod
    def derive_key(passphrase: str, salt: bytes, length: int = 32) -> bytes:
        """Derive a cryptographic key from a passphrase using Argon2id."""
        kdf = Argon2id(
            salt=salt,
            length=length,
            iterations=2,
            lanes=4,
            memory_cost=65536
        )
        return kdf.derive(passphrase.encode())

    @staticmethod
    def encrypt_private_key(private_key_pem: bytes, passphrase: str) -> dict:
        """Encrypt private key bytes with a passphrase."""
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = LocalKeyManager.derive_key(passphrase, salt)
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, private_key_pem, None)
        
        return {
            "version": "1.0",
            "kdf": "Argon2id",
            "cipher": "AES-256-GCM",
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    @staticmethod
    def decrypt_private_key(encrypted_data: dict, passphrase: str) -> bytes:
        """Decrypt private key bytes using a passphrase."""
        try:
            salt = base64.b64decode(encrypted_data['salt'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            
            key = LocalKeyManager.derive_key(passphrase, salt)
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            return None

    @staticmethod
    def protect_key_bundle(private_key_pem: bytes, login_pass: str, recovery_pass: str) -> dict:
        """Create a bundle containing the key encrypted for both daily and recovery access."""
        return {
            "login_slot": LocalKeyManager.encrypt_private_key(private_key_pem, login_pass),
            "recovery_slot": LocalKeyManager.encrypt_private_key(private_key_pem, recovery_pass)
        }

    @staticmethod
    def unlock_key_from_bundle(bundle: dict, passphrase: str) -> bytes:
        """Attempt to unlock the key using either the login or recovery slot."""
        # Try login slot first
        key = LocalKeyManager.decrypt_private_key(bundle['login_slot'], passphrase)
        if key: return key
        
        # Try recovery slot
        key = LocalKeyManager.decrypt_private_key(bundle['recovery_slot'], passphrase)
        return key
