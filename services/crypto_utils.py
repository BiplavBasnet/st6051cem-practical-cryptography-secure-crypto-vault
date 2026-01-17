import base64
import os
from typing import Tuple


class CryptoUtils:
    """Standardized cryptographic utility class for SecureCrypt Vault."""

    @staticmethod
    def b64e(data: bytes) -> str:
        """Encode bytes to base64 string."""
        return base64.b64encode(data).decode("utf-8")

    @staticmethod
    def b64d(data: str) -> bytes:
        """Decode base64 string to bytes."""
        return base64.b64decode(data.encode("utf-8"))

    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        """Generate cryptographically secure random salt."""
        return os.urandom(length)
