"""TOTP (RFC 6238) service for two-factor authentication.

Generates and verifies time-based OTP codes using HMAC-SHA1 with a 30-second window.
TOTP secrets are stored encrypted in the vault alongside the credential entry.
"""

import hashlib
import hmac
import os
import struct
import time
import base64
from typing import Tuple, Optional


class TOTPService:
    """RFC 6238 compliant TOTP implementation."""

    PERIOD = 30       # seconds
    DIGITS = 6
    ALGORITHM = "sha1"
    WINDOW = 1        # accept ±1 period for clock skew

    @staticmethod
    def generate_secret(length: int = 20) -> str:
        """Generate a random Base32-encoded TOTP secret."""
        raw = os.urandom(length)
        return base64.b32encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_secret(secret_b32: str) -> bytes:
        """Decode a Base32 secret, adding padding as needed."""
        padded = secret_b32.upper() + "=" * (-len(secret_b32) % 8)
        return base64.b32decode(padded)

    @classmethod
    def generate_totp(cls, secret_b32: str, timestamp: Optional[float] = None) -> str:
        """Generate a TOTP code for the given secret and time."""
        if timestamp is None:
            timestamp = time.time()
        counter = int(timestamp) // cls.PERIOD
        return cls._hotp(secret_b32, counter)

    @classmethod
