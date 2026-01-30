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
    def verify_totp(cls, secret_b32: str, code: str, timestamp: Optional[float] = None) -> bool:
        """Verify a TOTP code, accepting ±WINDOW periods for clock skew."""
        if timestamp is None:
            timestamp = time.time()
        counter = int(timestamp) // cls.PERIOD
        for offset in range(-cls.WINDOW, cls.WINDOW + 1):
            expected = cls._hotp(secret_b32, counter + offset)
            if hmac.compare_digest(expected, code.strip()):
                return True
        return False

    @classmethod
    def time_remaining(cls, timestamp: Optional[float] = None) -> int:
        """Seconds remaining until current TOTP code expires."""
        if timestamp is None:
            timestamp = time.time()
        return cls.PERIOD - (int(timestamp) % cls.PERIOD)

    @classmethod
    def _hotp(cls, secret_b32: str, counter: int) -> str:
        """HOTP algorithm (RFC 4226)."""
        key = cls._decode_secret(secret_b32)
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        return str(code_int % (10 ** cls.DIGITS)).zfill(cls.DIGITS)

    @staticmethod
    def build_otpauth_uri(secret_b32: str, account: str, issuer: str = "SecureCryptVault") -> str:
        """Build otpauth:// URI for QR code generation."""
        from urllib.parse import quote
        return (
            f"otpauth://totp/{quote(issuer)}:{quote(account)}"
            f"?secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
        )
