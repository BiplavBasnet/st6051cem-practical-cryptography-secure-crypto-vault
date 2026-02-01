"""Secure sharing service for one-time, expiry-enforced share packages.

Creates encrypted share packages that can optionally:
  - Self-destruct after first open (burn-after-read)
  - Expire after a configurable timestamp
  - Be locked to a specific recipient certificate
"""

import datetime
import json
import os
import uuid
from typing import Optional

from services.crypto_utils import CryptoUtils
from services.database import DBManager
from services.audit_log import AuditLog


class SharingService:
    """Create and open secure share packages (local-first)."""

    def __init__(self, db: DBManager, audit: AuditLog):
        self.db = db
        self.audit = audit
        self._ensure_table()

    def _ensure_table(self):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS share_packages (
                id TEXT PRIMARY KEY,
                sender_user_id INTEGER NOT NULL,
                recipient_fingerprint TEXT,
                encrypted_payload BLOB NOT NULL,
                encrypted_dek BLOB NOT NULL,
                nonce BLOB NOT NULL,
                burn_after_read INTEGER DEFAULT 0,
                expires_at TEXT,
                opened INTEGER DEFAULT 0,
                opened_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (sender_user_id) REFERENCES users(id)
            )
        """)
        conn.commit()
        conn.close()

    def create_share_package(
        self,
        sender_user_id: int,
        plaintext: str,
        recipient_pub_key_pem: Optional[str] = None,
        burn_after_read: bool = True,
        expires_in_hours: int = 24,
    ) -> dict:
        """Create an encrypted share package.

        Args:
            sender_user_id: ID of the sender
            plaintext: The secret text to share
            recipient_pub_key_pem: If provided, locks the package to this recipient
            burn_after_read: If True, package can only be opened once
            expires_in_hours: Hours until the package expires (0 = no expiry)

        Returns:
            dict with package_id and metadata
        """
        package_id = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
        expires_at = None
        if expires_in_hours > 0:
            expires_at = (now + datetime.timedelta(hours=expires_in_hours)).isoformat()

        # Generate ephemeral encryption key
        dek = os.urandom(32)

        if recipient_pub_key_pem:
            pub_key = CryptoUtils.load_public_key(
                recipient_pub_key_pem.encode() if isinstance(recipient_pub_key_pem, str) else recipient_pub_key_pem
            )
            enc_dek, nonce, ciphertext = CryptoUtils.hybrid_encrypt(
                pub_key, plaintext.encode("utf-8")
            )
            recipient_fp = CryptoUtils.compute_public_key_fingerprint(pub_key)
        else:
            # Encrypt with just the DEK (no recipient lock — anyone with the package can read)
            nonce, ciphertext = CryptoUtils.encrypt_aes_gcm(plaintext.encode("utf-8"), dek)
            enc_dek = dek  # stored as-is; the package itself is the "key"
            recipient_fp = None

        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO share_packages
               (id, sender_user_id, recipient_fingerprint, encrypted_payload,
                encrypted_dek, nonce, burn_after_read, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                package_id, sender_user_id, recipient_fp,
                ciphertext, enc_dek, nonce,
                1 if burn_after_read else 0,
                expires_at, now.isoformat(),
            ),
        )
        conn.commit()
        conn.close()

        self.audit.log_event(
            "SHARE_CREATED",
            {
                "package_id": package_id,
                "burn_after_read": burn_after_read,
                "expires_at": expires_at or "never",
                "has_recipient_lock": recipient_fp is not None,
            },
            user_id=sender_user_id,
        )

        return {
            "package_id": package_id,
            "burn_after_read": burn_after_read,
            "expires_at": expires_at,
            "recipient_locked": recipient_fp is not None,
        }

    def open_share_package(
        self,
        package_id: str,
        opener_user_id: int,
        priv_key_data: Optional[bytes] = None,
    ) -> tuple:
        """Open a share package.

        Returns:
            (plaintext, message) on success, (None, error_message) on failure
        """
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM share_packages WHERE id = ?", (package_id,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return None, "Share package not found"

        pkg = dict(row)

        # Check expiry
        if pkg["expires_at"]:
            expires = datetime.datetime.fromisoformat(pkg["expires_at"])
            if datetime.datetime.utcnow() > expires:
                conn.close()
                self.audit.log_event("SHARE_EXPIRED", {"package_id": package_id}, user_id=opener_user_id)
                return None, "Share package has expired"

        # Check burn-after-read
        if pkg["burn_after_read"] and pkg["opened"]:
            conn.close()
            return None, "Share package already opened (one-time use)"

        # Decrypt
        try:
            if pkg["recipient_fingerprint"] and priv_key_data:
                priv_key = CryptoUtils.load_private_key(priv_key_data)
                plaintext_bytes = CryptoUtils.hybrid_decrypt(
                    priv_key,
                    pkg["encrypted_dek"],
                    pkg["nonce"],
                    pkg["encrypted_payload"],
                )
            else:
                # No recipient lock — DEK is stored directly
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                aesgcm = AESGCM(bytes(pkg["encrypted_dek"]))
                plaintext_bytes = aesgcm.decrypt(
                    bytes(pkg["nonce"]), bytes(pkg["encrypted_payload"]), None
                )
        except Exception as e:
            conn.close()
            return None, f"Decryption failed: {str(e)}"

        # Mark as opened
        now = datetime.datetime.utcnow().isoformat()
        cursor.execute(
            "UPDATE share_packages SET opened = 1, opened_at = ? WHERE id = ?",
            (now, package_id),
        )
        conn.commit()
        conn.close()

        self.audit.log_event(
            "SHARE_OPENED",
            {"package_id": package_id, "burn_after_read": bool(pkg["burn_after_read"])},
            user_id=opener_user_id,
        )

        return plaintext_bytes.decode("utf-8"), "Success"

    def list_packages(self, user_id: int) -> list:
        """List share packages created by a user."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, burn_after_read, expires_at, opened, opened_at, created_at
               FROM share_packages WHERE sender_user_id = ?
               ORDER BY created_at DESC""",
            (user_id,),
        )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
