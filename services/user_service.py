import json
import os
import shutil
import datetime
from pathlib import Path

from services.crypto_utils import CryptoUtils
from services.pki_service import PKIService
from services.database import DBManager
from services.audit_log import AuditLog
from services.app_paths import keys_dir as app_keys_dir
from services.structured_logger import get_logger

_MIGRATE_LOG_SHOWN = False


class UserService:
    def __init__(self, db_manager: DBManager, pki_service: PKIService, audit_log: AuditLog, keys_dir=None):
        self.db = db_manager
        self.pki = pki_service
        self.audit_log = audit_log
        self.keys_dir = Path(keys_dir if keys_dir is not None else app_keys_dir()).resolve()
        self._secure_mkdir(self.keys_dir, 0o700)
        self._migrate_legacy_keys()

    def _migrate_legacy_keys(self):
        """Backward-compatible migration: if legacy ./keys exists and new keys dir is empty, copy user subfolders.
        Only runs when SECURECRYPT_MIGRATE_LEGACY_KEYS=1. Default is OFF for safety."""
        global _MIGRATE_LOG_SHOWN
        if os.getenv("SECURECRYPT_MIGRATE_LEGACY_KEYS") != "1":
            if not _MIGRATE_LOG_SHOWN:
                get_logger().info(
                    "Legacy ./keys migration is disabled. Set SECURECRYPT_MIGRATE_LEGACY_KEYS=1 to enable."
                )
                _MIGRATE_LOG_SHOWN = True
            return
        try:
            legacy = Path.cwd() / "keys"
            if not legacy.is_dir() or legacy.resolve() == self.keys_dir:
                return
            # Only migrate if new keys dir has no user subfolders
            try:
                existing = list(self.keys_dir.iterdir())
            except OSError:
                return
            if any(p.is_dir() for p in existing):
                return
            for sub in legacy.iterdir():
                if sub.is_dir() and not sub.name.startswith("."):
                    dst = self.keys_dir / sub.name
                    if not dst.exists():
                        shutil.copytree(sub, dst)
            # Best-effort chmod on copied dirs
            for sub in self.keys_dir.iterdir():
                if sub.is_dir():
                    try:
                        os.chmod(sub, 0o700)
                    except Exception:
                        pass
        except Exception:
            pass

    @staticmethod
    def _secure_mkdir(path: Path, mode: int = 0o700):
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path, mode)
        except Exception:
            pass

    @staticmethod
    def _secure_write_bytes(path: Path, data: bytes, mode: int = 0o600):
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(path), flags, mode)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        finally:
            try:
                os.chmod(path, mode)
            except Exception:
                pass

    def _validate_username_email(self, username: str, email: str):
        ok_u, msg_u = CryptoUtils.validate_input(username, "username")
        if not ok_u:
            return False, msg_u
        ok_e, msg_e = CryptoUtils.validate_input(email, "email")
        if not ok_e:
            return False, msg_e
        return True, "Valid"

    def _safe_user_dir(self, username: str) -> Path:
        # username regex already blocks dots/slashes; resolve-check is defense-in-depth
        user_dir = (self.keys_dir / username).resolve()
        if not str(user_dir).startswith(str(self.keys_dir) + os.sep):
            raise ValueError("Unsafe username/path detected")
        return user_dir

    def _parse_pub_from_bundle(self, key_bundle: dict, purpose: str):
        if not key_bundle or purpose not in key_bundle:
            raise ValueError(f"Missing key bundle for purpose: {purpose}")

        item = key_bundle[purpose]
        pub_pem = item.get("pub_pem")
        if not pub_pem:
            raise ValueError(f"Missing public key for purpose: {purpose}")

        pub_pem_bytes = pub_pem.encode() if isinstance(pub_pem, str) else pub_pem
        pub_key = CryptoUtils.load_public_key(pub_pem_bytes)

        # enforce modern minimum key size where available
        if hasattr(pub_key, "key_size") and pub_key.key_size < 2048:
            raise ValueError(f"Weak key size for {purpose}; minimum 2048 required")

        encrypted_priv = item.get("encrypted_priv")
        if encrypted_priv is not None and not isinstance(encrypted_priv, dict):
            raise ValueError("encrypted_priv must be protected bundle dict, not raw private key PEM")

        return pub_key, encrypted_priv

    def register_user(self, username, email, key_bundle=None):
        """Register user with purpose-separated keys and certificates."""
        valid, msg = self._validate_username_email(username, email)
        if not valid:
            return False, msg

        if not key_bundle:
            return False, "Client-side key bundle is required"

        conn = self.db.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                return False, "Username or Email already exists"

            user_keys_dir = self._safe_user_dir(username)
            self._secure_mkdir(user_keys_dir, 0o700)

            purposes = ["auth", "signing", "encryption"]
            certs_info = {}

            for purpose in purposes:
                pub_key, encrypted_priv = self._parse_pub_from_bundle(key_bundle, purpose)

                # Optional local mirror write if encrypted bundle provided
                priv_key_path = user_keys_dir / f"{purpose}_key.pem"
                if encrypted_priv is not None:
                    self._secure_write_bytes(
                        priv_key_path,
                        json.dumps(encrypted_priv).encode(),
                        mode=0o600,
                    )

                cert_pem = self.pki.issue_user_certificate(username, pub_key, purpose=purpose)
                cert_path = user_keys_dir / f"{purpose}_cert.pem"
                self._secure_write_bytes(cert_path, cert_pem, mode=0o644)

                certs_info[purpose] = {
                    "cert_path": cert_path,
                    "priv_key_path": str(priv_key_path),
                }

            cursor.execute(
                """
                INSERT INTO users (username, email, auth_cert_serial)
                VALUES (?, ?, ?)
                """,
                (username, email, None),
            )
            user_id = cursor.lastrowid

            from cryptography import x509

            for purpose, paths in certs_info.items():
                cert_data = Path(paths["cert_path"]).read_bytes()
                cert = x509.load_pem_x509_certificate(cert_data)

                cursor.execute(
                    """
                    INSERT INTO certificates (user_id, serial_number, subject, issuer, valid_from, valid_to, cert_data, key_usage)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        str(cert.serial_number),
                        str(cert.subject),
                        str(cert.issuer),
                        cert.not_valid_before_utc,
                        cert.not_valid_after_utc,
                        cert_data.decode(),
                        purpose,
                    ),
                )

            conn.commit()
            self.audit_log.log_event("USER_REGISTRATION", {"username": username, "email": email}, user_id=user_id)
            return True, f"User {username} registered successfully."

        except Exception as e:
            conn.rollback()
            self.audit_log.log_event("REGISTRATION_ERROR", {"username": username, "error": str(e)})
            return False, f"Registration failed: {str(e)}"
        finally:
            conn.close()

    def rotate_keys(self, username, key_bundle=None):
        """Rotate all user keys and issue new certificates."""
        if not key_bundle:
            return False, "Client-side key bundle is required for rotation"

        user = self.get_user_by_username(username)
        if not user:
            return False, "User not found"

        user_keys_dir = self._safe_user_dir(username)
        self._secure_mkdir(user_keys_dir, 0o700)

        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        old_keys_dir = user_keys_dir / f"old_{timestamp}"
        self._secure_mkdir(old_keys_dir, 0o700)

        for f in user_keys_dir.iterdir():
            if f.is_file() and not f.name.startswith("old_"):
                f.rename(old_keys_dir / f.name)

        conn = self.db.get_connection()
        cursor = conn.cursor()

        try:
            purposes = ["auth", "signing", "encryption"]
            from cryptography import x509

            # Revoke currently active certs before issuing replacements.
            cursor.execute(
                """
                UPDATE certificates
                SET revoked = 1
                WHERE user_id = ? AND revoked = 0 AND key_usage IN ('auth', 'signing', 'encryption')
                """,
                (user["id"],),
            )
            revoked_count = cursor.rowcount

            for purpose in purposes:
                pub_key, encrypted_priv = self._parse_pub_from_bundle(key_bundle, purpose)

                priv_key_path = user_keys_dir / f"{purpose}_key.pem"
                if encrypted_priv is not None:
                    self._secure_write_bytes(priv_key_path, json.dumps(encrypted_priv).encode(), mode=0o600)

                cert_pem = self.pki.issue_user_certificate(username, pub_key, purpose=purpose)
                cert_path = user_keys_dir / f"{purpose}_cert.pem"
                self._secure_write_bytes(cert_path, cert_pem, mode=0o644)

                cert = x509.load_pem_x509_certificate(cert_pem)
                cursor.execute(
                    """
                    INSERT INTO certificates (user_id, serial_number, subject, issuer, valid_from, valid_to, cert_data, key_usage)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user["id"],
                        str(cert.serial_number),
                        str(cert.subject),
                        str(cert.issuer),
                        cert.not_valid_before_utc,
                        cert.not_valid_after_utc,
                        cert_pem.decode(),
                        purpose,
                    ),
                )

            conn.commit()
            self.audit_log.log_event(
                "KEY_ROTATION",
                {"username": username, "revoked_old_certs": max(0, revoked_count)},
                user_id=user["id"],
            )
            return True, f"Keys rotated successfully for {username}."
        except Exception as e:
            conn.rollback()
            return False, f"Key rotation failed: {str(e)}"
        finally:
            conn.close()

    def get_user_certificate(self, user_id, purpose, include_revoked=False):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        if include_revoked:
            cursor.execute(
                """
                SELECT cert_data FROM certificates
                WHERE user_id = ? AND key_usage = ?
                ORDER BY id DESC LIMIT 1
                """,
                (user_id, purpose),
            )
        else:
            cursor.execute(
                """
                SELECT cert_data FROM certificates
                WHERE user_id = ? AND key_usage = ? AND revoked = 0
                ORDER BY id DESC LIMIT 1
                """,
                (user_id, purpose),
            )
        row = cursor.fetchone()
        conn.close()
        return row["cert_data"] if row else None

    def revoke_certificate(self, serial_number):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM certificates WHERE serial_number = ? LIMIT 1", (serial_number,))
        row = cursor.fetchone()
        user_id = int(row["user_id"]) if row and row.get("user_id") is not None else None
        cursor.execute("UPDATE certificates SET revoked = 1 WHERE serial_number = ?", (serial_number,))
        changed = cursor.rowcount
        conn.commit()
        conn.close()
        if changed:
            self.audit_log.log_event("CERT_REVOCATION", {"serial_number": serial_number}, user_id=user_id)
            return True, "Certificate revoked successfully"
        return False, "Certificate not found"

    def get_user_by_username(self, username):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        return user

    def get_user_by_id(self, user_id):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (int(user_id),))
        user = cursor.fetchone()
        conn.close()
        return user

    def reset_account_data_loss(self, username: str) -> tuple:
        """
        Phase 4: Reset local account state (data loss). Use when user forgot both phrases
        and will restore from backup. Clears vault, sessions, lockout, backup config, certs,
        and key files for this user. Does NOT delete backup files. Keeps users row.
        Returns (success: bool, message: str).
        """
        user = self.get_user_by_username(username)
        if not user:
            return False, "User not found"
        user_id = int(user["id"])

        self.audit_log.log_event("account_reset_confirmed", {"username": username, "user_id": user_id}, user_id=user_id)

        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vault_secrets WHERE owner_id = ?", (user_id,))
            cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM security_attempts WHERE username = ?", (username,))
            cursor.execute("DELETE FROM challenges WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM backup_recovery_config WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM backup_settings WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM certificates WHERE user_id = ?", (user_id,))
            conn.commit()
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

        # Remove key files (so user can re-initialize with new passphrase after restore)
        try:
            user_dir = self._safe_user_dir(username)
            for name in ("auth_key.pem", "signing_key.pem", "encryption_key.pem",
                         "auth_cert.pem", "signing_cert.pem", "encryption_cert.pem"):
                p = user_dir / name
                if p.exists():
                    p.unlink()
        except Exception:
            pass

        self.audit_log.log_event("account_reset_completed", {"username": username, "user_id": user_id}, user_id=user_id)
        return True, "Account reset. You can now restore from backup and set new passphrases."

    def finalize_post_restore_rekey(
        self,
        username: str,
        new_login_passphrase: str,
        new_recovery_passphrase: str,
        enc_priv_pem: bytes,
    ) -> tuple:
        """
        Phase 4: After restore, save key bundles and issue certs for auth/sign/enc.
        enc_priv_pem is the encryption private key (PEM bytes) from restore.
        Generates new auth and signing key pairs; uses provided enc key.
        Returns (success: bool, message: str).
        """
        from services.local_key_manager import LocalKeyManager

        user = self.get_user_by_username(username)
        if not user:
            return False, "User not found"
        user_id = int(user["id"])

        if not new_login_passphrase or len(new_login_passphrase) < 12:
            return False, "New login passphrase must be at least 12 characters"
        if not new_recovery_passphrase or len(new_recovery_passphrase) < 12:
            return False, "New recovery passphrase must be at least 12 characters"

        user_dir = self._safe_user_dir(username)
        self._secure_mkdir(user_dir, 0o700)

        # Generate auth and signing key pairs; use provided enc key
        auth_priv = CryptoUtils.generate_rsa_key_pair(2048)
        sign_priv = CryptoUtils.generate_rsa_key_pair(2048)
        enc_priv = CryptoUtils.load_private_key(enc_priv_pem)
        enc_pub = enc_priv.public_key()

        auth_pem = CryptoUtils.serialize_private_key(auth_priv)
        sign_pem = CryptoUtils.serialize_private_key(sign_priv)
        enc_pem = CryptoUtils.serialize_private_key(enc_priv)

        auth_bundle = LocalKeyManager.protect_key_bundle(auth_pem, new_login_passphrase, new_recovery_passphrase)
        sign_bundle = LocalKeyManager.protect_key_bundle(sign_pem, new_login_passphrase, new_recovery_passphrase)
        enc_bundle = LocalKeyManager.protect_key_bundle(enc_pem, new_login_passphrase, new_recovery_passphrase)

        self._secure_write_bytes(user_dir / "auth_key.pem", json.dumps(auth_bundle).encode(), mode=0o600)
        self._secure_write_bytes(user_dir / "signing_key.pem", json.dumps(sign_bundle).encode(), mode=0o600)
        self._secure_write_bytes(user_dir / "encryption_key.pem", json.dumps(enc_bundle).encode(), mode=0o600)

        # Issue and store certificates
        for purpose, priv_key in [("auth", auth_priv), ("signing", sign_priv), ("encryption", enc_priv)]:
            pub_key = priv_key.public_key()
            cert_pem = self.pki.issue_user_certificate(username, pub_key, purpose=purpose)
            self._secure_write_bytes(user_dir / f"{purpose}_cert.pem", cert_pem, mode=0o644)

        # Encryption cert was already inserted during restore; only insert auth and signing
        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            from cryptography import x509
            for purpose, priv_key in [("auth", auth_priv), ("signing", sign_priv)]:
                cert_path = user_dir / f"{purpose}_cert.pem"
                cert_data = cert_path.read_bytes()
                cert = x509.load_pem_x509_certificate(cert_data)
                cursor.execute(
                    """
                    INSERT INTO certificates (user_id, serial_number, subject, issuer, valid_from, valid_to, cert_data, key_usage)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        str(cert.serial_number),
                        str(cert.subject),
                        str(cert.issuer),
                        cert.not_valid_before_utc,
                        cert.not_valid_after_utc,
                        cert_data.decode(),
                        purpose,
                    ),
                )
            conn.commit()
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

        self.audit_log.log_event("post_restore_rekey_completed", {"username": username}, user_id=user_id)
        return True, "New passphrases set. You can now sign in with your new login passphrase."

    def get_user_certificates(self, user_id):
        """Get all certificates for a user. Returns list of dicts."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM certificates WHERE user_id = ? ORDER BY id DESC", (user_id,))
        rows = cursor.fetchall()
        conn.close()
        # Ensure all rows are converted to dicts for consistent access
        return [dict(row) for row in rows] if rows else []
