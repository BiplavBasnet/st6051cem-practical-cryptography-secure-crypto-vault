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
