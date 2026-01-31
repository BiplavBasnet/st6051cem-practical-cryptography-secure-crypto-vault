"""
Security & Backup Center - Phase 1 + Phase 2.

Phase 1: Encrypted backup with independent recovery factor (Backup Recovery Key or Backup Password).
Phase 2: Versioned local backups, retention, scheduled and change-triggered auto backup.
"""

import base64
import datetime
import hmac
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from services.app_paths import backups_dir_for_user
from services.audit_log import AuditLog
from services.crypto_utils import CryptoUtils
from services.database import DBManager


# Format version for backup envelope
BACKUP_FORMAT_VERSION = "sv_backup_recovery_v1"
PAYLOAD_FORMAT = "sv_backup_payload_v2"
VERIFIER_INFO = b"sv_backup_recovery_verifier_v1"
ENC_KEY_INFO = b"sv_backup_recovery_enc_v1"

# Minimum backup password length and strength
BACKUP_PASSWORD_MIN_LEN = 12

# Phase 2: retention and scheduler defaults
KEEP_LAST_N_DEFAULT = 10
KEEP_LAST_N_MIN = 1
KEEP_LAST_N_MAX = 100
SCHEDULE_INTERVAL_DEFAULT_HOURS = 24.0
DEBOUNCE_SECONDS = 60  # default for backward compat
ON_CHANGE_DEBOUNCE_DEFAULT = 60
ON_CHANGE_DEBOUNCE_MIN = 0  # 0 = immediate (runs on next tick)
ON_CHANGE_DEBOUNCE_MAX = 300
LATEST_FILENAME = "latest.json"
MANIFEST_FILENAME = "manifest.json"
# Phase 5: staleness warning
STALE_WARNING_DAYS_DEFAULT = 7
STALE_WARNING_DAYS_MIN = 1
STALE_WARNING_DAYS_MAX = 90


def _validate_backup_password(password: str) -> Tuple[bool, str]:
    """Validate backup password strength. Returns (ok, message)."""
    if not password or len(password) < BACKUP_PASSWORD_MIN_LEN:
        return False, f"Backup password must be at least {BACKUP_PASSWORD_MIN_LEN} characters"
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    if not (has_upper and has_lower and has_digit):
        return False, "Backup password must contain uppercase, lowercase, and a digit"
    return True, "OK"


def _recovery_key_to_bytes(recovery_key_b64: str) -> Optional[bytes]:
    """Decode base64 recovery key to 32 bytes. Returns None if invalid. Normalizes whitespace so pasted keys work."""
    if not recovery_key_b64:
        return None
    # Remove all whitespace (spaces, newlines, tabs) so pasting the key works
    normalized = "".join(recovery_key_b64.split())
    try:
        raw = base64.b64decode(normalized, validate=True)
        return raw if len(raw) == 32 else None
    except Exception:
        return None


def _bytes_to_recovery_key(key_bytes: bytes) -> str:
    """Encode 32-byte key to base64 for one-time display."""
    return base64.b64encode(key_bytes).decode("ascii")


class BackupService:
    """Service for backup recovery config and encrypted backup export/import (Phase 1 + 2)."""

    def __init__(self, db: DBManager, audit: AuditLog, secret_service: Any):
        self.db = db
        self.audit = audit
        self.secret_service = secret_service
        # Phase 2: in-memory cache for auto backup (never persisted)
        self._cached_auto_backup_key: Dict[int, Tuple[str, str]] = {}  # user_id -> (recovery_key_or_password, mode)
        self._pending_change_at: Dict[int, float] = {}  # user_id -> last vault change timestamp
        # Phase 5: prevent overlapping backup jobs per user
        self._backup_in_progress: Dict[int, bool] = {}

    def _get_config(self, user_id: int) -> Optional[Dict]:
        conn = self.db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT user_id, backup_enabled, backup_mode, verifier_salt, verifier_hash, created_at, last_backup_at FROM backup_recovery_config WHERE user_id = ?",
                (user_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "user_id": row["user_id"],
                "backup_enabled": bool(row["backup_enabled"]),
                "backup_mode": row["backup_mode"] or "recovery_key",
                "verifier_salt": row["verifier_salt"],
                "verifier_hash": row["verifier_hash"],
                "created_at": row["created_at"],
                "last_backup_at": row["last_backup_at"],
            }
        finally:
            conn.close()

    def _get_username_for_user_id(self, user_id: int) -> str:
        """Return username for user_id (for backup folder path). Safe fallback if not found."""
        conn = self.db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT username FROM users WHERE id = ?", (int(user_id),))
            row = cur.fetchone()
            return (row["username"] or "user").strip() if row else "user"
        finally:
            conn.close()

    def _backup_dir_for_user(self, user_id: int) -> Path:
        """Per-user backup directory; creates if missing."""
        username = self._get_username_for_user_id(user_id)
        return backups_dir_for_user(username)

    def _upsert_config(
        self,
        user_id: int,
        backup_enabled: bool,
        backup_mode: str,
        verifier_salt: str,
        verifier_hash: str,
    ) -> None:
        conn = self.db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO backup_recovery_config (user_id, backup_enabled, backup_mode, verifier_salt, verifier_hash, created_at, last_backup_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, NULL)
                ON CONFLICT(user_id) DO UPDATE SET
                    backup_enabled = excluded.backup_enabled,
                    backup_mode = excluded.backup_mode,
                    verifier_salt = excluded.verifier_salt,
                    verifier_hash = excluded.verifier_hash,
                    created_at = COALESCE(backup_recovery_config.created_at, excluded.created_at)
                """,
                (user_id, 1 if backup_enabled else 0, backup_mode, verifier_salt, verifier_hash),
            )
            conn.commit()
        finally:
            conn.close()

    def _update_last_backup(self, user_id: int) -> None:
        conn = self.db.get_connection()
        try:
            conn.execute(
                "UPDATE backup_recovery_config SET last_backup_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                (user_id,),
            )
            conn.commit()
        finally:
            conn.close()

    def get_backup_settings(self, user_id: int) -> Dict[str, Any]:
        conn = self.db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """SELECT user_id, backup_auto_enabled, backup_on_change_enabled,
                          schedule_interval_hours, keep_last_n_backups, updated_at,
                          latest_validation_ok, latest_validation_at, stale_warning_days,
                          on_change_debounce_seconds
                   FROM backup_settings WHERE user_id = ?""",
                (user_id,),
            )
            row = cur.fetchone()
            if not row:
                return {
                    "backup_auto_enabled": False,
                    "backup_on_change_enabled": False,
                    "schedule_interval_hours": SCHEDULE_INTERVAL_DEFAULT_HOURS,
                    "keep_last_n_backups": KEEP_LAST_N_DEFAULT,
                    "updated_at": None,
                    "latest_validation_ok": None,
                    "latest_validation_at": None,
                    "stale_warning_days": STALE_WARNING_DAYS_DEFAULT,
                    "on_change_debounce_seconds": ON_CHANGE_DEBOUNCE_DEFAULT,
                }
            row = dict(row)
            stale_days = row.get("stale_warning_days")
            if stale_days is None:
                stale_days = STALE_WARNING_DAYS_DEFAULT
            else:
                try:
                    stale_days = max(STALE_WARNING_DAYS_MIN, min(STALE_WARNING_DAYS_MAX, int(stale_days)))
                except (TypeError, ValueError):
                    stale_days = STALE_WARNING_DAYS_DEFAULT
            debounce_raw = row.get("on_change_debounce_seconds")
            if debounce_raw is None:
                debounce = ON_CHANGE_DEBOUNCE_DEFAULT
            else:
                try:
                    debounce = max(ON_CHANGE_DEBOUNCE_MIN, min(ON_CHANGE_DEBOUNCE_MAX, int(debounce_raw)))
                except (TypeError, ValueError):
                    debounce = ON_CHANGE_DEBOUNCE_DEFAULT
            return {
                "backup_auto_enabled": bool(row["backup_auto_enabled"]),
                "backup_on_change_enabled": bool(row["backup_on_change_enabled"]),
                "schedule_interval_hours": max(0.25, min(168, float(row["schedule_interval_hours"] or SCHEDULE_INTERVAL_DEFAULT_HOURS))),
                "keep_last_n_backups": max(KEEP_LAST_N_MIN, min(KEEP_LAST_N_MAX, int(row["keep_last_n_backups"] or KEEP_LAST_N_DEFAULT))),
                "updated_at": row["updated_at"],
                "latest_validation_ok": bool(row["latest_validation_ok"]) if row.get("latest_validation_ok") is not None else None,
                "latest_validation_at": row.get("latest_validation_at"),
                "stale_warning_days": stale_days,
                "on_change_debounce_seconds": debounce,
            }
        finally:
            conn.close()

    def update_backup_settings(
        self,
        user_id: int,
        backup_auto_enabled: Optional[bool] = None,
        backup_on_change_enabled: Optional[bool] = None,
        schedule_interval_hours: Optional[float] = None,
        keep_last_n_backups: Optional[int] = None,
        stale_warning_days: Optional[int] = None,
        on_change_debounce_seconds: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """Update backup automation settings. Validates ranges. Returns (success, message)."""
        try:
            if keep_last_n_backups is not None and (keep_last_n_backups < KEEP_LAST_N_MIN or keep_last_n_backups > KEEP_LAST_N_MAX):
                return False, f"keep_last_n_backups must be between {KEEP_LAST_N_MIN} and {KEEP_LAST_N_MAX}"
            if schedule_interval_hours is not None and (schedule_interval_hours < 0.25 or schedule_interval_hours > 168):
                return False, "schedule_interval_hours must be between 0.25 and 168"
            if stale_warning_days is not None and (stale_warning_days < STALE_WARNING_DAYS_MIN or stale_warning_days > STALE_WARNING_DAYS_MAX):
                return False, f"stale_warning_days must be between {STALE_WARNING_DAYS_MIN} and {STALE_WARNING_DAYS_MAX}"
            if on_change_debounce_seconds is not None and (on_change_debounce_seconds < ON_CHANGE_DEBOUNCE_MIN or on_change_debounce_seconds > ON_CHANGE_DEBOUNCE_MAX):
                return False, f"on_change_debounce_seconds must be between {ON_CHANGE_DEBOUNCE_MIN} and {ON_CHANGE_DEBOUNCE_MAX} (0=immediate)"
        except (TypeError, ValueError):
            return False, "Invalid setting value"

        current = self.get_backup_settings(user_id)
        auto = backup_auto_enabled if backup_auto_enabled is not None else current["backup_auto_enabled"]
        on_change = backup_on_change_enabled if backup_on_change_enabled is not None else current["backup_on_change_enabled"]
        interval = schedule_interval_hours if schedule_interval_hours is not None else current["schedule_interval_hours"]
        keep = keep_last_n_backups if keep_last_n_backups is not None else current["keep_last_n_backups"]
        stale_days = stale_warning_days if stale_warning_days is not None else current["stale_warning_days"]
        debounce = on_change_debounce_seconds if on_change_debounce_seconds is not None else current.get("on_change_debounce_seconds", ON_CHANGE_DEBOUNCE_DEFAULT)
        debounce = max(ON_CHANGE_DEBOUNCE_MIN, min(ON_CHANGE_DEBOUNCE_MAX, int(debounce)))

        conn = self.db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO backup_settings (user_id, backup_auto_enabled, backup_on_change_enabled,
                   schedule_interval_hours, keep_last_n_backups, updated_at, stale_warning_days, on_change_debounce_seconds)
                   VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET
                     backup_auto_enabled = excluded.backup_auto_enabled,
                     backup_on_change_enabled = excluded.backup_on_change_enabled,
                     schedule_interval_hours = excluded.schedule_interval_hours,
                     keep_last_n_backups = excluded.keep_last_n_backups,
                     updated_at = CURRENT_TIMESTAMP,
                     stale_warning_days = excluded.stale_warning_days,
                     on_change_debounce_seconds = excluded.on_change_debounce_seconds""",
                (user_id, 1 if auto else 0, 1 if on_change else 0, interval, keep, stale_days, debounce),
            )
            conn.commit()
            self.audit.log_event("backup_settings_updated", {"user_id": user_id}, user_id=user_id)
            return True, "Settings saved"
        except Exception as e:
            return False, str(e)
        finally:
            conn.close()

    def set_latest_validation_status(self, user_id: int, ok: bool) -> None:
        """Store latest backup validation result for dashboard (Phase 5). No secret data."""
        conn = self.db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE backup_settings SET latest_validation_ok = ?, latest_validation_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                (1 if ok else 0, user_id),
            )
            if cur.rowcount == 0:
                cur.execute(
                    """INSERT INTO backup_settings (user_id, backup_auto_enabled, backup_on_change_enabled,
                       schedule_interval_hours, keep_last_n_backups, updated_at, latest_validation_ok, latest_validation_at, stale_warning_days)
                       VALUES (?, 0, 0, ?, ?, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, ?)""",
                    (user_id, SCHEDULE_INTERVAL_DEFAULT_HOURS, KEEP_LAST_N_DEFAULT, 1 if ok else 0, STALE_WARNING_DAYS_DEFAULT),
                )
            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()

    def get_backup_folder_path(self, user_id: int) -> str:
        """Return local backup folder path for this user (Phase 5)."""
        return str(self._backup_dir_for_user(user_id))

    def _log_backup_event(self, user_id: int, event_type: str, summary: dict) -> None:
        conn = self.db.get_connection()
        try:
            conn.execute(
                "INSERT INTO backup_events (user_id, event_type, summary) VALUES (?, ?, ?)",
                (user_id, event_type, json.dumps(summary)),
            )
            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()

    def _compute_verifier(self, key_bytes: bytes, verifier_salt_b64: str) -> str:
        salt = CryptoUtils.b64d(verifier_salt_b64)
        derived = CryptoUtils.hkdf_expand(key_bytes, salt=salt, info=VERIFIER_INFO, length=32)
        return CryptoUtils.hmac_sha256_hex(derived, b"backup_verifier")

    def _verify_recovery_key(self, user_id: int, recovery_key_b64: str) -> bool:
        key_bytes = _recovery_key_to_bytes(recovery_key_b64)
        if not key_bytes:
            return False
        cfg = self._get_config(user_id)
        if not cfg or not cfg["backup_enabled"] or cfg["backup_mode"] != "recovery_key":
            return False
        expected = cfg["verifier_hash"]
        actual = self._compute_verifier(key_bytes, cfg["verifier_salt"])
        return hmac.compare_digest(expected, actual)

    def _verify_backup_password(self, user_id: int, password: str) -> bool:
        ok, _ = _validate_backup_password(password)
        if not ok:
            return False
        cfg = self._get_config(user_id)
        if not cfg or not cfg["backup_enabled"] or cfg["backup_mode"] != "backup_password":
            return False
        key_bytes = self._derive_key_from_backup_password(password, CryptoUtils.b64d(cfg["verifier_salt"]))
        expected = cfg["verifier_hash"]
        actual = self._compute_verifier(key_bytes, cfg["verifier_salt"])
        return hmac.compare_digest(expected, actual)

    def _derive_key_from_backup_password(self, password: str, salt: bytes) -> bytes:
        return CryptoUtils.derive_key_argon2id(
            password,
            salt,
            length=32,
            iterations=2,
            lanes=4,
            memory_cost=65536,
        )

    def get_backup_recovery_status(self, user_id: int) -> Dict[str, Any]:
        """Return backup recovery status: enabled, mode, created_at, has_verifier."""
        cfg = self._get_config(user_id)
        if not cfg:
            return {"enabled": False, "mode": None, "created_at": None, "has_verifier": False}
        return {
            "enabled": cfg["backup_enabled"],
            "mode": cfg["backup_mode"],
            "created_at": cfg["created_at"],
            "last_backup_at": cfg.get("last_backup_at"),
            "has_verifier": bool(cfg.get("verifier_hash")),
        }

    def initialize_backup_recovery_for_user(self, user_id: int) -> Tuple[bool, str, Optional[str]]:
        """
        Enable backup recovery with a newly generated Backup Recovery Key.
        Returns (success, message, one_time_recovery_key_b64).
        The key must be shown to the user once and never stored.
        """
        key_bytes = os.urandom(32)
        verifier_salt = CryptoUtils.b64e(os.urandom(16))
        verifier_hash = self._compute_verifier(key_bytes, verifier_salt)

        self._upsert_config(
            user_id=user_id,
            backup_enabled=True,
            backup_mode="recovery_key",
            verifier_salt=verifier_salt,
            verifier_hash=verifier_hash,
        )

        self.audit.log_event(
            "backup_recovery_enabled",
            {"user_id": user_id, "mode": "recovery_key"},
            user_id=user_id,
        )
        self._log_backup_event(user_id, "BACKUP_RECOVERY_ENABLED", {"mode": "recovery_key"})

        one_time_key = _bytes_to_recovery_key(key_bytes)
        return True, "Backup recovery key enabled. Store the key securely; it will not be shown again.", one_time_key

    def generate_backup_recovery_key(self, user_id: int) -> Tuple[bool, str, Optional[str]]:
        """
        Regenerate Backup Recovery Key (replaces previous). Returns (success, message, one_time_key_b64).
        """
        return self.initialize_backup_recovery_for_user(user_id)

    def set_backup_password(self, user_id: int, password: str) -> Tuple[bool, str]:
        """
        Enable or switch to backup password mode. Only a verifier is stored.
        Password must be distinct from main/recovery phrase (validated by strength only).
        """
        ok, msg = _validate_backup_password(password)
        if not ok:
            return False, msg

        verifier_salt_b64 = CryptoUtils.b64e(os.urandom(16))
        key_bytes = self._derive_key_from_backup_password(password, CryptoUtils.b64d(verifier_salt_b64))
        verifier_hash = self._compute_verifier(key_bytes, verifier_salt_b64)

        self._upsert_config(
            user_id=user_id,
            backup_enabled=True,
            backup_mode="backup_password",
            verifier_salt=verifier_salt_b64,
            verifier_hash=verifier_hash,
        )

        self.audit.log_event(
            "backup_recovery_enabled",
            {"user_id": user_id, "mode": "backup_password"},
            user_id=user_id,
        )
        self._log_backup_event(user_id, "BACKUP_RECOVERY_ENABLED", {"mode": "backup_password"})
        return True, "Backup password set. Use it only for backup/restore."

    def _build_backup_payload(self, user_id: int, priv_key_data: bytes) -> Tuple[Optional[bytes], Optional[str]]:
        """Build canonical backup payload (current user's vault only). Returns (payload_bytes, error_message)."""
        metadata = self.secret_service.get_secrets_metadata(user_id)
        entries: List[Dict] = []
        for m in metadata:
            pwd, msg = self.secret_service.decrypt_secret(user_id, m["id"], priv_key_data)
            if pwd is None:
                return None, f"Failed to export entry {m['id']}: {msg}"
            entries.append({
                "service": m.get("service_name") or m.get("service", ""),
                "username": m.get("username_email") or m.get("username", ""),
                "url": m.get("url") or "",
                "password": pwd,
                "created_at": str(m.get("created_at", "")),
            })

        payload = {
            "payload_format": PAYLOAD_FORMAT,
            "exported_at": datetime.datetime.utcnow().isoformat(),
            "entries": entries,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), None

    def _derive_encryption_key(
        self,
        mode: str,
        recovery_key_or_password: str,
        salt: bytes,
        *,
        skip_password_validation: bool = False,
    ) -> Optional[bytes]:
        """Derive encryption key. When skip_password_validation is True (e.g. for decrypt), backup_password mode accepts any non-empty string."""
        if mode == "recovery_key":
            key_bytes = _recovery_key_to_bytes(recovery_key_or_password)
            if not key_bytes:
                return None
            return CryptoUtils.hkdf_expand(key_bytes, salt=salt, info=ENC_KEY_INFO, length=32)
        if mode == "backup_password":
            if not (recovery_key_or_password or "").strip():
                return None
            if not skip_password_validation:
                ok, _ = _validate_backup_password(recovery_key_or_password)
                if not ok:
                    return None
            root = self._derive_key_from_backup_password(recovery_key_or_password, salt)
            return CryptoUtils.hkdf_expand(root, salt=salt, info=ENC_KEY_INFO, length=32)
        return None

    def _build_encrypted_envelope(
        self,
        user_id: int,
        priv_key_data: bytes,
        recovery_key_or_password: str,
        mode: str,
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """Build encrypted backup envelope (no write). Returns (envelope_dict, error_message)."""
        if mode not in ("recovery_key", "backup_password"):
            return None, "Invalid backup mode"
        cfg = self._get_config(user_id)
        if not cfg or not cfg["backup_enabled"] or cfg["backup_mode"] != mode:
            return None, "Backup recovery not enabled for this mode"
        if mode == "recovery_key":
            if not self._verify_recovery_key(user_id, recovery_key_or_password):
                return None, "Invalid backup recovery key or password"
        else:
            if not self._verify_backup_password(user_id, recovery_key_or_password):
                return None, "Invalid backup recovery key or password"
        payload_bytes, err = self._build_backup_payload(user_id, priv_key_data)
        if err:
            return None, err
        salt = os.urandom(16)
        enc_key = self._derive_encryption_key(mode, recovery_key_or_password, salt)
        if not enc_key:
            return None, "Key derivation failed"
        nonce = os.urandom(12)
        aad = b"sv_backup_recovery_v1"
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(enc_key)
        ct_with_tag = aesgcm.encrypt(nonce, payload_bytes, aad)
        key_verifier = CryptoUtils.hmac_sha256_hex(enc_key, b"backup_key_verifier")
        backup_id = str(uuid.uuid4())
        created_at = datetime.datetime.utcnow().isoformat() + "Z"
        envelope = {
            "format_version": BACKUP_FORMAT_VERSION,
            "app_version": None,
            "schema_version": 1,
            "created_at": created_at,
            "backup_id": backup_id,
            "user_id": user_id,
            "encryption": {
                "kdf": "hkdf" if mode == "recovery_key" else "argon2id",
                "algorithm": "AES-256-GCM",
                "salt": CryptoUtils.b64e(salt),
                "nonce": CryptoUtils.b64e(nonce),
            },
            "ciphertext": CryptoUtils.b64e(ct_with_tag),
            "key_verifier": key_verifier,
            "manifest": {"entry_count": len(json.loads(payload_bytes.decode("utf-8")).get("entries", []))},
        }
        return envelope, None

    def export_user_backup_encrypted(
        self,
        user_id: int,
        priv_key_data: bytes,
        destination_path_or_bytes: Union[str, Path, type(None)],
        recovery_key_or_password: str,
        mode: str = "recovery_key",
    ) -> Tuple[bool, str, Optional[Dict]]:
        """
        Export current user's vault as an encrypted backup.
        destination_path_or_bytes: file path to write, or None to return bundle dict only.
        mode: 'recovery_key' | 'backup_password'
        Returns (success, message, bundle_dict_if_not_written_to_file).
        """
        envelope, err = self._build_encrypted_envelope(user_id, priv_key_data, recovery_key_or_password, mode)
        if err:
            return False, err, None
        self._update_last_backup(user_id)
        self.audit.log_event(
            "local_backup_created",
            {"user_id": user_id, "backup_id": envelope["backup_id"], "entries": envelope["manifest"]["entry_count"]},
            user_id=user_id,
        )
        self._log_backup_event(
            user_id,
            "LOCAL_BACKUP_CREATED",
            {"backup_id": envelope["backup_id"], "format": BACKUP_FORMAT_VERSION},
        )
        if destination_path_or_bytes is not None:
            path = Path(destination_path_or_bytes)
            try:
                path.write_text(json.dumps(envelope, separators=(",", ":")), encoding="utf-8")
            except Exception as e:
                return False, str(e), None
            return True, f"Backup saved to {path}", None
        return True, "Backup created", envelope

    def decrypt_backup_package(
        self,
        backup_bytes_or_path: Union[bytes, str, Path],
        recovery_key_or_password: str,
        mode: str = "recovery_key",
    ) -> Tuple[bool, str, Optional[Dict]]:
        """
        Decrypt and parse backup package. Returns (success, message, payload_dict).
        payload_dict has 'entries' and 'payload_format'.
        """
        try:
            if isinstance(backup_bytes_or_path, (str, Path)):
                raw = Path(backup_bytes_or_path).read_bytes()
            else:
                raw = backup_bytes_or_path
            envelope = json.loads(raw.decode("utf-8"))
        except Exception as e:
            return False, f"Invalid backup file: {e}", None

        if envelope.get("format_version") != BACKUP_FORMAT_VERSION:
            return False, "Unsupported backup format version", None

        enc = envelope.get("encryption", {})
        salt_b64 = enc.get("salt")
        nonce_b64 = enc.get("nonce")
        ct_b64 = envelope.get("ciphertext")
        if not salt_b64 or not nonce_b64 or not ct_b64:
            return False, "Missing encryption metadata", None

        salt = CryptoUtils.b64d(salt_b64)
        nonce = CryptoUtils.b64d(nonce_b64)
        ct = CryptoUtils.b64d(ct_b64)
        enc_key = self._derive_encryption_key(
            mode, recovery_key_or_password, salt, skip_password_validation=True
        )
        if not enc_key:
            return False, "Key derivation failed", None

        stored_verifier = envelope.get("key_verifier")
        if stored_verifier:
            expected = CryptoUtils.hmac_sha256_hex(enc_key, b"backup_key_verifier")
            if not hmac.compare_digest(stored_verifier, expected):
                return False, "Invalid backup recovery key or password", None

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            plaintext = AESGCM(enc_key).decrypt(nonce, ct, b"sv_backup_recovery_v1")
        except Exception:
            return False, "Decryption failed (wrong key or corrupted data)", None

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception:
            return False, "Invalid payload structure", None

        if payload.get("payload_format") != PAYLOAD_FORMAT or "entries" not in payload:
            return False, "Invalid payload format", None

        return True, "OK", payload

    def decrypt_backup_package_auto(
        self,
        backup_bytes_or_path: Union[bytes, str, Path],
        recovery_key_or_password: str,
    ) -> Tuple[bool, str, Optional[Dict], Optional[str]]:
        """
        Decrypt backup by trying recovery key then backup password. No account needed.
        Returns (success, message, payload_dict or None, mode_used or None).
        """
        try:
            if isinstance(backup_bytes_or_path, (str, Path)):
                raw = Path(backup_bytes_or_path).read_bytes()
            else:
                raw = backup_bytes_or_path
            envelope = json.loads(raw.decode("utf-8"))
        except Exception as e:
            return False, f"Invalid backup file: {e}", None, None

        if envelope.get("format_version") != BACKUP_FORMAT_VERSION:
            return False, "Unsupported backup format version", None, None

        enc = envelope.get("encryption", {})
        salt_b64 = enc.get("salt")
        nonce_b64 = enc.get("nonce")
        ct_b64 = envelope.get("ciphertext")
        if not salt_b64 or not nonce_b64 or not ct_b64:
            return False, "Missing encryption metadata", None, None

        salt = CryptoUtils.b64d(salt_b64)
        nonce = CryptoUtils.b64d(nonce_b64)
        ct = CryptoUtils.b64d(ct_b64)
        stored_verifier = envelope.get("key_verifier")
        input_str = (recovery_key_or_password or "").strip()
        if not input_str:
            return False, "Enter your backup recovery key or backup password.", None, None

        for mode in ("recovery_key", "backup_password"):
            enc_key = self._derive_encryption_key(
                mode, input_str, salt, skip_password_validation=True
            )
            if not enc_key:
                continue
            if stored_verifier:
                expected = CryptoUtils.hmac_sha256_hex(enc_key, b"backup_key_verifier")
                if not hmac.compare_digest(stored_verifier, expected):
                    continue
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                plaintext = AESGCM(enc_key).decrypt(nonce, ct, b"sv_backup_recovery_v1")
            except Exception:
                continue
            try:
                payload = json.loads(plaintext.decode("utf-8"))
            except Exception:
                return False, "Invalid payload structure", None, None
            if payload.get("payload_format") != PAYLOAD_FORMAT or "entries" not in payload:
                return False, "Invalid payload format", None, None
            return True, "OK", payload, mode

        return False, "Invalid backup recovery key or password", None, None

    def validate_backup_package_auto(
        self,
        backup_bytes_or_path: Union[bytes, str, Path],
        recovery_key_or_password: str,
        user_id: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Validate backup by trying recovery key then backup password. No mode needed.
        Returns (success, message). Logs backup_validation_* and sets latest_validation_status when user_id given.
        """
        self.audit.log_event("backup_validation_started", {}, user_id=user_id)
        ok, msg, payload, _mode = self.decrypt_backup_package_auto(backup_bytes_or_path, recovery_key_or_password)
        if ok and payload:
            self.audit.log_event("backup_validation_success", {"entries": len(payload.get("entries", []))}, user_id=user_id)
            if user_id is not None:
                self.set_latest_validation_status(user_id, True)
            return True, "Backup is valid and can be restored"
        self.audit.log_event("backup_validation_failed", {"reason": msg}, user_id=user_id)
        if user_id is not None:
            self.set_latest_validation_status(user_id, False)
        return False, msg

    def validate_backup_package(
        self,
        backup_bytes_or_path: Union[bytes, str, Path],
        recovery_key_or_password: str,
        mode: str = "recovery_key",
        user_id: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Validate backup envelope and decrypt with given key/password without restoring.
        Returns (success, message). Logs backup_validation_started, backup_validation_success or backup_validation_failed.
        If user_id is provided, stores result for dashboard via set_latest_validation_status.
        """
        self.audit.log_event("backup_validation_started", {}, user_id=user_id)
        ok, msg, payload = self.decrypt_backup_package(backup_bytes_or_path, recovery_key_or_password, mode)
        if ok:
            self.audit.log_event("backup_validation_success", {"entries": len(payload.get("entries", []))}, user_id=user_id)
            if user_id is not None:
                self.set_latest_validation_status(user_id, True)
            return True, "Backup is valid and can be restored"
        self.audit.log_event("backup_validation_failed", {"reason": msg}, user_id=user_id)
        if user_id is not None:
            self.set_latest_validation_status(user_id, False)
        return False, msg

    def preview_backup_metadata(
        self,
        backup_bytes_or_path: Union[bytes, str, Path],
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Phase 4: Return safe metadata from backup envelope without decryption.
        No secret data. Returns (success, message, metadata_dict or None).
        """
        try:
            if isinstance(backup_bytes_or_path, (str, Path)):
                raw = Path(backup_bytes_or_path).read_bytes()
            else:
                raw = backup_bytes_or_path
            envelope = json.loads(raw.decode("utf-8"))
        except Exception as e:
            return False, f"Invalid backup file: {e}", None

        format_version = envelope.get("format_version")
        if format_version != BACKUP_FORMAT_VERSION:
            return False, "Unsupported backup format version", None

        manifest = envelope.get("manifest") or {}
        meta = {
            "format_version": format_version,
            "backup_id": envelope.get("backup_id"),
            "created_at": envelope.get("created_at"),
            "user_id": envelope.get("user_id"),
            "schema_version": envelope.get("schema_version"),
            "entry_count": manifest.get("entry_count", 0),
        }
        return True, "OK", meta

    def resolve_recovery_factor(self, user_id: int, input_str: str) -> Tuple[bool, Optional[str], str]:
        """
        Try to validate input as recovery key first, then as backup password.
        Returns (success, mode_used, error_message).
        Use this when the UI accepts 'recovery key or backup password' in one field.
        """
        if not (input_str or "").strip():
            return False, None, "Enter your backup recovery key or backup password."
        cfg = self._get_config(user_id)
        if not cfg or not cfg["backup_enabled"]:
            return False, None, "Backup recovery is not enabled."
        s = input_str.strip()
        if self._verify_recovery_key(user_id, s):
            return True, "recovery_key", ""
        if self._verify_backup_password(user_id, s):
            return True, "backup_password", ""
        return False, None, "Invalid backup recovery key or password."

    def set_auto_backup_key_for_session(self, user_id: int, recovery_key_or_password: str, mode: str) -> Tuple[bool, str]:
        """Store recovery key/password in memory for scheduled/change-triggered backups. Never persisted."""
        if mode not in ("recovery_key", "backup_password"):
            return False, "Invalid mode"
        cfg = self._get_config(user_id)
        if not cfg or not cfg["backup_enabled"] or cfg["backup_mode"] != mode:
            return False, "Backup recovery not enabled for this mode"
        if mode == "recovery_key":
            if not self._verify_recovery_key(user_id, recovery_key_or_password):
                return False, "Invalid backup recovery key or password"
        else:
            if not self._verify_backup_password(user_id, recovery_key_or_password):
                return False, "Invalid backup recovery key or password"
        self._cached_auto_backup_key[user_id] = (recovery_key_or_password, mode)
        return True, "Auto backup key set for this session"

    def clear_auto_backup_key_for_user(self, user_id: int) -> None:
        """Clear cached key for user (e.g. on logout)."""
        self._cached_auto_backup_key.pop(user_id, None)
        self._pending_change_at.pop(user_id, None)

    def clear_auto_backup_keys(self) -> None:
        """Clear all cached keys and pending state."""
        self._cached_auto_backup_key.clear()
        self._pending_change_at.clear()

    def create_local_backup_now(
        self,
        user_id: int,
        priv_key_data: bytes,
        reason: str = "manual",
        recovery_key_or_password: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Create a versioned local backup in app backup dir. reason: 'manual'|'scheduled'|'change'.
        If recovery_key_or_password/mode are None, uses cached key from set_auto_backup_key_for_session.
        Phase 5: in-progress guard prevents overlapping backups per user.
        """
        if self._backup_in_progress.get(user_id):
            return False, "Backup already in progress"
        self._backup_in_progress[user_id] = True
        try:
            return self._create_local_backup_now_impl(user_id, priv_key_data, reason, recovery_key_or_password, mode)
        finally:
            self._backup_in_progress.pop(user_id, None)

    def _create_local_backup_now_impl(
        self,
        user_id: int,
        priv_key_data: bytes,
        reason: str,
        recovery_key_or_password: Optional[str],
        mode: Optional[str],
    ) -> Tuple[bool, str]:
        if reason not in ("manual", "scheduled", "change_triggered"):
            reason = "manual"
        key_mode = mode
        key_or_pass = recovery_key_or_password
        if key_or_pass is None or key_mode is None:
            cached = self._cached_auto_backup_key.get(user_id)
            if not cached:
                return False, "Provide recovery key/password or set auto backup key for this session"
            key_or_pass, key_mode = cached
        envelope, err = self._build_encrypted_envelope(user_id, priv_key_data, key_or_pass, key_mode)
        if err:
            if reason != "manual":
                self.audit.log_event("local_backup_failed", {"user_id": user_id, "reason": reason, "error": err}, user_id=user_id)
            return False, err
        backup_dir = self._backup_dir_for_user(user_id)
        try:
            backup_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.audit.log_event("local_backup_failed", {"user_id": user_id, "reason": reason, "error": str(e)}, user_id=user_id)
            return False, f"Cannot create backup directory: {e}"
        # Filename: vault_backup_<username>_<YYYY-MM-DD>_<HH-MM-SS-AM/PM>.enc (12-hour, local time)
        created_str = envelope.get("created_at") or ""
        try:
            dt_utc = datetime.datetime.fromisoformat(created_str.replace("Z", "+00:00").strip())
            # Convert UTC to local time so filename matches user's clock
            if dt_utc.tzinfo is not None:
                dt_local = dt_utc.astimezone()
            else:
                dt_local = dt_utc
            dt = dt_local.replace(tzinfo=None)  # naive for strftime
            date_part = dt.strftime("%Y-%m-%d")
            hour12 = dt.hour % 12 or 12
            am_pm = "AM" if dt.hour < 12 else "PM"
            time_part = f"{hour12:02d}-{dt.minute:02d}-{dt.second:02d}-{am_pm}"
            ts = f"{date_part}_{time_part}"
        except Exception:
            ts = (created_str or "").replace(":", "-").replace("Z", "")[:19].replace("T", "_")
        username = self._get_username_for_user_id(user_id)
        safe_username = re.sub(r"[^\w\-.]", "_", username.strip())[:64] or "user"
        fname = f"vault_backup_{safe_username}_{ts}_{envelope['backup_id']}.enc"
        out_path = backup_dir / fname
        try:
            out_path.write_text(json.dumps(envelope, separators=(",", ":")), encoding="utf-8")
        except OSError as e:
            self.audit.log_event("local_backup_failed", {"user_id": user_id, "reason": reason, "error": str(e)}, user_id=user_id)
            return False, f"Failed to write backup file: {e}"
        self._update_last_backup(user_id)
        event_type = {"manual": "local_backup_created_manual", "scheduled": "local_backup_created_scheduled", "change_triggered": "local_backup_created_change_triggered"}.get(reason, "local_backup_created")
        self.audit.log_event(event_type, {"user_id": user_id, "backup_id": envelope["backup_id"], "path": fname}, user_id=user_id)
        self._log_backup_event(user_id, "LOCAL_BACKUP_CREATED", {"backup_id": envelope["backup_id"], "reason": reason})
        latest = {"backup_id": envelope["backup_id"], "path": fname, "created_at": envelope["created_at"], "entry_count": envelope["manifest"]["entry_count"]}
        try:
            (backup_dir / LATEST_FILENAME).write_text(json.dumps(latest, separators=(",", ":")), encoding="utf-8")
        except Exception:
            pass
        manifest_path = backup_dir / MANIFEST_FILENAME
        try:
            history = []
            if manifest_path.exists():
                try:
                    history = json.loads(manifest_path.read_text(encoding="utf-8"))
                except Exception:
                    history = []
            if not isinstance(history, list):
                history = []
            history.append({"backup_id": envelope["backup_id"], "path": fname, "created_at": envelope["created_at"], "reason": reason})
            manifest_path.write_text(json.dumps(history[-50:], separators=(",", ":")), encoding="utf-8")
        except Exception:
            pass
        pruned = self.prune_local_backups(user_id)
        if pruned:
            self.audit.log_event("local_backup_pruned", {"user_id": user_id, "count": pruned}, user_id=user_id)
        if reason == "change_triggered":
            self._pending_change_at.pop(user_id, None)
        msg = str(out_path)
        if pruned:
            msg += f". Pruned {pruned} old backup(s)."
        return True, msg

    def list_local_backups(self, user_id: int) -> List[Dict]:
        """List versioned local backup files for user (timestamp, size, path, backup_id, reason if in manifest)."""
        backup_dir = self._backup_dir_for_user(user_id)
        if not backup_dir.exists():
            return []
        manifest_path = backup_dir / MANIFEST_FILENAME
        by_path = {}
        if manifest_path.exists():
            try:
                for e in json.loads(manifest_path.read_text(encoding="utf-8")):
                    if isinstance(e, dict) and e.get("path"):
                        by_path[e["path"]] = e
            except Exception:
                pass
        result = []
        for p in backup_dir.iterdir():
            if p.is_file() and p.suffix == ".enc" and p.name.startswith("vault_backup_"):
                try:
                    stat = p.stat()
                    created_at = ""
                    backup_id = ""
                    reason = ""
                    if p.name in by_path:
                        created_at = by_path[p.name].get("created_at", "")
                        backup_id = by_path[p.name].get("backup_id", "")
                        reason = by_path[p.name].get("reason", "")
                    if not created_at:
                        try:
                            env = json.loads(p.read_text(encoding="utf-8"))
                            created_at = env.get("created_at", "")
                            backup_id = env.get("backup_id", "")
                        except Exception:
                            pass
                    result.append({
                        "path": str(p),
                        "filename": p.name,
                        "size": stat.st_size,
                        "created_at": created_at,
                        "backup_id": backup_id or p.stem,
                        "reason": reason,
                    })
                except OSError:
                    continue
        result.sort(key=lambda x: x.get("created_at") or "", reverse=True)
        return result

    def prune_local_backups(self, user_id: int) -> int:
        """Keep only keep_last_n_backups; delete older. Returns number of files deleted. Never deletes newest."""
        settings = self.get_backup_settings(user_id)
        keep_raw = settings.get("keep_last_n_backups", KEEP_LAST_N_DEFAULT)
        try:
            keep = max(KEEP_LAST_N_MIN, min(KEEP_LAST_N_MAX, int(keep_raw or KEEP_LAST_N_DEFAULT)))
        except (TypeError, ValueError):
            keep = KEEP_LAST_N_DEFAULT
        if keep < KEEP_LAST_N_MIN:
            keep = KEEP_LAST_N_MIN
        backups = self.list_local_backups(user_id)
        if len(backups) <= keep:
            return 0
        to_remove = backups[keep:]
        deleted = 0
        for b in to_remove:
            try:
                Path(b["path"]).unlink(missing_ok=True)
                deleted += 1
            except OSError as e:
                self.audit.log_event(
                    "local_backup_prune_delete_failed",
                    {"user_id": user_id, "path": b.get("filename", ""), "error": str(e)},
                    user_id=user_id,
                )
        return deleted

    def should_run_scheduled_backup(self, user_id: int) -> bool:
        """True if scheduled backup is enabled and next backup is due."""
        cfg = self._get_config(user_id)
        if not cfg or not cfg["backup_enabled"]:
            return False
        settings = self.get_backup_settings(user_id)
        if not settings.get("backup_auto_enabled"):
            return False
        last = cfg.get("last_backup_at")
        interval_hours = settings.get("schedule_interval_hours", SCHEDULE_INTERVAL_DEFAULT_HOURS)
        if last is None:
            return True
        try:
            if isinstance(last, str):
                last_dt = datetime.datetime.fromisoformat(last.replace("Z", "").strip())
            else:
                last_dt = last
            if last_dt.tzinfo:
                now = datetime.datetime.now(last_dt.tzinfo)
            else:
                now = datetime.datetime.utcnow()
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=None)
            delta = datetime.timedelta(hours=float(interval_hours))
            next_due = last_dt + delta
            return now >= next_due
        except Exception:
            return True

    def mark_backup_event(self, user_id: int, event_type: str) -> None:
        """Record a vault change for debounced backup-on-change. event_type e.g. 'secret_add'|'secret_delete'."""
        self._pending_change_at[user_id] = time.time()

    def process_pending_backup_jobs(
        self,
        user_id: int,
        priv_key_data: Optional[bytes] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Run scheduled or debounced change-triggered backup if due. Uses cached key.
        Returns (did_run, message_or_none). Safe to call from UI timer.
        """
        if priv_key_data is None:
            return False, None
        cfg = self._get_config(user_id)
        if not cfg or not cfg["backup_enabled"]:
            return False, None
        settings = self.get_backup_settings(user_id)
        did_run = False
        if settings.get("backup_auto_enabled") and self.should_run_scheduled_backup(user_id):
            ok, msg = self.create_local_backup_now(user_id, priv_key_data, reason="scheduled")
            did_run = ok
            if not ok and "Provide recovery key" not in (msg or ""):
                self.audit.log_event("local_backup_failed", {"user_id": user_id, "reason": "scheduled", "error": msg}, user_id=user_id)
            return did_run, msg
        last_change = self._pending_change_at.get(user_id)
        if settings.get("backup_on_change_enabled") and last_change is not None:
            debounce = settings.get("on_change_debounce_seconds", ON_CHANGE_DEBOUNCE_DEFAULT)
            try:
                debounce = max(ON_CHANGE_DEBOUNCE_MIN, min(ON_CHANGE_DEBOUNCE_MAX, int(debounce)))
            except (TypeError, ValueError):
                debounce = ON_CHANGE_DEBOUNCE_DEFAULT
            if (time.time() - last_change) >= debounce:
                self._pending_change_at.pop(user_id, None)
                ok, msg = self.create_local_backup_now(user_id, priv_key_data, reason="change_triggered")
                did_run = ok
                if not ok and "Provide recovery key" not in (msg or ""):
                    self.audit.log_event("local_backup_failed", {"user_id": user_id, "reason": "change_triggered", "error": msg}, user_id=user_id)
                return did_run, msg
        return False, None

    def get_backup_status(self, user_id: int) -> Dict[str, Any]:
        """Full backup health for dashboard (Phase 5): enabled, mode, last_backup_at, count, next_due, validation, staleness, restore_readiness."""
        status = self.get_backup_recovery_status(user_id)
        settings = self.get_backup_settings(user_id)
        backups = self.list_local_backups(user_id)
        cfg = self._get_config(user_id)
        last_backup_at = (cfg or {}).get("last_backup_at")
        next_due = None
        if status.get("enabled") and settings.get("backup_auto_enabled") and last_backup_at:
            try:
                interval = settings.get("schedule_interval_hours", SCHEDULE_INTERVAL_DEFAULT_HOURS)
                last_dt = datetime.datetime.fromisoformat(str(last_backup_at).replace("Z", "+00:00"))
                next_due = (last_dt + datetime.timedelta(hours=interval)).isoformat()
            except Exception:
                pass
        # Staleness: warn if no successful backup in the last N days
        stale_warning = None
        last_backup_age_days = None
        if last_backup_at:
            try:
                last_dt = datetime.datetime.fromisoformat(str(last_backup_at).replace("Z", "").strip())
                if last_dt.tzinfo:
                    now = datetime.datetime.now(last_dt.tzinfo)
                else:
                    now = datetime.datetime.utcnow()
                delta = now - last_dt
                last_backup_age_days = delta.total_seconds() / 86400.0
                threshold = settings.get("stale_warning_days", STALE_WARNING_DAYS_DEFAULT)
                if last_backup_age_days > threshold:
                    stale_warning = f"No successful backup in {int(last_backup_age_days)} days"
            except Exception:
                pass
        latest_validation_ok = settings.get("latest_validation_ok")
        latest_validation_at = settings.get("latest_validation_at")
        restore_readiness = (
            "Recovery is possible if you have a valid local backup and your Backup Recovery Key or Backup Password."
            if status.get("enabled") else "Enable Backup Recovery Key or Backup Password to allow restore from backup."
        )
        return {
            "enabled": status.get("enabled", False),
            "mode": status.get("mode"),
            "recovery_configured": status.get("has_verifier", False),
            "last_backup_at": last_backup_at,
            "last_backup_age_days": last_backup_age_days,
            "local_backup_count": len(backups),
            "next_scheduled_due": next_due,
            "backup_auto_enabled": settings.get("backup_auto_enabled", False),
            "backup_on_change_enabled": settings.get("backup_on_change_enabled", False),
            "on_change_debounce_seconds": settings.get("on_change_debounce_seconds", ON_CHANGE_DEBOUNCE_DEFAULT),
            "keep_last_n_backups": settings.get("keep_last_n_backups", KEEP_LAST_N_DEFAULT),
            "schedule_interval_hours": settings.get("schedule_interval_hours", SCHEDULE_INTERVAL_DEFAULT_HOURS),
            "latest_backup_path": backups[0]["path"] if backups else None,
            "latest_validation_ok": latest_validation_ok,
            "latest_validation_at": latest_validation_at,
            "staleness_warning": stale_warning,
            "restore_readiness": restore_readiness,
            "backup_folder_path": self.get_backup_folder_path(user_id),
            "stale_warning_days": settings.get("stale_warning_days", STALE_WARNING_DAYS_DEFAULT),
        }
