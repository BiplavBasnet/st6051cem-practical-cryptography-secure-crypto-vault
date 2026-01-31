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
