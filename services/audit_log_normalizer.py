"""
Normalization layer for audit log viewer: map raw event_type/details to
user-friendly category, status, action, message. Sanitize details (no secrets).
"""

import json
import re
from typing import Any, Dict, List, Optional

# Placeholder keys allowed in message templates (values from sanitized details only)
_MESSAGE_PLACEHOLDER_KEYS = frozenset({
    "service", "entries", "restored", "total", "count", "file", "added", "entry_count", "reason",
})
_MAX_PLACEHOLDER_LEN = 80

# Keys (case-insensitive) whose values must never be shown
SECRET_KEYS = frozenset({
    "password", "passphrase", "passwd", "pwd", "key", "token", "secret",
    "recovery", "backup_key", "backup_password", "priv_key", "enc_priv",
    "sign_priv", "auth_key", "session", "oauth", "certificate_pem",
})


def _is_secret_key(key: str) -> bool:
    k = (key or "").strip().lower()
    return any(s in k for s in SECRET_KEYS)


def _looks_like_secret_value(val: Any) -> bool:
    if not isinstance(val, str) or len(val) < 32:
        return False
    if re.match(r"^[A-Za-z0-9+/=]{32,}$", val):
        return True
    if re.match(r"^[0-9a-fA-F]{32,}$", val):
        return True
    return False


def sanitize_details(details: Any) -> Dict[str, Any]:
    """Return a copy of details with secret keys and secret-like values removed/redacted."""
    if details is None:
        return {}
    if not isinstance(details, dict):
        return {"value": "[redacted]" if _looks_like_secret_value(details) else str(details)[:200]}
    out = {}
    for k, v in details.items():
        if _is_secret_key(str(k)):
            out[str(k)] = "[redacted]"
            continue
        if isinstance(v, dict):
            out[str(k)] = sanitize_details(v)
        elif isinstance(v, list):
            out[str(k)] = [sanitize_details(x) if isinstance(x, dict) else ("[redacted]" if _looks_like_secret_value(x) else x) for x in v[:20]]
        elif _looks_like_secret_value(v):
            out[str(k)] = "[redacted]"
        else:
            out[str(k)] = v
    return out


def _user_facing_reason(reason: Any) -> str:
    """Turn backend reason into short user-facing phrase."""
    if reason is None:
        return ""
    s = str(reason).strip().lower()
    if "key" in s and ("invalid" in s or "incorrect" in s):
        return "Backup recovery key was incorrect."
    if "password" in s and ("invalid" in s or "wrong" in s):
        return "Password was incorrect."
    if "user not found" in s:
        return "User not found."
    if "vault_not_empty" in s:
        return "Vault is not empty; restore only when vault is empty."
    if "backup_user_mismatch" in s:
        return "Backup was created by a different account."
    if "locked" in s or "lock" in s:
        return "App is locked."
    if "expired" in s or "session" in s:
        return "Session expired. Please sign in again."
    if "reauth" in s or "re-auth" in s:
        return "Re-authentication required."
    if len(s) > 80:
        return s[:77] + "..."
    return s


# Event type -> (category, status, action, message_template or callable)
# Message can use {reason} from details.reason
_EVENT_MAP: Dict[str, tuple] = {
    # Session
    "session_locked_idle": ("Session", "Info", "Lock", "App locked due to inactivity."),
    "session_locked_manual": ("Session", "Info", "Lock", "App locked."),
    "session_unlocked": ("Session", "Success", "Unlock", "App unlocked."),
    "session_hard_expired": ("Session", "Warning", "Expiry", "Session expired. Please sign in again."),
    # Security / step-up
    "step_up_reauth_prompted": ("Security", "Info", "Re-auth", "Re-authentication required before sensitive action."),
    "step_up_reauth_success": ("Security", "Success", "Re-auth", "Re-authentication succeeded."),
    "step_up_reauth_failed": ("Security", "Failed", "Re-auth", "Re-authentication failed."),
    "AUTH_FAILURE": ("Security", "Failed", "Auth", "Authentication failed."),
    "AUTH_SUCCESS": ("Security", "Success", "Auth", "Authentication succeeded."),
    "SECURITY_ATTEMPT": ("Security", "Info", "Security", "Security-related attempt recorded."),
    "UNLOCK_FAILURE": ("Security", "Failed", "Unlock", "Unlock attempt failed."),
    "unlock_failed": ("Security", "Warning", "Unlock", "Wrong password. Try again."),
    "unlock_failed_repeated_threshold": ("Security", "Failed", "Unlock", "Multiple failed unlock attempts detected. Please wait before trying again."),
    "step_up_reauth_failed_threshold": ("Security", "Failed", "Re-auth", "Repeated re-authentication failures."),
    "suspicious_repeated_denied_requests": ("Extension", "Warning", "API", "Multiple autofill requests were blocked."),
    "security_settings_updated": ("Security", "Info", "Settings", "Security settings were changed."),
    "idle_lock_disabled": ("Session", "Info", "Settings", "Idle lock was disabled."),
    "hard_session_expiry_disabled": ("Session", "Info", "Settings", "Session expiry was disabled."),
    "step_up_reauth_disabled": ("Security", "Info", "Settings", "Step-up re-authentication was disabled."),
    "corrupt_backup_detected": ("Backup", "Failed", "Validate", "The backup file appears to be corrupted or invalid."),
    # Backup
    "local_backup_created_manual": ("Backup", "Success", "Backup", "Backup created (manual): {entries} entries."),
    "local_backup_created_scheduled": ("Backup", "Success", "Backup", "Backup created (scheduled): {entries} entries."),
    "local_backup_created_change_triggered": ("Backup", "Success", "Backup", "Backup created after vault change: {entries} entries."),
    "local_backup_created": ("Backup", "Success", "Backup", "Backup created: {entries} entries."),
    "local_backup_failed": ("Backup", "Failed", "Backup", "Backup failed."),
    "local_backup_pruned": ("Backup", "Info", "Backup", "Old backups removed: {count} deleted."),
    "backup_validation_started": ("Backup", "Info", "Validate", "Backup validation started."),
    "backup_validation_success": ("Backup", "Success", "Validate", "Backup validation succeeded: {entries} entries."),
    "backup_validation_failed": ("Backup", "Failed", "Validate", "Backup validation failed."),
    "backup_settings_updated": ("Backup", "Success", "Settings", "Backup settings updated."),
    # Restore
    "backup_restore_started": ("Restore", "Info", "Restore", "Restore started."),
    "backup_restore_completed": ("Restore", "Success", "Restore", "Restored {restored} of {total} entries."),
    "backup_restore_failed": ("Restore", "Failed", "Restore", "Restore failed: {reason}"),
    "backup_restore_validation_failed": ("Restore", "Failed", "Restore", "Restore validation failed: {reason}"),
    "backup_restore_validation_success": ("Restore", "Success", "Restore", "Restore validation passed: {entries} entries."),
    "post_restore_rekey_started": ("Restore", "Info", "Rekey", "Post-restore rekey started."),
    "post_restore_rekey_completed": ("Restore", "Success", "Rekey", "Post-restore rekey completed."),
    "post_restore_rekey_failed": ("Restore", "Failed", "Rekey", "Post-restore rekey failed."),
    # Vault
    "SECRET_ADDED": ("Vault", "Success", "Add", "Password entry added for {service}."),
    "SECRET_DELETED": ("Vault", "Success", "Delete", "Password entry deleted."),
    "SECRET_DECRYPTED": ("Vault", "Info", "Decrypt", "Password decrypted for {service}."),
    "SECRETS_IMPORTED_CSV": ("Vault", "Success", "Import", "Passwords imported from CSV: {added} added."),
    "SECRETS_IMPORTED_JSON": ("Vault", "Success", "Import", "Passwords imported from JSON: {added} added."),
    # Extension / API
    "api_request_denied_auth_required": ("Extension", "Warning", "API", "Autofill request blocked: Sign in required."),
    "api_request_denied_session_expired": ("Extension", "Warning", "API", "Autofill request blocked: Session expired."),
    "api_request_denied_locked": ("Extension", "Warning", "API", "Autofill request blocked: App is locked."),
    "api_request_denied_reauth_required": ("Extension", "Warning", "API", "Autofill request blocked: Re-authentication required."),
    "api_request_allowed_sensitive_action": ("Extension", "Info", "API", "Sensitive API action allowed (e.g. autofill)."),
    # User / account
    "USER_REGISTRATION": ("Security", "Success", "Register", "Account registered."),
    "REGISTRATION_ERROR": ("Security", "Failed", "Register", "Registration failed."),
    "account_reset_requested": ("Restore", "Info", "Reset", "Account reset requested."),
    "account_reset_confirmed": ("Restore", "Info", "Reset", "Account reset confirmed."),
    "account_reset_completed": ("Restore", "Success", "Reset", "Account reset completed."),
    "LOGIN_PASSPHRASE_RESET": ("Security", "Success", "Settings", "Login passphrase was reset."),
    "CERT_REVOCATION": ("Security", "Info", "Certificate", "Certificate revoked."),
    # Document
    "DOCUMENT_SIGNED": ("Security", "Success", "Sign", "Document signed: {file}."),
    # Sharing
    "SHARE_EXPIRED": ("Security", "Info", "Share", "Share expired."),
    # Vault backup export/import (encrypted backup)
    "VAULT_BACKUP_EXPORT": ("Backup", "Success", "Export", "Vault backup exported."),
    "VAULT_BACKUP_IMPORT": ("Backup", "Success", "Import", "Vault backup imported."),
    # Backup pruning
    "local_backup_prune_delete_failed": ("Backup", "Failed", "Backup", "Failed to remove old backup file."),
    # Key rotation
    "KEY_ROTATION": ("Security", "Success", "Certificate", "Keys rotated successfully."),
}


def _category_from_event_type(event_type: str) -> str:
    """Infer category from event_type prefix if not in map."""
    t = (event_type or "").strip().lower()
    if t.startswith("session_"):
        return "Session"
    if t.startswith("local_backup_") or t.startswith("backup_validation") or t.startswith("backup_settings"):
        return "Backup"
    if t.startswith("backup_restore") or t.startswith("post_restore"):
        return "Restore"
    if t.startswith("api_request"):
        return "Extension"
    if t.startswith("step_up_reauth") or t.startswith("AUTH_") or t.startswith("SECURITY_") or t.startswith("UNLOCK_"):
        return "Security"
    if t.startswith("SECRET"):
        return "Vault"
    if t.startswith("account_reset") or t.startswith("USER_") or "LOGIN" in t:
        return "Security"
    return "System"


def _fill_message_placeholders(message: str, details_safe: Dict[str, Any]) -> str:
    """Replace {key} placeholders in message with values from details_safe. Truncate long values."""
    if not message or "{" not in message:
        return message
    result = message
    for key in _MESSAGE_PLACEHOLDER_KEYS:
        placeholder = "{" + key + "}"
        if placeholder not in result:
            continue
        val = details_safe.get(key)
        if val is None or val == "" or val == "[redacted]":
            replacement = "—"
        else:
            s = str(val).strip()
            replacement = s[: _MAX_PLACEHOLDER_LEN] + ("..." if len(s) > _MAX_PLACEHOLDER_LEN else "")
        result = result.replace(placeholder, replacement)
    # entry_count can stand in for entries when present
    if "{entries}" in result and "entries" not in details_safe and "entry_count" in details_safe:
        ec = details_safe.get("entry_count")
        replacement = str(ec).strip()[: _MAX_PLACEHOLDER_LEN] if ec not in (None, "", "[redacted]") else "—"
        result = result.replace("{entries}", replacement)
    return result


def _status_from_event_type(event_type: str) -> str:
    t = (event_type or "").strip().lower()
    if "_failed" in t or "FAILURE" in t or "ERROR" in t:
        return "Failed"
    if "_success" in t or "_completed" in t or "SUCCESS" in t or "CREATED" in t:
        return "Success"
    if "denied" in t or "expired" in t:
        return "Warning"
    return "Info"


def normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert raw audit row to viewer row.
    In: id, user_id, event_type, details (dict), created_at
    Out: id, timestamp, category, action, status, message, event_code, source, details_safe
    """
    event_type = (row.get("event_type") or "").strip()
    details = row.get("details") or {}
    if not isinstance(details, dict):
        details = {}
    details_safe = sanitize_details(details)
    reason = details.get("reason") or details.get("error") or ""
    reason_phrase = _user_facing_reason(reason) if reason else ""

    if event_type in _EVENT_MAP:
        cat, status, action, msg_tpl = _EVENT_MAP[event_type]
        if "{reason}" in msg_tpl:
            message = msg_tpl.replace("{reason}", reason_phrase or "Unknown reason.")
        else:
            message = msg_tpl
        message = _fill_message_placeholders(message, details_safe)
    else:
        cat = _category_from_event_type(event_type)
        status = _status_from_event_type(event_type)
        action = event_type.replace("_", " ").title()[:40] if event_type else "Event"
        message = f"Activity: {event_type}" if event_type else "Activity recorded."

    created_at = row.get("created_at") or ""
    if isinstance(created_at, str) and len(created_at) > 19:
        created_at = created_at[:19]
    if created_at and not created_at.endswith(" UTC"):
        created_at = created_at.rstrip() + " UTC"

    return {
        "id": row.get("id"),
        "timestamp": created_at,
        "category": cat,
        "action": action,
        "status": status,
        "message": message,
        "event_code": event_type,
        "source": "Desktop",
        "details_safe": details_safe,
        "details_text": json.dumps(details_safe, indent=2) if details_safe else "",
    }


def normalize_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize a list of raw rows."""
    return [normalize_row(r) for r in rows]
