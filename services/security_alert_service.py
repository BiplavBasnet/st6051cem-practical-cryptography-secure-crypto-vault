"""
Centralized Security Alert Notification service.
- Accepts security-relevant events, classifies severity, formats plain-English messages.
- Publishes to UI (banner/toast via callback) and records to audit log (sanitized).
- Throttles/deduplicates to prevent spam.
"""

import time
from typing import Any, Callable, Dict, List, Optional

from services.audit_log import AuditLog
from services.audit_log_normalizer import sanitize_details


# Severity levels for UI styling and behavior
SEVERITY_INFO = "Info"
SEVERITY_WARNING = "Warning"
SEVERITY_CRITICAL = "Critical"

# Default throttle: suppress same (event_code, context_key) for this many seconds
DEFAULT_THROTTLE_SECONDS = 20


# Event code -> (severity, plain-English message)
# Message can use {reason} if context has "reason" or "message"
_ALERT_MAP: Dict[str, tuple] = {
    # Session - Info
    "session_locked_idle": (SEVERITY_INFO, "App locked due to inactivity."),
    "session_locked_manual": (SEVERITY_INFO, "App locked."),
    "session_hard_expired": (SEVERITY_INFO, "Session expired. Please sign in again."),
    "session_unlocked": (SEVERITY_INFO, "App unlocked."),
    "step_up_reauth_prompted": (SEVERITY_INFO, "Re-authentication required for this action."),
    # Unlock / auth - Warning or Critical
    "unlock_failed": (SEVERITY_WARNING, "Wrong password. Try again."),
    "unlock_failed_repeated_threshold": (
        SEVERITY_CRITICAL,
        "Multiple failed unlock attempts detected. Please wait before trying again.",
    ),
    "step_up_reauth_failed": (SEVERITY_WARNING, "Re-authentication failed. Please try again."),
    "step_up_reauth_failed_threshold": (
        SEVERITY_CRITICAL,
        "Repeated re-authentication failures. Please try again later.",
    ),
    # Extension / API
    "api_request_denied_auth_required": (
        SEVERITY_WARNING,
        "Autofill request blocked: sign in to the app first.",
    ),
    "api_request_denied_session_expired": (
        SEVERITY_WARNING,
        "Autofill request blocked: session expired.",
    ),
    "api_request_denied_locked": (
        SEVERITY_WARNING,
        "Autofill request blocked because the app is locked.",
    ),
    "api_request_denied_reauth_required": (
        SEVERITY_WARNING,
        "Autofill request blocked: re-authentication required.",
    ),
    "suspicious_repeated_denied_requests": (
        SEVERITY_CRITICAL,
        "Multiple autofill requests were blocked. Check that the app is unlocked.",
    ),
    # Backup
    "local_backup_failed": (SEVERITY_WARNING, "Backup failed."),
    "backup_validation_failed": (
        SEVERITY_WARNING,
        "Backup validation failed: the selected backup file appears to be invalid or corrupted.",
    ),
    "corrupt_backup_detected": (
        SEVERITY_CRITICAL,
        "The backup file appears to be corrupted or invalid.",
    ),
    # Restore
    "backup_restore_failed": (SEVERITY_CRITICAL, "Restore failed."),
    "post_restore_rekey_failed": (
        SEVERITY_CRITICAL,
        "Restore blocked: could not save new keys. Please try again.",
    ),
    "backup_restore_validation_failed": (
        SEVERITY_CRITICAL,
        "Restore validation failed. The backup file may be invalid or the recovery key incorrect.",
    ),
    # Settings
    "security_settings_updated": (SEVERITY_INFO, "Security settings were changed."),
    "idle_lock_disabled": (SEVERITY_INFO, "Idle lock was disabled."),
    "hard_session_expiry_disabled": (SEVERITY_INFO, "Session expiry was disabled."),
    "step_up_reauth_disabled": (SEVERITY_INFO, "Step-up re-authentication was disabled."),
}


def _context_key(context: Optional[Dict[str, Any]]) -> str:
    """Stable key for throttling: path + reason, or empty."""
    if not context or not isinstance(context, dict):
        return ""
    parts = []
    if "path" in context:
        parts.append(str(context.get("path", ""))[:80])
    if "reason" in context:
        parts.append(str(context.get("reason", ""))[:80])
    return "|".join(parts)


def _format_message(template: str, context: Optional[Dict[str, Any]]) -> str:
    """Replace {reason} in template with context reason/message if present."""
    if not context or not isinstance(context, dict):
        return template
    reason = context.get("reason") or context.get("message") or ""
    if not reason:
        return template
    # Sanitize: no long tracebacks
    reason_str = str(reason).strip()[:200]
    if "{" in template and "reason" in template:
        return template.replace("{reason}", reason_str)
    return template


class SecurityAlertService:
    """
    Centralized security alert service.
    - notify_security_alert: main entry; throttle, format, log, publish to UI.
    - publish_alert_to_ui is injected by desktop (runs on main thread).
    """

    def __init__(
        self,
        audit: AuditLog,
        publish_alert_to_ui: Optional[Callable[[str, str, str, Optional[Dict]], None]] = None,
        throttle_seconds: float = DEFAULT_THROTTLE_SECONDS,
    ):
        self.audit = audit
        self._publish_alert_to_ui = publish_alert_to_ui
        self._throttle_seconds = throttle_seconds
        # (event_code, context_key) -> last_shown_timestamp
        self._last_shown: Dict[tuple, float] = {}
        # Optional: repeated count per key for aggregation (e.g. "repeated 5 times")
        self._repeat_count: Dict[tuple, int] = {}

    def format_security_alert_message(
        self, event_code: str, context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Return plain-English message for the event. No secrets, no tracebacks."""
        if event_code in _ALERT_MAP:
            _, template = _ALERT_MAP[event_code]
            return _format_message(template, context)
        # Fallback
        return f"Security event: {event_code.replace('_', ' ')}."

    def _get_severity(self, event_code: str, severity_override: Optional[str]) -> str:
        if severity_override in (SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL):
            return severity_override
        if event_code in _ALERT_MAP:
            sev, _ = _ALERT_MAP[event_code]
            return sev
        return SEVERITY_INFO

    def should_suppress_duplicate_alert(
        self, event_code: str, context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """True if we should suppress UI for this alert (within throttle window)."""
        key = (event_code, _context_key(context))
        now = time.time()
        last = self._last_shown.get(key, 0)
        if now - last < self._throttle_seconds:
            self._repeat_count[key] = self._repeat_count.get(key, 0) + 1
            return True
        return False

    def log_security_alert(
        self,
        event_code: str,
        context: Optional[Dict[str, Any]],
        severity: str,
        message: str,
        user_id: Optional[int] = None,
    ) -> None:
        """Write one audit log entry. Context is sanitized (no secrets)."""
        try:
            safe = sanitize_details(context) if context else {}
            safe["severity"] = severity
            safe["message"] = message[:500]
            self.audit.log_event(event_code, safe, user_id=user_id)
        except Exception:
            pass

    def notify_security_alert(
        self,
        event_code: str,
        context: Optional[Dict[str, Any]] = None,
        severity: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> None:
        """
        Main entry: classify severity, optionally throttle UI, format message,
        log to audit, and publish to UI.
        """
        severity = self._get_severity(event_code, severity)
        message = self.format_security_alert_message(event_code, context)

        # Always log
        self.log_security_alert(event_code, context, severity, message, user_id=user_id)

        # Throttle UI
        if self.should_suppress_duplicate_alert(event_code, context):
            return

        key = (event_code, _context_key(context))
        self._last_shown[key] = time.time()
        repeat = self._repeat_count.pop(key, 0)
        if repeat > 0:
            message = f"{message} (repeated {repeat + 1} times.)"

        if self._publish_alert_to_ui:
            try:
                self._publish_alert_to_ui(severity, message, event_code, context)
            except Exception:
                pass

    def set_publish_alert_to_ui(
        self, callback: Optional[Callable[[str, str, str, Optional[Dict]], None]]
    ) -> None:
        """Inject UI callback (e.g. from desktop app)."""
        self._publish_alert_to_ui = callback

    def get_recent_alerts(
        self,
        list_audit_logs_fn: Callable[..., List[Dict]],
        limit: int = 10,
        **kwargs: Any,
    ) -> List[Dict]:
        """
        Return recent security-related audit entries.
        list_audit_logs_fn is typically api.list_audit_logs; kwargs can include
        category filter, etc. Caller passes limit and optional filters.
        """
        try:
            return list_audit_logs_fn(limit=limit, **kwargs)
        except Exception:
            return []
