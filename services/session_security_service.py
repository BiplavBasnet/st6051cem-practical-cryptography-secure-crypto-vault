"""
Session Security Architecture + Policy Layer (Phase 6.1).
Centralized session state and timing; local-only, no cloud.
Idle -> LOCK (not full logout); hard expiry; optional fresh login on restart.
"""

import time
import uuid
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


class SessionState(str, Enum):
    LOGGED_OUT = "LOGGED_OUT"
    ACTIVE_UNLOCKED = "ACTIVE_UNLOCKED"
    LOCKED_IDLE = "LOCKED_IDLE"
    LOCKED_MANUAL = "LOCKED_MANUAL"
    EXPIRED_HARD = "EXPIRED_HARD"
    REAUTH_REQUIRED = "REAUTH_REQUIRED"


# Policy defaults and allowed ranges
DEFAULT_IDLE_LOCK_ENABLED = True
DEFAULT_IDLE_LOCK_MINUTES = 5
IDLE_LOCK_MINUTES_MIN = 1
IDLE_LOCK_MINUTES_MAX = 120

DEFAULT_HARD_SESSION_EXPIRY_ENABLED = True
DEFAULT_HARD_SESSION_EXPIRY_HOURS = 8
HARD_SESSION_EXPIRY_HOURS_MIN = 1
HARD_SESSION_EXPIRY_HOURS_MAX = 24

DEFAULT_REQUIRE_FRESH_LOGIN_ON_APP_RESTART = True
DEFAULT_STEP_UP_REAUTH_WINDOW_SECONDS = 90
STEP_UP_REAUTH_WINDOW_MIN = 60
STEP_UP_REAUTH_WINDOW_MAX = 300

# Phase 6.3: step-up re-auth
DEFAULT_STEP_UP_REAUTH_ENABLED = True
DEFAULT_STEP_UP_TTL_SECONDS = 90
STEP_UP_TTL_MIN = 60
STEP_UP_TTL_MAX = 300

# Sensitive action policy: action_id -> requires_step_up_reauth (and optional per-action ttl override)
SENSITIVE_ACTION_POLICY: Dict[str, Dict[str, Any]] = {
    "reveal_password": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "copy_password": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "delete_secret": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "retrieve_secret_for_extension": {"requires_step_up_reauth": False, "reauth_ttl_seconds": None},
    "reveal_backup_recovery_key": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "export_vault": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "export_backup": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "reset_account": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "restore_backup": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "change_main_password": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "set_backup_password": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "create_backup": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "show_import_passwords": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
    "import_passwords": {"requires_step_up_reauth": True, "reauth_ttl_seconds": None},
}


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _validate_policy(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a validated policy dict with safe defaults; backward compatible."""
    out = {}
    if not raw or not isinstance(raw, dict):
        raw = {}

    out["idle_lock_enabled"] = bool(raw.get("idle_lock_enabled", DEFAULT_IDLE_LOCK_ENABLED))
    out["idle_lock_minutes"] = int(_clamp(
        float(raw.get("idle_lock_minutes", DEFAULT_IDLE_LOCK_MINUTES)),
        IDLE_LOCK_MINUTES_MIN, IDLE_LOCK_MINUTES_MAX
    ))

    out["hard_session_expiry_enabled"] = bool(raw.get("hard_session_expiry_enabled", DEFAULT_HARD_SESSION_EXPIRY_ENABLED))
    out["hard_session_expiry_hours"] = int(_clamp(
        float(raw.get("hard_session_expiry_hours", DEFAULT_HARD_SESSION_EXPIRY_HOURS)),
        HARD_SESSION_EXPIRY_HOURS_MIN, HARD_SESSION_EXPIRY_HOURS_MAX
    ))

    out["require_fresh_login_on_app_restart"] = bool(raw.get("require_fresh_login_on_app_restart", raw.get("enforce_on_restart", DEFAULT_REQUIRE_FRESH_LOGIN_ON_APP_RESTART)))
    out["enforce_on_restart"] = out["require_fresh_login_on_app_restart"]  # alias for Phase 6.4
    out["step_up_reauth_window_seconds"] = int(_clamp(
        float(raw.get("step_up_reauth_window_seconds", DEFAULT_STEP_UP_REAUTH_WINDOW_SECONDS)),
        STEP_UP_REAUTH_WINDOW_MIN, STEP_UP_REAUTH_WINDOW_MAX
    ))
    # Phase 6.3: step-up re-auth
    out["step_up_reauth_enabled"] = bool(raw.get("step_up_reauth_enabled", DEFAULT_STEP_UP_REAUTH_ENABLED))
    out["step_up_ttl_seconds"] = int(_clamp(
        float(raw.get("step_up_ttl_seconds", DEFAULT_STEP_UP_TTL_SECONDS)),
        STEP_UP_TTL_MIN, STEP_UP_TTL_MAX
    ))
    return out


class SessionSecurityService:
    """
    Central session security manager: states, timing, policy, cache-clearing hooks.
    No UI; other modules call get_session_state(), lock_session(), etc.
    """

    def __init__(self, policy: Optional[Dict[str, Any]] = None):
        self._policy = _validate_policy(policy)
        self._state = SessionState.LOGGED_OUT
        self._session_started_at: Optional[float] = None
        self._last_activity_at: Optional[float] = None
        self._last_unlock_at: Optional[float] = None
        self._locked_at: Optional[float] = None
        self._lock_reason: Optional[str] = None
        self._hard_expiry_at: Optional[float] = None
        self._app_instance_id: Optional[str] = None
        self._user_id: Optional[int] = None
        self._clear_callbacks: List[Callable[[], None]] = []
        # Phase 6.3: step-up re-auth (short-lived approval; cleared on lock/logout)
        self._step_up_valid_until: Optional[float] = None

    def set_policy(self, policy: Optional[Dict[str, Any]]) -> None:
        """Update policy (e.g. after loading from config); validated."""
        self._policy = _validate_policy(policy)

    def get_policy(self) -> Dict[str, Any]:
        """Return current policy (copy)."""
        return dict(self._policy)

    def get_session_state(self) -> SessionState:
        return self._state

    def get_app_instance_id(self) -> Optional[str]:
        return self._app_instance_id

    def set_app_instance_id(self, instance_id: str) -> None:
        self._app_instance_id = instance_id

    def ensure_app_instance_id(self) -> str:
        if not self._app_instance_id:
            self._app_instance_id = str(uuid.uuid4())
        return self._app_instance_id

    def on_login(self, user_id: int) -> None:
        """Call after successful full login; starts session and sets hard expiry."""
        now = time.time()
        self._user_id = user_id
        self._state = SessionState.ACTIVE_UNLOCKED
        self._session_started_at = now
        self._last_activity_at = now
        self._last_unlock_at = now
        self._locked_at = None
        self._lock_reason = None
        hours = self._policy["hard_session_expiry_hours"]
        if self._policy["hard_session_expiry_enabled"] and hours > 0:
            self._hard_expiry_at = now + hours * 3600
        else:
            self._hard_expiry_at = None

    def on_logout(self) -> None:
        """Call on explicit logout; clears state and runs clear callbacks."""
        self._run_clear_callbacks()
        self._state = SessionState.LOGGED_OUT
        self._session_started_at = None
        self._last_activity_at = None
        self._last_unlock_at = None
        self._locked_at = None
        self._lock_reason = None
        self._hard_expiry_at = None
        self._user_id = None
        self.clear_step_up_state()

    def mark_user_activity(self) -> Optional[str]:
        """
        Call on user activity. Updates last_activity_at.
        Returns None if ok; or 'expired' if hard-expired (caller should force full login).
        """
        if self._state == SessionState.LOGGED_OUT:
            return None
        now = time.time()
        self._last_activity_at = now
        if self.is_hard_expired():
            self._state = SessionState.EXPIRED_HARD
            self.clear_step_up_state()
            self._run_clear_callbacks()
            return "expired"
        return None

    def lock_session(self, reason: str = "manual") -> None:
        """
        Lock the session (idle or manual). Sets LOCKED_IDLE or LOCKED_MANUAL,
        runs clear callbacks. Does not clear user identity; caller may show lock screen or login.
        """
        if self._state == SessionState.LOGGED_OUT:
            return
        now = time.time()
        self._locked_at = now
        self._lock_reason = reason or "manual"
        if reason == "idle":
            self._state = SessionState.LOCKED_IDLE
        else:
            self._state = SessionState.LOCKED_MANUAL
        self.clear_step_up_state()
        self._run_clear_callbacks()

    def unlock_session(self) -> None:
        """Call after user re-authenticates (e.g. passphrase) and keys are restored."""
        if self._state not in (SessionState.LOCKED_IDLE, SessionState.LOCKED_MANUAL):
            return
        now = time.time()
        self._state = SessionState.ACTIVE_UNLOCKED
        self._last_unlock_at = now
        self._last_activity_at = now
        self._locked_at = None
        self._lock_reason = None
        hours = self._policy["hard_session_expiry_hours"]
        if self._policy["hard_session_expiry_enabled"] and hours > 0:
            self._hard_expiry_at = now + hours * 3600
        else:
            self._hard_expiry_at = None

    def is_locked(self) -> bool:
        return self._state in (SessionState.LOCKED_IDLE, SessionState.LOCKED_MANUAL)

    def is_hard_expired(self) -> bool:
        if self._state == SessionState.LOGGED_OUT or self._hard_expiry_at is None:
            return False
        return time.time() >= self._hard_expiry_at

    def should_require_full_login(self) -> bool:
        """True if session is logged out, hard-expired, or require_fresh_login_on_app_restart and new instance."""
        if self._state == SessionState.LOGGED_OUT:
            return True
        if self._state == SessionState.EXPIRED_HARD:
            return True
        if self._policy["require_fresh_login_on_app_restart"]:
            # Session is not persisted across restarts; so we only have a session in this run.
            # If we ever add persisted session, we'd check app_instance_id here.
            return False
        return False

    def register_clear_callback(self, callback: Callable[[], None]) -> None:
        """Register a callback to run when locking, expiring, or logging out (clear caches)."""
        if callback not in self._clear_callbacks:
            self._clear_callbacks.append(callback)

    def _run_clear_callbacks(self) -> None:
        for cb in self._clear_callbacks:
            try:
                cb()
            except Exception:
                pass

    def clear_sensitive_session_caches(self) -> None:
        """Explicitly run all registered clear callbacks (e.g. from app on lock/expire/logout)."""
        self._run_clear_callbacks()

    def get_session_security_status(self) -> Dict[str, Any]:
        """For UI or API: state and timing (no secrets)."""
        now = time.time()
        status = {
            "state": self._state.value,
            "user_id": self._user_id,
            "session_started_at": self._session_started_at,
            "last_activity_at": self._last_activity_at,
            "last_unlock_at": self._last_unlock_at,
            "locked_at": self._locked_at,
            "lock_reason": self._lock_reason,
            "hard_expiry_at": self._hard_expiry_at,
            "app_instance_id": self._app_instance_id,
            "idle_lock_enabled": self._policy["idle_lock_enabled"],
            "idle_lock_minutes": self._policy["idle_lock_minutes"],
            "hard_session_expiry_enabled": self._policy["hard_session_expiry_enabled"],
            "hard_session_expiry_hours": self._policy["hard_session_expiry_hours"],
        }
        status["is_locked"] = self.is_locked()
        status["is_hard_expired"] = self.is_hard_expired()
        status["seconds_until_hard_expiry"] = (self._hard_expiry_at - now) if self._hard_expiry_at and now < self._hard_expiry_at else None
        status["step_up_valid_until"] = self._step_up_valid_until
        status["step_up_reauth_enabled"] = self._policy.get("step_up_reauth_enabled", DEFAULT_STEP_UP_REAUTH_ENABLED)
        return status

    # --- Phase 6.3: Step-up re-auth for sensitive actions ---

    def clear_step_up_state(self) -> None:
        """Clear short-lived step-up approval (e.g. on lock, logout, hard expiry)."""
        self._step_up_valid_until = None

    def _get_action_policy(self, action_name: str) -> Dict[str, Any]:
        """Return policy for action; default to step-up required with global TTL."""
        return SENSITIVE_ACTION_POLICY.get(action_name, {"requires_step_up_reauth": True, "reauth_ttl_seconds": None})

    def _ttl_seconds_for_action(self, action_name: str) -> int:
        policy = self._get_action_policy(action_name)
        ttl = policy.get("reauth_ttl_seconds")
        if ttl is not None and isinstance(ttl, (int, float)):
            return int(_clamp(float(ttl), STEP_UP_TTL_MIN, STEP_UP_TTL_MAX))
        return self._policy.get("step_up_ttl_seconds", DEFAULT_STEP_UP_TTL_SECONDS)

    def is_step_up_valid(self, action_name: Optional[str] = None) -> bool:
        """True if step-up is not required for this action, or global approval is still within TTL."""
        if not self._policy.get("step_up_reauth_enabled", DEFAULT_STEP_UP_REAUTH_ENABLED):
            return True
        if self._state != SessionState.ACTIVE_UNLOCKED:
            return False
        if self._step_up_valid_until is None:
            return False
        if time.time() >= self._step_up_valid_until:
            self._step_up_valid_until = None
            return False
        return True

    def require_step_up_for_action(self, action_name: str, context: Optional[Dict[str, Any]] = None, allow_when_locked: bool = False) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Returns (ok, error_payload). If session locked/expired -> lock/expired payload.
        If step-up required and not currently valid -> reauth_required payload.
        When allow_when_locked=True (e.g. extension API), locked state does not deny.
        """
        if self._state == SessionState.LOGGED_OUT:
            return False, get_lock_error_payload("logged_out", "Session not found. Please log in.")
        if not allow_when_locked and self.is_locked():
            return False, get_reauth_error_payload("APP_LOCKED", "App is locked. Unlock to continue.")
        if self.is_hard_expired():
            return False, get_reauth_error_payload("SESSION_EXPIRED", "Session expired. Sign in again.")
        if allow_when_locked and self.is_locked():
            return True, None  # Extension allowed when app is locked (session still valid)
        if not self._policy.get("step_up_reauth_enabled", DEFAULT_STEP_UP_REAUTH_ENABLED):
            return True, None
        policy = self._get_action_policy(action_name)
        if not policy.get("requires_step_up_reauth", True):
            return True, None
        if self.is_step_up_valid(action_name):
            return True, None
        return False, get_reauth_error_payload("REAUTH_REQUIRED", "Re-authentication required for this action.")

    def complete_step_up_reauth_success(self, action_name: Optional[str] = None) -> None:
        """Call after user successfully re-authenticated; grants short-lived approval (global TTL)."""
        ttl = self._ttl_seconds_for_action(action_name or "global") if action_name else self._policy.get("step_up_ttl_seconds", DEFAULT_STEP_UP_TTL_SECONDS)
        self._step_up_valid_until = time.time() + ttl

    def get_step_up_status(self) -> Dict[str, Any]:
        """Status for UI/API (no secrets)."""
        now = time.time()
        valid = self._step_up_valid_until is not None and now < self._step_up_valid_until
        return {
            "step_up_reauth_enabled": self._policy.get("step_up_reauth_enabled", DEFAULT_STEP_UP_REAUTH_ENABLED),
            "step_up_ttl_seconds": self._policy.get("step_up_ttl_seconds", DEFAULT_STEP_UP_TTL_SECONDS),
            "step_up_valid": valid,
            "step_up_valid_until": self._step_up_valid_until,
            "seconds_remaining": (self._step_up_valid_until - now) if valid and self._step_up_valid_until else 0,
        }

    # --- Non-UI enforcement helpers for other modules / future API ---

    def require_unlocked_session_or_error(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Returns (ok, error_payload). If session is locked or logged out, ok=False and error_payload for API.
        """
        if self._state == SessionState.LOGGED_OUT:
            return False, get_lock_error_payload("logged_out", "Session not found. Please log in.")
        if self.is_locked():
            return False, get_lock_error_payload("locked", "Session is locked. Unlock or log in again.")
        return True, None

    def require_not_hard_expired_or_error(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Returns (ok, error_payload). If hard-expired, ok=False."""
        if self.is_hard_expired():
            return False, get_lock_error_payload("expired", "Session expired. Sign in again.")
        return True, None

    def require_full_login_if_expired(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Returns (ok, error_payload). If full login required (expired or restart policy), ok=False."""
        if self.should_require_full_login():
            return False, get_lock_error_payload("login_required", "Please log in.")
        if self.is_hard_expired():
            return False, get_lock_error_payload("expired", "Session expired. Sign in again.")
        return True, None


def get_lock_error_payload(reason: str, message: str) -> Dict[str, Any]:
    """Standard payload for localhost API when lock/expiry blocks an action (Phase 6.x)."""
    return {
        "error": "session_locked",
        "reason": reason,
        "message": message,
    }


def get_reauth_error_payload(code: str, message: str) -> Dict[str, Any]:
    """Structured error for extension/API when step-up or session state blocks action (Phase 6.3)."""
    return {
        "error": "reauth_required",
        "reason": code,  # REAUTH_REQUIRED | APP_LOCKED | SESSION_EXPIRED
        "message": message,
        "ok": False,
    }


# Phase 6.5: Stable machine-readable codes for extension/localhost API
API_DENIAL_AUTH_REQUIRED = "AUTH_REQUIRED"
API_DENIAL_SESSION_EXPIRED = "SESSION_EXPIRED"
API_DENIAL_APP_LOCKED = "APP_LOCKED"
API_DENIAL_REAUTH_REQUIRED = "REAUTH_REQUIRED"
API_DENIAL_ACTION_DENIED = "ACTION_DENIED"


def get_api_error_payload(reason: str, message: str) -> Dict[str, Any]:
    """Phase 6.5: Structured API error for extension – no sensitive internals, no tracebacks."""
    return {
        "ok": False,
        "error": "api_denied",
        "reason": reason,
        "message": message,
    }


def verify_step_up_identity_app_password(
    username: str, password: str, auth_bundle_path: Any
) -> Tuple[bool, Optional[str]]:
    """
    App-level step-up verification (Phase 6.3). Returns (True, None) on success, (False, error_message) on failure.
    This is the abstraction point for step-up re-auth: the desktop app calls this for sensitive actions.
    Future enhancement: an optional OS-native implementation (e.g. Windows Hello / Credential UI) can be
    plugged in here while keeping this app-password implementation as the default (local-only, no cloud).
    """
    try:
        from pathlib import Path
        import json as _json
        from services.local_key_manager import LocalKeyManager
        path = Path(auth_bundle_path) if auth_bundle_path is not None else None
        if path is None:
            return False, "Auth key path missing."
        if not path.exists():
            return False, "Auth key not found."
        bundle = _json.loads(path.read_text(encoding="utf-8"))
        unlocked = LocalKeyManager.unlock_key_from_bundle(bundle, password)
        return (True, None) if unlocked else (False, "Invalid password.")
    except Exception:
        return False, "Verification failed."
