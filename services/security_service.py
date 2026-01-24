import datetime
import time
import re
from services.database import DBManager
from services.audit_log import AuditLog


class SecurityService:
    """Handles rate limiting, lockout controls, password policy, and credential risk analysis."""

    # Progressive backoff: consecutive unlock failures => 2^n seconds delay (capped at 60s)
    _unlock_failure_counts: dict = {}  # username -> consecutive failure count
    _unlock_last_attempt: dict = {}    # username -> timestamp of last failed attempt

    def __init__(self, db: DBManager, audit: AuditLog):
        self.db = db
        self.audit = audit

    def record_attempt(self, username: str, attempt_type: str, successful: bool, client_fingerprint: str = "global"):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO security_attempts (username, attempt_type, successful, client_fingerprint)
            VALUES (?, ?, ?, ?)
            """,
            (username, attempt_type, 1 if successful else 0, client_fingerprint or "global"),
        )
        cursor.execute("SELECT id FROM users WHERE username = ? LIMIT 1", (username,))
        row = cursor.fetchone()
        user_id = int(row["id"]) if row and row["id"] is not None else None
        conn.commit()
        conn.close()

        self.audit.log_event(
            "SECURITY_ATTEMPT",
            {
                "username": username,
                "type": attempt_type,
                "status": "SUCCESS" if successful else "FAILURE",
                "client_fingerprint": client_fingerprint or "global",
            },
            user_id=user_id,
        )

    # ── Progressive backoff for local unlock attempts ──────────────────

    def check_unlock_backoff(self, username: str):
        """Return (must_wait, wait_seconds) for progressive unlock backoff."""
        count = self._unlock_failure_counts.get(username, 0)
        if count == 0:
            return False, 0
        last_ts = self._unlock_last_attempt.get(username, 0)
        delay = min(2 ** count, 60)  # 2, 4, 8, 16, 32, 60
        elapsed = time.time() - last_ts
        if elapsed < delay:
            return True, int(delay - elapsed)
        return False, 0

    def record_unlock_failure(self, username: str):
        """Record a failed local unlock attempt for progressive backoff."""
        self._unlock_failure_counts[username] = self._unlock_failure_counts.get(username, 0) + 1
        self._unlock_last_attempt[username] = time.time()
        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ? LIMIT 1", (username,))
            row = cursor.fetchone()
            user_id = int(row["id"]) if row and row["id"] is not None else None
        finally:
            conn.close()
        self.audit.log_event(
            "UNLOCK_FAILURE",
            {"username": username, "consecutive": self._unlock_failure_counts[username]},
            user_id=user_id,
        )

    def reset_unlock_backoff(self, username: str):
        """Reset backoff counter on successful unlock."""
        self._unlock_failure_counts.pop(username, None)
        self._unlock_last_attempt.pop(username, None)

    # ── Lockout controls ──────────────────────────────────────────────
