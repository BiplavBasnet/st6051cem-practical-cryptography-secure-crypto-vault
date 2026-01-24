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

    def check_lockout(self, username: str, attempt_type: str, client_fingerprint: str = "global"):
        """
        Returns (is_locked, message, remaining_attempts).

        Login policy:
        - Per-fingerprint: 10 failed attempts / 28 min window.
        - Global username guard: 30 failed attempts / 28 min window.

        Recovery policy:
        - 5 failed attempts / 24h window (global by username).
        """
        conn = self.db.get_connection()
        cursor = conn.cursor()

        now = datetime.datetime.utcnow()
        fp = client_fingerprint or "global"

        if attempt_type == "login":
            per_client_limit = 10
            global_limit = 30
            window_minutes = 28
            since = now - datetime.timedelta(minutes=window_minutes)

            cursor.execute(
                """
                SELECT COUNT(*) as count FROM security_attempts
                WHERE username = ? AND attempt_type = 'login' AND successful = 0
                  AND client_fingerprint = ? AND created_at > ?
                """,
                (username, fp, since),
            )
            per_client_failures = cursor.fetchone()["count"]

            cursor.execute(
                """
                SELECT COUNT(*) as count FROM security_attempts
                WHERE username = ? AND attempt_type = 'login' AND successful = 0
                  AND created_at > ?
                """,
                (username, since),
            )
            global_failures = cursor.fetchone()["count"]

            is_locked = per_client_failures >= per_client_limit or global_failures >= global_limit
            if is_locked:
                cursor.execute(
                    """
                    SELECT MAX(created_at) as last FROM security_attempts
                    WHERE username = ? AND attempt_type = 'login' AND successful = 0
                    """,
                    (username,),
                )
                last_fail_str = cursor.fetchone()["last"]
                if last_fail_str:
                    last_fail = datetime.datetime.fromisoformat(last_fail_str)
                    lockout_end = last_fail + datetime.timedelta(minutes=window_minutes)
                    wait_sec = (lockout_end - now).total_seconds()
                    if wait_sec > 0:
                        conn.close()
                        return True, f"Account temporarily locked. Try again in {int(wait_sec//60)}m {int(wait_sec%60)}s.", 0

            remaining = max(0, per_client_limit - per_client_failures)
            conn.close()
            return False, "", remaining

        if attempt_type == "recovery":
            limit = 5
            since = now - datetime.timedelta(hours=24)
            cursor.execute(
                """
                SELECT COUNT(*) as count FROM security_attempts
                WHERE username = ? AND attempt_type = 'recovery' AND successful = 0
                  AND created_at > ?
                """,
                (username, since),
            )
            failures = cursor.fetchone()["count"]

            if failures >= limit:
                conn.close()
                return True, "Daily recovery limit reached. Try again in 24 hours.", 0

            conn.close()
            return False, "", limit - failures

        conn.close()
        return False, "", 999

    # ── Passphrase policy (unified: length ≥12, 3 of 4 classes) ────────

    @staticmethod
    def validate_passphrase(phrase: str) -> tuple[bool, str]:
        """Validate passphrase for registration/creation.
        Policy: length ≥12 and at least 3 of 4 classes: lowercase, uppercase, digit, symbol.
        Returns (True, "") if valid, else (False, reason_string).
        """
        if not phrase or len(phrase) < 12:
            return False, "Passphrase must be at least 12 characters."
        classes = 0
        if re.search(r"[a-z]", phrase):
            classes += 1
        if re.search(r"[A-Z]", phrase):
            classes += 1
        if re.search(r"[0-9]", phrase):
            classes += 1
        if re.search(r"[^A-Za-z0-9]", phrase):
            classes += 1
        if classes < 3:
            return False, "Passphrase must include at least 3 of: lowercase, uppercase, digit, or symbol."
        return True, ""

    # ── Password policy ───────────────────────────────────────────────
