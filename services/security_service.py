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
