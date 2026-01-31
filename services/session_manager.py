"""Device / session management service.

Tracks local sessions with device fingerprint, last-active time, creation time.
Sessions can be listed and revoked through the UI.
"""

import datetime
import hashlib
import os
import platform
import uuid


class SessionManager:
    """Manage local device sessions for the vault."""

    def __init__(self, db_manager):
        self.db = db_manager
        self._ensure_table()

    def _ensure_table(self):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                device_name TEXT,
                created_at TEXT NOT NULL,
                last_active TEXT NOT NULL,
                revoked INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.commit()
        conn.close()

    @staticmethod
    def _get_device_id() -> str:
        """Generate a stable device fingerprint from hostname + OS + machine ID."""
        raw = f"{platform.node()}|{platform.system()}|{platform.machine()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _get_device_name() -> str:
        return f"{platform.node()} ({platform.system()} {platform.release()})"

    def create_session(self, user_id: int) -> dict:
        """Create a new session for the current device."""
        session_id = str(uuid.uuid4())
        device_id = self._get_device_id()
        device_name = self._get_device_name()
        now = datetime.datetime.utcnow().isoformat()

        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO sessions (id, user_id, device_id, device_name, created_at, last_active)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (session_id, user_id, device_id, device_name, now, now),
        )
        conn.commit()
        conn.close()

        return {
            "id": session_id,
            "user_id": user_id,
            "device_id": device_id,
            "device_name": device_name,
            "created_at": now,
            "last_active": now,
        }

    def touch_session(self, session_id: str):
        """Update last_active timestamp for a session."""
        now = datetime.datetime.utcnow().isoformat()
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE sessions SET last_active = ? WHERE id = ? AND revoked = 0",
            (now, session_id),
        )
        conn.commit()
        conn.close()

    def get_active_sessions(self, user_id: int) -> list:
        """List all non-revoked sessions for a user."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, device_id, device_name, created_at, last_active
               FROM sessions WHERE user_id = ? AND revoked = 0
               ORDER BY last_active DESC""",
            (user_id,),
        )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def revoke_session(self, session_id: str, user_id: int) -> bool:
        """Revoke a specific session."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE sessions SET revoked = 1 WHERE id = ? AND user_id = ?",
            (session_id, user_id),
        )
        changed = cursor.rowcount
        conn.commit()
        conn.close()
        return changed > 0

    def revoke_all(self, user_id: int, except_session: str = None) -> int:
        """Revoke all sessions for a user, optionally keeping one."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        if except_session:
            cursor.execute(
                "UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id != ? AND revoked = 0",
                (user_id, except_session),
            )
        else:
            cursor.execute(
                "UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0",
                (user_id,),
            )
        count = cursor.rowcount
        conn.commit()
        conn.close()
        return count
