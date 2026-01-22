import hashlib
import json
import threading
import datetime
from typing import Any, Dict, List, Optional

from services.database import DBManager
from services.structured_logger import get_logger

_AUDIT_LOCK = threading.Lock()


class AuditLog:
    """
    Tamper-evident Audit Logging service using hash-chaining.
    Every event is linked to the previous one via a SHA-256 digest.
    """

    def __init__(self, db_manager: DBManager):
        self.db = db_manager
        self._logger = get_logger()

    @staticmethod
    def _normalize_details(details):
        if details is None:
            return {}
        if isinstance(details, (dict, list, str, int, float, bool)):
            return details
        return str(details)

    def _compute_hash(self, event_type, details, user_id, prev_hash, created_at):
        payload = {
            "type": event_type,
            "details": details,
            "user_id": user_id,
            "prev_hash": prev_hash,
            "timestamp": created_at,
        }
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload_json.encode()).hexdigest()

    def log_event(self, event_type, details, user_id=None, actor_username=None):
        """Logs a new event and updates the hash chain. user_id is the actor (owner) of the event. Thread-safe."""
        with _AUDIT_LOCK:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute("SELECT event_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                prev_hash = row["event_hash"] if row else "0" * 64

                created_at = datetime.datetime.utcnow().replace(microsecond=0).isoformat(sep=" ")
                safe_details = self._normalize_details(details)

                current_hash = self._compute_hash(
                    event_type=event_type,
                    details=safe_details,
                    user_id=user_id,
                    prev_hash=prev_hash,
                    created_at=created_at,
                )

                cols = "user_id, event_type, details, prev_hash, event_hash, created_at"
                placeholders = "?, ?, ?, ?, ?, ?"
                vals = [user_id, event_type, json.dumps(safe_details), prev_hash, current_hash, created_at]
                cursor.execute("PRAGMA table_info(audit_logs)")
                table_cols = {r[1] for r in cursor.fetchall()}
                if "actor_username" in table_cols:
                    cols += ", actor_username"
                    placeholders += ", ?"
                    vals.append(actor_username if actor_username else None)
                cursor.execute(
                    f"INSERT INTO audit_logs ({cols}) VALUES ({placeholders})",
                    vals,
                )

                conn.commit()
                return True
            except Exception:
                conn.rollback()
                self._logger.error("Audit log write failed")
                return False
            finally:
                conn.close()
