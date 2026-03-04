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

    def list_events(
        self,
        limit: int = 500,
        since_ts: Optional[str] = None,
        until_ts: Optional[str] = None,
        sort_by: str = "created_at",
        sort_desc: bool = True,
        user_id: Optional[int] = None,
        include_system: bool = False,
    ) -> List[Dict[str, Any]]:
        """Read audit log rows for the viewer.
        
        SECURITY: user_id is REQUIRED. If not provided, returns empty list.
        Users can only view their own activity logs.
        """
        # STRICT SECURITY: Require user_id to prevent viewing other users' logs
        if user_id is None:
            return []
        
        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            where_parts = []
            params: List[Any] = []
            # Always filter by user_id (required for security)
            if include_system:
                where_parts.append("(user_id = ? OR user_id IS NULL)")
                params.append(user_id)
            else:
                where_parts.append("user_id = ?")
                params.append(user_id)
            if since_ts:
                where_parts.append("created_at >= ?")
                params.append(since_ts)
            if until_ts:
                where_parts.append("created_at <= ?")
                params.append(until_ts)
            where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
            order_col = "created_at" if sort_by == "created_at" else sort_by
            if order_col not in ("id", "user_id", "event_type", "created_at"):
                order_col = "created_at"
            direction = "DESC" if sort_desc else "ASC"
            params.append(limit)
            cursor.execute(
                f"""
                SELECT id, user_id, event_type, details, created_at
                FROM audit_logs
                {where_sql}
                ORDER BY {order_col} {direction}
                LIMIT ?
                """,
                params,
            )
            rows = cursor.fetchall()
            out = []
            for r in rows:
                details = {}
                if r["details"]:
                    try:
                        details = json.loads(r["details"]) if isinstance(r["details"], str) else r["details"]
                    except Exception:
                        details = {}
                if not isinstance(details, dict):
                    details = {"value": details}
                out.append({
                    "id": r["id"],
                    "user_id": r["user_id"],
                    "event_type": r["event_type"] or "",
                    "details": details,
                    "created_at": r["created_at"] or "",
                })
            return out
        finally:
            conn.close()

    def verify_integrity(self):
        """Verifies the entire hash chain for consistency."""
        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
            rows = cursor.fetchall()

            expected_prev_hash = "0" * 64

            for row in rows:
                # Verify continuity first
                if row["prev_hash"] != expected_prev_hash:
                    return False, f"Break in chain at ID {row['id']}: Continuity error"

                # Rebuild hash from persisted row values
                try:
                    details = json.loads(row["details"]) if row["details"] else {}
                except Exception:
                    return False, f"Tamper detected at ID {row['id']}: Invalid details JSON"

                recalculated_hash = self._compute_hash(
                    event_type=row["event_type"],
                    details=details,
                    user_id=row["user_id"],
                    prev_hash=row["prev_hash"],
                    created_at=row["created_at"],
                )

                if row["event_hash"] != recalculated_hash:
                    return False, f"Tamper detected at ID {row['id']}: Content mismatch"

                expected_prev_hash = row["event_hash"]

            return True, "Audit chain integrity verified"
        finally:
            conn.close()
