import hashlib
import json
import datetime
from services.database import DBManager

class AuditLog:
    """
    Tamper-evident Audit Logging service using hash-chaining.
    Every event is linked to the previous one via a SHA-256 digest.
    """
    def __init__(self, db_manager: DBManager):
        self.db = db_manager

    def log_event(self, event_type, details, user_id=None):
        """Logs a new event and updates the hash chain."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            # 1. Get the hash of the last entry
            cursor.execute("SELECT event_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            prev_hash = row['event_hash'] if row else "0" * 64
            
            timestamp = datetime.datetime.now().isoformat()
            
            # 2. Prepare event data for hashing
            log_payload = {
                "type": event_type,
                "details": details,
                "user_id": user_id,
                "prev_hash": prev_hash,
                "timestamp": timestamp
            }
            
            payload_json = json.dumps(log_payload, sort_keys=True)
            current_hash = hashlib.sha256(payload_json.encode()).hexdigest()
            
            # 3. Store the log
            cursor.execute("""
                INSERT INTO audit_logs (user_id, event_type, details, prev_hash, event_hash)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, event_type, json.dumps(details), prev_hash, current_hash))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Audit Log Error: {e}")
            return False
        finally:
            conn.close()

    def verify_integrity(self):
        """Verifies the entire hash chain for consistency."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
        rows = cursor.fetchall()
        
        expected_prev_hash = "0" * 64
        for row in rows:
            # Reconstruct payload exactly as it was during log_event
            details = json.loads(row['details'])
            payload = {
                "type": row['event_type'],
                "details": details,
                "user_id": row['user_id'],
                "prev_hash": row['prev_hash'],
                "timestamp": datetime.datetime.fromisoformat(row['created_at']).isoformat() if isinstance(row['created_at'], str) else row['created_at'].isoformat()
            }
            
            # Recalculate hash
            payload_json = json.dumps(payload, sort_keys=True)
            recalculated_hash = hashlib.sha256(payload_json.encode()).hexdigest()
            
            if row['event_hash'] != recalculated_hash:
                return False, f"Tamper detected at ID {row['id']}: Content mismatch"
                
            if row['prev_hash'] != expected_prev_hash:
                return False, f"Break in chain at ID {row['id']}: Continuity error"
            
            expected_prev_hash = row['event_hash']
            
        return True, "Audit chain integrity verified"
