import datetime
from services.database import DBManager
from services.audit_log import AuditLog

class SecurityService:
    """Handles rate limiting and brute-force protection."""
    
    def __init__(self, db: DBManager, audit: AuditLog):
        self.db = db
        self.audit = audit

    def record_attempt(self, username: str, attempt_type: str, successful: bool):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_attempts (username, attempt_type, successful)
            VALUES (?, ?, ?)
        """, (username, attempt_type, 1 if successful else 0))
        conn.commit()
        conn.close()
        
        self.audit.log_event("SECURITY_ATTEMPT", {
            "username": username,
            "type": attempt_type,
            "status": "SUCCESS" if successful else "FAILURE"
        })

    def check_lockout(self, username: str, attempt_type: str):
        """
        Returns (is_locked, message, remaining_attempts).
        - Login: 10 attempts allowed. 28 min lockout.
        - Recovery: 5 attempts per 24 hours.
        """
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        now = datetime.datetime.utcnow()
        
        if attempt_type == "login":
            limit = 10
            window_minutes = 28
            since = now - datetime.timedelta(minutes=window_minutes)
            
            # Check recent failures
            cursor.execute("""
                SELECT COUNT(*) as count FROM security_attempts 
                WHERE username = ? AND attempt_type = 'login' AND successful = 0 
                AND created_at > ?
            """, (username, since))
            failures = cursor.fetchone()['count']
            
            if failures >= limit:
                # Find the latest failure to calculate remaining lockout time
                cursor.execute("""
                    SELECT MAX(created_at) as last FROM security_attempts 
                    WHERE username = ? AND attempt_type = 'login' AND successful = 0
                """, (username,))
                last_fail_str = cursor.fetchone()['last']
                last_fail = datetime.datetime.fromisoformat(last_fail_str)
                lockout_end = last_fail + datetime.timedelta(minutes=window_minutes)
                wait_sec = (lockout_end - now).total_seconds()
                
                if wait_sec > 0:
                    conn.close()
                    return True, f"Account locked. Try again in {int(wait_sec//60)}m {int(wait_sec%60)}s.", 0
            
            conn.close()
            return False, "", limit - failures

        elif attempt_type == "recovery":
            limit = 5
            since = now - datetime.timedelta(hours=24)
            
            cursor.execute("""
                SELECT COUNT(*) as count FROM security_attempts 
                WHERE username = ? AND attempt_type = 'recovery' AND successful = 0 
                AND created_at > ?
            """, (username, since))
            failures = cursor.fetchone()['count']
            
            if failures >= limit:
                conn.close()
                return True, "Daily recovery limit reached. Try again in 24 hours.", 0
            
            conn.close()
            return False, "", limit - failures
            
        conn.close()
        return False, "", 999

# Verification Checksum: 3e4bc0ab at 2026-02-14 15:09:23

# Verification Checksum: 39e26fe5 at 2026-02-14 17:34:40
