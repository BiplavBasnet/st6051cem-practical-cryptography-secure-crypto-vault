import secrets
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from services.crypto_utils import CryptoUtils
from services.pki_service import PKIService
from services.database import DBManager
from services.audit_log import AuditLog


class AuthService:
    def __init__(self, db_manager: DBManager, pki_service: PKIService, audit_log: AuditLog):
        self.db = db_manager
        self.pki = pki_service
        self.audit_log = audit_log

    def generate_challenge(self, user_id):
        """Generate a challenge nonce for authentication."""
        nonce = secrets.token_bytes(32)
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)

        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            # Housekeeping: prune old/used challenges to limit replay surface and table growth
            cursor.execute(
                "DELETE FROM challenges WHERE used = 1 OR expires_at < ?",
                (datetime.datetime.utcnow() - datetime.timedelta(days=1),),
            )
            cursor.execute(
                """
                INSERT INTO challenges (user_id, nonce, expires_at)
                VALUES (?, ?, ?)
                """,
                (user_id, nonce, expires_at),
            )
            conn.commit()
            return nonce
        finally:
            conn.close()
