import os
import secrets
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
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
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO challenges (user_id, nonce, expires_at)
            VALUES (?, ?, ?)
        """, (user_id, nonce, expires_at))
        conn.commit()
        conn.close()
        return nonce

    def verify_challenge(self, user_id, nonce, signature, user_public_key_pem):
        """Verify the challenge signature using the user's public key."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        try:
            # Check if challenge exists and is valid
            cursor.execute("""
                SELECT id FROM challenges 
                WHERE user_id = ? AND nonce = ? AND used = 0 AND expires_at > ?
            """, (user_id, nonce, datetime.datetime.utcnow()))
            challenge = cursor.fetchone()

            if not challenge:
                self.audit_log.log_event("AUTH_FAILURE", {"user_id": user_id, "reason": "Invalid or expired challenge"})
                return False, "Invalid or expired challenge"

            cert_bytes = user_public_key_pem.encode() if isinstance(user_public_key_pem, str) else user_public_key_pem

            # 1. Full Certificate Validation (Tier 1 Requirement: EKU enforcement)
            valid, msg = self.pki.validate_certificate(
                cert_bytes,
                db_manager=self.db,
                required_eku=[x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
            )
            if not valid:
                self.audit_log.log_event("AUTH_FAILURE", {"user_id": user_id, "reason": f"Cert validation failed: {msg}"})
                return False, f"Certificate validation failed: {msg}"

            cert = x509.load_pem_x509_certificate(cert_bytes)
            public_key = cert.public_key()

            if CryptoUtils.verify_signature(public_key, nonce, signature):
                # Mark challenge as used
                cursor.execute("UPDATE challenges SET used = 1 WHERE id = ?", (challenge['id'],))
                conn.commit()
                self.audit_log.log_event("AUTH_SUCCESS", {"user_id": user_id})
                return True, "Success"

            self.audit_log.log_event("AUTH_FAILURE", {"user_id": user_id, "reason": "Invalid signature"})
            return False, "Invalid signature"
        finally:
            conn.close()

    def establish_session(self, user_ephemeral_pub_bytes):
        """Establish a session with Forward Secrecy using ECDH."""
        server_ephemeral_priv = CryptoUtils.generate_ephemeral_ecdh_keys()
        server_ephemeral_pub = server_ephemeral_priv.public_key()
        
        user_ephemeral_pub = serialization.load_pem_public_key(user_ephemeral_pub_bytes)
        shared_secret = CryptoUtils.derive_shared_secret(server_ephemeral_priv, user_ephemeral_pub)
        
        return CryptoUtils.serialize_public_key(server_ephemeral_pub), shared_secret
