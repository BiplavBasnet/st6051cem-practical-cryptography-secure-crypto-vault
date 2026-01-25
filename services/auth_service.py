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

    def verify_challenge(self, user_id, nonce, signature, user_public_key_pem):
        """
        Verify challenge-response authentication.

        Security checks:
        1) Challenge validity (exists, not expired, unused)
        2) Certificate validation (CA signature, expiry, revocation, CLIENT_AUTH EKU)
        3) Certificate-user binding (anti-spoofing)
        4) Signature over nonce (private-key possession proof)
        """
        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()

            # 1) Challenge validity
            cursor.execute(
                """
                SELECT id FROM challenges
                WHERE user_id = ? AND nonce = ? AND used = 0 AND expires_at > ?
                """,
                (user_id, nonce, datetime.datetime.utcnow()),
            )
            challenge = cursor.fetchone()
            if not challenge:
                self.audit_log.log_event(
                    "AUTH_FAILURE",
                    {"user_id": user_id, "reason": "Invalid or expired challenge"},
                    user_id=user_id,
                )
                return False, "Invalid or expired challenge"

            # Normalize certificate input
            cert_bytes = (
                user_public_key_pem.encode()
                if isinstance(user_public_key_pem, str)
                else user_public_key_pem
            )
            if not cert_bytes:
                self.audit_log.log_event(
                    "AUTH_FAILURE",
                    {"user_id": user_id, "reason": "Missing certificate"},
                    user_id=user_id,
                )
                return False, "Missing certificate"

            # 2) Validate certificate
            valid, msg = self.pki.validate_certificate(
                cert_bytes,
                db_manager=self.db,
                required_eku=[x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH],
            )
            if not valid:
                self.audit_log.log_event(
                    "AUTH_FAILURE",
                    {"user_id": user_id, "reason": f"Cert validation failed: {msg}"},
                    user_id=user_id,
                )
                return False, f"Certificate validation failed: {msg}"

            cert = x509.load_pem_x509_certificate(cert_bytes)
            cert_serial = str(cert.serial_number)

            # 3) Bind cert to challenged user + auth usage
            cursor.execute(
                """
                SELECT 1
                FROM certificates
                WHERE user_id = ?
                  AND serial_number = ?
                  AND key_usage = 'auth'
                  AND revoked = 0
                LIMIT 1
                """,
                (user_id, cert_serial),
            )
            if not cursor.fetchone():
                self.audit_log.log_event(
                    "AUTH_FAILURE",
                    {
                        "user_id": user_id,
                        "reason": "Certificate does not belong to challenged user",
                        "cert_serial": cert_serial,
                    },
                    user_id=user_id,
                )
                return False, "Certificate-user mismatch"

            # 4) Verify signature of nonce
            public_key = cert.public_key()
            if not CryptoUtils.verify_signature(public_key, nonce, signature):
                self.audit_log.log_event(
                    "AUTH_FAILURE",
                    {"user_id": user_id, "reason": "Invalid signature"},
                    user_id=user_id,
                )
                return False, "Invalid signature"

            # Mark challenge as used
            cursor.execute("UPDATE challenges SET used = 1 WHERE id = ?", (challenge["id"],))
            conn.commit()

            self.audit_log.log_event(
                "AUTH_SUCCESS",
                {"user_id": user_id, "cert_serial": cert_serial},
                user_id=user_id,
            )
            return True, "Success"
        finally:
            conn.close()

    def establish_session(self, user_ephemeral_pub_bytes):
        """Establish a session with Forward Secrecy using ECDH."""
        server_ephemeral_priv = CryptoUtils.generate_ephemeral_ecdh_keys()
        server_ephemeral_pub = server_ephemeral_priv.public_key()

        user_ephemeral_pub = serialization.load_pem_public_key(user_ephemeral_pub_bytes)
        shared_secret = CryptoUtils.derive_shared_secret(server_ephemeral_priv, user_ephemeral_pub)

        return CryptoUtils.serialize_public_key(server_ephemeral_pub), shared_secret
