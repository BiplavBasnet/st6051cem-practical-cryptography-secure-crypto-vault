import os
from cryptography import x509

from services.database import DBManager
from services.crypto_utils import CryptoUtils
from services.pki_service import PKIService
from services.audit_log import AuditLog
from services.auth_service import AuthService
from services.user_service import UserService
from services.document_service import DocumentService
from services.security_service import SecurityService
from services.secret_service import SecretService
from services.totp_service import TOTPService
from services.session_manager import SessionManager
from services.backup_service import BackupService
from services.audit_log_normalizer import normalize_row
from services.structured_logger import get_logger


class VaultAPI:
    """Single source of truth API for cryptographic operations."""

    def __init__(self):
        self.db = DBManager()
        # Ensure schema exists for CLI, tests, and desktop startup in fresh workdirs.
        self.db.setup_database()
        self.audit = AuditLog(self.db)
        self.pki = PKIService()
        self.security = SecurityService(self.db, self.audit)
        self.auth = AuthService(self.db, self.pki, self.audit)
        self.user_service = UserService(self.db, self.pki, self.audit)
        self.doc_service = DocumentService(self.db, self.pki, self.audit)
        self.secret_service = SecretService(self.db, self.audit, self.pki)
        self.backup_service = BackupService(self.db, self.audit, self.secret_service)
        self.totp = TOTPService()
        self.session_manager = SessionManager(self.db)
        self.logger = get_logger()
        # Phase 6.1: optional session security for lock/expiry checks (injected by desktop)
        self.session_security = None
        # Security alert service (injected by desktop) for unified alerts + audit
        self.security_alert_service = None

    def set_session_security(self, service):
        """Inject session security service so API can respect lock state (Phase 6.1+)."""
        self.session_security = service

    def record_extension_api_denied(self, event_type: str, path: str, user_id=None):
        """Phase 6.5: Audit log for denied extension API requests (sanitized, no secrets)."""
        try:
            self.audit.log_event(event_type, {"path": path}, user_id=user_id)
        except Exception:
            pass

    def record_extension_api_allowed_sensitive(self, path: str, user_id: int):
        """Phase 6.5: Audit log when sensitive extension action is allowed."""
        try:
            self.audit.log_event("api_request_allowed_sensitive_action", {"path": path}, user_id=user_id)
        except Exception:
            pass

    def check_lockout(self, username, attempt_type, client_fingerprint="global"):
        return self.security.check_lockout(username, attempt_type, client_fingerprint)

    def record_attempt(self, username, attempt_type, successful, client_fingerprint="global"):
        return self.security.record_attempt(username, attempt_type, successful, client_fingerprint)

    # ── Progressive backoff ───────────────────────────────────────────

    def check_unlock_backoff(self, username):
        return self.security.check_unlock_backoff(username)

    def record_unlock_failure(self, username):
        return self.security.record_unlock_failure(username)

    def reset_unlock_backoff(self, username):
        return self.security.reset_unlock_backoff(username)

    def validate_passphrase(self, phrase: str):
        """Validate passphrase for registration (length ≥12, 3 of 4 classes). Returns (ok, reason)."""
        return SecurityService.validate_passphrase(phrase)

    # ── Registration / Login ──────────────────────────────────────────

    def register_user(self, username, email, key_bundle=None):
        return self.user_service.register_user(username, email, key_bundle)

    def login_user(self, username, private_key_path=None, priv_key_data=None, client_fingerprint="global"):
        """PKI challenge-response login + forward secrecy session key derivation."""
        is_locked, lock_msg, _ = self.security.check_lockout(username, "login", client_fingerprint)
        if is_locked:
            return False, None, None, lock_msg

        user = self.user_service.get_user_by_username(username)
        if not user:
            self.security.record_attempt(username, "login", False, client_fingerprint)
            return False, None, None, "Invalid credentials"

        if not priv_key_data:
            if not private_key_path or not os.path.exists(private_key_path):
                self.security.record_attempt(username, "login", False, client_fingerprint)
                return False, None, None, "Invalid credentials"

        try:
            nonce = self.auth.generate_challenge(user["id"])

            if not priv_key_data:
                with open(private_key_path, "rb") as f:
                    priv_key_data = f.read()

            priv_key = CryptoUtils.load_private_key(priv_key_data)
            signature = CryptoUtils.sign_data(priv_key, nonce)
            cert_pem = self.get_active_certificate(user["id"], "auth")
            if not cert_pem:
                self.security.record_attempt(username, "login", False, client_fingerprint)
                return False, None, None, "No active authentication certificate found"

            success, msg = self.auth.verify_challenge(user["id"], nonce, signature, cert_pem)
            self.security.record_attempt(username, "login", success, client_fingerprint)

            if not success:
                return False, None, None, msg

            user_ephemeral_priv = CryptoUtils.generate_ephemeral_ecdh_keys()
            user_pub_bytes = CryptoUtils.serialize_public_key(user_ephemeral_priv.public_key())
            _, shared_secret = self.auth.establish_session(user_pub_bytes)

            self.logger.info("Login successful for user %s", username)
            return True, user, shared_secret, "Authentication Successful"

        except Exception as e:
            self.security.record_attempt(username, "login", False, client_fingerprint)
            self.logger.error("Login error for user %s: %s", username, str(e))
            return False, None, None, "Login failed. Please check your credentials and try again."

    def sign_document(self, user_id, username, file_path, private_key_path=None, priv_key_data=None):
        if not priv_key_data:
            if not private_key_path or not os.path.exists(private_key_path):
                return False, "Signing key not found"
        return self.doc_service.sign_document(user_id, file_path, private_key_path, priv_key_data)

    def verify_document(self, file_path):
        return self.doc_service.verify_document(file_path)

    def encrypt_document(self, file_path, recipient_usernames):
        recipient_ids = []
        for r in recipient_usernames:
            u = self.user_service.get_user_by_username(r.strip())
            if u:
                recipient_ids.append(u["id"])

        if not recipient_ids:
            return False, "No valid recipients found"

        encrypted_data = self.doc_service.encrypt_for_recipients(file_path, recipient_ids)
        return True, encrypted_data

    def decrypt_document(self, encrypted_json, user_id, username, private_key_path=None, priv_key_data=None):
        if not priv_key_data:
            if not private_key_path or not os.path.exists(private_key_path):
                return None, "Encryption key not found"
        return self.doc_service.decrypt_document(encrypted_json, user_id, private_key_path, priv_key_data)

    def rotate_keys(self, username, key_bundle=None):
        return self.user_service.rotate_keys(username, key_bundle)

    def verify_audit_integrity(self):
        return self.audit.verify_integrity()

    def revoke_certificate(self, serial_number):
        return self.user_service.revoke_certificate(serial_number)

    def get_user_certificates(self, user_id):
        return self.user_service.get_user_certificates(user_id)

    def get_active_certificate(self, user_id, purpose):
        """Get active certificate for a user and purpose. Returns PEM string or None."""
        try:
            certs = self.user_service.get_user_certificates(user_id)
            if not certs or not isinstance(certs, list):
                return None
            for c in certs:
                # Convert to dict if it's a Row object
                if not isinstance(c, dict):
                    try:
                        c = dict(c)
                    except (TypeError, ValueError):
                        continue
                
                # Now c is guaranteed to be a dict
                key_usage = c.get("key_usage")
                revoked = c.get("revoked", 0)
                cert_data = c.get("cert_data")
                
                if key_usage == purpose and not revoked and cert_data:
                    return cert_data
            return None
        except Exception as e:
            self.logger.error("Error getting active certificate: %s", e, exc_info=True)
        return None

    def get_audit_logs(self, limit=20):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,))
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return logs

    def validate_password(self, password):
        return self.security.validate_password(password)

    def calculate_strength(self, password):
        return self.security.calculate_strength(password)

    # ── Insecure credential flags ─────────────────────────────────────

    def check_insecure_flags(self, password, username="", service=""):
        return self.security.check_insecure_flags(password, username, service)

    def check_lookalike_domain(self, new_domain, existing_domains):
        return self.security.check_lookalike_domain(new_domain, existing_domains)

    # ── TOTP ──────────────────────────────────────────────────────────

    def generate_totp_secret(self):
        return self.totp.generate_secret()

    def generate_totp_code(self, secret):
        return self.totp.generate_totp(secret)

    def verify_totp_code(self, secret, code):
        return self.totp.verify_totp(secret, code)

    def totp_time_remaining(self):
        return self.totp.time_remaining()

    # ── Session management ────────────────────────────────────────────
    def create_session(self, user_id):
        return self.session_manager.create_session(user_id)

    def get_active_sessions(self, user_id):
        return self.session_manager.get_active_sessions(user_id)

    def revoke_session(self, session_id, user_id):
        return self.session_manager.revoke_session(session_id, user_id)

    def revoke_all(self, user_id, except_session=None):
        return self.session_manager.revoke_all(user_id, except_session)

    def touch_session(self, session_id):
        return self.session_manager.touch_session(session_id)

    # ── Vault operations ──────────────────────────────────────────────
