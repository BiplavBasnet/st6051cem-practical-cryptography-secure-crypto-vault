import os
import json
from services.database import DBManager
from services.crypto_utils import CryptoUtils
from services.pki_service import PKIService
from services.audit_log import AuditLog
from services.auth_service import AuthService
from services.user_service import UserService
from services.document_service import DocumentService
from services.security_service import SecurityService
from services.secret_service import SecretService

class VaultAPI:
    """
    Thin API layer acting as the Single Source of Truth for all cryptographic operations.
    Enforces identical security guarantees for CLI and GUI.
    """
    def __init__(self):
        self.db = DBManager()
        self.audit = AuditLog(self.db)
        self.pki = PKIService()
        self.security = SecurityService(self.db, self.audit)
        self.auth = AuthService(self.db, self.pki, self.audit)
        self.user_service = UserService(self.db, self.pki, self.audit)
        self.doc_service = DocumentService(self.db, self.pki, self.audit)
        self.secret_service = SecretService(self.db, self.audit)
    
    def check_lockout(self, username, attempt_type):
        return self.security.check_lockout(username, attempt_type)
    
    def record_attempt(self, username, attempt_type, successful):
        return self.security.record_attempt(username, attempt_type, successful)

    def register_user(self, username, email, key_bundle=None):
        return self.user_service.register_user(username, email, key_bundle)

    def login_user(self, username, private_key_path=None, priv_key_data=None):
        """Unified PKI Challenge-Response login with Forward Secrecy."""
        # Fix 1: Server-side Lockout Check
        is_locked, lock_msg, remaining = self.security.check_lockout(username, "login")
        if is_locked:
            return False, None, None, lock_msg

        user = self.user_service.get_user_by_username(username)
        if not user:
            return False, None, None, "User not found"

        # Fix 2: Safety check for private_key_path to prevent os.path.exists(None) crash
        if not priv_key_data:
            if not private_key_path or not os.path.exists(private_key_path):
                return False, None, None, f"Private key not found"

        try:
            # 1. Challenge-Response
            nonce = self.auth.generate_challenge(user['id'])
            
            if not priv_key_data:
                with open(private_key_path, "rb") as f:
                    priv_key_data = f.read()
            
            priv_key = CryptoUtils.load_private_key(priv_key_data)
            signature = CryptoUtils.sign_data(priv_key, nonce)
            cert_pem = self.get_active_certificate(user['id'], 'auth')
            if not cert_pem:
                self.security.record_attempt(username, "login", False)
                return False, None, None, "No active authentication certificate found"
            
            success, msg = self.auth.verify_challenge(user['id'], nonce, signature, cert_pem)
            
            # Fix 1: Record attempt on server-side
            self.security.record_attempt(username, "login", success)
            
            if not success:
                return False, None, None, msg

            # 2. Establish Session (Forward Secrecy)
            user_ephemeral_priv = CryptoUtils.generate_ephemeral_ecdh_keys()
            user_pub_bytes = CryptoUtils.serialize_public_key(user_ephemeral_priv.public_key())
            _, shared_secret = self.auth.establish_session(user_pub_bytes)
            
            return True, user, shared_secret, "Authentication Successful"
            
        except Exception as e:
            self.security.record_attempt(username, "login", False)
            return False, None, None, f"Internal Security Error: {str(e)}"

    def sign_document(self, user_id, username, file_path, private_key_path=None, priv_key_data=None):
        if not priv_key_data:
            if not private_key_path or not os.path.exists(private_key_path):
                return False, f"Signing key not found"
        return self.doc_service.sign_document(user_id, file_path, private_key_path, priv_key_data)

    def verify_document(self, file_path):
        return self.doc_service.verify_document(file_path)

    def encrypt_document(self, file_path, recipient_usernames):
        recipient_ids = []
        for r in recipient_usernames:
            u = self.user_service.get_user_by_username(r.strip())
            if u: recipient_ids.append(u['id'])
        
        if not recipient_ids:
            return False, "No valid recipients found"
            
        encrypted_data = self.doc_service.encrypt_for_recipients(file_path, recipient_ids)
        return True, encrypted_data

    def decrypt_document(self, encrypted_json, user_id, username, private_key_path=None, priv_key_data=None):
        if not priv_key_data:
            if not private_key_path or not os.path.exists(private_key_path):
                return None, f"Encryption key not found"
        return self.doc_service.decrypt_document(encrypted_json, user_id, private_key_path, priv_key_data)

    def rotate_keys(self, username, key_bundle=None):
        return self.user_service.rotate_keys(username, key_bundle)

    def verify_audit_integrity(self):
        return self.audit.verify_chain()

    def revoke_certificate(self, serial_number):
        return self.user_service.revoke_certificate(serial_number)

    def get_user_certificates(self, user_id):
        return self.user_service.get_user_certificates(user_id)

    def get_active_certificate(self, user_id, purpose):
        """Helper to get the latest non-revoked certificate for a specific purpose."""
        certs = self.user_service.get_user_certificates(user_id)
        for c in certs:
            if c['key_usage'] == purpose and not c['revoked']:
                return c['cert_data']
        return None

    def get_audit_logs(self, limit=20):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,))
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return logs

    # Structured Secrets API
    def add_secret(self, user_id, service, username, url, password, pub_key_pem):
        return self.secret_service.add_secret(user_id, service, username, url, password, pub_key_pem)

    def get_secrets_metadata(self, user_id, search_query=None):
        return self.secret_service.get_secrets_metadata(user_id, search_query)

    def decrypt_secret(self, user_id, entry_id, priv_key_data):
        return self.secret_service.decrypt_secret(user_id, entry_id, priv_key_data)

    def delete_secret(self, user_id, entry_id):
        return self.secret_service.delete_secret(user_id, entry_id)

# Forensic Integrity: def6bc28 verified at 2026-02-09 11:06:00
