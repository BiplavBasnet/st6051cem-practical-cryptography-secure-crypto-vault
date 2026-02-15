import os
import json
import datetime
from services.crypto_utils import CryptoUtils
from services.pki_service import PKIService
from services.database import DBManager
from services.audit_log import AuditLog

class UserService:
    def __init__(self, db_manager: DBManager, pki_service: PKIService, audit_log: AuditLog, keys_dir="keys"):
        self.db = db_manager
        self.pki = pki_service
        self.audit_log = audit_log
        self.keys_dir = keys_dir
        os.makedirs(self.keys_dir, exist_ok=True)

    def register_user(self, username, email, key_bundle=None):
        """
        Register a new user. If key_bundle is provided, it uses the externally 
        generated (and potentially encrypted) keys. Otherwise, it generates plain keys.
        """
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                return False, "Username or Email already exists"

            user_keys_dir = os.path.join(self.keys_dir, username)
            os.makedirs(user_keys_dir, exist_ok=True)

            # 1. Handle Keys
            purposes = ["auth", "signing", "encryption"]
            certs_info = {}

            for purpose in purposes:
                if key_bundle and purpose in key_bundle:
                    # Use provided keys
                    priv_key_bytes = key_bundle[purpose].get('encrypted_priv')
                    pub_pem = key_bundle[purpose]['pub_pem']
                    if isinstance(pub_pem, str): pub_pem = pub_pem.encode()
                    pub_key = CryptoUtils.load_public_key(pub_pem)
                else:
                    # Internal plain generation (legacy/fallback)
                    priv_key = CryptoUtils.generate_rsa_key_pair(3072)
                    pub_key = priv_key.public_key()
                    priv_key_bytes = CryptoUtils.serialize_private_key(priv_key)
                
                # Save private key material ONLY if provided or generated internally
                priv_key_path = os.path.join(user_keys_dir, f"{purpose}_key.pem")
                if priv_key_bytes:
                    with open(priv_key_path, "wb") as f:
                        if isinstance(priv_key_bytes, dict):
                            f.write(json.dumps(priv_key_bytes).encode())
                        else:
                            f.write(priv_key_bytes)
                
                # Issue Certificate
                cert_pem = self.pki.issue_user_certificate(username, pub_key, purpose=purpose)
                cert_path = os.path.join(user_keys_dir, f"{purpose}_cert.pem")
                with open(cert_path, "wb") as f:
                    f.write(cert_pem)
                
                certs_info[purpose] = {
                    "cert_path": cert_path,
                    "priv_key_path": priv_key_path
                }

            # 2. Store user in DB
            cursor.execute("""
                INSERT INTO users (username, email, auth_cert_serial)
                VALUES (?, ?, ?)
            """, (username, email, None))
            user_id = cursor.lastrowid

            # 3. Store certificates in DB
            from cryptography import x509
            for purpose, paths in certs_info.items():
                with open(paths['cert_path'], "rb") as f:
                    cert_data = f.read()
                    cert = x509.load_pem_x509_certificate(cert_data)
                    
                    cursor.execute("""
                        INSERT INTO certificates (user_id, serial_number, subject, issuer, valid_from, valid_to, cert_data, key_usage)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        user_id,
                        str(cert.serial_number),
                        str(cert.subject),
                        str(cert.issuer),
                        cert.not_valid_before_utc,
                        cert.not_valid_after_utc,
                        cert_data.decode(),
                        purpose
                    ))

            conn.commit()
            self.audit_log.log_event("USER_REGISTRATION", {"username": username, "email": email})
            return True, f"User {username} registered successfully. Keys stored in {user_keys_dir}"

        except Exception as e:
            conn.rollback()
            self.audit_log.log_event("REGISTRATION_ERROR", {"username": username, "error": str(e)})
            return False, f"Registration failed: {str(e)}"
        finally:
            conn.close()

    def rotate_keys(self, username, key_bundle=None):
        """
        Rotate keys for an existing user.
        """
        user = self.get_user_by_username(username)
        if not user:
            return False, "User not found"

        user_keys_dir = os.path.join(self.keys_dir, username)
        
        # Backup old keys
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        old_keys_dir = os.path.join(user_keys_dir, f"old_{timestamp}")
        os.makedirs(old_keys_dir, exist_ok=True)
        
        for f in os.listdir(user_keys_dir):
            if os.path.isfile(os.path.join(user_keys_dir, f)) and not f.startswith("old_"):
                os.rename(os.path.join(user_keys_dir, f), os.path.join(old_keys_dir, f))

        # Generate New Keys
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            purposes = ["auth", "signing", "encryption"]
            for purpose in purposes:
                if key_bundle and purpose in key_bundle:
                    priv_key_bytes = key_bundle[purpose].get('encrypted_priv')
                    pub_pem = key_bundle[purpose]['pub_pem']
                    if isinstance(pub_pem, str): pub_pem = pub_pem.encode()
                    pub_key = CryptoUtils.load_public_key(pub_pem)
                else:
                    priv_key = CryptoUtils.generate_rsa_key_pair(3072)
                    pub_key = priv_key.public_key()
                    priv_key_bytes = CryptoUtils.serialize_private_key(priv_key)
                
                priv_key_path = os.path.join(user_keys_dir, f"{purpose}_key.pem")
                if priv_key_bytes:
                    with open(priv_key_path, "wb") as f:
                        if isinstance(priv_key_bytes, dict):
                            f.write(json.dumps(priv_key_bytes).encode())
                        else:
                            f.write(priv_key_bytes)
                
                cert_pem = self.pki.issue_user_certificate(username, pub_key, purpose=purpose)
                cert_path = os.path.join(user_keys_dir, f"{purpose}_cert.pem")
                with open(cert_path, "wb") as f:
                    f.write(cert_pem)
                
                from cryptography import x509
                cert = x509.load_pem_x509_certificate(cert_pem)
                
                cursor.execute("""
                    INSERT INTO certificates (user_id, serial_number, subject, issuer, valid_from, valid_to, cert_data, key_usage)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user['id'],
                    str(cert.serial_number),
                    str(cert.subject),
                    str(cert.issuer),
                    cert.not_valid_before_utc,
                    cert.not_valid_after_utc,
                    cert_pem.decode(),
                    purpose
                ))

            conn.commit()
            self.audit_log.log_event("KEY_ROTATION", {"username": username})
            return True, f"Keys rotated successfully for {username}."
        except Exception as e:
            conn.rollback()
            return False, f"Key rotation failed: {str(e)}"
        finally:
            conn.close()


    def get_user_certificate(self, user_id, purpose, include_revoked=False):
        """Get the latest certificate for a specific user and purpose."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        if include_revoked:
            cursor.execute(
                """
                SELECT cert_data FROM certificates
                WHERE user_id = ? AND key_usage = ?
                ORDER BY id DESC LIMIT 1
                """,
                (user_id, purpose)
            )
        else:
            cursor.execute(
                """
                SELECT cert_data FROM certificates
                WHERE user_id = ? AND key_usage = ? AND revoked = 0
                ORDER BY id DESC LIMIT 1
                """,
                (user_id, purpose)
            )
        row = cursor.fetchone()
        conn.close()
        return row['cert_data'] if row else None

    def revoke_certificate(self, serial_number):
        """Revoke a certificate by its serial number."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE certificates SET revoked = 1 WHERE serial_number = ?", (serial_number,))
        conn.commit()
        conn.close()
        self.audit_log.log_event("CERT_REVOCATION", {"serial_number": serial_number})
        return True, "Certificate revoked successfully"

    def get_user_by_username(self, username):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        return user

    def get_user_certificates(self, user_id):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM certificates WHERE user_id = ? ORDER BY id DESC", (user_id,))
        certs = cursor.fetchall()
        conn.close()
        return certs
