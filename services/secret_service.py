import hashlib
import json
from services.database import DBManager
from services.crypto_utils import CryptoUtils
from services.audit_log import AuditLog
from cryptography import x509

class SecretService:
    """Handles structured secret storage with per-entry encryption."""
    
    def __init__(self, db: DBManager, audit: AuditLog):
        self.db = db
        self.audit = audit

    def add_secret(self, user_id, service, username, url, password, pub_key_pem):
        """Encrypt and store a new secret entry."""
        try:
            pem_bytes = pub_key_pem.encode() if isinstance(pub_key_pem, str) else pub_key_pem
            
            # 1. Extract public key (handle cert vs raw public key)
            try:
                # Try loading as certificate first
                cert = x509.load_pem_x509_certificate(pem_bytes)
                pub_key = cert.public_key()
            except:
                # Fallback to raw public key
                pub_key = CryptoUtils.load_public_key(pem_bytes)
                
            enc_dek, nonce, ciphertext = CryptoUtils.hybrid_encrypt(pub_key, password.encode())
            
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO vault_secrets (owner_id, service_name, username_email, url, encrypted_password, encrypted_dek, nonce)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (int(user_id), service, username, url, ciphertext, enc_dek, nonce))
            conn.commit()
            conn.close()
            
            self.audit.log_event("SECRET_ADDED", {"user_id": user_id, "service": service})
            return True, "Secret added successfully"
        except Exception as e:
            return False, f"Failed to add secret: {str(e)}"

    def get_secrets_metadata(self, user_id, search_query=None):
        """Retrieve plaintext metadata for indexing and search."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        if search_query:
            q = f"%{search_query.lower()}%"
            cursor.execute("""
                SELECT id, service_name, username_email, url, created_at 
                FROM vault_secrets 
                WHERE owner_id = ? AND (
                    LOWER(service_name) LIKE ? OR 
                    LOWER(username_email) LIKE ? OR 
                    (url IS NOT NULL AND LOWER(url) LIKE ?)
                )
                ORDER BY service_name ASC
            """, (int(user_id), q, q, q))
        else:
            cursor.execute("""
                SELECT id, service_name, username_email, url, created_at 
                FROM vault_secrets 
                WHERE owner_id = ? 
                ORDER BY service_name ASC
            """, (int(user_id),))
            
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def decrypt_secret(self, user_id, entry_id, priv_key_data):
        """Decrypt a single specific entry using the provided private key data."""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT encrypted_password, encrypted_dek, nonce, service_name 
                FROM vault_secrets 
                WHERE id = ? AND owner_id = ?
            """, (int(entry_id), int(user_id)))
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None, "Secret entry not found"
            
            priv_key = CryptoUtils.load_private_key(priv_key_data)
            plaintext_bytes = CryptoUtils.hybrid_decrypt(
                priv_key, 
                row['encrypted_dek'], 
                row['nonce'], 
                row['encrypted_password']
            )
            
            self.audit.log_event("SECRET_DECRYPTED", {"user_id": user_id, "service": row['service_name']})
            return plaintext_bytes.decode(), "Success"
        except Exception as e:
            return None, f"Decryption failed: {str(e)}"

    def delete_secret(self, user_id, entry_id):
        """Remove a secret entry."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vault_secrets WHERE id = ? AND owner_id = ?", (int(entry_id), int(user_id)))
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        if success:
            self.audit.log_event("SECRET_DELETED", {"user_id": user_id, "entry_id": entry_id})
        return success
