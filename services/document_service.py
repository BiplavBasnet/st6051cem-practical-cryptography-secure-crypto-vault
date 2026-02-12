import os
import datetime
import hashlib
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from services.crypto_utils import CryptoUtils
from services.pki_service import PKIService
from services.database import DBManager
from services.audit_log import AuditLog

class DocumentService:
    def __init__(self, db_manager: DBManager, pki_service: PKIService, audit_log: AuditLog, tsa_dir="tsa"):
        self.db = db_manager
        self.pki = pki_service
        self.audit_log = audit_log
        self.tsa_dir = tsa_dir
        os.makedirs(self.tsa_dir, exist_ok=True)
        self.tsa_key_path = os.path.join(self.tsa_dir, "tsa_key.pem")
        self._setup_tsa()

    def _setup_tsa(self):
        """Setup a simulated Time-Stamping Authority."""
        if not os.path.exists(self.tsa_key_path):
            priv_key = CryptoUtils.generate_rsa_key_pair(3072)
            with open(self.tsa_key_path, "wb") as f:
                f.write(CryptoUtils.serialize_private_key(priv_key))

    def get_tsa_key(self):
        with open(self.tsa_key_path, "rb") as f:
            return CryptoUtils.load_private_key(f.read())

    def create_timestamp_token(self, data_hash):
        """Simulate a TSA signing a hash with a timestamp."""
        tsa_key = self.get_tsa_key()
        timestamp = datetime.datetime.utcnow().isoformat()
        token_payload = json.dumps({"hash": data_hash, "timestamp": timestamp}).encode()
        signature = CryptoUtils.sign_data(tsa_key, token_payload)
        return json.dumps({
            "payload": token_payload.decode(),
            "signature": signature.hex()
        }).encode()

    def sign_document(self, user_id, file_path, priv_key_path=None, priv_key_data=None):
        """Sign a document with RSA-PSS and get a TSA timestamp token (Tier 1 Enhancement)."""
        conn = None
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()

            if not priv_key_data:
                with open(priv_key_path, "rb") as f:
                    priv_key_data = f.read()
            
            private_key = CryptoUtils.load_private_key(priv_key_data)
            
            # Fix 2: Enforce active signing cert and match
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Fetch the latest non-revoked signing certificate serial for this user
            cursor.execute("""
                SELECT serial_number, cert_data FROM certificates 
                WHERE user_id = ? AND key_usage = 'signing' AND revoked = 0
                ORDER BY id DESC LIMIT 1
            """, (user_id,))
            cert_row = cursor.fetchone()
            
            if not cert_row:
                return False, "No active signing certificate found"
            
            cert_serial = cert_row['serial_number']
            cert_pem = cert_row['cert_data']
            cert_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
            
            # Validate selected cert via PKI
            valid, msg = self.pki.validate_certificate(
                cert_bytes, 
                db_manager=self.db, 
                required_ku=["digital_signature", "content_commitment"]
            )
            if not valid:
                return False, f"Signing certificate validation failed: {msg}"

            # Sign payload
            signature = CryptoUtils.sign_data(private_key, file_hash.encode())
            
            # Verify match before insert
            cert_obj = x509.load_pem_x509_certificate(cert_bytes)
            if not CryptoUtils.verify_signature(cert_obj.public_key(), file_hash.encode(), signature):
                return False, "Private key does not match the active signing certificate"

            ts_token = self.create_timestamp_token(file_hash)

            cursor.execute("""
                INSERT INTO signed_documents (user_id, cert_serial, file_name, file_hash, signature, timestamp_token)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, cert_serial, os.path.basename(file_path), file_hash, signature, ts_token))
            conn.commit()
            
            self.audit_log.log_event("DOCUMENT_SIGNED", {"user_id": user_id, "file": os.path.basename(file_path), "cert_serial": cert_serial})
            return True, "Document signed successfully"
        except Exception as e:
            return False, f"Signing failed: {str(e)}"
        finally:
            if conn:
                conn.close()

    def verify_document(self, file_path):
        """Verify all signatures associated with a document hash."""
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()

            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.*, u.username 
                FROM signed_documents s
                JOIN users u ON s.user_id = u.id
                WHERE s.file_hash = ?
            """, (file_hash,))
            rows = cursor.fetchall()
            conn.close()

            results = []
            for row in rows:
                valid, msg = self.verify_document_signature(row, file_hash)
                results.append({
                    "username": row['username'],
                    "valid": valid,
                    "message": msg
                })
            return results
        except Exception as e:
            return [{"username": "System", "valid": False, "message": str(e)}]

    def verify_document_signature(self, row, file_hash):
        """Low-level verification of a single signature row."""
        # 1. Get the certificate (By serial if possible, fallback to latest)
        conn = self.db.get_connection()
        cursor = conn.cursor()
        if row['cert_serial']:
            cursor.execute("SELECT cert_data FROM certificates WHERE serial_number = ?", (row['cert_serial'],))
        else:
            # Fallback to latest for legacy signatures
            cursor.execute("SELECT cert_data FROM certificates WHERE user_id = ? AND key_usage = 'signing' ORDER BY id DESC LIMIT 1", (row['user_id'],))
        
        cert_row = cursor.fetchone()
        conn.close()
        
        if not cert_row:
            return False, "Signer certificate not found"
            
        cert_pem = cert_row['cert_data']
        cert_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
        
        # 2. Validate Certificate (Check revocation, CA signature, and KeyUsage)
        valid, msg = self.pki.validate_certificate(
            cert_bytes, 
            db_manager=self.db, 
            required_ku=["digital_signature", "content_commitment"]
        )
        if not valid:
            return False, f"Certificate invalid: {msg}"

        # Load public key and verify signature
        cert = x509.load_pem_x509_certificate(cert_bytes)
        public_key = cert.public_key()
        signature = row['signature']
        
        if not CryptoUtils.verify_signature(public_key, file_hash.encode(), signature):
            return False, "RSA-PSS Digital signature mismatch"

        # 3. Verify TSA Token (Deep Verification)
        if row['timestamp_token']:
            token_valid = self.verify_timestamp_token(row['timestamp_token'], file_hash)
            if not token_valid:
                return False, "TSA Timestamp Token verification failed or hash mismatch"
            return True, "Valid (Includes TSA Verification)"

        return True, "Valid (RSA-PSS Only)"

    def verify_timestamp_token(self, token_json, expected_hash):
        """Verify the signature and hash inside a TSA token."""
        try:
            data = json.loads(token_json)
            payload = json.loads(data['payload'])
            if payload['hash'] != expected_hash:
                return False
            
            tsa_pub = self.get_tsa_key().public_key()
            signature = bytes.fromhex(data['signature'])
            return CryptoUtils.verify_signature(tsa_pub, data['payload'].encode(), signature)
        except Exception:
            return False

    def encrypt_for_recipients(self, file_path, recipient_user_ids):
        """
        Encrypt a document for multiple recipients (Tier 2: Cryptographic Access Control).
        Uses hybrid encryption with multiple KEK wraps.
        """
        with open(file_path, "rb") as f:
            file_data = f.read()
            
        raw_dek = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(raw_dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, file_data, None)
        
        encrypted_deks = {}
        
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        for r_id in recipient_user_ids:
            cursor.execute("""
                SELECT cert_data FROM certificates
                WHERE user_id = ? AND key_usage = 'encryption' AND revoked = 0
                ORDER BY id DESC
                LIMIT 1
            """, (r_id,))
            row = cursor.fetchone()
            if row:
                cert_pem = row['cert_data']
                cert_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
                valid, _ = self.pki.validate_certificate(
                    cert_bytes,
                    db_manager=self.db,
                    required_ku=["key_encipherment"]
                )
                if not valid:
                    continue

                cert = x509.load_pem_x509_certificate(cert_bytes)
                enc_dek = cert.public_key().encrypt(
                    raw_dek,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_deks[r_id] = enc_dek.hex()
        
        conn.close()
        
        result = {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "encrypted_deks": encrypted_deks
        }
        return json.dumps(result)

    def decrypt_document(self, encrypted_json, user_id, priv_key_path=None, priv_key_data=None):
        """Decrypt a document if the user is an authorized recipient."""
        try:
            data = json.loads(encrypted_json)
            if str(user_id) not in data['encrypted_deks']:
                return None, "User not authorized"
            
            if not priv_key_data:
                with open(priv_key_path, "rb") as f:
                    priv_key_data = f.read()
                    
            private_key = CryptoUtils.load_private_key(priv_key_data)
            enc_dek = bytes.fromhex(data['encrypted_deks'][str(user_id)])
            raw_dek = private_key.decrypt(
                enc_dek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            aesgcm = AESGCM(raw_dek)
            nonce = bytes.fromhex(data['nonce'])
            ciphertext = bytes.fromhex(data['ciphertext'])
            
            return aesgcm.decrypt(nonce, ciphertext, None), "Success"
        except Exception as e:
            return None, f"Decryption failed: {str(e)}"

    def get_document_signatures(self, file_path):
        """Get all signatures for a document hash."""
        with open(file_path, "rb") as f:
            file_data = f.read()
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.username, sd.signature, c.cert_data
            FROM signed_documents sd
            JOIN users u ON sd.user_id = u.id
            JOIN certificates c ON sd.user_id = c.user_id AND c.key_usage = 'signing'
            WHERE sd.file_hash = ?
        """, (file_hash,))
        
        results = cursor.fetchall()
        conn.close()
        return results

# Forensic Integrity: 46df96fc verified at 2026-02-12 14:58:59
