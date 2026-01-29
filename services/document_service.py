import os
import datetime
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services.crypto_utils import CryptoUtils
from services.pki_service import PKIService
from services.database import DBManager
from services.audit_log import AuditLog
from services.app_paths import app_dir


class DocumentService:
    def __init__(self, db_manager: DBManager, pki_service: PKIService, audit_log: AuditLog, tsa_dir=None):
        self.db = db_manager
        self.pki = pki_service
        self.audit_log = audit_log
        self.tsa_dir = Path(tsa_dir) if tsa_dir is not None else (app_dir() / "tsa")
        self.tsa_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.tsa_dir, 0o700)
        except Exception:
            pass
        self.tsa_key_path = self.tsa_dir / "tsa_key.pem"
        self._setup_tsa()

    @staticmethod
    def _secure_write(path: Path, data: bytes, mode: int = 0o600):
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(path), flags, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            os.chmod(path, mode)
        except Exception:
            pass

    def _setup_tsa(self):
        """Setup simulated TSA with private key stored as file permissions 0600."""
        if not self.tsa_key_path.exists():
            priv_key = CryptoUtils.generate_rsa_key_pair(3072)
            self._secure_write(self.tsa_key_path, CryptoUtils.serialize_private_key(priv_key), 0o600)
        else:
            try:
                os.chmod(self.tsa_key_path, 0o600)
            except Exception:
                pass

    def get_tsa_key(self):
        return CryptoUtils.load_private_key(self.tsa_key_path.read_bytes())

    def create_timestamp_token(self, data_hash):
        tsa_key = self.get_tsa_key()
        timestamp = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        token_payload = json.dumps({"hash": data_hash, "timestamp": timestamp}, separators=(",", ":")).encode()
        signature = CryptoUtils.sign_data(tsa_key, token_payload)
        return json.dumps({"payload": token_payload.decode(), "signature": signature.hex()}).encode()

    def sign_document(self, user_id, file_path, priv_key_path=None, priv_key_data=None):
        conn = None
        try:
            file_path = Path(file_path)
            if not file_path.exists() or not file_path.is_file():
                return False, "File not found"

            file_data = file_path.read_bytes()
            file_hash = hashlib.sha256(file_data).hexdigest()

            if not priv_key_data:
                if not priv_key_path:
                    return False, "Signing key not found"
                priv_key_data = Path(priv_key_path).read_bytes()

            private_key = CryptoUtils.load_private_key(priv_key_data)

            conn = self.db.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT serial_number, cert_data FROM certificates
                WHERE user_id = ? AND key_usage = 'signing' AND revoked = 0
                ORDER BY id DESC LIMIT 1
                """,
                (user_id,),
            )
            cert_row = cursor.fetchone()
            if not cert_row:
                return False, "No active signing certificate found"

            cert_serial = cert_row["serial_number"]
            cert_pem = cert_row["cert_data"]
            cert_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem

            valid, msg = self.pki.validate_certificate(
                cert_bytes,
                db_manager=self.db,
                required_ku=["digital_signature", "content_commitment"],
            )
            if not valid:
                return False, f"Signing certificate validation failed: {msg}"

            signature = CryptoUtils.sign_data(private_key, file_hash.encode())

            cert_obj = x509.load_pem_x509_certificate(cert_bytes)
            if not CryptoUtils.verify_signature(cert_obj.public_key(), file_hash.encode(), signature):
                return False, "Private key does not match the active signing certificate"

            ts_token = self.create_timestamp_token(file_hash)

            cursor.execute(
                """
                INSERT INTO signed_documents (user_id, cert_serial, file_name, file_hash, signature, timestamp_token)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, cert_serial, file_path.name, file_hash, signature, ts_token),
            )
            conn.commit()

            self.audit_log.log_event("DOCUMENT_SIGNED", {"user_id": user_id, "file": file_path.name, "cert_serial": cert_serial}, user_id=user_id)
            return True, "Document signed successfully"
        except Exception as e:
            return False, f"Signing failed: {str(e)}"
        finally:
            if conn:
                conn.close()
