import csv
import datetime
import io
import json
import os
import unicodedata
from collections import Counter
from pathlib import Path

from services.app_paths import config_path
from urllib.parse import parse_qsl, urlencode, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from services.audit_log import AuditLog
from services.crypto_utils import CryptoUtils
from services.database import DBManager
from services.structured_logger import get_logger


class SecretService:
    """Handles structured secret storage with per-entry encryption and secure indexing."""

    INDEX_MASTER_KEY_PATH = config_path("duplicate_index_master.key")

    def __init__(self, db: DBManager, audit: AuditLog, pki=None):
        self.db = db
        self.audit = audit
        self.pki = pki
        self._logger = get_logger()
        self._index_master_key = self._load_or_create_index_master_key()

    @classmethod
    def _load_or_create_index_master_key(cls) -> bytes:
        path = cls.INDEX_MASTER_KEY_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            data = path.read_bytes()
            if len(data) >= 32:
                return data[:32]
        key = os.urandom(32)
        path.write_bytes(key)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return key

    def _derive_user_key(self, user_id: int, purpose: str) -> bytes:
        salt = f"sv:user:{int(user_id)}".encode("utf-8")
        info = f"secure-vault:{purpose}:v1".encode("utf-8")
        return CryptoUtils.hkdf_expand(self._index_master_key, info=info, salt=salt, length=32)

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        if not url:
            return True
        parsed = urlparse(url.strip())
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    @staticmethod
    def _canonicalize_url(url: str) -> str:
        if not url:
            return ""
        raw = str(url).strip()
        if not raw:
            return ""

        # Non-http labels are kept trimmed as-is (e.g. "internal portal")
        if "://" not in raw:
            return raw

        p = urlparse(raw)
        if p.scheme not in {"http", "https"} or not p.netloc:
            return raw

        scheme = p.scheme.lower()
        host = (p.hostname or "").lower()
        if not host:
            return raw

        port = p.port
        default_port = 80 if scheme == "http" else 443
        port_part = f":{port}" if port and port != default_port else ""

        path = p.path or "/"
        if path != "/" and path.endswith("/"):
            path = path[:-1]

        q_items = parse_qsl(p.query, keep_blank_values=True)
        q_items.sort(key=lambda kv: (kv[0], kv[1]))
        query = urlencode(q_items, doseq=True)

        out = f"{scheme}://{host}{port_part}{path}"
        if query:
            out += f"?{query}"
        return out

    @staticmethod
    def _clean_text(value, *, max_len: int = 255, field_name: str = "field"):
        """Permissive sanitizer for real-world imports."""
        if value is None:
            return False, f"{field_name} cannot be empty", ""

        txt = str(value).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
        if not txt:
            return False, f"{field_name} cannot be empty", ""

        # Remove control chars but keep printable Unicode.
        txt = "".join(ch for ch in txt if not unicodedata.category(ch).startswith("C"))
        txt = txt.strip()
        if not txt:
            return False, f"{field_name} cannot be empty", ""

        if len(txt) > max_len:
            txt = txt[:max_len]

        return True, "Valid", txt

    def _validate_metadata(self, service: str, username: str, url: str | None):
        ok, msg, service_clean = self._clean_text(service, max_len=255, field_name="service")
        if not ok:
            return False, f"Invalid service: {msg}", None

        ok, msg, username_clean = self._clean_text(username, max_len=254, field_name="username/email")
        if not ok:
            return False, f"Invalid username/email: {msg}", None

        url_clean = ""
        canonical_url = ""
        if url is not None and str(url).strip():
            ok, msg, candidate = self._clean_text(url, max_len=600, field_name="URL")
            if not ok:
                return False, f"Invalid URL field: {msg}", None
            url_clean = candidate
            canonical_url = self._canonicalize_url(candidate)

        return True, "Valid", {
            "service": service_clean,
            "username": username_clean,
            "url": url_clean,
            "canonical_url": canonical_url,
        }

    @staticmethod
    def _canonical_tuple(service: str, username: str, canonical_url: str, password: str) -> bytes:
        # Strict exact match token over normalized storage tuple.
        joined = "\x1f".join([service, username, canonical_url or "", password])
        return joined.encode("utf-8")

    def _duplicate_token(self, user_id: int, service: str, username: str, canonical_url: str, password: str) -> str:
        key = self._derive_user_key(int(user_id), "dup-index")
        payload = self._canonical_tuple(service, username, canonical_url, password)
        return CryptoUtils.hmac_sha256_hex(key, payload)

    def _reuse_token(self, user_id: int, password: str) -> str:
        key = self._derive_user_key(int(user_id), "reuse-index")
        return CryptoUtils.hmac_sha256_hex(key, password.encode("utf-8"))

    @staticmethod
    def _build_entry_aad(service: str, username: str, canonical_url: str) -> bytes:
        marker = "|".join(["sv-entry-v3", service, username, canonical_url or ""])
        return marker.encode("utf-8")

    def _resolve_owner_public_key(self, user_id: int, pub_key_pem):
        """Return validated public key bound to authenticated user."""
        pem_bytes = pub_key_pem.encode() if isinstance(pub_key_pem, str) else pub_key_pem

        cert = None
        try:
            cert = x509.load_pem_x509_certificate(pem_bytes)
        except Exception:
            cert = None

        if cert is not None:
            if not self.pki:
                raise ValueError("PKI validation service unavailable")

            valid, msg = self.pki.validate_certificate(
                pem_bytes,
                db_manager=self.db,
                required_ku=["key_encipherment"],
            )
            if not valid:
                raise ValueError(f"Invalid encryption certificate: {msg}")

            cert_serial = str(cert.serial_number)
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 1 FROM certificates
                WHERE user_id = ?
                  AND serial_number = ?
                  AND key_usage = 'encryption'
                  AND revoked = 0
                LIMIT 1
                """,
                (int(user_id), cert_serial),
            )
            owned = cursor.fetchone()
            conn.close()
            if not owned:
                raise ValueError("Encryption certificate does not belong to the authenticated user")

            return cert.public_key()

        # Return validated public key bound to authenticated user.
        owner_id = int(user_id)
        pub_key = CryptoUtils.load_public_key(pub_key_pem)

        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cert_data FROM certificates WHERE user_id = ? AND key_usage = ? AND revoked = 0",
            (owner_id, "encryption"),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            raise ValueError("No active encryption certificate found for user")

        cert_pem = row["cert_data"]
        cert_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
        active_cert = x509.load_pem_x509_certificate(cert_bytes)
        active_pub = active_cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        incoming_pub = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if incoming_pub != active_pub:
            raise ValueError("Provided public key does not match active encryption certificate")

        return pub_key

    def add_secret(self, user_id, service, username, url, password, pub_key_pem, totp_secret=None):
        """Encrypt and store secret entry bound to owner's active encryption cert."""
        valid, msg, cleaned = self._validate_metadata(service, username, url)
        if not valid:
            return False, msg

        if not password:
            return False, "Password cannot be empty"

        try:
            owner_id = int(user_id)
            dup_token = self._duplicate_token(
                owner_id,
                cleaned["service"],
                cleaned["username"],
                cleaned["canonical_url"],
                str(password),
            )

            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id FROM vault_secrets
                WHERE owner_id = ? AND duplicate_token = ?
                LIMIT 1
                """,
                (owner_id, dup_token),
            )
            exists = cursor.fetchone()
            conn.close()
            if exists:
                return False, "Duplicate blocked by strict exact match (service+username+url+password)"

            pub_key = self._resolve_owner_public_key(owner_id, pub_key_pem)
            aad = self._build_entry_aad(cleaned["service"], cleaned["username"], cleaned["canonical_url"])
            enc_dek, nonce, ciphertext = CryptoUtils.hybrid_encrypt(pub_key, str(password).encode("utf-8"), associated_data=aad)
            reuse_token = self._reuse_token(owner_id, str(password))

            # Encrypt TOTP secret if provided
            enc_totp = None
            totp_nonce = None
            enc_totp_dek = None
            if totp_secret:
                # We use the same DEK for TOTP to keep it simple, or derived?
                # Let's derive a separate nonce for security.
                # DEK is only accessible if we have the private key.
                # For simplicity in this implementation, we'll use the DEK we just generated with hybrid_encrypt.
                # But wait, hybrid_encrypt generates its own ephemeral DEK.
                # We should probably use a consistent approach.
                # Actually, let's just encrypt it with the same public key independently for now or use the DEK.
                # Re-using the DEK is better.
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                # We need the raw DEK. hybrid_encrypt doesn't return it.
                # Let's use a manual hybrid approach or just hybrid_encrypt again.
                # Hybrid encrypt for TOTP is fine.
                enc_totp_dek, totp_nonce, enc_totp = CryptoUtils.hybrid_encrypt(pub_key, str(totp_secret).encode("utf-8"), associated_data=aad)

            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO vault_secrets (
                    owner_id, service_name, username_email, url, canonical_url,
                    encrypted_password, encrypted_dek, nonce,
                    encrypted_totp, totp_nonce, encrypted_totp_dek,
                    duplicate_token, reuse_token, crypto_version, password_updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    owner_id,
                    cleaned["service"],
                    cleaned["username"],
                    cleaned["url"],
                    cleaned["canonical_url"],
                    ciphertext,
                    enc_dek,
                    nonce,
                    enc_totp,
                    totp_nonce,
                    enc_totp_dek,
                    dup_token,
                    reuse_token,
                    "v3-aead-envelope-aad",
                    datetime.datetime.utcnow(),
                ),
            )
            conn.commit()
            conn.close()

            self.audit.log_event("SECRET_ADDED", {"user_id": user_id, "service": service}, user_id=user_id)
            return True, "Secret added successfully"
        except Exception as e:
            return False, f"Failed to add secret: {str(e)}"
