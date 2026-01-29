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

    def get_secrets_metadata(self, user_id, search_query=None, sort_column="service_name", sort_direction="ASC"):
        conn = self.db.get_connection()
        cursor = conn.cursor()

        # Validate sort column to prevent SQL injection
        valid_columns = {
            "service_name": "service_name",
            "username_email": "username_email",
            "url": "url",
            "created_at": "created_at",
            "id": "id"
        }
        sort_col = valid_columns.get(sort_column, "service_name")
        sort_dir = "ASC" if sort_direction.upper() == "ASC" else "DESC"

        if search_query:
            # Escape LIKE wildcards so user input is matched literally
            escaped = (search_query.lower()
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_"))
            q = f"%{escaped}%"
            cursor.execute(
                f"""
                SELECT id, service_name, username_email, url, created_at
                FROM vault_secrets
                WHERE owner_id = ? AND (
                    LOWER(service_name) LIKE ? OR
                    LOWER(username_email) LIKE ? OR
                    (url IS NOT NULL AND LOWER(url) LIKE ?)
                )
                ORDER BY {sort_col} {sort_dir}
                """,
                (int(user_id), q, q, q),
            )
        else:
            cursor.execute(
                f"""
                SELECT id, service_name, username_email, url, created_at
                FROM vault_secrets
                WHERE owner_id = ?
                ORDER BY {sort_col} {sort_dir}
                """,
                (int(user_id),),
            )

        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def decrypt_secret(self, user_id, entry_id, priv_key_data):
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT encrypted_password, encrypted_dek, nonce,
                       encrypted_totp, totp_nonce, encrypted_totp_dek,
                       service_name, username_email, canonical_url, crypto_version
                FROM vault_secrets
                WHERE id = ? AND owner_id = ?
                """,
                (int(entry_id), int(user_id)),
            )
            row = cursor.fetchone()
            conn.close()

            if not row:
                return None, "Secret entry not found"

            priv_key = CryptoUtils.load_private_key(priv_key_data)

            version = str(row["crypto_version"] or "")
            plaintext_bytes = None
            totp_secret_bytes = None

            # Preferred v3 path with AAD binding
            if version.startswith("v3"):
                aad = self._build_entry_aad(row["service_name"], row["username_email"], row["canonical_url"] or "")
                plaintext_bytes = CryptoUtils.hybrid_decrypt(
                    priv_key,
                    row["encrypted_dek"],
                    row["nonce"],
                    row["encrypted_password"],
                    associated_data=aad,
                )
                if row["encrypted_totp"] and row["totp_nonce"] and row["encrypted_totp_dek"]:
                   try:
                       totp_secret_bytes = CryptoUtils.hybrid_decrypt(
                           priv_key,
                           row["encrypted_totp_dek"],
                           row["totp_nonce"],
                           row["encrypted_totp"],
                           associated_data=aad,
                       )
                   except Exception:
                       totp_secret_bytes = None
            else:
                # Fallback to v1/v2 (no AAD)
                plaintext_bytes = CryptoUtils.hybrid_decrypt(
                    priv_key,
                    row["encrypted_dek"],
                    row["nonce"],
                    row["encrypted_password"],
                )

            if plaintext_bytes is None:
                return None, "Decryption failed: password could not be decrypted"
            
            pwd = plaintext_bytes.decode("utf-8")
            totp = totp_secret_bytes.decode("utf-8") if totp_secret_bytes else None
            
            # Return both if needed? The UI expect just pwd for now.
            # I'll modify the API to return a dict or tuple.
            self.audit.log_event("SECRET_DECRYPTED", {"user_id": user_id, "service": row["service_name"]}, user_id=user_id)
            return {"password": pwd, "totp_secret": totp}, "Success"

        except Exception as e:
            return None, f"Decryption failed: {str(e)}"

    def delete_secret(self, user_id, entry_id):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM vault_secrets WHERE id = ? AND owner_id = ?",
            (int(entry_id), int(user_id)),
        )
        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        if deleted:
            self.audit.log_event("SECRET_DELETED", {"user_id": user_id, "entry_id": entry_id}, user_id=user_id)
            return True, "Secret deleted"
        return False, "Secret not found"

    def import_secrets_from_csv(self, user_id, csv_path, pub_key_pem, max_rows: int = 10000):
        """Import secrets from CSV with resilient header matching and continue-on-error."""
        added = 0
        skipped = 0
        failed = 0
        messages = []

        path = Path(csv_path)
        if not path.exists():
            return False, {"error": "CSV file not found"}

        try:
            with path.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames:
                    return False, {"error": "CSV has no header row"}

                # Canonicalize headers (lowercase, remove spaces/underscores)
                canon = {}
                for h in reader.fieldnames:
                    key = "".join(ch for ch in (h or "").strip().lower() if ch.isalnum())
                    canon[key] = h

                service_key = None
                user_key = None
                url_key = None
                pass_key = None

                # Support various CSV formats including Firefox, Chrome, Brave, etc.
                service_alias = ["service", "sitename", "name", "website", "title", "hostname", "origin", "formactionorigin"]
                user_alias = ["username", "user", "email", "login", "userid", "user name"]
                url_alias = ["url", "website", "site", "loginurl", "origin", "formactionorigin", "http realm"]
                pass_alias = ["password", "pass", "pwd", "secret", "passwd"]

                for k in service_alias:
                    if k in canon:
                        service_key = canon[k]
                        break
                for k in user_alias:
                    if k in canon:
                        user_key = canon[k]
                        break
                for k in url_alias:
                    if k in canon:
                        url_key = canon[k]
                        break
                for k in pass_alias:
                    if k in canon:
                        pass_key = canon[k]
                        break

                if not service_key or not user_key or not pass_key:
                    # Try url_key fallback for service (e.g. url,username,password CSV)
                    if url_key and not service_key:
                        service_key = url_key

                # Only return "Missing required columns" if STILL missing after fallback
                if not service_key or not user_key or not pass_key:
                    detected = ", ".join(reader.fieldnames) if reader.fieldnames else "none"
                    missing = []
                    if not service_key:
                        missing.append("service/website/url")
                    if not user_key:
                        missing.append("username/email")
                    if not pass_key:
                        missing.append("password")
                    return False, {
                        "error": (
                            f"Missing required columns: {', '.join(missing)}. "
                            f"Detected headers: {detected}. "
                            "Expected columns: service/website/url, username/email, password"
                        )
                    }

                for idx, row in enumerate(reader, start=2):  # data starts after header line
                    if idx - 1 > max_rows:
                        failed += 1
                        messages.append(f"Row {idx}: import limit exceeded ({max_rows})")
                        break

                    service = (row.get(service_key) or "").strip()
                    username = (row.get(user_key) or "").strip()
                    url = (row.get(url_key) or "").strip() if url_key else ""
                    password = (row.get(pass_key) or "")
                    
                    # For Firefox format: if service is empty but URL exists, use URL domain as service
                    if not service and url:
                        from urllib.parse import urlparse
                        try:
                            parsed = urlparse(url)
                            service = parsed.netloc or parsed.path.split('/')[0] or url
                        except Exception:
                            service = url
                    
                    # If still no service name, use a default
                    if not service:
                        service = "Imported Entry"

                    if not service or not username or not password:
                        skipped += 1
                        messages.append(f"Row {idx}: missing required fields")
                        continue

                    ok, msg = self.add_secret(user_id, service, username, url, password, pub_key_pem)
                    if ok:
                        added += 1
                    else:
                        if "Duplicate blocked" in msg:
                            skipped += 1
                            messages.append(f"Row {idx}: duplicate exact match")
                        else:
                            failed += 1
                            messages.append(f"Row {idx}: {msg}")

            self.audit.log_event(
                "SECRETS_IMPORTED_CSV",
                {
                    "user_id": user_id,
                    "file": str(path.name),
                    "added": added,
                    "skipped": skipped,
                    "failed": failed,
                },
                user_id=user_id,
            )

            return True, {
                "added": added,
                "imported": added,
                "skipped": skipped,
                "failed": failed,
                "total_rows": added + skipped + failed,  # Add total_rows for UI
                "errors": messages,
                "messages": messages[:200],
            }
        except UnicodeDecodeError as e:
            error_detail = f"File encoding error. Please ensure the CSV file is UTF-8 encoded. Error: {str(e)}"
            self._logger.error("CSV import encoding error: %s", e)
            return False, {"error": error_detail, "message": error_detail}
        except csv.Error as e:
            error_detail = f"CSV parsing error: {str(e)}. Please check the CSV file format."
            self._logger.error("CSV import parsing error: %s", e)
            return False, {"error": error_detail, "message": error_detail}
        except Exception as e:
            import traceback
            error_detail = f"Import error: {str(e)}"
            self._logger.error("CSV import exception: %s\n%s", error_detail, traceback.format_exc())
            return False, {"error": error_detail, "message": error_detail}

    def import_secrets_from_json(self, user_id, json_path, pub_key_pem, max_rows: int = 10000):
        """Import secrets from JSON file (browser exports like Firefox, Chrome, etc.)."""
        added = 0
        skipped = 0
        failed = 0
        messages = []

        path = Path(json_path)
        if not path.exists():
            return False, {"error": "JSON file not found"}

        try:
            with path.open("r", encoding="utf-8-sig") as f:
                data = json.load(f)
            
            # Handle different JSON formats
            entries = []
            if isinstance(data, list):
                # Direct array of entries
                entries = data
            elif isinstance(data, dict):
                # Check for common browser export formats
                if "logins" in data:
                    # Firefox format
                    entries = data["logins"]
                elif "entries" in data:
                    # Generic format
                    entries = data["entries"]
                elif "passwords" in data:
                    entries = data["passwords"]
                else:
                    # Try to find any array in the dict
                    for key, value in data.items():
                        if isinstance(value, list) and value:
                            entries = value
                            break
            
            if not entries:
                return False, {"error": "No password entries found in JSON file. Expected array of entries or object with 'logins', 'entries', or 'passwords' key."}

            for idx, entry in enumerate(entries, start=1):
                if idx > max_rows:
                    failed += 1
                    messages.append(f"Row {idx}: import limit exceeded ({max_rows})")
                    break

                # Extract fields with flexible key matching
                service = ""
                username = ""
                url = ""
                password = ""

                # Try various key names (case-insensitive)
                entry_lower = {str(k).lower(): v for k, v in entry.items() if isinstance(k, str)}
                
                # Service/name
                for key in ["hostname", "origin", "url", "site", "website", "name", "service", "title", "formactionorigin"]:
                    if key in entry_lower:
                        val = entry_lower[key]
                        if isinstance(val, str) and val.strip():
                            service = val.strip()
                            break
                
                # Username
                for key in ["username", "user", "email", "login", "userid", "user name"]:
                    if key in entry_lower:
                        val = entry_lower[key]
                        if isinstance(val, str) and val.strip():
                            username = val.strip()
                            break
                
                # URL
                for key in ["url", "website", "site", "loginurl", "origin", "formactionorigin", "http realm"]:
                    if key in entry_lower:
                        val = entry_lower[key]
                        if isinstance(val, str) and val.strip():
                            url = val.strip()
                            break
                
                # Password
                for key in ["password", "pass", "pwd", "secret", "passwd"]:
                    if key in entry_lower:
                        val = entry_lower[key]
                        if isinstance(val, str) and val.strip():
                            password = val.strip()
                            break

                # Extract service from URL if not found
                if not service and url:
                    from urllib.parse import urlparse
                    try:
                        parsed = urlparse(url)
                        service = parsed.netloc or parsed.path.split('/')[0] or url
                    except Exception:
                        service = url

                if not service:
                    service = "Imported Entry"

                if not username or not password:
                    skipped += 1
                    messages.append(f"Row {idx}: missing required fields (username or password)")
                    continue

                ok, msg = self.add_secret(user_id, service, username, url, password, pub_key_pem)
                if ok:
                    added += 1
                else:
                    if "Duplicate blocked" in msg:
                        skipped += 1
                        messages.append(f"Row {idx}: duplicate exact match")
                    else:
                        failed += 1
                        messages.append(f"Row {idx}: {msg}")

            self.audit.log_event(
                "SECRETS_IMPORTED_JSON",
                {
                    "user_id": user_id,
                    "file": str(path.name),
                    "added": added,
                    "skipped": skipped,
                    "failed": failed,
                },
                user_id=user_id,
            )

            return True, {
                "added": added,
                "imported": added,
                "skipped": skipped,
                "failed": failed,
                "total_rows": added + skipped + failed,
                "errors": messages,
                "messages": messages[:200],
            }
        except json.JSONDecodeError as e:
            error_detail = f"Invalid JSON format: {str(e)}"
            self._logger.error("JSON import parsing error: %s", e)
            return False, {"error": error_detail, "message": error_detail}
        except UnicodeDecodeError as e:
            error_detail = f"File encoding error. Please ensure the JSON file is UTF-8 encoded. Error: {str(e)}"
            self._logger.error("JSON import encoding error: %s", e)
            return False, {"error": error_detail, "message": error_detail}
        except Exception as e:
            import traceback
            error_detail = f"Import error: {str(e)}"
            self._logger.error("JSON import exception: %s\n%s", error_detail, traceback.format_exc())
            return False, {"error": error_detail, "message": error_detail}

    @staticmethod
    def _password_strength_score(pwd: str):
        import re

        score = 0
        reasons = []

        if len(pwd) >= 12:
            score += 1
        else:
            reasons.append("short")

        if re.search(r"[A-Z]", pwd):
            score += 1
        else:
            reasons.append("no uppercase")

        if re.search(r"[a-z]", pwd):
            score += 1
        else:
            reasons.append("no lowercase")

        if re.search(r"[0-9]", pwd):
            score += 1
        else:
            reasons.append("no number")

        if re.search(r"[^A-Za-z0-9]", pwd):
            score += 1
        else:
            reasons.append("no symbol")

        return min(score, 4), reasons

    def get_password_health(self, user_id, priv_key_data):
        """Return password health summary for dashboard."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, service_name, encrypted_password, encrypted_dek, nonce,
                   username_email, canonical_url, crypto_version, password_updated_at
            FROM vault_secrets
            WHERE owner_id = ?
            """,
            (int(user_id),),
        )
        rows = cursor.fetchall()
        conn.close()

        total = len(rows)
        if total == 0:
            return {
                "total": 0,
                "weak": 0,
                "reused": 0,
                "old": 0,
                "details": [],
            }

        priv_key = CryptoUtils.load_private_key(priv_key_data)

        plaintext_passwords = []
        details = []

        now = datetime.datetime.utcnow()

        for r in rows:
            try:
                version = str(r["crypto_version"] or "")
                pwd = None
                if version.startswith("v3"):
                    aad = self._build_entry_aad(r["service_name"], r["username_email"], r["canonical_url"] or "")
                    try:
                        pwd = CryptoUtils.hybrid_decrypt(
                            priv_key,
                            r["encrypted_dek"],
                            r["nonce"],
                            r["encrypted_password"],
                            associated_data=aad,
                        ).decode("utf-8")
                    except Exception:
                        pwd = None

                if pwd is None:
                    pwd = CryptoUtils.hybrid_decrypt(
                        priv_key,
                        r["encrypted_dek"],
                        r["nonce"],
                        r["encrypted_password"],
                        associated_data=None,
                    ).decode("utf-8")

                score, reasons = self._password_strength_score(pwd)
                age_days = 0
                created = r["password_updated_at"]
                if created:
                    created_dt = created if isinstance(created, datetime.datetime) else datetime.datetime.fromisoformat(str(created))
                    age_days = (now - created_dt).days

                details.append(
                    {
                        "id": r["id"],
                        "service": r["service_name"],
                        "score": score,
                        "reasons": reasons,
                        "age_days": max(0, age_days),
                        "password": pwd,
                    }
                )
                plaintext_passwords.append(pwd)
            except Exception:
                continue

        counts = Counter(plaintext_passwords)

        # Count as weak when objectively low score OR short length indicator.
        weak = sum(1 for d in details if d["score"] <= 2 or ("short" in d.get("reasons", [])))
        reused = sum(1 for d in details if counts.get(d["password"], 0) > 1)
        old = sum(1 for d in details if d["age_days"] >= 180)

        for d in details:
            d["reused"] = counts.get(d["password"], 0) > 1
            d.pop("password", None)

        return {
            "total": total,
            "weak": weak,
            "reused": reused,
            "reused_entries": reused,
            "old": old,
            "old_entries": old,
            "details": details,
        }

    def get_near_duplicates(self, user_id: int):
        """Find potential near-duplicate accounts by service+username+canonical_url."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT service_name, username_email, canonical_url, COUNT(*) as cnt
            FROM vault_secrets
            WHERE owner_id = ?
            GROUP BY service_name, username_email, canonical_url
            HAVING COUNT(*) > 1
            ORDER BY cnt DESC, service_name ASC
            """,
            (int(user_id),),
        )
        groups = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return groups

    def _log_backup_event(self, user_id: int, event_type: str, summary: dict):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO backup_events (user_id, event_type, summary) VALUES (?, ?, ?)",
            (int(user_id), event_type, json.dumps(summary, ensure_ascii=False)),
        )
        conn.commit()
        conn.close()

    @staticmethod
    def _backup_kdf_params():
        return {
            "algorithm": "argon2id",
            "length": 32,
            "iterations": 2,
            "lanes": 4,
            "memory_cost": 65536,
        }

    def export_encrypted_backup(self, user_id: int, priv_key_data: bytes, backup_passphrase: str):
        """Export user vault as encrypted backup JSON object."""
        if not backup_passphrase or len(backup_passphrase) < 12:
            return False, "Backup passphrase must be at least 12 characters", None

        metadata = self.get_secrets_metadata(user_id)
        entries = []
        for m in metadata:
            pwd, msg = self.decrypt_secret(user_id, m["id"], priv_key_data)
            if pwd is None:
                return False, f"Failed to export entry {m['id']}: {msg}", None
            entries.append(
                {
                    "service": m["service_name"] if "service_name" in m else m.get("service"),
                    "username": m["username_email"] if "username_email" in m else m.get("username"),
                    "url": m.get("url") or "",
                    "password": pwd,
                    "created_at": str(m.get("created_at", "")),
                }
            )

        payload = {
            "payload_format": "sv_backup_payload_v2",
            "exported_at": datetime.datetime.utcnow().isoformat(),
            "entries": entries,
        }
        payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

        kdf = self._backup_kdf_params()
        salt = os.urandom(16)
        root_key = CryptoUtils.derive_key_argon2id(
            backup_passphrase,
            salt,
            length=kdf["length"],
            iterations=kdf["iterations"],
            lanes=kdf["lanes"],
            memory_cost=kdf["memory_cost"],
        )
        enc_key = CryptoUtils.hkdf_expand(root_key, info=b"sv:backup:enc:v2", salt=salt)
        mac_key = CryptoUtils.hkdf_expand(root_key, info=b"sv:backup:mac:v2", salt=salt)

        aad = b"sv-backup-v2"
        nonce = os.urandom(12)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        ciphertext = AESGCM(enc_key).encrypt(nonce, payload_bytes, aad)

        header = {
            "format": "sv_backup_v2",
            "cipher": "AES-256-GCM",
            "aad": "sv-backup-v2",
            "created_at": datetime.datetime.utcnow().isoformat(),
            "nonce": CryptoUtils.b64e(nonce),
            "kdf": {
                **kdf,
                "salt": CryptoUtils.b64e(salt),
            },
        }

        header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
        mac_hex = CryptoUtils.hmac_sha256_hex(mac_key, header_bytes + ciphertext)

        bundle = {
            **header,
            "ciphertext": CryptoUtils.b64e(ciphertext),
            "mac": mac_hex,
        }

        self.audit.log_event(
            "VAULT_BACKUP_EXPORT",
            {"user_id": int(user_id), "entries": len(entries), "format": "sv_backup_v2"},
            user_id=int(user_id),
        )
        self._log_backup_event(int(user_id), "EXPORT", {"entries": len(entries), "format": "sv_backup_v2"})
        return True, "Backup exported", bundle

    def import_encrypted_backup(
        self,
        user_id: int,
        pub_key_pem,
        backup_obj: dict,
        backup_passphrase: str,
        max_rows: int = 50000,
    ):
        """Import encrypted backup JSON object into user's vault."""
        try:
            if str(backup_obj.get("format", "")) != "sv_backup_v2":
                return False, {"error": "Unsupported backup format"}

            kdf = backup_obj.get("kdf", {})
            salt_b64 = kdf.get("salt")
            if not salt_b64:
                return False, {"error": "Invalid backup metadata: missing KDF salt"}

            salt = CryptoUtils.b64d(salt_b64)
            nonce = CryptoUtils.b64d(backup_obj.get("nonce", ""))
            ciphertext = CryptoUtils.b64d(backup_obj.get("ciphertext", ""))
            mac_hex = backup_obj.get("mac", "")
            aad = (backup_obj.get("aad") or "sv-backup-v2").encode("utf-8")

            root_key = CryptoUtils.derive_key_argon2id(
                backup_passphrase,
                salt,
                length=int(kdf.get("length", 32)),
                iterations=int(kdf.get("iterations", 2)),
                lanes=int(kdf.get("lanes", 4)),
                memory_cost=int(kdf.get("memory_cost", 65536)),
            )
            enc_key = CryptoUtils.hkdf_expand(root_key, info=b"sv:backup:enc:v2", salt=salt)
            mac_key = CryptoUtils.hkdf_expand(root_key, info=b"sv:backup:mac:v2", salt=salt)

            header = {
                "format": backup_obj.get("format"),
                "cipher": backup_obj.get("cipher"),
                "aad": backup_obj.get("aad"),
                "created_at": backup_obj.get("created_at"),
                "nonce": backup_obj.get("nonce"),
                "kdf": backup_obj.get("kdf"),
            }
            header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if not CryptoUtils.hmac_compare(mac_hex, mac_key, header_bytes + ciphertext):
                return False, {"error": "Backup integrity check failed"}

            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            payload_bytes = AESGCM(enc_key).decrypt(nonce, ciphertext, aad)
            payload = json.loads(payload_bytes.decode("utf-8"))

            entries = payload.get("entries", [])
            if not isinstance(entries, list):
                return False, {"error": "Invalid backup payload"}

            return self._merge_backup_entries(user_id, entries, pub_key_pem, max_rows, "sv_backup_v2")
        except Exception as e:
            return False, {"error": f"Backup import failed: {e}"}

    def _merge_backup_entries(
        self,
        user_id: int,
        entries: list,
        pub_key_pem,
        max_rows: int = 50000,
        format_label: str = "backup",
    ):
        """Merge decrypted backup entries into vault. Returns (True, result_dict) or (False, error_dict)."""
        if not isinstance(entries, list):
            return False, {"error": "Invalid backup payload"}

        added = 0
        skipped = 0
        failed = 0
        messages = []

        for i, e in enumerate(entries, start=1):
            if i > max_rows:
                failed += 1
                messages.append(f"Stopped at limit {max_rows}")
                break

            service = (e.get("service") or "").strip()
            username = (e.get("username") or "").strip()
            url = (e.get("url") or "").strip()
            password = e.get("password") or ""

            if not service or not username or not password:
                skipped += 1
                messages.append(f"Row {i}: missing required values")
                continue

            ok, msg = self.add_secret(user_id, service, username, url, password, pub_key_pem)
            if ok:
                added += 1
            else:
                if "Duplicate blocked" in msg:
                    skipped += 1
                    messages.append(f"Row {i}: duplicate exact match")
                else:
                    failed += 1
                    messages.append(f"Row {i}: {msg}")

        self.audit.log_event(
            "VAULT_BACKUP_IMPORT",
            {
                "user_id": int(user_id),
                "added": added,
                "skipped": skipped,
                "failed": failed,
                "format": format_label,
            },
            user_id=int(user_id),
        )
        self._log_backup_event(
            int(user_id),
            "IMPORT",
            {"added": added, "skipped": skipped, "failed": failed, "format": format_label},
        )

        return True, {
            "added": added,
            "imported": added,
            "skipped": skipped,
            "failed": failed,
            "errors": messages,
            "messages": messages[:200],
        }

    def export_secrets_as_csv(self, user_id, priv_key_data):
        """Decrypt all secrets and return them as a CSV string."""
        secrets_meta = self.get_secrets_metadata(user_id)
        if not secrets_meta:
            return ""

        output = io.StringIO()
        # Use headers that are compatible with our own importer
        writer = csv.DictWriter(output, fieldnames=["service", "username", "password", "url", "totp_secret"])
        writer.writeheader()

        for meta in secrets_meta:
            res, msg = self.decrypt_secret(user_id, meta["id"], priv_key_data)
            if msg == "Success":
                password = res["password"] if isinstance(res, dict) else res
                totp = res.get("totp_secret") if isinstance(res, dict) else ""
                writer.writerow({
                    "service": meta.get("service_name", ""),
                    "username": meta.get("username_email", ""),
                    "password": password,
                    "url": meta.get("url", ""),
                    "totp_secret": totp
                })
        
        return output.getvalue()

    def export_secrets_as_json(self, user_id, priv_key_data):
        """Decrypt all secrets and return them as a JSON string."""
        secrets_meta = self.get_secrets_metadata(user_id)
        if not secrets_meta:
            return json.dumps([], indent=2)
        
        entries = []
        for meta in secrets_meta:
            res, msg = self.decrypt_secret(user_id, meta["id"], priv_key_data)
            if msg == "Success":
                password = res["password"] if isinstance(res, dict) else res
                totp = res.get("totp_secret") if isinstance(res, dict) else ""
                entries.append({
                    "service": meta.get("service_name", ""),
                    "username": meta.get("username_email", ""),
                    "password": password,
                    "url": meta.get("url", ""),
                    "totp_secret": totp,
                    "created_at": meta.get("created_at", "")
                })
        
        return json.dumps(entries, indent=2, ensure_ascii=False)