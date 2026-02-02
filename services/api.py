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

    def add_secret(self, user_id, service, username, url, password, pub_key_pem, totp_secret=None):
        ok, msg = self.secret_service.add_secret(user_id, service, username, url, password, pub_key_pem, totp_secret=totp_secret)
        if ok:
            self.backup_service.mark_backup_event(int(user_id), "secret_add")
        return ok, msg

    def get_secrets_metadata(self, user_id, search_query=None, sort_column="service_name", sort_direction="ASC"):
        return self.secret_service.get_secrets_metadata(user_id, search_query, sort_column, sort_direction)

    def decrypt_secret(self, user_id, entry_id, priv_key_data):
        return self.secret_service.decrypt_secret(user_id, entry_id, priv_key_data)

    def delete_secret(self, user_id, entry_id):
        ok, msg = self.secret_service.delete_secret(user_id, entry_id)
        if ok:
            self.backup_service.mark_backup_event(int(user_id), "secret_delete")
        return ok, msg

    def import_secrets_from_csv(self, user_id, csv_path, pub_key_pem, max_rows=10000):
        ok, result = self.secret_service.import_secrets_from_csv(user_id, csv_path, pub_key_pem, max_rows=max_rows)
        if ok and isinstance(result, dict):
            if "imported" not in result and "added" in result:
                result["imported"] = result.get("added", 0)
            if "errors" not in result:
                result["errors"] = result.get("messages", [])
            if result.get("imported", 0) or result.get("added", 0):
                self.backup_service.mark_backup_event(int(user_id), "secret_add")
        elif not ok and isinstance(result, dict):
            # Ensure error message is available in both 'error' and 'message' keys for UI compatibility
            error_msg = result.get("error") or result.get("message") or "Import failed"
            result["error"] = error_msg
            result["message"] = error_msg
        return ok, result

    def import_secrets_from_json(self, user_id, json_path, pub_key_pem, max_rows=10000):
        ok, result = self.secret_service.import_secrets_from_json(user_id, json_path, pub_key_pem, max_rows=max_rows)
        if ok and isinstance(result, dict):
            if "imported" not in result and "added" in result:
                result["imported"] = result.get("added", 0)
            if "errors" not in result:
                result["errors"] = result.get("messages", [])
            if result.get("imported", 0) or result.get("added", 0):
                self.backup_service.mark_backup_event(int(user_id), "secret_add")
        elif not ok and isinstance(result, dict):
            # Ensure error message is available in both 'error' and 'message' keys for UI compatibility
            error_msg = result.get("error") or result.get("message") or "Import failed"
            result["error"] = error_msg
            result["message"] = error_msg
        return ok, result

    def get_password_health(self, user_id, priv_key_data):
        health = self.secret_service.get_password_health(user_id, priv_key_data)
        if isinstance(health, dict):
            if "reused_entries" not in health:
                health["reused_entries"] = health.get("reused", 0)
            if "old_entries" not in health:
                health["old_entries"] = health.get("old", 0)
        return health

    def get_near_duplicates(self, user_id):
        return self.secret_service.get_near_duplicates(user_id)

    def export_secrets_as_csv(self, user_id, priv_key_data):
        return self.secret_service.export_secrets_as_csv(user_id, priv_key_data)
    
    def export_secrets_as_json(self, user_id, priv_key_data):
        return self.secret_service.export_secrets_as_json(user_id, priv_key_data)

    def export_vault_backup(self, user_id, priv_key_data, backup_passphrase):
        return self.secret_service.export_encrypted_backup(user_id, priv_key_data, backup_passphrase)

    def import_recovery_backup(self, user_id, backup_path_or_bytes, recovery_key_or_password, pub_key_pem):
        """
        Import from a recovery-format backup (Create Encrypted Backup).
        Decrypts with recovery key or backup password, then merges entries into the vault.
        Returns (ok, result_dict) where result_dict has added/skipped/failed/errors or error key.
        """
        ok, msg, payload, _mode = self.backup_service.decrypt_backup_package_auto(
            backup_path_or_bytes, recovery_key_or_password
        )
        if not ok or not payload:
            return False, {"error": msg or "Decryption failed"}
        entries = payload.get("entries", [])
        return self.secret_service._merge_backup_entries(
            user_id, entries, pub_key_pem, max_rows=50000, format_label="sv_backup_recovery_v1"
        )

    def import_vault_backup(self, user_id, pub_key_pem, backup_obj, backup_passphrase):
        ok, result = self.secret_service.import_encrypted_backup(user_id, pub_key_pem, backup_obj, backup_passphrase)
        # FIXED: Ensure result is always a dict for UI compatibility
        if not ok:
            if isinstance(result, dict):
                # Ensure both error and message keys exist
                error_msg = result.get("error") or result.get("message") or "Import failed"
                result["error"] = error_msg
                result["message"] = error_msg
            elif isinstance(result, (list, tuple, str)):
                # Convert non-dict results to dict
                error_msg = str(result[0]) if isinstance(result, (list, tuple)) and result else str(result)
                result = {"error": error_msg, "message": error_msg}
            else:
                result = {"error": "Import failed", "message": "Import failed"}
        elif isinstance(result, dict):
            # Ensure all expected keys exist for successful import
            if "imported" not in result and "added" in result:
                result["imported"] = result.get("added", 0)
        return ok, result

    # ── Security & Backup Center (Phase 1: independent recovery factor) ──

    def get_backup_recovery_status(self, user_id):
        return self.backup_service.get_backup_recovery_status(user_id)

    def resolve_recovery_factor(self, user_id, input_str):
        """Try recovery key then backup password; returns (success, mode_used, error_message)."""
        return self.backup_service.resolve_recovery_factor(user_id, input_str)

    def initialize_backup_recovery_for_user(self, user_id):
        return self.backup_service.initialize_backup_recovery_for_user(user_id)

    def generate_backup_recovery_key(self, user_id):
        return self.backup_service.generate_backup_recovery_key(user_id)

    def set_backup_password(self, user_id, password):
        return self.backup_service.set_backup_password(user_id, password)

    def export_user_backup_encrypted(self, user_id, priv_key_data, destination_path_or_bytes, recovery_key_or_password, mode="recovery_key"):
        return self.backup_service.export_user_backup_encrypted(
            user_id, priv_key_data, destination_path_or_bytes, recovery_key_or_password, mode
        )

    def decrypt_backup_package(self, backup_bytes_or_path, recovery_key_or_password, mode="recovery_key"):
        return self.backup_service.decrypt_backup_package(backup_bytes_or_path, recovery_key_or_password, mode)

    def decrypt_backup_package_auto(self, backup_bytes_or_path, recovery_key_or_password):
        """Decrypt by trying recovery key then backup password. Returns (ok, msg, payload, mode_used)."""
        return self.backup_service.decrypt_backup_package_auto(backup_bytes_or_path, recovery_key_or_password)

    def validate_backup_package_auto(self, backup_bytes_or_path, recovery_key_or_password, user_id=None):
        """Validate backup by trying recovery key then backup password. No mode needed."""
        return self.backup_service.validate_backup_package_auto(
            backup_bytes_or_path, recovery_key_or_password, user_id=user_id
        )

    def validate_backup_package(self, backup_bytes_or_path, recovery_key_or_password, mode="recovery_key", user_id=None):
        """Validate backup; if user_id given, stores result for health dashboard (Phase 5)."""
        return self.backup_service.validate_backup_package(
            backup_bytes_or_path, recovery_key_or_password, mode, user_id=user_id
        )

    def list_local_backups(self, user_id):
        return self.backup_service.list_local_backups(user_id)

    # ── Security & Backup Center (Phase 2: versioned auto backup) ──

    def get_backup_settings(self, user_id):
        return self.backup_service.get_backup_settings(user_id)

    def update_backup_settings(self, user_id, **kwargs):
        return self.backup_service.update_backup_settings(user_id, **kwargs)

    def set_auto_backup_key_for_session(self, user_id, recovery_key_or_password, mode):
        return self.backup_service.set_auto_backup_key_for_session(user_id, recovery_key_or_password, mode)

    def clear_auto_backup_key_for_user(self, user_id):
        return self.backup_service.clear_auto_backup_key_for_user(user_id)

    def create_local_backup_now(self, user_id, priv_key_data, reason="manual", recovery_key_or_password=None, mode=None):
        return self.backup_service.create_local_backup_now(
            user_id, priv_key_data, reason=reason,
            recovery_key_or_password=recovery_key_or_password, mode=mode,
        )

    def prune_local_backups(self, user_id):
        return self.backup_service.prune_local_backups(user_id)

    def should_run_scheduled_backup(self, user_id):
        return self.backup_service.should_run_scheduled_backup(user_id)

    def mark_backup_event(self, user_id, event_type):
        return self.backup_service.mark_backup_event(user_id, event_type)

    def process_pending_backup_jobs(self, user_id, priv_key_data=None):
        return self.backup_service.process_pending_backup_jobs(user_id, priv_key_data)

    def get_backup_status(self, user_id):
        return self.backup_service.get_backup_status(user_id)

    def get_backup_folder_path(self, user_id):
        """Phase 5: Local backup folder path for this user."""
        return self.backup_service.get_backup_folder_path(user_id)

    def list_audit_logs(
        self,
        limit=500,
        since_ts=None,
        until_ts=None,
        category=None,
        status=None,
        search=None,
        sort_by="created_at",
        sort_desc=True,
        user_id=None,
        include_system=False,
    ):
        """
        List audit log entries for the Activity Log viewer. When user_id is set, only
        that user's events are returned (and optionally system events when include_system=True).
        Returns list of normalized dicts: id, timestamp, category, action, status, message, etc.
        """
        raw = self.audit.list_events(
            limit=limit,
            since_ts=since_ts,
            until_ts=until_ts,
            sort_by="created_at",
            sort_desc=True,
            user_id=user_id,
            include_system=include_system,
        )
        rows = [normalize_row(r) for r in raw]
        if category and category != "All":
            rows = [r for r in rows if (r.get("category") or "") == category]
        if status and status != "All":
            rows = [r for r in rows if (r.get("status") or "") == status]
        if search and search.strip():
            q = search.strip().lower()
            def matches(r):
                for f in ("message", "category", "action", "status", "event_code", "source"):
                    if q in (str(r.get(f) or "")).lower():
                        return True
                if q in (r.get("details_text") or "").lower():
                    return True
                return False
            rows = [r for r in rows if matches(r)]
        if sort_by and sort_by != "created_at":
            key_map = {"category": "category", "status": "status", "action": "action", "time": "timestamp", "timestamp": "timestamp"}
            sort_key = key_map.get(sort_by, "timestamp")
            rows = sorted(rows, key=lambda r: (str(r.get(sort_key) or "")), reverse=sort_desc)
        elif sort_by == "created_at" and not sort_desc:
            rows = list(reversed(rows))
        return rows

    # ── Phase 4: Reset + local restore ──

    def reset_account_data_loss(self, username):
        """Phase 4: Reset local account state (data loss). Preserves backup files and audit log."""
        self.audit.log_event("account_reset_requested", {"username": username}, user_id=None)
        return self.user_service.reset_account_data_loss(username)

    def preview_backup_metadata(self, backup_bytes_or_path):
        """Phase 4: Safe metadata from backup envelope (no decryption, no secrets)."""
        return self.backup_service.preview_backup_metadata(backup_bytes_or_path)

    def restore_backup_from_local_file(self, username, file_path, recovery_key_or_password, mode=None):
        """
        Phase 4: Restore vault from local encrypted backup. Requires backup to belong to same account (user_id).
        If mode is None, tries recovery key then backup password automatically.
        Returns (success, message, enc_priv_pem_bytes or None). enc_priv_pem is for finalize_post_restore_rekey.
        """
        self.audit.log_event("backup_restore_started", {"username": username}, user_id=None)
        ok, msg, meta = self.backup_service.preview_backup_metadata(file_path)
        if not ok:
            self.audit.log_event("backup_restore_failed", {"reason": msg}, user_id=None)
            return False, msg, None
        backup_user_id = meta.get("user_id")
        user = self.user_service.get_user_by_username(username)
        if not user:
            self.audit.log_event("backup_restore_failed", {"reason": "User not found"}, user_id=None)
            return False, "User not found", None
        user_id = int(user["id"])
        if int(backup_user_id) != user_id:
            self.audit.log_event("backup_restore_failed", {"reason": "backup_user_mismatch"}, user_id=None)
            return False, "This backup was created by a different account. Restore only into the account that created it (same username).", None

        # Require reset first: do not restore over existing vault data
        conn = self.db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as n FROM vault_secrets WHERE owner_id = ?", (user_id,))
            n = cur.fetchone()["n"]
        finally:
            conn.close()
        if n and int(n) > 0:
            self.audit.log_event("backup_restore_failed", {"reason": "vault_not_empty"}, user_id=user_id)
            return False, "Account still has vault data. Reset the account first (Step 1 of Restore from Backup), then restore.", None

        if mode is None:
            ok, msg, payload, _ = self.backup_service.decrypt_backup_package_auto(file_path, recovery_key_or_password)
        else:
            ok, msg, payload = self.backup_service.decrypt_backup_package(file_path, recovery_key_or_password, mode)
        if not ok:
            self.audit.log_event("backup_restore_validation_failed", {"reason": msg}, user_id=user_id)
            self.audit.log_event("backup_restore_failed", {"reason": msg}, user_id=user_id)
            return False, msg, None
        self.audit.log_event("backup_restore_validation_success", {"entries": len(payload.get("entries", []))}, user_id=user_id)

        new_priv = CryptoUtils.generate_rsa_key_pair(2048)
        new_pub = new_priv.public_key()
        new_pub_pem = CryptoUtils.serialize_public_key(new_pub)

        cert_pem = self.pki.issue_user_certificate(username, new_pub, purpose="encryption")
        cert = x509.load_pem_x509_certificate(cert_pem)
        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO certificates (user_id, serial_number, subject, issuer, valid_from, valid_to, cert_data, key_usage)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    str(cert.serial_number),
                    str(cert.subject),
                    str(cert.issuer),
                    cert.not_valid_before_utc,
                    cert.not_valid_after_utc,
                    cert_pem.decode() if isinstance(cert_pem, bytes) else cert_pem,
                    "encryption",
                ),
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            self.audit.log_event("backup_restore_failed", {"reason": str(e)}, user_id=user_id)
            return False, str(e), None
        finally:
            conn.close()

        entries = payload.get("entries") or []
        restored = 0
        for ent in entries:
            service = ent.get("service") or ""
            un = ent.get("username") or ""
            url = ent.get("url") or ""
            pwd = ent.get("password") or ""
            ok_add, _ = self.secret_service.add_secret(user_id, service, un, url, pwd, new_pub_pem)
            if ok_add:
                restored += 1

        enc_priv_pem = CryptoUtils.serialize_private_key(new_priv)
        self.audit.log_event("backup_restore_completed", {"username": username, "restored": restored, "total": len(entries)}, user_id=user_id)
        return True, f"Restored {restored} of {len(entries)} entries.", enc_priv_pem

    def finalize_post_restore_rekey(self, username, new_login_passphrase, new_recovery_passphrase, enc_priv_pem):
        """Phase 4: Save key bundles and certs after restore; user can then login with new passphrase."""
        self.audit.log_event("post_restore_rekey_started", {"username": username}, user_id=None)
        ok, msg = self.user_service.finalize_post_restore_rekey(
            username, new_login_passphrase, new_recovery_passphrase, enc_priv_pem
        )
        if not ok:
            self.audit.log_event("post_restore_rekey_failed", {"reason": msg}, user_id=None)
        return ok, msg

    def clear_all_data(self):
        self.db.clear_all_data()

