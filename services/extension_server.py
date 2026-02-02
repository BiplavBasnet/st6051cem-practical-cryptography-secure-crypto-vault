import ast
import json
import os
import secrets
import threading
import platform
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from urllib.parse import parse_qs, urlparse

from services.app_paths import config_path, keys_dir
from services.session_security_service import (
    get_api_error_payload,
    get_lock_error_payload,
    get_reauth_error_payload,
    API_DENIAL_AUTH_REQUIRED,
    API_DENIAL_APP_LOCKED,
    API_DENIAL_REAUTH_REQUIRED,
    API_DENIAL_SESSION_EXPIRED,
)


# Phase 6.5: Central API security gate (order: auth -> expired -> step-up)
# Note: App locked state does NOT block extension; only session expired does.
def _check_sensitive_request(session, api, action_name: str):
    """
    Returns (allowed: bool, payload: dict | None, audit_event: str | None, user_id: int | None).
    If not allowed, payload is the structured error for 403 response; audit_event is for logging.
    """
    if not session or not isinstance(session, dict) or "user_id" not in session:
        return False, get_api_error_payload(
            API_DENIAL_AUTH_REQUIRED, "Sign in to the desktop app to use autofill."
        ), "api_request_denied_auth_required", None
    user_id = session.get("user_id")
    sec = getattr(api, "session_security", None)
    if sec and sec.is_locked():
        return False, get_api_error_payload(
            API_DENIAL_APP_LOCKED, "App is locked. Unlock the desktop app to use autofill."
        ), "api_request_denied_locked", user_id
    if sec and sec.is_hard_expired():
        return False, get_api_error_payload(
            API_DENIAL_SESSION_EXPIRED, "Session expired. Sign in again."
        ), "api_request_denied_session_expired", user_id
    if sec:
        ok, err = sec.require_step_up_for_action(action_name, allow_when_locked=True)
        if not ok and err:
            reason = err.get("reason", API_DENIAL_REAUTH_REQUIRED)
            msg = err.get("message", "Re-auth required for autofill.")
            return False, get_api_error_payload(reason, msg), "api_request_denied_reauth_required", user_id
    return True, None, None, user_id


def _extract_password_string(res):
    """Always return the password as a plain string. Handles dict, string, or stringified dict."""
    if res is None:
        return ""
    if isinstance(res, dict):
        p = res.get("password")
        return str(p) if p is not None else ""
    if isinstance(res, str):
        s = res.strip()
        if s.startswith("{") and ("password" in s or "totp_secret" in s):
            try:
                parsed = ast.literal_eval(s)
                return str(parsed.get("password", "")) if isinstance(parsed, dict) else s
            except (ValueError, SyntaxError):
                pass
        return s
    return str(res)


class ExtensionServer:
    """Local API server for browser extension autofill."""

    def __init__(self, api, session_provider, host="127.0.0.1", port=5005, token_path=None, on_request_denied_ui=None):
        self.api = api
        self.session_provider = session_provider
        self.host = host
        self.port = port
        self.token_path = (config_path("extension_token.txt") if token_path is None else Path(token_path))
        self.token_path.parent.mkdir(parents=True, exist_ok=True)
        self._token = self._load_or_create_token()
        self._httpd = None
        self._thread = None
        # Phase 6.5: optional callback (reason: str) for desktop UI notification when request denied
        self.on_request_denied_ui = on_request_denied_ui
        # Track token usage: {token: {"browser": str, "device": str, "last_used": str}}
        self._token_usage_path = config_path("extension_token_usage.json")
        self._token_usage = self._load_token_usage()
        self._usage_lock = threading.Lock()

    def _load_or_create_token(self):
        if self.token_path.exists():
            t = self.token_path.read_text(encoding="utf-8").strip()
            if t:
                return t
        token = secrets.token_urlsafe(24)
        self.token_path.write_text(token, encoding="utf-8")
        try:
            if os.name != "nt":
                os.chmod(self.token_path, 0o600)
        except Exception:
            pass
        return token

    @property
    def token(self):
        return self._token

    def _load_token_usage(self):
        """Load token usage tracking data."""
        if self._token_usage_path.exists():
            try:
                with open(self._token_usage_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def _save_token_usage(self):
        """Save token usage tracking data."""
        try:
            with open(self._token_usage_path, 'w', encoding='utf-8') as f:
                json.dump(self._token_usage, f, indent=2)
            if os.name != "nt":
                os.chmod(self._token_usage_path, 0o600)
        except Exception:
            pass
    
    def _detect_browser(self, user_agent):
        """Detect browser from User-Agent string."""
        ua = (user_agent or "").lower()
        if "chrome" in ua and "edg" not in ua:
            return "Chrome"
        elif "edg" in ua:
            return "Edge"
        elif "firefox" in ua:
            return "Firefox"
        elif "safari" in ua and "chrome" not in ua:
            return "Safari"
        elif "opera" in ua or "opr" in ua:
            return "Opera"
        else:
            return "Unknown Browser"
    
    def _get_device_info(self):
        """Get current device information."""
        return f"{platform.node()} ({platform.system()} {platform.release()})"
    
    def get_token_usage(self):
        """Get token usage information."""
        with self._usage_lock:
            return self._token_usage.get(self._token, {})

    def regenerate_token(self):
        """Regenerate token and clear usage tracking for old token."""
        old_token = self._token
        self._token = secrets.token_urlsafe(24)
        self.token_path.write_text(self._token, encoding="utf-8")
        try:
            if os.name != "nt":
                os.chmod(self.token_path, 0o600)
        except Exception:
            pass

        # Clear usage for old token
        with self._usage_lock:
            if old_token in self._token_usage:
                del self._token_usage[old_token]
            self._save_token_usage()
        
        return self._token

    def _make_handler(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def _get_request_origin(self):
                return (self.headers.get('Origin') or '').strip()

            def _is_allowed_origin(self, origin: str) -> bool:
                if not origin:
                    return True  # requests without Origin (e.g., curl) are OK on localhost
                o = origin.lower()
                return o.startswith('chrome-extension://') or o.startswith('moz-extension://') or o.startswith('ms-browser-extension://')

            def _token_from_headers(self) -> str:
                # Prefer Authorization: Bearer <token>, then X-Extension-Token
                auth = (self.headers.get('Authorization') or '').strip()
                if auth.lower().startswith('bearer '):
                    return auth.split(' ', 1)[1].strip()
                return (self.headers.get('X-Extension-Token') or '').strip()

            def _token_from_query(self) -> str:
                try:
                    parsed = urlparse(self.path)
                    q = parse_qs(parsed.query)
                    return (q.get('token', [''])[0] or '').strip()
                except Exception:
                    return ''

            def _token_from_body(self, body: dict) -> str:
                return str((body or {}).get('token') or '').strip()
            def _send(self, code, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                origin = self._get_request_origin()
                if self._is_allowed_origin(origin):
                    self.send_header("Access-Control-Allow-Origin", origin if origin else "null")
                    self.send_header("Vary", "Origin")
                else:
                    # Disallow unknown Origins
                    self.send_header("Access-Control-Allow-Origin", "null")
                    self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Extension-Token")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):
                self._send(200, {"ok": True})

            def do_GET(self):
                parsed = urlparse(self.path)

                if parsed.path == "/health":
                    return self._send(200, {"ok": True, "service": "extension-api"})

                if parsed.path == "/api/extension/get-matches":
                    # Return multiple matching entries for selection
                    q = parse_qs(parsed.query)
                    token = (self._token_from_headers() or self._token_from_query()).strip()
                    site_url = (q.get("url", [""])[0] or "").strip().lower()

                    if token != parent.token:
                        return self._send(401, {"ok": False, "message": "Invalid token"})
                    
                    # Track token usage
                    user_agent = self.headers.get("User-Agent", "")
                    browser = parent._detect_browser(user_agent)
                    device = parent._get_device_info()
                    with parent._usage_lock:
                        parent._token_usage[token] = {
                            "browser": browser,
                            "device": device,
                            "last_used": datetime.utcnow().isoformat()
                        }
                        parent._save_token_usage()

                    session = parent.session_provider()
                    allowed, payload, audit_event, uid = _check_sensitive_request(
                        session, parent.api, "retrieve_secret_for_extension"
                    )
                    if not allowed:
                        try:
                            alert_svc = getattr(parent.api, "security_alert_service", None)
                            if alert_svc:
                                alert_svc.notify_security_alert(
                                    audit_event,
                                    context={"path": "/api/extension/get-matches"},
                                    user_id=uid,
                                )
                            else:
                                parent.api.record_extension_api_denied(audit_event, "/api/extension/get-matches", uid)
                                if parent.on_request_denied_ui:
                                    parent.on_request_denied_ui(payload.get("reason", "ACTION_DENIED"))
                        except Exception:
                            pass
                        return self._send(403, payload)
                    try:
                        try:
                            parent.api.record_extension_api_allowed_sensitive("/api/extension/get-matches", uid)
                        except Exception:
                            pass
                        user_id = session["user_id"]
                        entries = parent.api.get_secrets_metadata(user_id)
                        if not entries:
                            return self._send(200, {"ok": True, "matches": []})

                        domain = urlparse(site_url).netloc.lower() if site_url else ""

                        def score(e):
                            s = 0
                            svc = (e.get("service_name") or "").lower()
                            url = (e.get("url") or "").lower()
                            if domain and domain in url:
                                s += 100
                            if domain and domain in svc:
                                s += 60
                            if site_url and site_url in url:
                                s += 30
                            return s

                        scored = [(score(e), e) for e in entries]
                        scored.sort(key=lambda x: x[0], reverse=True)
                        
                        # Return top 10 matches (only metadata, no passwords)
                        matches = []
                        for score_val, entry in scored[:10]:
                            if score_val > 0:  # Only include entries with some match
                                matches.append({
                                    "id": entry["id"],
                                    "service": entry.get("service_name", ""),
                                    "username": entry.get("username_email", ""),
                                    "url": entry.get("url", ""),
                                    "score": score_val
                                })
                        
                        return self._send(200, {"ok": True, "matches": matches})
                    except Exception:
                        return self._send(500, {"ok": False, "message": "Request failed."})


                if parsed.path != "/api/extension/get-best":
                    return self._send(404, {"ok": False, "message": "Not found"})

                q = parse_qs(parsed.query)
                token = (self._token_from_headers() or self._token_from_query()).strip()
                site_url = (q.get("url", [""])[0] or "").strip().lower()

                if token != parent.token:
                    return self._send(401, {"ok": False, "message": "Invalid token"})
                
                # Track token usage
                user_agent = self.headers.get("User-Agent", "")
                browser = parent._detect_browser(user_agent)
                device = parent._get_device_info()
                with parent._usage_lock:
                    parent._token_usage[token] = {
                        "browser": browser,
                        "device": device,
                        "last_used": datetime.utcnow().isoformat()
                    }
                    parent._save_token_usage()

                session = parent.session_provider()
                allowed, payload, audit_event, uid = _check_sensitive_request(
                    session, parent.api, "retrieve_secret_for_extension"
                )
                if not allowed:
                    try:
                        alert_svc = getattr(parent.api, "security_alert_service", None)
                        if alert_svc:
                            alert_svc.notify_security_alert(
                                audit_event,
                                context={"path": "/api/extension/get-best"},
                                user_id=uid,
                            )
                        else:
                            parent.api.record_extension_api_denied(audit_event, "/api/extension/get-best", uid)
                            if parent.on_request_denied_ui:
                                parent.on_request_denied_ui(payload.get("reason", "ACTION_DENIED"))
                    except Exception:
                        pass
                    return self._send(403, payload)
                if not isinstance(session, dict) or "user_id" not in session or "enc_priv" not in session:
                    return self._send(401, get_api_error_payload("ACTION_DENIED", "Desktop app session incomplete. Please log in again."))

                try:
                    try:
                        parent.api.record_extension_api_allowed_sensitive("/api/extension/get-best", uid)
                    except Exception:
                        pass
                    user_id = session["user_id"]
                    enc_priv = session["enc_priv"]
                    
                    if not user_id or not enc_priv:
                        return self._send(401, {"ok": False, "message": "Desktop app session incomplete. Please log in again."})
                    
                    entries = parent.api.get_secrets_metadata(user_id)
                    if not entries:
                        return self._send(200, {"ok": True, "entry": None})

                    domain = urlparse(site_url).netloc.lower() if site_url else ""

                    def score(e):
                        s = 0
                        svc = (e.get("service_name") or "").lower()
                        url = (e.get("url") or "").lower()
                        if domain and domain in url:
                            s += 100
                        if domain and domain in svc:
                            s += 60
                        if site_url and site_url in url:
                            s += 30
                        return s

                    entries = sorted(entries, key=score, reverse=True)
                    if not entries:
                        return self._send(200, {"ok": True, "entry": None})
                    
                    best = entries[0]
                    res, msg = parent.api.decrypt_secret(user_id, best["id"], enc_priv)
                    if msg != "Success":
                        return self._send(500, {"ok": False, "message": msg})

                    pw = _extract_password_string(res)
                    totp = res.get("totp_secret") if isinstance(res, dict) else None

                    result = {
                        "service": best.get("service_name", ""),
                        "username": best.get("username_email", ""),
                        "password": pw,
                        "url": best.get("url", ""),
                    }
                    return self._send(200, {"ok": True, "entry": result})
                except Exception:
                    return self._send(500, {"ok": False, "message": "Request failed."})

            def do_POST(self):
                """Handle POST requests for phrase verification and save/update secrets."""
                parsed = urlparse(self.path)
                MAX_BODY_SIZE = 1 * 1024 * 1024  # 1MB
                try:
                    content_length = int(self.headers.get('Content-Length', 0) or 0)
                except (ValueError, TypeError):
                    return self._send(400, {"ok": False, "message": "Invalid Content-Length"})
                if content_length <= 0:
                    return self._send(400, {"ok": False, "message": "No data"})
                if content_length > MAX_BODY_SIZE:
                    return self._send(413, {"ok": False, "message": "Request body too large"})
                try:
                    post_data = json.loads(self.rfile.read(content_length).decode('utf-8'))
                except Exception:
                    return self._send(400, {"ok": False, "message": "Invalid JSON"})
                
                token = (self._token_from_headers() or self._token_from_body(post_data)).strip()
                
                if token != parent.token:
                    return self._send(401, {"ok": False, "message": "Invalid token"})

                session = parent.session_provider()
                allowed, payload, audit_event, uid = _check_sensitive_request(
                    session, parent.api, "retrieve_secret_for_extension"
                )
                if not allowed:
                    try:
                        alert_svc = getattr(parent.api, "security_alert_service", None)
                        if alert_svc:
                            alert_svc.notify_security_alert(
                                audit_event,
                                context={"path": parsed.path},
                                user_id=uid,
                            )
                        else:
                            parent.api.record_extension_api_denied(audit_event, parsed.path, uid)
                            if parent.on_request_denied_ui:
                                parent.on_request_denied_ui(payload.get("reason", "ACTION_DENIED"))
                    except Exception:
                        pass
                    return self._send(403, payload)
                try:
                    try:
                        parent.api.record_extension_api_allowed_sensitive(parsed.path, uid)
                    except Exception:
                        pass
                    user_id = session["user_id"]
                    username = session.get("username", "")
                    enc_priv = session.get("enc_priv")
                    
                    if not enc_priv:
                        return self._send(401, {"ok": False, "message": "Session incomplete"})

                    # Verify phrase using auth key bundle
                    from services.local_key_manager import LocalKeyManager
                    from pathlib import Path

                    auth_path = keys_dir() / username / "auth_key.pem"
                    if not auth_path.exists():
                        return self._send(401, {"ok": False, "message": "Auth key not found"})
                    try:
                        bundle_data = json.loads(auth_path.read_text(encoding="utf-8"))
                    except (json.JSONDecodeError, OSError) as e:
                        return self._send(500, {"ok": False, "message": "Auth key file invalid"})
                    phrase = str(post_data.get("phrase") or "").strip()
                    unlocked = LocalKeyManager.unlock_key_from_bundle(bundle_data, phrase)
                    if not unlocked:
                        parent.api.record_unlock_failure(username)
                        must_wait, wait_seconds = parent.api.check_unlock_backoff(username)
                        if must_wait:
                            return self._send(429, {"ok": False, "message": "Too many failed attempts", "wait_seconds": wait_seconds})
                        return self._send(401, {"ok": False, "message": "Invalid master phrase"})
                    parent.api.reset_unlock_backoff(username)

                    # Handle save/update secret
                    if parsed.path == "/api/extension/save-secret":
                        service = str(post_data.get("service") or "").strip()
                        username_email = str(post_data.get("username") or "").strip()
                        url = str(post_data.get("url") or "").strip()
                        password = str(post_data.get("password") or "").strip()
                        entry_id = post_data.get("entry_id")  # Optional, for updates
                        
                        if not service or not username_email or not password:
                            return self._send(400, {"ok": False, "message": "Missing required fields"})
                        
                        # Get encryption public key
                        cert_pem = parent.api.get_active_certificate(user_id, "encryption")
                        if not cert_pem:
                            return self._send(500, {"ok": False, "message": "No encryption certificate found"})
                        
                        if entry_id is not None:
                            # Update existing entry - delete old and create new
                            try:
                                eid = int(entry_id)
                                parent.api.delete_secret(user_id, eid)
                            except (ValueError, TypeError):
                                return self._send(400, {"ok": False, "message": "Invalid entry_id"})
                            except Exception:
                                pass  # Continue even if delete fails
                        
                        # Add new/updated secret
                        success, msg = parent.api.add_secret(
                            user_id, service, username_email, url, password, cert_pem
                        )
                        
                        if success:
                            return self._send(200, {"ok": True, "message": "Secret saved successfully"})
                        else:
                            return self._send(500, {"ok": False, "message": msg or "Failed to save secret"})
                    
                    # Handle verify-phrase (existing endpoint)
                    elif parsed.path == "/api/extension/verify-phrase":
                        entry_id_val = post_data.get("entry_id")
                        if entry_id_val is None:
                            return self._send(400, {"ok": False, "message": "Missing entry_id"})
                        try:
                            entry_id = int(entry_id_val)
                        except (ValueError, TypeError):
                            return self._send(400, {"ok": False, "message": "Invalid entry_id"})
                        
                        res, msg = parent.api.decrypt_secret(user_id, entry_id, enc_priv)
                        if msg != "Success":
                            return self._send(500, {"ok": False, "message": msg})

                        pw = _extract_password_string(res)
                        
                        entries = parent.api.get_secrets_metadata(user_id)
                        entry_meta = next((e for e in entries if e["id"] == entry_id), None)
                        
                        result = {
                            "service": entry_meta.get("service_name", "") if entry_meta else "",
                            "username": entry_meta.get("username_email", "") if entry_meta else "",
                            "password": pw,
                            "url": entry_meta.get("url", "") if entry_meta else "",
                        }
                        return self._send(200, {"ok": True, "entry": result})
                    else:
                        return self._send(404, {"ok": False, "message": "Not found"})
                        
                except Exception:
                    return self._send(500, {"ok": False, "message": "Request failed."})

            def log_message(self, fmt, *args):
                return

        return Handler

    def start(self):
        if self._httpd is not None:
            return True, "Already running"

        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port), self._make_handler())
            self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._thread.start()
            return True, f"Extension API running on http://{self.host}:{self.port}"
        except Exception as e:
            self._httpd = None
            self._thread = None
            return False, str(e)

    def stop(self):
        """Stop the extension server with proper error handling."""
        if self._httpd is None:
            return True, "Not running"
        
        thread = self._thread
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
            if thread and thread.is_alive():
                thread.join(timeout=2.0)
        except Exception as e:
            # If shutdown fails, try to close anyway
            try:
                if self._httpd:
                    self._httpd.server_close()
            except Exception:
                pass
            return False, f"Error stopping server: {e}"
        finally:
            # Always clean up references
            self._httpd = None
            self._thread = None
        
        return True, "Stopped"