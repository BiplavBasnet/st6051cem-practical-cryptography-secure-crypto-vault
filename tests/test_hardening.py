"""Tests for new Phase 1-2 features: TOTP, sessions, security hardening, sharing."""

import os
import sys
import time
import shutil
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.totp_service import TOTPService
from services.security_service import SecurityService
from services.api import VaultAPI
from services.crypto_utils import CryptoUtils
from services.local_key_manager import LocalKeyManager


# ── Helpers ───────────────────────────────────────────────────────────

def _make_key_bundle(login_pass="LoginPass_12345!", recovery_pass="RecoveryPass_12345!"):
    bundle = {}
    for purpose in ["auth", "signing", "encryption"]:
        priv = CryptoUtils.generate_rsa_key_pair(2048)
        priv_pem = CryptoUtils.serialize_private_key(priv)
        bundle[purpose] = {
            "encrypted_priv": LocalKeyManager.protect_key_bundle(priv_pem, login_pass, recovery_pass),
            "pub_pem": CryptoUtils.serialize_public_key(priv.public_key()).decode(),
        }
    return bundle


@pytest.fixture()
def env():
    base = tempfile.mkdtemp(prefix="hardening_test_")
    old_base = os.environ.pop("SECURECRYPT_BASE_DIR", None)
    os.environ["SECURECRYPT_BASE_DIR"] = base
    try:
        api = VaultAPI()
        yield {"api": api, "base": base}
    finally:
        os.environ.pop("SECURECRYPT_BASE_DIR", None)
        if old_base:
            os.environ["SECURECRYPT_BASE_DIR"] = old_base
        shutil.rmtree(base, ignore_errors=True)


# ── TOTP Tests ────────────────────────────────────────────────────────

class TestTOTP:
    def test_generate_and_verify(self):
        secret = TOTPService.generate_secret()
        assert len(secret) >= 16
        code = TOTPService.generate_totp(secret)
        assert len(code) == 6
        assert TOTPService.verify_totp(secret, code)

    def test_wrong_code_fails(self):
        secret = TOTPService.generate_secret()
        assert not TOTPService.verify_totp(secret, "000000")

    def test_time_remaining(self):
        remaining = TOTPService.time_remaining()
        assert 0 < remaining <= 30

    def test_otpauth_uri(self):
        secret = TOTPService.generate_secret()
        uri = TOTPService.build_otpauth_uri(secret, "user@example.com")
        assert uri.startswith("otpauth://totp/")
        assert secret in uri

    def test_window_tolerance(self):
        secret = TOTPService.generate_secret()
        # Code from 30 seconds ago should still validate (window=1)
        past_code = TOTPService.generate_totp(secret, time.time() - 30)
        assert TOTPService.verify_totp(secret, past_code)


# ── Progressive Backoff Tests ─────────────────────────────────────────

class TestProgressiveBackoff:
    def test_no_backoff_initially(self, env):
        api = env["api"]
        must_wait, secs = api.check_unlock_backoff("testuser")
        assert must_wait is False
        assert secs == 0

    def test_backoff_after_failures(self, env):
        api = env["api"]
        api.register_user("backoff_user", "bu@test.com", _make_key_bundle())
        api.record_unlock_failure("backoff_user")
        api.record_unlock_failure("backoff_user")
        must_wait, secs = api.check_unlock_backoff("backoff_user")
        assert must_wait is True
        assert secs > 0

    def test_backoff_reset_on_success(self, env):
        api = env["api"]
        api.record_unlock_failure("reset_user")
        api.record_unlock_failure("reset_user")
        api.reset_unlock_backoff("reset_user")
        must_wait, _ = api.check_unlock_backoff("reset_user")
        assert must_wait is False


# ── Insecure Credential Flags Tests ──────────────────────────────────

class TestInsecureFlags:
    def test_short_password(self):
        flags = SecurityService.check_insecure_flags("abc", "user", "svc")
        assert any("short" in f.lower() for f in flags)

    def test_password_equals_username(self):
        flags = SecurityService.check_insecure_flags("myuser", "myuser", "")
        assert any("username" in f.lower() for f in flags)

    def test_password_equals_service(self):
        flags = SecurityService.check_insecure_flags("gmail", "", "gmail")
        assert any("service" in f.lower() for f in flags)

    def test_strong_password_no_flags(self):
        flags = SecurityService.check_insecure_flags("V3ry$tr0ng!Pass#2024", "alice", "bank")
        assert len(flags) == 0


# ── Lookalike Domain Tests ───────────────────────────────────────────

class TestLookalikeDomain:
    def test_detects_typosquat(self):
        existing = ["google.com", "github.com", "bank.example.com"]
        warnings = SecurityService.check_lookalike_domain("gooogle.com", existing)
        assert len(warnings) >= 1

    def test_exact_match_not_flagged(self):
        existing = ["google.com"]
        warnings = SecurityService.check_lookalike_domain("google.com", existing)
        assert len(warnings) == 0

    def test_unrelated_domain_not_flagged(self):
        existing = ["google.com"]
        warnings = SecurityService.check_lookalike_domain("microsoft.com", existing)
        assert len(warnings) == 0


# ── Session Management Tests ─────────────────────────────────────────

class TestSessionManagement:
    def test_create_and_list_sessions(self, env):
        api = env["api"]
        kb = _make_key_bundle()
        api.register_user("sess_user", "sess@test.com", kb)
        user = api.user_service.get_user_by_username("sess_user")

        session = api.create_session(user["id"])
        assert "id" in session
        assert session["user_id"] == user["id"]

        sessions = api.get_active_sessions(user["id"])
        assert len(sessions) >= 1

    def test_revoke_session(self, env):
        api = env["api"]
        kb = _make_key_bundle()
        api.register_user("rev_user", "rev@test.com", kb)
        user = api.user_service.get_user_by_username("rev_user")

        session = api.create_session(user["id"])
        revoked = api.revoke_session(session["id"], user["id"])
        assert revoked is True

        sessions = api.get_active_sessions(user["id"])
        assert len(sessions) == 0


# ── Strength Scoring Tests ───────────────────────────────────────────

class TestStrengthScoring:
    def test_strong_password(self, env):
        score, reasons = env["api"].calculate_strength("MyStr0ng!P@ssw0rd2024")
        assert score >= 3
        assert len(reasons) == 0 or all(isinstance(r, str) for r in reasons)

    def test_weak_password(self, env):
        score, reasons = env["api"].calculate_strength("abc")
        assert score <= 1
        assert len(reasons) > 0

    def test_sequential_pattern_penalty(self, env):
        score1, _ = env["api"].calculate_strength("Abcdefgh123!")
        score2, _ = env["api"].calculate_strength("Xk9$mP2wQ!rL")
        # The one with sequential pattern should score lower or equal
        assert score1 <= score2


# ── Vault TOTP & Decryption Tests ────────────────────────────────────

class TestVaultDecryption:
    def test_add_and_decrypt_with_totp(self, env):
        api = env["api"]
        kb = _make_key_bundle()
        api.register_user("vault_user", "vu@test.com", kb)
        user = api.user_service.get_user_by_username("vault_user")
        
        cert = api.get_active_certificate(user["id"], "encryption")
        enc_priv = LocalKeyManager.unlock_key_from_bundle(kb["encryption"]["encrypted_priv"], "LoginPass_12345!")

        ok, msg = api.add_secret(
            user["id"],
            service="TestService",
            username="testuser",
            url="https://test.com",
            password="TestPassword123!",
            pub_key_pem=cert,
            totp_secret="JBSWY3DPEHPK3PXP" # Base32 secret
        )
        assert ok is True

        metadata = api.get_secrets_metadata(user["id"])
        entry_id = metadata[0]["id"]

        # Decrypt
        res, msg_dec = api.decrypt_secret(user["id"], entry_id, enc_priv)
        assert res["password"] == "TestPassword123!"
        assert res["totp_secret"] == "JBSWY3DPEHPK3PXP"

        # Verify TOTP generation
        code = api.generate_totp_code(res["totp_secret"])
        assert len(code) == 6
        assert code.isdigit()

