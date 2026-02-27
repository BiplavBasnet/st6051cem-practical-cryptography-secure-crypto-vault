"""Fuzz / negative tests for malformed imports and backups."""

import os
import sys
import json
import shutil
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.api import VaultAPI
from services.crypto_utils import CryptoUtils
from services.local_key_manager import LocalKeyManager


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


def _unlock(bundle, purpose, passphrase):
    return LocalKeyManager.unlock_key_from_bundle(bundle[purpose]["encrypted_priv"], passphrase)


@pytest.fixture()
def env():
    base = tempfile.mkdtemp(prefix="fuzz_test_")
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


class TestMalformedCSVImport:
    def test_empty_csv(self, env):
        api = env["api"]
        base = Path(env["base"])
        kb = _make_key_bundle()
        api.register_user("fuzz_user", "fuzz@test.com", kb)
        user = api.user_service.get_user_by_username("fuzz_user")
        cert = api.get_active_certificate(user["id"], "encryption")

        csv_path = base / "empty.csv"
        csv_path.write_text("", encoding="utf-8")
        ok, result = api.import_secrets_from_csv(user["id"], str(csv_path), cert)
        assert isinstance(ok, bool)

    def test_csv_no_header(self, env):
        api = env["api"]
        base = Path(env["base"])
        kb = _make_key_bundle()
        api.register_user("nohead_user", "nohead@test.com", kb)
        user = api.user_service.get_user_by_username("nohead_user")
        cert = api.get_active_certificate(user["id"], "encryption")

        csv_path = base / "noheader.csv"
        csv_path.write_text("gmail,http://gmail.com,alice,pass123\n", encoding="utf-8")
        ok, result = api.import_secrets_from_csv(user["id"], str(csv_path), cert)
        assert isinstance(ok, bool)

    def test_csv_binary_garbage(self, env):
        api = env["api"]
        base = Path(env["base"])
        kb = _make_key_bundle()
        api.register_user("garbage_user", "garbage@test.com", kb)
        user = api.user_service.get_user_by_username("garbage_user")
        cert = api.get_active_certificate(user["id"], "encryption")

        csv_path = base / "garbage.csv"
        csv_path.write_bytes(os.urandom(256))
        ok, result = api.import_secrets_from_csv(user["id"], str(csv_path), cert)
        assert ok is False or (ok is True and isinstance(result, dict))

    def test_csv_huge_field(self, env):
        api = env["api"]
        base = Path(env["base"])
        kb = _make_key_bundle()
        api.register_user("huge_user", "huge@test.com", kb)
        user = api.user_service.get_user_by_username("huge_user")
        cert = api.get_active_certificate(user["id"], "encryption")

        csv_path = base / "huge.csv"
        csv_path.write_text(
            "name,url,username,password\n" + "A" * 10000 + ",http://x.com,user,pass\n",
            encoding="utf-8",
        )
        ok, result = api.import_secrets_from_csv(user["id"], str(csv_path), cert)
        assert isinstance(ok, bool)


class TestMalformedBackup:
    def test_import_empty_backup(self, env):
        api = env["api"]
        kb = _make_key_bundle()
        api.register_user("bak_user", "bak@test.com", kb)
        user = api.user_service.get_user_by_username("bak_user")
        cert = api.get_active_certificate(user["id"], "encryption")

        result = api.import_vault_backup(user["id"], cert, {}, "SomePassphrase12!")
        assert isinstance(result, tuple)

    def test_import_corrupted_backup(self, env):
        api = env["api"]
        kb = _make_key_bundle()
        api.register_user("corrupt_user", "corrupt@test.com", kb)
        user = api.user_service.get_user_by_username("corrupt_user")
        cert = api.get_active_certificate(user["id"], "encryption")

        corrupted = {"version": "2.0", "data": "not-real-encrypted-data", "salt": "abcd"}
        result = api.import_vault_backup(user["id"], cert, corrupted, "SomePassphrase12!")
        assert isinstance(result, tuple)
        if isinstance(result[0], bool):
            assert result[0] is False

    def test_import_wrong_passphrase(self, env):
        api = env["api"]
        kb = _make_key_bundle()
        api.register_user("wrongpw_user", "wrongpw@test.com", kb)
        user = api.user_service.get_user_by_username("wrongpw_user")
        cert = api.get_active_certificate(user["id"], "encryption")
        enc_priv = _unlock(kb, "encryption", "LoginPass_12345!")

        api.add_secret(user["id"], "test_svc", "user@test.com", "http://test.com", "TestPass123!", cert)
        export_result = api.export_vault_backup(user["id"], enc_priv, "CorrectPass123!")
        if isinstance(export_result, tuple):
            ok_export = export_result[0]
            backup = export_result[1] if len(export_result) > 1 else None
        else:
            ok_export = bool(export_result)
            backup = export_result

        if ok_export and backup and isinstance(backup, dict):
            import_result = api.import_vault_backup(user["id"], cert, backup, "WrongPassphrase!")
            assert isinstance(import_result, tuple)
            ok_import = import_result[0]
            detail = import_result[1] if len(import_result) > 1 else {}
            assert ok_import is False or (isinstance(detail, dict) and "error" in detail)
