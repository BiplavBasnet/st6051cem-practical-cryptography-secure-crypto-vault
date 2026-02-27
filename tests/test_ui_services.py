"""Tests for UI service integrations including CSV import and password health."""

import tempfile
import shutil
import os
from pathlib import Path

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


def test_csv_import_and_password_health():
    base = tempfile.mkdtemp(prefix="ui_service_test_")
    old_base = os.environ.pop("SECURECRYPT_BASE_DIR", None)
    os.environ["SECURECRYPT_BASE_DIR"] = base
    try:
        api = VaultAPI()
        kb = _make_key_bundle()
        ok, msg = api.register_user("alice", "alice@example.com", kb)
        assert ok, msg

        user = api.user_service.get_user_by_username("alice")
        cert = api.get_active_certificate(user["id"], "encryption")

        csv_path = Path(base) / "sample.csv"
        csv_path.write_text(
            "\n".join([
                "name,url,username,password,note",
                "Gmail,https://mail.google.com,alice@gmail.com,Weakpass1,mail",
                "Bank,https://bank.example.com,alice,Strong!Pass#123,bank",
                "Dev,https://github.com,alice,Strong!Pass#123,dup",
                ""
            ]),
            encoding="utf-8",
        )

        ok, result = api.import_secrets_from_csv(user["id"], str(csv_path), cert)
        assert ok
        assert result["imported"] == 3

        enc_priv = _unlock(kb, "encryption", "LoginPass_12345!")
        health = api.get_password_health(user["id"], enc_priv)
        assert health["total"] == 3
        assert health["weak"] >= 1
        assert health["reused_entries"] >= 2
    finally:
        os.environ.pop("SECURECRYPT_BASE_DIR", None)
        if old_base:
            os.environ["SECURECRYPT_BASE_DIR"] = old_base
        shutil.rmtree(base, ignore_errors=True)


def test_csv_import_url_username_password_only():
    """CSV with headers url,username,password (no service/name) must import successfully via url fallback."""
    base = tempfile.mkdtemp(prefix="ui_csv_url_")
    old_base = os.environ.pop("SECURECRYPT_BASE_DIR", None)
    os.environ["SECURECRYPT_BASE_DIR"] = base
    try:
        api = VaultAPI()
        kb = _make_key_bundle()
        ok, msg = api.register_user("bob", "bob@example.com", kb)
        assert ok, msg

        user = api.user_service.get_user_by_username("bob")
        cert = api.get_active_certificate(user["id"], "encryption")

        csv_path = Path(base) / "url_only.csv"
        csv_path.write_text(
            "url,username,password\n"
            "https://site.example.com,user1,Pass123!\n"
            "https://other.com,user2,Secret456!\n",
            encoding="utf-8",
        )

        ok, result = api.import_secrets_from_csv(user["id"], str(csv_path), cert)
        assert ok, result.get("error", result)
        assert result.get("imported", 0) == 2
    finally:
        os.environ.pop("SECURECRYPT_BASE_DIR", None)
        if old_base:
            os.environ["SECURECRYPT_BASE_DIR"] = old_base
        shutil.rmtree(base, ignore_errors=True)
