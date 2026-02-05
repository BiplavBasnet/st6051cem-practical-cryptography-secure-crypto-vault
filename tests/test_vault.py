import os
import sys
import json
import shutil
import tempfile
import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

# Ensure project root importable even when pytest starts from different cwd
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.api import VaultAPI
from services.crypto_utils import CryptoUtils
from services.local_key_manager import LocalKeyManager


def _make_key_bundle(login_pass: str = "LoginPass_12345!", recovery_pass: str = "RecoveryPass_12345!"):
    bundle = {}
    for purpose in ["auth", "signing", "encryption"]:
        priv = CryptoUtils.generate_rsa_key_pair(2048)
        priv_pem = CryptoUtils.serialize_private_key(priv)
        pub_pem = CryptoUtils.serialize_public_key(priv.public_key()).decode()
        bundle[purpose] = {
            "encrypted_priv": LocalKeyManager.protect_key_bundle(priv_pem, login_pass, recovery_pass),
            "pub_pem": pub_pem,
        }
    return bundle


def _unlock(bundle, purpose, login_pass):
    return LocalKeyManager.unlock_key_from_bundle(bundle[purpose]["encrypted_priv"], login_pass)



@pytest.fixture()
def env():
    base = tempfile.mkdtemp(prefix="vault_test_")
    old_base = os.environ.pop("SECURECRYPT_BASE_DIR", None)
    old_data = os.environ.pop("SECURECRYPT_DATA_DIR", None)
    old_config = os.environ.pop("SECURECRYPT_CONFIG_DIR", None)
    old_logs = os.environ.pop("SECURECRYPT_LOG_DIR", None)
    old_backup = os.environ.pop("SECURECRYPT_BACKUP_DIR", None)
    os.environ["SECURECRYPT_BASE_DIR"] = base
    try:
        api = VaultAPI()
        yield {"api": api, "base": base}
    finally:
        for k in list(os.environ.keys()):
            if k.startswith("SECURECRYPT_"):
                os.environ.pop(k, None)
        if old_base:
            os.environ["SECURECRYPT_BASE_DIR"] = old_base
        if old_data:
            os.environ["SECURECRYPT_DATA_DIR"] = old_data
        if old_config:
            os.environ["SECURECRYPT_CONFIG_DIR"] = old_config
        if old_logs:
            os.environ["SECURECRYPT_LOG_DIR"] = old_logs
        if old_backup:
            os.environ["SECURECRYPT_BACKUP_DIR"] = old_backup
        shutil.rmtree(base, ignore_errors=True)


def test_registration_issues_purpose_bound_certificates(env):
    api = env["api"]
    kb = _make_key_bundle("alice_login_pass_1234", "alice_recovery_pass_12345")

    ok, _ = api.register_user("alice", "alice@example.com", kb)
    assert ok

    user = api.user_service.get_user_by_username("alice")
    auth_cert_pem = api.user_service.get_user_certificate(user["id"], "auth")
    sign_cert_pem = api.user_service.get_user_certificate(user["id"], "signing")
    enc_cert_pem = api.user_service.get_user_certificate(user["id"], "encryption")

    auth_cert = x509.load_pem_x509_certificate(auth_cert_pem.encode())
    sign_cert = x509.load_pem_x509_certificate(sign_cert_pem.encode())
    enc_cert = x509.load_pem_x509_certificate(enc_cert_pem.encode())

    auth_ku = auth_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    sign_ku = sign_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    enc_ku = enc_cert.extensions.get_extension_for_class(x509.KeyUsage).value

    assert auth_ku.digital_signature is True
    assert sign_ku.content_commitment is True
    assert enc_ku.key_encipherment is True


def test_login_challenge_response_and_cert_spoofing_block(env):
    api = env["api"]
    kb = _make_key_bundle("alice_login_pass_1234", "alice_recovery_pass_12345")
    api.register_user("alice", "alice@example.com", kb)

    # Valid login with correct key
    auth_priv = _unlock(kb, "auth", "alice_login_pass_1234")
    ok, _, _, _ = api.login_user("alice", priv_key_data=auth_priv)
    assert ok is True

    # Spoofed client key should fail challenge verification
    attacker_priv = CryptoUtils.serialize_private_key(CryptoUtils.generate_rsa_key_pair(2048))
    ok2, _, _, msg2 = api.login_user("alice", priv_key_data=attacker_priv)
    assert ok2 is False
    assert "Invalid signature" in msg2 or "failed" in msg2.lower()

    # Replay (MITM) simulation: same signed challenge cannot be reused
    user = api.user_service.get_user_by_username("alice")
    nonce_replay = api.auth.generate_challenge(user["id"])
    sig_replay = CryptoUtils.sign_data(CryptoUtils.load_private_key(auth_priv), nonce_replay)
    cert_pem = api.get_active_certificate(user["id"], "auth")

    first_ok, _ = api.auth.verify_challenge(user["id"], nonce_replay, sig_replay, cert_pem)
    replay_ok, replay_msg = api.auth.verify_challenge(user["id"], nonce_replay, sig_replay, cert_pem)

    assert first_ok is True
    assert replay_ok is False
    assert "expired challenge" in replay_msg.lower() or "invalid" in replay_msg.lower()

    # Explicit certificate spoofing simulation: forged cert (not signed by CA)
    nonce = api.auth.generate_challenge(user["id"])

    fake_priv = CryptoUtils.generate_rsa_key_pair(2048)
    fake_pub = fake_priv.public_key()
    forged_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mallory Inc"),
        x509.NameAttribute(NameOID.COMMON_NAME, "alice"),
    ])
    forged_cert = (
        x509.CertificateBuilder()
        .subject_name(forged_subject)
        .issuer_name(forged_subject)
        .public_key(fake_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
        .sign(fake_priv, hashes.SHA256())
    )

    forged_sig = CryptoUtils.sign_data(fake_priv, nonce)
    valid, msg = api.auth.verify_challenge(
        user["id"],
        nonce,
        forged_sig,
        forged_cert.public_bytes(serialization.Encoding.PEM),
    )
    assert valid is False
    assert "CA signature" in msg or "validation" in msg.lower()


def test_document_sign_verify_multisig_and_integrity(env):
    api = env["api"]

    kb_a = _make_key_bundle("alice_login_pass_1234", "alice_recovery_pass_12345")
    kb_b = _make_key_bundle("bob_login_pass_123456", "bob_recovery_pass_1234567")
    api.register_user("alice", "alice@example.com", kb_a)
    api.register_user("bob", "bob@example.com", kb_b)

    alice = api.user_service.get_user_by_username("alice")
    bob = api.user_service.get_user_by_username("bob")

    doc = Path("agreement.txt")
    doc.write_text("contract-v1")

    ok1, _ = api.sign_document(alice["id"], "alice", str(doc), priv_key_data=_unlock(kb_a, "signing", "alice_login_pass_1234"))
    ok2, _ = api.sign_document(bob["id"], "bob", str(doc), priv_key_data=_unlock(kb_b, "signing", "bob_login_pass_123456"))
    assert ok1 and ok2

    results = api.verify_document(str(doc))
    assert len(results) >= 2
    assert all(r["valid"] for r in results)

    # Tamper attack simulation: change document => no matching trusted signature for new hash
    doc.write_text("contract-v2-tampered")
    tampered = api.verify_document(str(doc))
    assert tampered == []


def test_confidentiality_with_recipient_access_control(env):
    api = env["api"]
    kb_a = _make_key_bundle("alice_login_pass_1234", "alice_recovery_pass_12345")
    kb_b = _make_key_bundle("bob_login_pass_123456", "bob_recovery_pass_1234567")
    kb_c = _make_key_bundle("charlie_login_12345", "charlie_recovery_12345")

    api.register_user("alice", "alice@example.com", kb_a)
    api.register_user("bob", "bob@example.com", kb_b)
    api.register_user("charlie", "charlie@example.com", kb_c)

    alice = api.user_service.get_user_by_username("alice")
    bob = api.user_service.get_user_by_username("bob")
    charlie = api.user_service.get_user_by_username("charlie")

    Path("secret.bin").write_bytes(b"top-secret-payload")
    ok, enc_json = api.encrypt_document("secret.bin", ["alice", "bob"])
    assert ok is True

    dec_a, msg_a = api.decrypt_document(enc_json, alice["id"], "alice", priv_key_data=_unlock(kb_a, "encryption", "alice_login_pass_1234"))
    dec_b, msg_b = api.decrypt_document(enc_json, bob["id"], "bob", priv_key_data=_unlock(kb_b, "encryption", "bob_login_pass_123456"))
    dec_c, msg_c = api.decrypt_document(enc_json, charlie["id"], "charlie", priv_key_data=_unlock(kb_c, "encryption", "charlie_login_12345"))

    assert msg_a == "Success" and dec_a == b"top-secret-payload"
    assert msg_b == "Success" and dec_b == b"top-secret-payload"
    assert dec_c is None and "authorized" in msg_c


def test_revocation_and_lockout_controls(env):
    api = env["api"]
    kb = _make_key_bundle("alice_login_pass_1234", "alice_recovery_pass_12345")
    api.register_user("alice", "alice@example.com", kb)
    user = api.user_service.get_user_by_username("alice")

    # Revoke active auth cert -> login should fail gracefully
    certs = api.get_user_certificates(user["id"])
    active_auth = next(c for c in certs if c["key_usage"] == "auth" and c["revoked"] == 0)
    api.revoke_certificate(active_auth["serial_number"])

    ok, _, _, msg = api.login_user("alice", priv_key_data=_unlock(kb, "auth", "alice_login_pass_1234"))
    assert ok is False
    assert "No active authentication certificate" in msg or "Certificate validation failed" in msg

    # Brute-force lockout policy (10 failed login attempts)
    for _ in range(10):
        api.record_attempt("alice", "login", False)
    is_locked, _, remaining = api.check_lockout("alice", "login")
    assert is_locked is True
    assert remaining == 0


def test_auth_cert_user_binding_blocks_spoofing(env):
    api = env["api"]

    kb_a = _make_key_bundle("alice_login_pass_1234", "alice_recovery_pass_12345")
    kb_b = _make_key_bundle("bob_login_pass_123456", "bob_recovery_pass_1234567")

    ok_a, _ = api.register_user("alice_bind", "alice_bind@example.com", kb_a)
    ok_b, _ = api.register_user("bob_bind", "bob_bind@example.com", kb_b)
    assert ok_a and ok_b

    alice = api.user_service.get_user_by_username("alice_bind")
    bob = api.user_service.get_user_by_username("bob_bind")

    # Challenge is generated for Alice
    nonce = api.auth.generate_challenge(alice["id"])

    # Bob signs Alice's nonce with Bob's auth private key
    bob_auth_priv = _unlock(kb_b, "auth", "bob_login_pass_123456")
    bob_sig = CryptoUtils.sign_data(CryptoUtils.load_private_key(bob_auth_priv), nonce)

    # Bob presents Bob's valid auth certificate for Alice's challenge (spoof attempt)
    bob_auth_cert = api.user_service.get_user_certificate(bob["id"], "auth")

    valid, msg = api.auth.verify_challenge(alice["id"], nonce, bob_sig, bob_auth_cert)
    assert valid is False
    assert "mismatch" in msg.lower() or "belong" in msg.lower()


def test_audit_log_tamper_detection(env):
    api = env["api"]
    api.audit.log_event("TEST_EVENT", {"data": "secure"})
    valid, _ = api.verify_audit_integrity()
    assert valid is True

    # Tamper with log row
    conn = api.db.get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE audit_logs SET details = 'tampered' WHERE id = 1")
    conn.commit()
    conn.close()

    valid2, msg2 = api.verify_audit_integrity()
    assert valid2 is False
    assert "Tamper detected" in msg2

# Verification Checksum: 36f022db at 2026-02-14 19:46:20


def test_register_rejects_path_traversal_username(env):
    api = env["api"]
    kb = _make_key_bundle()
    ok, msg = api.register_user("../evil", "evil@example.com", kb)
    assert ok is False
    assert "Username" in msg or "Invalid" in msg or "Unsafe" in msg


def test_secret_encryption_cert_must_belong_to_owner(env):
    api = env["api"]

    ka = _make_key_bundle()
    kb = _make_key_bundle()

    assert api.register_user("alice", "alice@example.com", ka)[0]
    assert api.register_user("bob", "bob@example.com", kb)[0]

    alice = api.user_service.get_user_by_username("alice")
    bob = api.user_service.get_user_by_username("bob")

    # Bob's encryption cert should not be usable by Alice to add her secret
    bob_enc_cert = api.get_active_certificate(bob["id"], "encryption")
    ok, msg = api.add_secret(
        alice["id"],
        service="bank",
        username="alice@bank.com",
        url="bank portal",
        password="S3cret!Passw0rd",
        pub_key_pem=bob_enc_cert,
    )
    assert ok is False
    assert "does not belong" in msg or "mismatch" in msg


def test_lockout_is_scoped_by_client_fingerprint(env):
    api = env["api"]
    api.register_user("fpuser", "fp@example.com", _make_key_bundle())

    for _ in range(10):
        api.record_attempt("fpuser", "login", False, client_fingerprint="attackerA")

    locked_a, _, _ = api.check_lockout("fpuser", "login", client_fingerprint="attackerA")
    locked_b, _, _ = api.check_lockout("fpuser", "login", client_fingerprint="attackerB")

    assert locked_a is True
    assert locked_b is False


def test_key_rotation_revokes_previous_certificates(env):
    api = env["api"]

    kb1 = _make_key_bundle("alice_login_pass_1234", "alice_recovery_pass_12345")
    assert api.register_user("rotate_user", "rotate_user@example.com", kb1)[0]
    user = api.user_service.get_user_by_username("rotate_user")

    before = api.get_user_certificates(user["id"])
    active_before = [c for c in before if c["revoked"] == 0 and c["key_usage"] in {"auth", "signing", "encryption"}]
    assert len(active_before) == 3

    kb2 = _make_key_bundle("alice_login_pass_1234", "alice_recovery_pass_12345")
    ok, msg = api.rotate_keys("rotate_user", kb2)
    assert ok, msg

    after = api.get_user_certificates(user["id"])
    active_after = [c for c in after if c["revoked"] == 0 and c["key_usage"] in {"auth", "signing", "encryption"}]
    revoked_after = [c for c in after if c["revoked"] == 1 and c["key_usage"] in {"auth", "signing", "encryption"}]

    # Exactly one current cert per purpose after rotation; prior set should be revoked.
    assert len(active_after) == 3
    assert len(revoked_after) >= 3
