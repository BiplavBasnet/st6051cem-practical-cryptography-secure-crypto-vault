import json
import os
import threading
import time
from pathlib import Path

from services.app_paths import config_path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services.crypto_utils import CryptoUtils
from services.structured_logger import get_logger


class LocalKeyManager:
    """Protect local private keys with a passphrase-derived KEK and optional recovery path.

    Upgrade highlights:
    - Argon2id with versioned KDF metadata
    - First-run local benchmark profile for safer machine-tuned parameters
    - HKDF purpose separation for enc/mac/recovery keys
    """

    KDF_PROFILE_PATH = config_path("kdf_profile.json")
    KDF_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    DEFAULT_KDF = {
        "algorithm": "argon2id",
        "version": 2,
        "length": 32,
        "iterations": 2,
        "lanes": 4,
        "memory_cost": 65536,
    }

    @classmethod
    def _load_kdf_profile(cls):
        if cls.KDF_PROFILE_PATH.exists():
            try:
                raw = json.loads(cls.KDF_PROFILE_PATH.read_text(encoding="utf-8"))
                if all(k in raw for k in ["iterations", "lanes", "memory_cost", "length"]):
                    out = dict(cls.DEFAULT_KDF)
                    out.update(raw)
                    return out
            except Exception:
                pass
        return None

    _kdf_benchmark_lock = threading.Lock()
    _kdf_non_blocking = False  # Set by GUI to avoid blocking on first run

    @classmethod
    def _save_kdf_profile(cls, profile: dict):
        """Save KDF profile with atomic write (temp + rename) to avoid corruption on concurrent access."""
        try:
            cls.KDF_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = cls.KDF_PROFILE_PATH.with_suffix(cls.KDF_PROFILE_PATH.suffix + ".tmp")
            tmp_path.write_text(json.dumps(profile, indent=2), encoding="utf-8")
            try:
                os.chmod(tmp_path, 0o600)
            except Exception:
                pass
            os.replace(tmp_path, cls.KDF_PROFILE_PATH)
        except Exception as e:
            get_logger().warning("Failed to save KDF profile: %s", e)

    @classmethod
    def _benchmark_kdf(cls):
        """Quick local benchmark to keep unlock cost reasonably high but responsive."""
        # Intentionally conservative to avoid unusable devices.
        candidates = [
            {"iterations": 2, "lanes": 2, "memory_cost": 32768, "length": 32},
            {"iterations": 2, "lanes": 4, "memory_cost": 65536, "length": 32},
            {"iterations": 3, "lanes": 4, "memory_cost": 65536, "length": 32},
            {"iterations": 2, "lanes": 4, "memory_cost": 131072, "length": 32},
        ]

        salt = os.urandom(16)
        target_ms_min = 120
        target_ms_max = 450

        best = None
        best_ms = 0.0

        for c in candidates:
            try:
                t0 = time.perf_counter()
                CryptoUtils.derive_key_argon2id(
                    "benchmark-passphrase",
                    salt,
                    length=c["length"],
                    iterations=c["iterations"],
                    lanes=c["lanes"],
                    memory_cost=c["memory_cost"],
                )
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
            except Exception:
                continue

            if target_ms_min <= elapsed_ms <= target_ms_max:
                best = c
                best_ms = elapsed_ms

        if not best:
            # fallback: strongest measured under upper bound, else default
            under = []
            for c in candidates:
                try:
                    t0 = time.perf_counter()
                    CryptoUtils.derive_key_argon2id(
                        "benchmark-passphrase",
                        salt,
                        length=c["length"],
                        iterations=c["iterations"],
                        lanes=c["lanes"],
                        memory_cost=c["memory_cost"],
                    )
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    if elapsed_ms <= target_ms_max:
                        under.append((elapsed_ms, c))
                except Exception:
                    continue

            if under:
                # choose the slowest acceptable under upper bound
                under.sort(key=lambda x: x[0])
                best_ms, best = under[-1]
            else:
                best = dict(cls.DEFAULT_KDF)
                best_ms = -1

        profile = dict(cls.DEFAULT_KDF)
        profile.update(best)
        profile["benchmark_ms"] = round(best_ms, 2) if best_ms >= 0 else None
        return profile

    @classmethod
    def get_kdf_profile(cls, non_blocking: bool = False):
        """Return KDF profile. If non_blocking=True and profile not on disk, return default and benchmark in background."""
        prof = cls._load_kdf_profile()
        if prof:
            return prof
        use_non_blocking = non_blocking or getattr(cls, "_kdf_non_blocking", False)
        if use_non_blocking:
            def _benchmark_and_save():
                try:
                    with cls._kdf_benchmark_lock:
                        if cls._load_kdf_profile():
                            return
                        prof = cls._benchmark_kdf()
                        cls._save_kdf_profile(prof)
                except Exception as e:
                    get_logger().warning("KDF benchmark thread failed: %s", e, exc_info=True)
            t = threading.Thread(target=_benchmark_and_save, daemon=True)
            t.start()
            return dict(cls.DEFAULT_KDF)
        prof = cls._benchmark_kdf()
        cls._save_kdf_profile(prof)
        return prof

    @classmethod
    def _derive_kek(cls, passphrase: str, salt: bytes, kdf_params: dict | None = None):
        cfg = dict(cls.get_kdf_profile())
        if kdf_params:
            cfg.update(kdf_params)

        kek = CryptoUtils.derive_key_argon2id(
            passphrase,
            salt,
            length=int(cfg.get("length", 32)),
            iterations=int(cfg.get("iterations", 2)),
            lanes=int(cfg.get("lanes", 4)),
            memory_cost=int(cfg.get("memory_cost", 65536)),
        )

        return kek, cfg

    @staticmethod
    def protect_key_bundle(private_key_pem: bytes, login_passphrase: str, recovery_phrase: str) -> dict:
        """Encrypt private key bytes into a portable JSON bundle."""
        # Derive KEK from login phrase
        login_salt = os.urandom(16)
        kek_root, kdf_cfg = LocalKeyManager._derive_kek(login_passphrase, login_salt)
        enc_key = CryptoUtils.hkdf_expand(kek_root, info=b"sv:keybundle:enc:v2", salt=login_salt)
        mac_key = CryptoUtils.hkdf_expand(kek_root, info=b"sv:keybundle:mac:v2", salt=login_salt)

        nonce = os.urandom(12)
        aad = b"sv-keybundle-v2"
        ciphertext = AESGCM(enc_key).encrypt(nonce, private_key_pem, aad)
        mac_hex = CryptoUtils.hmac_sha256_hex(mac_key, nonce + ciphertext + aad)

        # Recovery wrap with separated context
        rec_salt = os.urandom(16)
        rec_root, rec_cfg = LocalKeyManager._derive_kek(recovery_phrase, rec_salt, kdf_cfg)
        rec_key = CryptoUtils.hkdf_expand(rec_root, info=b"sv:keybundle:recovery:v2", salt=rec_salt)
        rec_nonce = os.urandom(12)
        recovery_wrapped = AESGCM(rec_key).encrypt(rec_nonce, kek_root, b"sv-recovery-wrap-v2")

        return {
            "version": "2.0",
            "cipher": "AES-256-GCM",
            "aad": "sv-keybundle-v2",
            "kdf": {
                "algorithm": "argon2id",
                "length": int(kdf_cfg.get("length", 32)),
                "iterations": int(kdf_cfg.get("iterations", 2)),
                "lanes": int(kdf_cfg.get("lanes", 4)),
                "memory_cost": int(kdf_cfg.get("memory_cost", 65536)),
            },
            "login": {
                "salt": CryptoUtils.b64e(login_salt),
                "nonce": CryptoUtils.b64e(nonce),
                "ciphertext": CryptoUtils.b64e(ciphertext),
                "mac": mac_hex,
            },
            "recovery": {
                "salt": CryptoUtils.b64e(rec_salt),
                "nonce": CryptoUtils.b64e(rec_nonce),
                "wrapped_kek": CryptoUtils.b64e(recovery_wrapped),
                "kdf": {
                    "algorithm": "argon2id",
                    "length": int(rec_cfg.get("length", 32)),
                    "iterations": int(rec_cfg.get("iterations", 2)),
                    "lanes": int(rec_cfg.get("lanes", 4)),
                    "memory_cost": int(rec_cfg.get("memory_cost", 65536)),
                },
            },
        }

    @staticmethod
    def unlock_key_from_bundle(bundle: dict, login_passphrase: str) -> bytes | None:
        """Decrypt private key using login passphrase. Supports v1 and v2 bundles."""
        try:
            version = str(bundle.get("version") or "1.0")
            if version.startswith("1"):
                # legacy format
                salt = CryptoUtils.b64d(bundle["salt"])
                nonce = CryptoUtils.b64d(bundle["nonce"])
                ct = CryptoUtils.b64d(bundle["ciphertext"])
                kek = CryptoUtils.derive_key_argon2id(login_passphrase, salt)
                return AESGCM(kek).decrypt(nonce, ct, None)

            login = bundle["login"]
            kdf = bundle.get("kdf", {})
            salt = CryptoUtils.b64d(login["salt"])
            nonce = CryptoUtils.b64d(login["nonce"])
            ct = CryptoUtils.b64d(login["ciphertext"])
            aad = (bundle.get("aad") or "sv-keybundle-v2").encode("utf-8")

            root, _ = LocalKeyManager._derive_kek(login_passphrase, salt, kdf)
            enc_key = CryptoUtils.hkdf_expand(root, info=b"sv:keybundle:enc:v2", salt=salt)
            mac_key = CryptoUtils.hkdf_expand(root, info=b"sv:keybundle:mac:v2", salt=salt)

            if not CryptoUtils.hmac_compare(login.get("mac", ""), mac_key, nonce + ct + aad):
                return None

            return AESGCM(enc_key).decrypt(nonce, ct, aad)
        except Exception:
            return None

    @staticmethod
