#!/usr/bin/env python3
"""Non-GUI smoke check: imports, app paths, API init, backup create/validate (no secrets printed)."""

import os
import sys
import tempfile
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)


def run():
    results = []
    base = tempfile.mkdtemp(prefix="smoke_")
    try:
        os.environ["SECURECRYPT_BASE_DIR"] = base

        # 1. Imports
        try:
            from services.api import VaultAPI
            from services.app_paths import app_dir, config_path, db_path
            from config.design_tokens import get_theme
            results.append(("imports", True))
        except Exception as e:
            results.append(("imports", False))
            print(f"FAIL imports: {e}")
            return 1

        # 2. App paths with env override
        try:
            d = app_dir()
            assert d.as_posix().endswith(base.split(os.sep)[-1]) or base in str(d)
            results.append(("app_paths", True))
        except Exception as e:
            results.append(("app_paths", False))
            print(f"FAIL app_paths: {e}")

        # 3. API init
        try:
            api = VaultAPI()
            assert api.db is not None and api.secret_service is not None
            results.append(("api_init", True))
        except Exception as e:
            results.append(("api_init", False))
            print(f"FAIL api_init: {e}")

        # 4. Register user + add secret
        user = enc_priv = cert = kb = None
        try:
            kb = {}
            from services.crypto_utils import CryptoUtils
            from services.local_key_manager import LocalKeyManager
            for purpose in ["auth", "signing", "encryption"]:
                priv = CryptoUtils.generate_rsa_key_pair(2048)
                priv_pem = CryptoUtils.serialize_private_key(priv)
                pub_pem = CryptoUtils.serialize_public_key(priv.public_key()).decode()
                kb[purpose] = {
                    "encrypted_priv": LocalKeyManager.protect_key_bundle(
                        priv_pem, "SmokePass_123!", "Recovery_123!"
                    ),
                    "pub_pem": pub_pem,
                }
            ok, _ = api.register_user("smoke_user", "smoke@test.local", kb)
            assert ok
            user = api.user_service.get_user_by_username("smoke_user")
            cert = api.get_active_certificate(user["id"], "encryption")
            enc_priv = LocalKeyManager.unlock_key_from_bundle(
                kb["encryption"]["encrypted_priv"], "SmokePass_123!"
            )
            api.add_secret(user["id"], "test_svc", "user", "http://test.com", "pass123", cert)
            results.append(("register_add_secret", True))
        except Exception as e:
            results.append(("register_add_secret", False))
            print(f"FAIL register_add_secret: {e}")

        # 5. Backup create + validate (only if register succeeded)
        try:
            if user is None or enc_priv is None or cert is None:
                results.append(("backup_create_validate", False))
            else:
                export_result = api.export_vault_backup(user["id"], enc_priv, "BackupPass_123!")
                ok_exp = export_result[0] if isinstance(export_result, tuple) else bool(export_result)
                backup = export_result[2] if isinstance(export_result, tuple) and len(export_result) > 2 else None
                assert ok_exp and backup and isinstance(backup, dict)
                ok_imp, _ = api.import_vault_backup(user["id"], cert, backup, "BackupPass_123!")
                assert ok_imp
                results.append(("backup_create_validate", True))
        except Exception as e:
            results.append(("backup_create_validate", False))
            print(f"FAIL backup: {e}")

    finally:
        os.environ.pop("SECURECRYPT_BASE_DIR", None)
        shutil.rmtree(base, ignore_errors=True)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}: {name}")
    print(f"\nSmoke check: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(run())
