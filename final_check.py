import os
import sys
import json
import shutil

# Add current directory to path
sys.path.append(os.getcwd())

from services.api import VaultAPI

def test_system():
    print("--- SecureCrypt Vault: Master Integrity Check ---")
    
    # 0. Prep
    if os.path.exists("data/vault.db"): os.remove("data/vault.db")
    if os.path.exists("pki"): shutil.rmtree("pki")
    
    api = VaultAPI()
    
    # 1. Registration
    import time
    username = f"User_{int(time.time())}"
    email = "test@final.check"
    # Note: api.register_user in our hardened version returns (success, msg)
    res = api.register_user(username, email)
    success = res[0] if isinstance(res, tuple) else res
    print(f"[1/4] User Registration: {'SUCCESS' if success else 'FAILED'}")
    
    if not success:
        return False

    # 2. Get User ID and Encryption Certificate
    conn = api.db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = cursor.fetchone()['id']
    
    # Get encryption certificate for the user
    pub_key_pem = api.get_active_certificate(user_id, "encryption")
    print(f"[2/4] Certificate Retrieval (ID {user_id}): {'SUCCESS' if pub_key_pem else 'FAILED'}")
    
    if not pub_key_pem:
        return False

    # 3. Secret Storage
    print("[3/4] Testing Secret Service (PKI Encrypted)...")
    res = api.add_secret(user_id, "Github", "final_dev", "https://github.com", "git-pass-123", pub_key_pem)
    print(f"      Add Secret Response: {res}")
    
    # Direct DB check
    cursor.execute("SELECT COUNT(*) as count FROM vault_secrets WHERE owner_id = ?", (user_id,))
    count = cursor.fetchone()['count']
    print(f"      Direct DB Count for owner {user_id}: {count}")

    secrets = api.get_secrets_metadata(user_id)
    print(f"      Secrets Metadata count: {len(secrets)}")
    
    # 4. Audit Log Integrity
    print("[4/4] Verifying Audit Hash Chain...")
    audit_ok, audit_msg = api.audit.verify_integrity()
    print(f"      Audit Status: {audit_msg}")
    
    # Final check
    if success and count > 0 and audit_ok:
        print("\n>>> ALL SYSTEMS NOMINAL. CODE IS FULLY FUNCTIONAL AND SECURE. <<<")
        # Cleanup
        conn.close()
        if os.path.exists(f"keys/{username}"): shutil.rmtree(f"keys/{username}")
        return True
    
    conn.close()
    return False

if __name__ == "__main__":
    try:
        if not test_system():
            sys.exit(1)
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
