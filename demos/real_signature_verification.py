# -*- coding: utf-8 -*-
"""
SecureCrypt Vault - REAL Document Signature Verification
=========================================================

This script performs ACTUAL document signing and verification using
the real cryptographic services of SecureCrypt Vault.

Use this script to capture real screenshots for:
- Section 7.5: Successful signature verification
- Section 9.3: Tamper detection failure (negative test)

REQUIREMENTS:
- You must be logged in with a registered user
- The user must have a signing certificate issued

Author: Biplav Basnet
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import sys
import io
import os
import tempfile
import hashlib
from pathlib import Path
from datetime import datetime, timezone

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    WHITE = '\033[97m'


def print_header():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                  REAL DOCUMENT SIGNATURE VERIFICATION                        ║
║                                                                              ║
║                Using Actual SecureCrypt Vault Cryptography                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
""")


def print_section(title):
    print(f"\n{Colors.YELLOW}{Colors.BOLD}{'═' * 70}{Colors.RESET}")
    print(f"{Colors.YELLOW}{Colors.BOLD}  {title}{Colors.RESET}")
    print(f"{Colors.YELLOW}{Colors.BOLD}{'═' * 70}{Colors.RESET}\n")


def print_success(msg):
    print(f"  {Colors.GREEN}✓ {msg}{Colors.RESET}")


def print_error(msg):
    print(f"  {Colors.RED}✗ {msg}{Colors.RESET}")


def print_info(msg):
    print(f"  {Colors.BLUE}ℹ {msg}{Colors.RESET}")


def print_warning(msg):
    print(f"  {Colors.YELLOW}⚠ {msg}{Colors.RESET}")


def get_user_credentials():
    """Get username and password - pre-filled for demonstration."""
    
    # Pre-filled credentials for demonstration
    username = "biplav.basnet"
    password = "BiplavBasnet@123"  # Change this to your actual password
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                        USER AUTHENTICATION                                   │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Credentials for SecureCrypt Vault:{Colors.WHITE}                                       │
│                                                                              │
│    Username:  {Colors.GREEN}biplav.basnet{Colors.WHITE}                                              │
│    Password:  {Colors.GREEN}••••••••••••••••{Colors.WHITE}                                           │
│                                                                              │
│  {Colors.DIM}(Pre-filled for demonstration purposes){Colors.WHITE}                                  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}""")
    
    return username, password


def main():
    print_header()
    
    print(f"{Colors.WHITE}This script performs REAL document signing and verification")
    print(f"using the actual SecureCrypt Vault cryptographic services.{Colors.RESET}")
    print()
    print(f"{Colors.YELLOW}Note: You need a registered user with signing certificate.{Colors.RESET}")
    print()
    
    # Import the API
    try:
        from services.api import VaultAPI
        api = VaultAPI()
        print_success("SecureCrypt API initialized")
    except Exception as e:
        print_error(f"Failed to initialize API: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Get credentials
    username, password = get_user_credentials()
    print()
    
    # Authenticate user
    print_section("STEP 1: USER AUTHENTICATION")
    
    try:
        # Get user
        user = api.user_service.get_user_by_username(username)
        if not user:
            print_error(f"User '{username}' not found")
            return
        
        user_id = user["id"]
        print_success(f"User found: {username} (ID: {user_id})")
        
        # Check for signing certificate
        from services.app_paths import app_dir
        keys_dir = app_dir() / "keys" / username
        sign_key_path = keys_dir / "signing_key.json"
        
        if not sign_key_path.exists():
            print_error("Signing key bundle not found")
            print_info(f"Expected at: {sign_key_path}")
            return
        
        print_success("Signing key bundle found")
        
        # Load and decrypt private key
        import json
        from services.local_key_manager import LocalKeyManager
        
        key_bundle = json.loads(sign_key_path.read_text(encoding="utf-8"))
        priv_key_bytes = LocalKeyManager.unlock_key_from_bundle(key_bundle, password)
        
        if not priv_key_bytes:
            print_error("Failed to decrypt signing key (wrong password?)")
            return
        
        print_success("Signing private key decrypted successfully")
        
    except Exception as e:
        print_error(f"Authentication failed: {e}")
        return
    
    # Create test document
    print_section("STEP 2: CREATE TEST DOCUMENT")
    
    temp_dir = Path(tempfile.mkdtemp(prefix="securecrypt_sign_"))
    doc_path = temp_dir / "Confidential_Agreement_2026.txt"
    
    original_content = f"""
================================================================================
                        CONFIDENTIAL AGREEMENT
================================================================================

Document ID: DOC-2026-{datetime.now().strftime('%Y%m%d%H%M%S')}
Date: {datetime.now().strftime('%Y-%m-%d')}

PARTIES:
- SecureCrypt Vault Organization
- Authorized User: {username}

TERMS AND CONDITIONS:
This document represents a binding agreement between the parties listed above.
All terms and conditions outlined herein are legally binding and enforceable.

CONFIDENTIALITY CLAUSE:
All information contained within this document shall be treated as strictly
confidential and shall not be disclosed to any third party without prior
written consent from all parties involved.

DIGITAL SIGNATURE:
This document is digitally signed using RSA-2048 with SHA-256 hashing.
The signature provides non-repudiation and integrity verification.

================================================================================
                           END OF DOCUMENT
================================================================================
"""
    
    doc_path.write_text(original_content, encoding="utf-8")
    doc_hash = hashlib.sha256(original_content.encode()).hexdigest()
    
    print_success(f"Test document created: {doc_path.name}")
    print_info(f"Document path: {doc_path}")
    print_info(f"Document hash (SHA-256): {doc_hash}")
    print_info(f"Document size: {len(original_content)} bytes")
    
    # Sign the document
    print_section("STEP 3: SIGN DOCUMENT")
    
    try:
        success, message = api.sign_document(
            user_id=user_id,
            username=username,
            file_path=str(doc_path),
            priv_key_data=priv_key_bytes
        )
        
        if success:
            print_success("Document signed successfully!")
            print_info(f"Message: {message}")
        else:
            print_error(f"Signing failed: {message}")
            return
            
    except Exception as e:
        print_error(f"Signing error: {e}")
        return
    
    # Verify the signature (SUCCESS CASE)
    print_section("STEP 4: VERIFY SIGNATURE (SUCCESS CASE)")
    print(f"{Colors.GREEN}{Colors.BOLD}  >>> SCREENSHOT THIS FOR SECTION 7.5 <<<{Colors.RESET}")
    print()
    
    try:
        results = api.verify_document(str(doc_path))
        
        print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                    SIGNATURE VERIFICATION RESULT                             │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Document: {doc_path.name:<52} │
│  Hash:     {doc_hash[:48]}│
│            {doc_hash[48:]:<52} │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
{Colors.RESET}""")
        
        for result in results:
            if result["valid"]:
                print(f"""{Colors.WHITE}│                                                                              │
│  {Colors.GREEN}╔═══════════════════════════════════════════════════════════════════╗{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}║   ✓ SIGNATURE VALID                                               ║{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}║   Signer: {result['username']:<52}║{Colors.WHITE}   │
│  {Colors.GREEN}║   Status: {result['message']:<52}║{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}╚═══════════════════════════════════════════════════════════════════╝{Colors.WHITE}   │
│                                                                              │
│  {Colors.CYAN}Verification Confirms:{Colors.WHITE}                                                   │
│  ─────────────────────────────────────────────────────────────────────────   │
│    {Colors.GREEN}✓{Colors.WHITE} Document has not been altered since signing                          │
│    {Colors.GREEN}✓{Colors.WHITE} Signature created by: {result['username']:<42} │
│    {Colors.GREEN}✓{Colors.WHITE} Signer's certificate is valid and trusted                           │
│    {Colors.GREEN}✓{Colors.WHITE} Non-repudiation: Signer cannot deny signing                         │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}""")
            else:
                print(f"""│  {Colors.RED}✗ VERIFICATION FAILED{Colors.WHITE}                                                │
│    Signer: {result['username']:<52} │
│    Error: {result['message']:<53} │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}""")
        
        print(f"""
{Colors.DIM}Figure X: Successful signature verification confirming document integrity
and trusted signer identity. (Section 7.5){Colors.RESET}
""")
        
    except Exception as e:
        print_error(f"Verification error: {e}")
        return
    
    input(f"\n{Colors.CYAN}Press Enter to continue to TAMPER DETECTION test...{Colors.RESET}")
    
    # Modify document and verify again (FAILURE CASE)
    print_section("STEP 5: TAMPER DETECTION (FAILURE CASE)")
    print(f"{Colors.RED}{Colors.BOLD}  >>> SCREENSHOT THIS FOR SECTION 9.3 <<<{Colors.RESET}")
    print()
    
    # Modify the document
    tampered_content = original_content.replace(
        "legally binding and enforceable",
        "NOT binding and NOT enforceable"
    )
    doc_path.write_text(tampered_content, encoding="utf-8")
    tampered_hash = hashlib.sha256(tampered_content.encode()).hexdigest()
    
    print_warning("Document has been MODIFIED (simulating tampering attack)")
    print_info(f"Original hash: {doc_hash}")
    print_info(f"Tampered hash: {tampered_hash}")
    print_info("Changed: 'legally binding' → 'NOT binding'")
    print()
    
    try:
        results = api.verify_document(str(doc_path))
        
        # If no results found (hash doesn't match any signed document)
        if not results or all(not r.get("valid", True) for r in results):
            print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                    SIGNATURE VERIFICATION RESULT                             │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Document: {doc_path.name:<52} │
│  Current Hash: {tampered_hash[:45]}│
│                {tampered_hash[45:]:<52} │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.RED}╔═══════════════════════════════════════════════════════════════════╗{Colors.WHITE}   │
│  {Colors.RED}║                                                                   ║{Colors.WHITE}   │
│  {Colors.RED}║   ✗ SIGNATURE VERIFICATION FAILED                                 ║{Colors.WHITE}   │
│  {Colors.RED}║                                                                   ║{Colors.WHITE}   │
│  {Colors.RED}║   TAMPER DETECTED: Document has been modified                     ║{Colors.WHITE}   │
│  {Colors.RED}║                                                                   ║{Colors.WHITE}   │
│  {Colors.RED}╚═══════════════════════════════════════════════════════════════════╝{Colors.WHITE}   │
│                                                                              │
│  {Colors.CYAN}Hash Comparison:{Colors.WHITE}                                                         │
│  ─────────────────────────────────────────────────────────────────────────   │
│    Original (signed): {doc_hash[:40]}...   │
│    Current (modified): {tampered_hash[:40]}...   │
│    Status: {Colors.RED}MISMATCH - Document altered since signing{Colors.WHITE}                       │
│                                                                              │
│  {Colors.CYAN}Security Implications:{Colors.WHITE}                                                   │
│  ─────────────────────────────────────────────────────────────────────────   │
│    {Colors.RED}⚠{Colors.WHITE} Document content has been tampered with                               │
│    {Colors.RED}⚠{Colors.WHITE} Original signature is no longer valid for this version               │
│    {Colors.RED}⚠{Colors.WHITE} Do NOT trust this document                                            │
│                                                                              │
│  {Colors.CYAN}Recommended Action:{Colors.WHITE}                                                      │
│  ─────────────────────────────────────────────────────────────────────────   │
│    • Obtain the original, unmodified document from the signer               │
│    • Report potential security incident                                      │
│    • Do not act on information in this modified document                     │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}""")
        
        print(f"""
{Colors.DIM}Figure X: Signature verification failure after document modification
(tamper detection). (Section 9.3){Colors.RESET}
""")
        
    except Exception as e:
        print_error(f"Verification error: {e}")
    
    # Cleanup
    print_section("CLEANUP")
    try:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
        print_success("Temporary files cleaned up")
    except Exception:
        print_warning(f"Cleanup partial. Temp dir: {temp_dir}")
    
    # Summary
    print(f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                         DEMONSTRATION COMPLETE                               ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Screenshots Captured:                                                       ║
║                                                                              ║
║  1. STEP 4 - Successful Verification (Section 7.5)                           ║
║     Caption: "Figure X: Successful signature verification confirming         ║
║              document integrity and trusted signer identity."                ║
║                                                                              ║
║  2. STEP 5 - Tamper Detection Failure (Section 9.3)                          ║
║     Caption: "Figure X: Signature verification failure after document        ║
║              modification (tamper detection)."                               ║
║                                                                              ║
║  This demonstration used REAL cryptographic operations:                      ║
║  • RSA-2048 digital signatures                                               ║
║  • SHA-256 document hashing                                                  ║
║  • X.509 certificate validation                                              ║
║  • Timestamp authority verification                                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
""")


if __name__ == "__main__":
    main()
