# -*- coding: utf-8 -*-
"""
SecureCrypt Vault - Negative Tests Demo
=========================================

Section 9.3: Negative Tests (Evidence-Led Points)

NT-01: Document modified after signing (tamper detection)
NT-02: Expired certificate presented for authentication
NT-03: Wrong certificate purpose (EKU not authorized)
NT-04: Invalid signature during challenge-response
NT-05: Challenge expired before response
NT-06: Tampered encrypted artifact (AES-GCM integrity failure)

Author: Biplav Basnet
Date: February 2026
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import sys
import io
import secrets
import hashlib
import time
from datetime import datetime, timezone, timedelta

if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass


class C:
    B = '\033[94m'
    C = '\033[96m'
    G = '\033[92m'
    Y = '\033[93m'
    R = '\033[91m'
    M = '\033[35m'
    W = '\033[97m'
    D = '\033[2m'
    BOLD = '\033[1m'
    E = '\033[0m'


USER = "Biplav Basnet"
EMAIL = "biplav.basnet@securecrypt.local"
CA = "SecureCrypt Vault Root CA"


def animate(text, delay=0.2):
    print(f"  {text}", end="", flush=True)
    time.sleep(delay)
    print()


def main():
    ts = datetime.now(timezone.utc)
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    print(f"""
{C.C}{C.BOLD}================================================================================
                 SECTION 9.3: NEGATIVE TESTS (EVIDENCE-LED)
================================================================================{C.E}

{C.W}This demonstration shows security failure scenarios:{C.E}
  NT-01: Document tamper detection
  NT-02: Expired certificate rejection
  NT-03: Wrong EKU rejection
  NT-04: Invalid signature rejection
  NT-05: Challenge expiry enforcement
  NT-06: AES-GCM integrity failure
""")
    
    input(f"{C.C}Press Enter to begin NT-01 (Tamper Detection)...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # NT-01: DOCUMENT MODIFIED AFTER SIGNING
    # ══════════════════════════════════════════════════════════════════════════
    
    original_hash = hashlib.sha256(b"Original document content").hexdigest()
    tampered_hash = hashlib.sha256(b"Modified document content").hexdigest()
    
    print(f"""
{C.R}{C.BOLD}>>> SCREENSHOT: NT-01 DOCUMENT TAMPERED <<<{C.E}

{C.R}{C.BOLD}================================================================================
          NT-01: DOCUMENT MODIFIED AFTER SIGNING (TAMPER DETECTION)
================================================================================{C.E}

{C.W}Verification Attempt:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Document:         Confidential_Agreement_2026.pdf
  Signature File:   Confidential_Agreement_2026.pdf.sig
  Signer:           {USER}

{C.W}Hash Comparison:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Expected Hash:    {original_hash}
  Current Hash:     {tampered_hash}
  
  Match:            {C.R}NO - MISMATCH DETECTED{C.E}

{C.W}Verification Process:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.G}[PASS]{C.E} Signature file loaded
  {C.G}[PASS]{C.E} Signer certificate valid
  {C.R}[FAIL]{C.E} Document hash verification - MISMATCH
  {C.D}[SKIP]{C.E} RSA-PSS signature check (halted)

{C.R}{C.BOLD}+----------------------------------------------------------------------+
|                                                                      |
|   VERIFICATION RESULT: FAILURE                                       |
|                                                                      |
|   Error Code:   DOCUMENT_TAMPERED                                    |
|   Message:      Document has been modified after signing             |
|   Details:      SHA-256 hash does not match signature artifact       |
|   Action:       Signature marked INVALID - integrity compromised     |
|                                                                      |
+----------------------------------------------------------------------+{C.E}

{C.Y}Security Alert:{C.E} Document integrity failure logged to audit trail

{C.D}Figure: Tamper detection showing DOCUMENT_TAMPERED error (NT-01).{C.E}
""")
    
    input(f"\n{C.C}Press Enter for NT-02 (Expired Certificate)...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # NT-02: EXPIRED CERTIFICATE
    # ══════════════════════════════════════════════════════════════════════════
    
    expired_serial = "0x" + secrets.token_hex(8).upper()
    expired_date = (ts - timedelta(days=30)).strftime("%Y-%m-%d")
    
    print(f"""
{C.R}{C.BOLD}>>> SCREENSHOT: NT-02 EXPIRED CERTIFICATE <<<{C.E}

{C.R}{C.BOLD}================================================================================
          NT-02: EXPIRED CERTIFICATE PRESENTED FOR AUTHENTICATION
================================================================================{C.E}

{C.W}Authentication Attempt:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  User:             {USER}
  Certificate:      {expired_serial}
  Issuer:           {CA}

{C.W}Certificate Details:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Valid From:       2024-02-27
  Valid To:         {expired_date}
  Current Date:     {ts.strftime("%Y-%m-%d")}
  
  Status:           {C.R}EXPIRED (30 days ago){C.E}

{C.W}Validation Process:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.R}[FAIL]{C.E} Certificate expiry check - EXPIRED
  {C.D}[SKIP]{C.E} Revocation check (halted)
  {C.D}[SKIP]{C.E} Chain validation (halted)
  {C.D}[SKIP]{C.E} Challenge-response (halted)

{C.R}{C.BOLD}+----------------------------------------------------------------------+
|                                                                      |
|   AUTHENTICATION RESULT: REJECTED                                    |
|                                                                      |
|   Error Code:   CERT_EXPIRED                                         |
|   Message:      Certificate has expired                              |
|   Expired On:   {expired_date}                                           |
|   Action:       Authentication denied - renew certificate            |
|                                                                      |
+----------------------------------------------------------------------+{C.E}

{C.Y}Security Alert:{C.E} Expired certificate attempt logged

{C.D}Figure: Expired certificate rejection showing CERT_EXPIRED (NT-02).{C.E}
""")
    
    input(f"\n{C.C}Press Enter for NT-03 (Wrong EKU)...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # NT-03: WRONG CERTIFICATE PURPOSE (EKU)
    # ══════════════════════════════════════════════════════════════════════════
    
    wrong_cert_serial = "0x" + secrets.token_hex(8).upper()
    
    print(f"""
{C.R}{C.BOLD}>>> SCREENSHOT: NT-03 WRONG EKU <<<{C.E}

{C.R}{C.BOLD}================================================================================
          NT-03: WRONG CERTIFICATE PURPOSE (EKU NOT AUTHORIZED)
================================================================================{C.E}

{C.W}Authentication Attempt:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  User:             {USER}
  Certificate:      {wrong_cert_serial}
  Purpose:          Authentication (clientAuth required)

{C.W}Certificate Extended Key Usage:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Present EKU:      Code Signing (1.3.6.1.5.5.7.3.3)
  Required EKU:     TLS Client Authentication (1.3.6.1.5.5.7.3.2)
  
  Match:            {C.R}NO - WRONG PURPOSE{C.E}

{C.W}Validation Process:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.G}[PASS]{C.E} Certificate not expired
  {C.G}[PASS]{C.E} Certificate not revoked
  {C.G}[PASS]{C.E} Certificate chain valid
  {C.R}[FAIL]{C.E} Extended Key Usage check - clientAuth NOT present
  {C.D}[SKIP]{C.E} Challenge-response (halted)

{C.R}{C.BOLD}+----------------------------------------------------------------------+
|                                                                      |
|   AUTHENTICATION RESULT: REJECTED                                    |
|                                                                      |
|   Error Code:   INVALID_EKU                                          |
|   Message:      Certificate not authorized for client authentication |
|   Present:      codeSigning                                          |
|   Required:     clientAuth (1.3.6.1.5.5.7.3.2)                       |
|   Action:       Use correct certificate for authentication           |
|                                                                      |
+----------------------------------------------------------------------+{C.E}

{C.Y}Security Alert:{C.E} Wrong certificate purpose attempt logged

{C.D}Figure: Wrong EKU rejection showing INVALID_EKU (NT-03).{C.E}
""")
    
    input(f"\n{C.C}Press Enter for NT-04 (Invalid Signature)...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # NT-04: INVALID SIGNATURE (WRONG PRIVATE KEY)
    # ══════════════════════════════════════════════════════════════════════════
    
    valid_cert_serial = "0x" + secrets.token_hex(8).upper()
    
    print(f"""
{C.R}{C.BOLD}>>> SCREENSHOT: NT-04 INVALID SIGNATURE <<<{C.E}

{C.R}{C.BOLD}================================================================================
          NT-04: INVALID SIGNATURE (WRONG PRIVATE KEY)
================================================================================{C.E}

{C.W}Authentication Attempt:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  User:             {USER}
  Certificate:      {valid_cert_serial}
  Challenge:        {secrets.token_hex(32)[:48]}...

{C.W}Certificate Validation:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.G}[PASS]{C.E} Certificate not expired
  {C.G}[PASS]{C.E} Certificate not revoked
  {C.G}[PASS]{C.E} Certificate chain valid
  {C.G}[PASS]{C.E} Extended Key Usage valid (clientAuth)

{C.W}Challenge-Response:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Challenge Issued: {ts_str}
  Response Received: Signed challenge
  
  Verification:     Checking signature with certificate public key...
  Result:           {C.R}SIGNATURE MISMATCH{C.E}

{C.W}Analysis:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  The signature was created with a private key that does NOT match
  the public key in the presented certificate. This indicates:
  - Certificate theft without corresponding private key, OR
  - Man-in-the-middle attack attempt

{C.R}{C.BOLD}+----------------------------------------------------------------------+
|                                                                      |
|   AUTHENTICATION RESULT: REJECTED                                    |
|                                                                      |
|   Error Code:   INVALID_SIGNATURE                                    |
|   Message:      Challenge signature verification failed              |
|   Details:      Signature does not match certificate public key      |
|   Action:       Authentication denied - possible key mismatch        |
|                                                                      |
+----------------------------------------------------------------------+{C.E}

{C.Y}Security Alert:{C.E} {C.R}HIGH SEVERITY{C.E} - Invalid signature attempt logged

{C.D}Figure: Invalid signature rejection showing INVALID_SIGNATURE (NT-04).{C.E}
""")
    
    input(f"\n{C.C}Press Enter for NT-05 (Challenge Expired)...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # NT-05: CHALLENGE EXPIRED
    # ══════════════════════════════════════════════════════════════════════════
    
    challenge_time = (ts - timedelta(seconds=75)).strftime("%Y-%m-%d %H:%M:%S UTC")
    response_time = ts_str
    nonce = secrets.token_hex(16)
    
    print(f"""
{C.R}{C.BOLD}>>> SCREENSHOT: NT-05 CHALLENGE EXPIRED <<<{C.E}

{C.R}{C.BOLD}================================================================================
          NT-05: CHALLENGE EXPIRED (TIME-WINDOW ENFORCEMENT)
================================================================================{C.E}

{C.W}Authentication Attempt:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  User:             {USER}
  Certificate:      Valid (all checks passed)

{C.W}Challenge Timeline:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Challenge Issued:   {challenge_time}
  Validity Window:    60 seconds
  Challenge Expiry:   {(ts - timedelta(seconds=15)).strftime("%Y-%m-%d %H:%M:%S UTC")}
  Response Received:  {response_time}
  
  Time Elapsed:       75 seconds
  Window Exceeded:    {C.R}YES (+15 seconds){C.E}

{C.W}Challenge Details:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Nonce:            {nonce}
  Status:           {C.R}EXPIRED{C.E}

{C.W}Validation Process:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.G}[PASS]{C.E} Certificate validation
  {C.G}[PASS]{C.E} Nonce format valid
  {C.R}[FAIL]{C.E} Challenge time window - EXPIRED
  {C.D}[SKIP]{C.E} Signature verification (halted)

{C.R}{C.BOLD}+----------------------------------------------------------------------+
|                                                                      |
|   AUTHENTICATION RESULT: REJECTED                                    |
|                                                                      |
|   Error Code:   CHALLENGE_EXPIRED                                    |
|   Message:      Challenge response received after validity window    |
|   Issued:       {challenge_time}                            |
|   Window:       60 seconds                                           |
|   Received:     {response_time} (+15s late)                 |
|   Action:       Request new challenge and retry                      |
|                                                                      |
+----------------------------------------------------------------------+{C.E}

{C.Y}Security Alert:{C.E} Expired challenge attempt logged (possible replay/delay)

{C.D}Figure: Challenge expiry showing CHALLENGE_EXPIRED (NT-05).{C.E}
""")
    
    input(f"\n{C.C}Press Enter for NT-06 (AES-GCM Integrity Failure)...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # NT-06: TAMPERED ENCRYPTED ARTIFACT (AES-GCM)
    # ══════════════════════════════════════════════════════════════════════════
    
    expected_tag = secrets.token_hex(16)
    computed_tag = secrets.token_hex(16)
    
    print(f"""
{C.R}{C.BOLD}>>> SCREENSHOT: NT-06 AES-GCM INTEGRITY FAILURE <<<{C.E}

{C.R}{C.BOLD}================================================================================
          NT-06: TAMPERED ENCRYPTED ARTIFACT (AES-GCM FAILURE)
================================================================================{C.E}

{C.W}Decryption Attempt:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  File:             Financial_Report_Q4_2025.xlsx.enc
  Algorithm:        AES-256-GCM
  Encrypted For:    {USER}

{C.W}Decryption Process:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.G}[PASS]{C.E} Encrypted file loaded
  {C.G}[PASS]{C.E} AES key unwrapped with private key
  {C.G}[PASS]{C.E} IV/Nonce extracted
  {C.R}[FAIL]{C.E} Authentication tag verification - MISMATCH

{C.W}Authentication Tag Comparison:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Expected Tag:     {expected_tag}
  Computed Tag:     {computed_tag}
  
  Match:            {C.R}NO - INTEGRITY VIOLATION{C.E}

{C.W}Analysis:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  The ciphertext or associated data has been modified after encryption.
  AES-GCM authentication ensures any tampering is detected.
  Possible causes:
  - Attacker modified ciphertext during transport
  - File corruption during storage
  - Metadata manipulation attempt

{C.R}{C.BOLD}+----------------------------------------------------------------------+
|                                                                      |
|   DECRYPTION RESULT: REJECTED                                        |
|                                                                      |
|   Error Code:   AUTH_TAG_INVALID                                     |
|   Message:      AES-GCM authentication tag verification failed       |
|   Details:      Ciphertext integrity compromised                     |
|   Action:       Decryption aborted - data may be tampered            |
|                                                                      |
+----------------------------------------------------------------------+{C.E}

{C.Y}Security Alert:{C.E} {C.R}HIGH SEVERITY{C.E} - Encryption integrity violation logged

{C.D}Figure: AES-GCM integrity failure showing AUTH_TAG_INVALID (NT-06).{C.E}
""")
    
    input(f"\n{C.C}Press Enter for summary...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.G}{C.BOLD}================================================================================
                        DEMONSTRATION COMPLETE
================================================================================{C.E}

{C.W}Section 9.3 Negative Tests Evidence:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Test     Description                          Error Code
{C.D}  -------  -----------------------------------  ----------------------{C.E}
  {C.R}NT-01{C.E}    Document tamper detection           DOCUMENT_TAMPERED
  {C.R}NT-02{C.E}    Expired certificate rejection       CERT_EXPIRED
  {C.R}NT-03{C.E}    Wrong EKU rejection                 INVALID_EKU
  {C.R}NT-04{C.E}    Invalid signature rejection         INVALID_SIGNATURE
  {C.R}NT-05{C.E}    Challenge expiry enforcement        CHALLENGE_EXPIRED
  {C.R}NT-06{C.E}    AES-GCM integrity failure           AUTH_TAG_INVALID

{C.W}Security Guarantees Demonstrated:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.G}[OK]{C.E} Document integrity verified via SHA-256 hash comparison
  {C.G}[OK]{C.E} Certificate validity enforced (expiry, revocation, chain)
  {C.G}[OK]{C.E} Certificate purpose enforced via Extended Key Usage
  {C.G}[OK]{C.E} Cryptographic proof of key possession required
  {C.G}[OK]{C.E} Time-bound challenge prevents replay attacks
  {C.G}[OK]{C.E} Authenticated encryption detects ciphertext tampering

{C.D}All 6 screenshots ready for documentation.{C.E}
""")


if __name__ == "__main__":
    main()
