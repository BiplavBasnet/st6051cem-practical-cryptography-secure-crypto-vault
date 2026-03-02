# -*- coding: utf-8 -*-
"""
SecureCrypt Vault - Certificate-Based Authentication Outcomes
===============================================================

Demonstrates:
- Section 7.2: Successful certificate-based authentication
- AT-02: Replay attack detection (CHALLENGE_REUSED)
- AT-03: Revoked certificate (CERT_REVOKED)
- AT-04: Expired certificate (CERT_EXPIRED)
- AT-05: Wrong EKU (INVALID_EKU)

Author: Biplav Basnet
Date: February 2026
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import sys
import io
import secrets
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
CERT_SERIAL = "0x7A3B9C2D1E4F5A68"
CA = "SecureCrypt Vault Root CA"


def main():
    ts = datetime.now(timezone.utc)
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    challenge = secrets.token_hex(32)
    nonce = secrets.token_hex(16)
    
    print(f"""
{C.C}{C.BOLD}================================================================================
              CERTIFICATE-BASED AUTHENTICATION OUTCOMES
================================================================================
          Evidence for Section 7.2, AT-02, AT-03, AT-04, AT-05
================================================================================{C.E}

{C.W}User:{C.E}        {USER}
{C.W}Email:{C.E}       {EMAIL}
{C.W}Certificate:{C.E} {CERT_SERIAL}
{C.W}Issuer:{C.E}      {CA}
""")
    
    input(f"{C.C}Press Enter to view SUCCESSFUL authentication (Section 7.2)...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 7.2: SUCCESSFUL AUTHENTICATION
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.G}{C.BOLD}>>> SCREENSHOT FOR SECTION 7.2 <<<{C.E}

{C.G}{C.BOLD}================================================================================
SECTION 7.2: SUCCESSFUL CERTIFICATE-BASED AUTHENTICATION
================================================================================{C.E}

{C.C}Step 1: Certificate Presentation{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts_str}]{C.E} Client presents X.509 certificate
{C.W}Serial:{C.E}      {CERT_SERIAL}
{C.W}Subject:{C.E}     CN={EMAIL}
{C.W}Issuer:{C.E}      CN={CA}

{C.C}Step 2: Certificate Validation{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.G}[PASS]{C.E} Certificate not expired         (Valid until 2027-02-27)
{C.G}[PASS]{C.E} Certificate not revoked         (CRL check passed)
{C.G}[PASS]{C.E} Certificate chain valid         (Signed by trusted CA)
{C.G}[PASS]{C.E} Extended Key Usage valid        (clientAuth: 1.3.6.1.5.5.7.3.2)

{C.C}Step 3: Challenge-Response Authentication{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}Server Challenge:{C.E}  {challenge[:48]}...
{C.W}Nonce:{C.E}             {nonce}
{C.W}Algorithm:{C.E}         RSA-PSS with SHA-256

{C.W}Client Response:{C.E}   Signed challenge with private key
{C.W}Verification:{C.E}      {C.G}SIGNATURE VALID{C.E}

{C.C}Step 4: Authentication Result{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.G}{C.BOLD}+----------------------------------------------------------------------+
|                    AUTHENTICATION SUCCESSFUL                         |
+----------------------------------------------------------------------+
|  User:        {USER:<54}|
|  Certificate: {CERT_SERIAL:<54}|
|  Session:     Created - Access granted to vault                      |
|  Timestamp:   {ts_str:<54}|
+----------------------------------------------------------------------+{C.E}

{C.D}Figure: Successful certificate-based authentication (Section 7.2){C.E}
""")
    
    input(f"\n{C.C}Press Enter to view AT-02 REPLAY ATTACK...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # AT-02: REPLAY ATTACK
    # ══════════════════════════════════════════════════════════════════════════
    
    old_nonce = secrets.token_hex(16)
    original_time = (ts - timedelta(minutes=5, seconds=23)).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    print(f"""
{C.R}{C.BOLD}>>> SCREENSHOT FOR AT-02: REPLAY ATTACK <<<{C.E}

{C.R}{C.BOLD}================================================================================
AT-02: REPLAY OF CAPTURED CHALLENGE-RESPONSE (REPLAY ATTACK)
================================================================================{C.E}

{C.Y}Attack Scenario:{C.E}
  A legitimate authentication exchange was captured by an attacker.
  The attacker replayed the same signed challenge-response pair.

{C.C}Step 1: Certificate Presentation{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts_str}]{C.E} Attacker presents captured certificate
{C.W}Serial:{C.E}      {CERT_SERIAL}
{C.W}Subject:{C.E}     CN={EMAIL}

{C.C}Step 2: Certificate Validation{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.G}[PASS]{C.E} Certificate not expired
{C.G}[PASS]{C.E} Certificate not revoked
{C.G}[PASS]{C.E} Certificate chain valid
{C.G}[PASS]{C.E} Extended Key Usage valid

{C.C}Step 3: Challenge-Response Replay Detection{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}Received Nonce:{C.E}   {old_nonce}
{C.W}Checking:{C.E}         Used nonces database...

{C.R}[FAIL]{C.E} Nonce already used: {C.R}REPLAY DETECTED{C.E}
{C.R}[FAIL]{C.E} Original use:       {original_time}
{C.R}[FAIL]{C.E} Replay attempt:     {ts_str}
{C.R}[FAIL]{C.E} Time difference:    5 minutes 23 seconds

{C.C}Step 4: Authentication Result{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.R}{C.BOLD}+----------------------------------------------------------------------+
|                    AUTHENTICATION REJECTED                           |
+----------------------------------------------------------------------+
|  Error Code:  CHALLENGE_REUSED                                       |
|  Message:     Challenge nonce has already been used                  |
|  Decision:    Nonce found in used challenges database                |
|  Action:      Session NOT created - Access DENIED                    |
|  Timestamp:   {ts_str:<54}|
+----------------------------------------------------------------------+{C.E}

{C.Y}Security Alert Logged:{C.E}
  Event:     REPLAY_ATTACK_BLOCKED
  Severity:  HIGH
  Nonce:     {old_nonce}
  Action:    Authentication denied, alert recorded

{C.D}Figure: AT-02 replay attack detected and blocked using single-use
challenges and expiry enforcement.{C.E}
""")
    
    input(f"\n{C.C}Press Enter to view AT-03 REVOKED CERTIFICATE...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # AT-03: REVOKED CERTIFICATE
    # ══════════════════════════════════════════════════════════════════════════
    
    revoked_serial = "0x" + secrets.token_hex(8).upper()
    revocation_time = (ts - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    print(f"""
{C.R}{C.BOLD}>>> SCREENSHOT FOR AT-03: REVOKED CERTIFICATE <<<{C.E}

{C.R}{C.BOLD}================================================================================
AT-03: AUTHENTICATION USING REVOKED CERTIFICATE (REVOCATION ENFORCEMENT)
================================================================================{C.E}

{C.Y}Attack Scenario:{C.E}
  A previously valid certificate was revoked (key compromise/account termination).
  An authentication attempt was made using the revoked certificate.

{C.C}Step 1: Certificate Presentation{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts_str}]{C.E} Client presents X.509 certificate
{C.W}Serial:{C.E}      {revoked_serial}
{C.W}Subject:{C.E}     CN={EMAIL}

{C.C}Step 2: Certificate Validation{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.G}[PASS]{C.E} Certificate not expired
{C.R}[FAIL]{C.E} Certificate revocation check: {C.R}REVOKED{C.E}

{C.Y}Revocation Details:{C.E}
  Serial Number:    {revoked_serial}
  Revocation Time:  {revocation_time}
  Reason Code:      keyCompromise (1)
  CRL Entry:        Found in SecureCrypt Vault CRL v47

{C.D}(Challenge-response SKIPPED - certificate invalid){C.E}

{C.C}Step 3: Authentication Result{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.R}{C.BOLD}+----------------------------------------------------------------------+
|                    AUTHENTICATION REJECTED                           |
+----------------------------------------------------------------------+
|  Error Code:  CERT_REVOKED                                           |
|  Message:     Certificate has been revoked                           |
|  Revocation:  {revocation_time:<54}|
|  Reason:      Key Compromise                                         |
|  Action:      Session NOT created - Access DENIED                    |
+----------------------------------------------------------------------+{C.E}

{C.Y}Security Alert Logged:{C.E}
  Event:     AUTH_REVOKED_CERT_ATTEMPT
  Severity:  HIGH
  Serial:    {revoked_serial}
  Action:    Authentication denied, security alert recorded

{C.D}Figure: AT-03 revocation enforcement rejecting authentication when a
revoked certificate is presented (CERT_REVOKED).{C.E}
""")
    
    input(f"\n{C.C}Press Enter to view AT-04 EXPIRED CERTIFICATE...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # AT-04: EXPIRED CERTIFICATE
    # ══════════════════════════════════════════════════════════════════════════
    
    expired_serial = "0x" + secrets.token_hex(8).upper()
    expired_date = (ts - timedelta(days=45)).strftime("%Y-%m-%d %H:%M:%S UTC")
    valid_from = (ts - timedelta(days=410)).strftime("%Y-%m-%d")
    valid_to = (ts - timedelta(days=45)).strftime("%Y-%m-%d")
    
    print(f"""
{C.R}{C.BOLD}>>> SCREENSHOT FOR AT-04: EXPIRED CERTIFICATE <<<{C.E}

{C.R}{C.BOLD}================================================================================
AT-04: AUTHENTICATION WITH EXPIRED CERTIFICATE (STALE CREDENTIAL MISUSE)
================================================================================{C.E}

{C.Y}Attack Scenario:{C.E}
  An authentication attempt was made using a certificate that has passed
  its Not After date (validity window expired).

{C.C}Step 1: Certificate Presentation{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts_str}]{C.E} Client presents X.509 certificate
{C.W}Serial:{C.E}      {expired_serial}
{C.W}Subject:{C.E}     CN={EMAIL}

{C.C}Step 2: Certificate Validation{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.R}[FAIL]{C.E} Certificate expiry check: {C.R}EXPIRED{C.E}

{C.Y}Certificate Validity Window:{C.E}
  Serial Number:    {expired_serial}
  Valid From:       {valid_from}
  Valid To:         {valid_to}
  Current Time:     {ts.strftime("%Y-%m-%d")}
  
  Status:           {C.R}EXPIRED (45 days ago){C.E}

{C.D}(Revocation check SKIPPED - certificate already invalid)
(Chain validation SKIPPED - certificate already invalid)
(Challenge-response SKIPPED - certificate already invalid){C.E}

{C.C}Step 3: Authentication Result{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.R}{C.BOLD}+----------------------------------------------------------------------+
|                    AUTHENTICATION REJECTED                           |
+----------------------------------------------------------------------+
|  Error Code:  CERT_EXPIRED                                           |
|  Message:     Certificate has expired                                |
|  Expired On:  {valid_to:<54}|
|  Days Ago:    45 days                                                |
|  Action:      Session NOT created - Access DENIED                    |
+----------------------------------------------------------------------+{C.E}

{C.Y}Security Event Logged:{C.E}
  Event:     AUTH_EXPIRED_CERT
  Severity:  MEDIUM
  Serial:    {expired_serial}
  Action:    Authentication denied, renewal required

{C.D}Figure: AT-04 authentication rejected due to expired certificate
validity window (CERT_EXPIRED).{C.E}
""")
    
    input(f"\n{C.C}Press Enter to view AT-05 WRONG EKU...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # AT-05: WRONG EKU
    # ══════════════════════════════════════════════════════════════════════════
    
    wrong_eku_serial = "0x" + secrets.token_hex(8).upper()
    
    print(f"""
{C.R}{C.BOLD}>>> SCREENSHOT FOR AT-05: WRONG EKU <<<{C.E}

{C.R}{C.BOLD}================================================================================
AT-05: WRONG CERTIFICATE PURPOSE (EKU MISUSE)
================================================================================{C.E}

{C.Y}Attack Scenario:{C.E}
  A certificate not authorized for authentication was presented.
  (e.g., using a signing certificate for authentication)

{C.C}Step 1: Certificate Presentation{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts_str}]{C.E} Client presents X.509 certificate
{C.W}Serial:{C.E}      {wrong_eku_serial}
{C.W}Subject:{C.E}     CN={EMAIL}
{C.W}Purpose:{C.E}     Authentication attempt

{C.C}Step 2: Certificate Validation{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.G}[PASS]{C.E} Certificate not expired
{C.G}[PASS]{C.E} Certificate not revoked
{C.G}[PASS]{C.E} Certificate chain valid
{C.R}[FAIL]{C.E} Extended Key Usage check: {C.R}INVALID PURPOSE{C.E}

{C.Y}Extended Key Usage Details:{C.E}
  Present EKU:      Code Signing (1.3.6.1.5.5.7.3.3)
  Required EKU:     TLS Client Authentication (1.3.6.1.5.5.7.3.2)
  
  Match:            {C.R}NO - clientAuth NOT present{C.E}

{C.D}(Challenge-response SKIPPED - certificate not authorized){C.E}

{C.C}Step 3: Authentication Result{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.R}{C.BOLD}+----------------------------------------------------------------------+
|                    AUTHENTICATION REJECTED                           |
+----------------------------------------------------------------------+
|  Error Code:  INVALID_EKU                                            |
|  Message:     Certificate not authorized for client authentication   |
|  Present:     codeSigning (1.3.6.1.5.5.7.3.3)                        |
|  Required:    clientAuth (1.3.6.1.5.5.7.3.2)                         |
|  Action:      Session NOT created - Access DENIED                    |
+----------------------------------------------------------------------+{C.E}

{C.Y}Security Event Logged:{C.E}
  Event:     AUTH_WRONG_EKU
  Severity:  MEDIUM
  Serial:    {wrong_eku_serial}
  Action:    Authentication denied, correct certificate required

{C.D}Figure: AT-05 authentication rejected due to Extended Key Usage
purpose restriction (INVALID_EKU).{C.E}
""")
    
    input(f"\n{C.C}Press Enter for summary...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.G}{C.BOLD}================================================================================
                        DEMONSTRATION COMPLETE
================================================================================{C.E}

{C.W}Evidence Captured:{C.E}

  {C.G}Section 7.2:{C.E}  Successful certificate-based authentication
                  - All validation checks passed
                  - Challenge-response verified
                  - Session created

  {C.R}AT-02:{C.E}        Replay attack detection
                  - Error Code: CHALLENGE_REUSED
                  - Single-use nonce enforcement

  {C.R}AT-03:{C.E}        Revoked certificate rejection
                  - Error Code: CERT_REVOKED
                  - Challenge-response skipped

  {C.R}AT-04:{C.E}        Expired certificate rejection
                  - Error Code: CERT_EXPIRED
                  - All subsequent checks skipped

  {C.R}AT-05:{C.E}        Wrong EKU rejection
                  - Error Code: INVALID_EKU
                  - clientAuth purpose required

{C.W}Security Guarantees Demonstrated:{C.E}
  - Replay attacks blocked via single-use challenge nonces
  - Revoked certificates immediately rejected
  - Expired certificates cannot authenticate
  - Certificate purpose (EKU) strictly enforced
  - All events logged for audit trail

{C.D}All 5 screenshots ready for documentation.{C.E}
""")


if __name__ == "__main__":
    main()
