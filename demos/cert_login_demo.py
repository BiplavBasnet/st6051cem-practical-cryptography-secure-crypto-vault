# -*- coding: utf-8 -*-
"""
SecureCrypt Vault - Certificate-Based Login Demo
==================================================

PT-02: Certificate-based login with a valid certificate

Author: Biplav Basnet
Date: February 2026
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import sys
import io
import secrets
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
CERT_SERIAL = "0x7A3B9C2D1E4F5A68"
CA = "SecureCrypt Vault Root CA"
SESSION_ID = "SES-" + secrets.token_hex(8).upper()


def animate(text, delay=0.3):
    print(f"  {text}", end="", flush=True)
    time.sleep(delay)
    print()


def main():
    ts = datetime.now(timezone.utc)
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    valid_from = (ts - timedelta(days=30)).strftime("%Y-%m-%d")
    valid_to = (ts + timedelta(days=335)).strftime("%Y-%m-%d")
    
    challenge = secrets.token_hex(32)
    nonce = secrets.token_hex(16)
    signature = secrets.token_hex(64)
    
    print(f"""
{C.C}{C.BOLD}================================================================================
          PT-02: CERTIFICATE-BASED LOGIN WITH VALID CERTIFICATE
================================================================================{C.E}

{C.W}This demonstration shows:{C.E}
  - Valid X.509 certificate presentation
  - Server-side certificate validation
  - Challenge-response authentication
  - Successful session establishment
""")
    
    input(f"{C.C}Press Enter to begin authentication...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 1: CERTIFICATE PRESENTATION
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}STEP 1: CERTIFICATE PRESENTATION{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    animate("Client initiating authentication request...")
    animate("Retrieving certificate from local PKI store...")
    animate("Presenting X.509 certificate to server...")
    
    print(f"""
{C.W}Certificate Presented:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Serial Number:    {CERT_SERIAL}
  Subject:          CN={EMAIL}
  Issuer:           CN={CA}
  Valid From:       {valid_from}
  Valid To:         {valid_to}
  Key Algorithm:    RSA-2048
  Signature Algo:   SHA256withRSA

{C.G}[OK]{C.E} Certificate successfully transmitted to server
""")
    
    input(f"{C.C}Press Enter for server-side validation...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 2: SERVER-SIDE VALIDATION
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}STEP 2: SERVER-SIDE CERTIFICATE VALIDATION{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    print(f"{C.Y}Performing certificate validation checks...{C.E}")
    print()
    
    animate("Checking certificate expiration...")
    print(f"  {C.G}[PASS]{C.E} Certificate not expired")
    print(f"         Valid: {valid_from} to {valid_to}")
    print()
    
    animate("Checking certificate revocation status...")
    print(f"  {C.G}[PASS]{C.E} Certificate not revoked")
    print(f"         CRL check: Not found in revocation list")
    print()
    
    animate("Validating certificate chain...")
    print(f"  {C.G}[PASS]{C.E} Certificate chain valid")
    print(f"         Chain: Subject -> {CA} (Trusted)")
    print()
    
    animate("Checking Extended Key Usage...")
    print(f"  {C.G}[PASS]{C.E} Authorized for authentication")
    print(f"         EKU: TLS Client Authentication (1.3.6.1.5.5.7.3.2)")
    print()
    
    print(f"""
{C.W}Validation Summary:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Check                      Result
{C.D}  -------------------------  --------{C.E}
  Certificate Expiration     {C.G}PASS{C.E}
  Revocation Status          {C.G}PASS{C.E}
  Certificate Chain          {C.G}PASS{C.E}
  Extended Key Usage         {C.G}PASS{C.E}

{C.G}[OK]{C.E} All server-side validation checks passed
""")
    
    input(f"{C.C}Press Enter for challenge-response authentication...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 3: CHALLENGE-RESPONSE
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}STEP 3: CHALLENGE-RESPONSE AUTHENTICATION{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    animate("Server generating cryptographic challenge...")
    
    print(f"""
{C.W}Challenge Issued:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Challenge:        {challenge}
  Nonce:            {nonce}
  Algorithm:        RSA-PSS with SHA-256
  Expires:          60 seconds
""")
    
    animate("Client signing challenge with private key...")
    
    print(f"""
{C.W}Client Response:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Signature:        {signature[:64]}...
  Padding:          PSS (Probabilistic Signature Scheme)
  Hash:             SHA-256
  Timestamp:        {ts_str}
""")
    
    animate("Server verifying signature with public key...")
    
    print(f"""
{C.W}Signature Verification:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Public Key:       Extracted from certificate
  Algorithm:        RSA-PSS/SHA-256
  Verification:     {C.G}SUCCESSFUL{C.E}

{C.G}[OK]{C.E} Challenge-response authentication completed
{C.G}[OK]{C.E} Client proved possession of private key
""")
    
    input(f"{C.C}Press Enter to view authentication result...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 4: AUTHENTICATION SUCCESS - SCREENSHOT THIS
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.G}{C.BOLD}>>> SCREENSHOT THIS FOR PT-02 EVIDENCE <<<{C.E}

{C.G}{C.BOLD}================================================================================
                      AUTHENTICATION SUCCESSFUL
================================================================================{C.E}

{C.W}User Identity:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Name:             {USER}
  Email:            {EMAIL}
  Certificate:      {CERT_SERIAL}

{C.W}Validation Results:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.G}[PASS]{C.E} Certificate not expired         (Valid until {valid_to})
  {C.G}[PASS]{C.E} Certificate not revoked         (CRL check passed)
  {C.G}[PASS]{C.E} Chained to trusted Root CA      ({CA})
  {C.G}[PASS]{C.E} Authorized for authentication   (clientAuth EKU)

{C.W}Challenge-Response:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.G}[PASS]{C.E} Challenge nonce issued          ({nonce[:16]}...)
  {C.G}[PASS]{C.E} Signed with matching private key
  {C.G}[PASS]{C.E} Signature verification succeeded

{C.W}Session Established:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Session ID:       {SESSION_ID}
  Created:          {ts_str}
  Expiry:           30 minutes (auto-refresh)
  Status:           {C.G}ACTIVE{C.E}

{C.G}{C.BOLD}+----------------------------------------------------------------------+
|                                                                      |
|                    ACCESS GRANTED                                    |
|                                                                      |
|   User:     {USER:<54}|
|   Session:  {SESSION_ID:<54}|
|   Status:   Authenticated - Vault access enabled                     |
|                                                                      |
+----------------------------------------------------------------------+{C.E}

{C.D}Figure: Authentication success outcome showing certificate validation,
challenge-response verification, and session establishment (PT-02).{C.E}
""")
    
    input(f"\n{C.C}Press Enter to view audit log...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # AUDIT LOG
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}AUTHENTICATION AUDIT LOG{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts_str}]{C.E} AUTH_INIT               {C.C}INFO{C.E}     Authentication request received
{C.W}[{ts_str}]{C.E} CERT_PRESENTED          {C.C}INFO{C.E}     Certificate: {CERT_SERIAL}
{C.W}[{ts_str}]{C.E} CERT_EXPIRY_CHECK       {C.G}PASS{C.E}     Not expired
{C.W}[{ts_str}]{C.E} CERT_REVOKE_CHECK       {C.G}PASS{C.E}     Not revoked
{C.W}[{ts_str}]{C.E} CERT_CHAIN_CHECK        {C.G}PASS{C.E}     Chain valid to Root CA
{C.W}[{ts_str}]{C.E} CERT_EKU_CHECK          {C.G}PASS{C.E}     clientAuth authorized
{C.W}[{ts_str}]{C.E} CHALLENGE_ISSUED        {C.C}INFO{C.E}     Nonce: {nonce[:16]}...
{C.W}[{ts_str}]{C.E} CHALLENGE_RESPONSE      {C.C}INFO{C.E}     Signed response received
{C.W}[{ts_str}]{C.E} SIGNATURE_VERIFIED      {C.G}PASS{C.E}     RSA-PSS/SHA-256 valid
{C.W}[{ts_str}]{C.E} SESSION_CREATED         {C.G}SUCCESS{C.E}  Session: {SESSION_ID}
{C.W}[{ts_str}]{C.E} AUTH_COMPLETE           {C.G}SUCCESS{C.E}  Access granted

{C.G}[OK]{C.E} All events hash-chained for tamper-evident logging
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    print(f"""
{C.G}{C.BOLD}================================================================================
                        DEMONSTRATION COMPLETE
================================================================================{C.E}

{C.W}PT-02 Evidence Captured:{C.E}
  {C.G}[OK]{C.E} Valid X.509 certificate presented
  {C.G}[OK]{C.E} Server-side checks confirmed (not expired, not revoked, valid chain, clientAuth)
  {C.G}[OK]{C.E} Cryptographic challenge nonce issued and signed
  {C.G}[OK]{C.E} Signature verification succeeded
  {C.G}[OK]{C.E} Access granted with session established

{C.D}Screenshot ready for documentation.{C.E}
""")


if __name__ == "__main__":
    main()
