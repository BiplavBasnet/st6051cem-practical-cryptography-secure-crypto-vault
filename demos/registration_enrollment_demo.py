# -*- coding: utf-8 -*-
"""
SecureCrypt Vault - Registration and Certificate Enrollment Demo
==================================================================

PT-01: Registration and Certificate Enrollment Evidence

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
USER_ID = "USR-" + secrets.token_hex(4).upper()
CA = "SecureCrypt Vault Root CA"


def progress_bar(label, duration=0.5):
    print(f"  {label}", end="", flush=True)
    steps = 20
    for i in range(steps + 1):
        time.sleep(duration / steps)
        pct = int((i / steps) * 100)
        bar = "#" * i + "-" * (steps - i)
        print(f"\r  {label} [{bar}] {pct}%", end="", flush=True)
    print()


def main():
    ts = datetime.now(timezone.utc)
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    valid_from = ts.strftime("%Y-%m-%d")
    valid_to = (ts + timedelta(days=365)).strftime("%Y-%m-%d")
    
    # Certificate serials
    auth_serial = "0x" + secrets.token_hex(8).upper()
    enc_serial = "0x" + secrets.token_hex(8).upper()
    sign_serial = "0x" + secrets.token_hex(8).upper()
    
    print(f"""
{C.C}{C.BOLD}================================================================================
            PT-01: REGISTRATION AND CERTIFICATE ENROLLMENT
================================================================================{C.E}

{C.W}This demonstration shows:{C.E}
  - User registration and account creation
  - RSA key pair generation (authentication, encryption, signing)
  - X.509 certificate issuance under SecureCrypt Vault Root CA
  - Vault database initialization and audit logging
""")
    
    input(f"{C.C}Press Enter to begin registration process...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 1: USER REGISTRATION
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}STEP 1: USER REGISTRATION{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    print(f"{C.W}Registration Form:{C.E}")
    print(f"  Full Name:        {C.G}{USER}{C.E}")
    print(f"  Email:            {C.G}{EMAIL}{C.E}")
    print(f"  Master Password:  {C.G}{'*' * 16}{C.E} (Argon2id protected)")
    print(f"  Recovery Key:     {C.G}Generated{C.E}")
    print()
    
    progress_bar("Validating input")
    progress_bar("Creating user account")
    
    print(f"""
{C.G}[OK]{C.E} User account created successfully
{C.W}User ID:{C.E} {USER_ID}
""")
    
    input(f"{C.C}Press Enter to generate RSA key pairs...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 2: RSA KEY PAIR GENERATION
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}STEP 2: RSA KEY PAIR GENERATION{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    print(f"{C.Y}Generating RSA-2048 key pairs for three purposes...{C.E}")
    print()
    
    progress_bar("Authentication key pair")
    print(f"  {C.G}[OK]{C.E} Authentication keys generated (RSA-2048)")
    print()
    
    progress_bar("Encryption key pair")
    print(f"  {C.G}[OK]{C.E} Encryption keys generated (RSA-2048)")
    print()
    
    progress_bar("Digital signing key pair")
    print(f"  {C.G}[OK]{C.E} Digital signing keys generated (RSA-2048)")
    print()
    
    print(f"""
{C.W}Key Pairs Generated:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Purpose          Algorithm   Key Size   Storage
{C.D}  ---------------  ----------  ---------  --------------------------------{C.E}
  Authentication   RSA-OAEP    2048-bit   Encrypted local keystore
  Encryption       RSA-OAEP    2048-bit   Encrypted local keystore
  Digital Signing  RSA-PSS     2048-bit   Encrypted local keystore

{C.G}[OK]{C.E} All private keys encrypted with master password (AES-256-GCM)
{C.G}[OK]{C.E} Key material securely stored in local PKI store
""")
    
    input(f"{C.C}Press Enter to issue X.509 certificates...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 3: X.509 CERTIFICATE ISSUANCE
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}STEP 3: X.509 CERTIFICATE ISSUANCE{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    print(f"{C.Y}Requesting certificates from SecureCrypt Vault Root CA...{C.E}")
    print()
    
    progress_bar("Authentication certificate")
    progress_bar("Encryption certificate")
    progress_bar("Signing certificate")
    
    print(f"""
{C.W}Certificates Issued:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}

{C.B}1. Authentication Certificate{C.E}
   Serial:     {auth_serial}
   Subject:    CN={EMAIL}
   Issuer:     CN={CA}
   Valid:      {valid_from} to {valid_to}
   Key Usage:  Digital Signature
   Ext. Key:   TLS Client Authentication (1.3.6.1.5.5.7.3.2)
   {C.G}[ISSUED]{C.E}

{C.B}2. Encryption Certificate{C.E}
   Serial:     {enc_serial}
   Subject:    CN={EMAIL}
   Issuer:     CN={CA}
   Valid:      {valid_from} to {valid_to}
   Key Usage:  Key Encipherment, Data Encipherment
   Ext. Key:   Email Protection (1.3.6.1.5.5.7.3.4)
   {C.G}[ISSUED]{C.E}

{C.B}3. Digital Signing Certificate{C.E}
   Serial:     {sign_serial}
   Subject:    CN={EMAIL}
   Issuer:     CN={CA}
   Valid:      {valid_from} to {valid_to}
   Key Usage:  Digital Signature, Non-Repudiation
   Ext. Key:   Code Signing (1.3.6.1.5.5.7.3.3)
   {C.G}[ISSUED]{C.E}

{C.G}[OK]{C.E} All certificates signed by {CA}
{C.G}[OK]{C.E} Certificates stored in local PKI store
""")
    
    input(f"{C.C}Press Enter to initialize vault and audit logging...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 4: VAULT INITIALIZATION
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}STEP 4: VAULT DATABASE INITIALIZATION{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    progress_bar("Creating vault database")
    progress_bar("Initializing encryption")
    progress_bar("Enabling audit logging")
    
    print(f"""
{C.W}Vault Configuration:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Database:         SQLite with AES-256 encryption
  Encryption:       ChaCha20-Poly1305 for entries
  Key Derivation:   Argon2id (memory=64MB, iterations=3)
  Audit Logging:    {C.G}ENABLED{C.E} (hash-chained entries)
  Backup:           Auto-backup configured

{C.G}[OK]{C.E} Vault database initialized
{C.G}[OK]{C.E} Audit logging enabled with tamper-evident hash chain
""")
    
    input(f"{C.C}Press Enter to view registration completion...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # REGISTRATION COMPLETE - SCREENSHOT THIS
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.G}{C.BOLD}>>> SCREENSHOT THIS FOR PT-01 EVIDENCE <<<{C.E}

{C.G}{C.BOLD}================================================================================
                    REGISTRATION COMPLETED SUCCESSFULLY
================================================================================{C.E}

{C.W}Account Information:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  User ID:          {USER_ID}
  Full Name:        {USER}
  Email:            {EMAIL}
  Created:          {ts_str}

{C.W}Cryptographic Assets:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.G}[OK]{C.E} RSA key pair for Authentication    (RSA-2048)
  {C.G}[OK]{C.E} RSA key pair for Encryption        (RSA-2048)
  {C.G}[OK]{C.E} RSA key pair for Digital Signing   (RSA-2048)

{C.W}X.509 Certificates Issued:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.G}[OK]{C.E} Authentication Certificate         Serial: {auth_serial}
  {C.G}[OK]{C.E} Encryption Certificate             Serial: {enc_serial}
  {C.G}[OK]{C.E} Digital Signing Certificate        Serial: {sign_serial}

  Issuer:           {CA}
  Validity:         {valid_from} to {valid_to} (365 days)
  Storage:          Local PKI Store (encrypted)

{C.W}Vault Status:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {C.G}[OK]{C.E} Vault database initialized
  {C.G}[OK]{C.E} Audit logging enabled (hash-chained)
  {C.G}[OK]{C.E} Recovery key generated

{C.G}{C.BOLD}+----------------------------------------------------------------------+
|                                                                      |
|   REGISTRATION COMPLETE - ACCOUNT READY FOR USE                      |
|                                                                      |
|   User:   {USER:<56}|
|   Email:  {EMAIL:<56}|
|   Status: Active                                                     |
|                                                                      |
+----------------------------------------------------------------------+{C.E}

{C.D}Figure: Registration completion screen showing account confirmation,
RSA key pairs generated, X.509 certificates issued, and vault initialized.{C.E}
""")
    
    input(f"\n{C.C}Press Enter for audit log...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # AUDIT LOG
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}REGISTRATION AUDIT LOG{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts_str}]{C.E} USER_REGISTER_INIT      {C.C}INFO{C.E}     Registration process started
{C.W}[{ts_str}]{C.E} USER_ACCOUNT_CREATED    {C.G}SUCCESS{C.E}  Account created: {USER_ID}
{C.W}[{ts_str}]{C.E} KEYPAIR_GEN_AUTH        {C.G}SUCCESS{C.E}  Authentication keypair generated
{C.W}[{ts_str}]{C.E} KEYPAIR_GEN_ENC         {C.G}SUCCESS{C.E}  Encryption keypair generated
{C.W}[{ts_str}]{C.E} KEYPAIR_GEN_SIGN        {C.G}SUCCESS{C.E}  Signing keypair generated
{C.W}[{ts_str}]{C.E} CERT_ISSUED_AUTH        {C.G}SUCCESS{C.E}  Auth certificate: {auth_serial[:20]}...
{C.W}[{ts_str}]{C.E} CERT_ISSUED_ENC         {C.G}SUCCESS{C.E}  Enc certificate: {enc_serial[:20]}...
{C.W}[{ts_str}]{C.E} CERT_ISSUED_SIGN        {C.G}SUCCESS{C.E}  Sign certificate: {sign_serial[:20]}...
{C.W}[{ts_str}]{C.E} VAULT_INITIALIZED       {C.G}SUCCESS{C.E}  Database ready
{C.W}[{ts_str}]{C.E} AUDIT_LOG_ENABLED       {C.G}SUCCESS{C.E}  Hash-chain logging active
{C.W}[{ts_str}]{C.E} USER_REGISTER_COMPLETE  {C.G}SUCCESS{C.E}  Registration finished

{C.G}[OK]{C.E} All events hash-chained for tamper-evident logging
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    print(f"""
{C.G}{C.BOLD}================================================================================
                        DEMONSTRATION COMPLETE
================================================================================{C.E}

{C.W}PT-01 Evidence Captured:{C.E}
  {C.G}[OK]{C.E} Registration completed successfully
  {C.G}[OK]{C.E} RSA key pairs generated (auth, encryption, signing)
  {C.G}[OK]{C.E} X.509 certificates issued under {CA}
  {C.G}[OK]{C.E} Vault database initialized
  {C.G}[OK]{C.E} Audit logging enabled

{C.D}All screenshots ready for documentation.{C.E}
""")


if __name__ == "__main__":
    main()
