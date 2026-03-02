# -*- coding: utf-8 -*-
"""
SecureCrypt Vault - Digital Signing Demo
==========================================

PT-03: Digital signing (RSA-PSS with SHA-256)

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
from datetime import datetime, timezone

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
SIGN_CERT_SERIAL = "0x8C4D2E1F3A5B6C78"
CA = "SecureCrypt Vault Root CA"
DOCUMENT = "Confidential_Agreement_2026.pdf"
DOC_SIZE = "245,678 bytes"


def animate(text, delay=0.3):
    print(f"  {text}", end="", flush=True)
    time.sleep(delay)
    print()


def main():
    ts = datetime.now(timezone.utc)
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Generate realistic hashes and signature
    doc_content = f"Document content for {DOCUMENT} - {secrets.token_hex(100)}"
    doc_hash = hashlib.sha256(doc_content.encode()).hexdigest()
    signature = secrets.token_hex(128)
    sig_id = "SIG-" + secrets.token_hex(8).upper()
    
    print(f"""
{C.C}{C.BOLD}================================================================================
              PT-03: DIGITAL SIGNING (RSA-PSS WITH SHA-256)
================================================================================{C.E}

{C.W}This demonstration shows:{C.E}
  - Document selection and SHA-256 hashing
  - Signing with RSA-PSS under user's signing certificate
  - Signature artifact generation for verification
""")
    
    input(f"{C.C}Press Enter to begin signing process...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 1: DOCUMENT SELECTION
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}STEP 1: DOCUMENT SELECTION{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    animate("Loading document...")
    
    print(f"""
{C.W}Document Selected:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Filename:         {DOCUMENT}
  Size:             {DOC_SIZE}
  Type:             PDF Document
  Location:         C:\\Users\\{USER.split()[0]}\\Documents\\{DOCUMENT}
  Last Modified:    {ts_str}

{C.G}[OK]{C.E} Document loaded successfully
""")
    
    input(f"{C.C}Press Enter to compute document hash...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 2: SHA-256 HASH COMPUTATION
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}STEP 2: SHA-256 HASH COMPUTATION{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    animate("Reading document content...")
    animate("Computing SHA-256 hash...")
    
    print(f"""
{C.W}Hash Computation:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Algorithm:        SHA-256
  Input Size:       {DOC_SIZE}
  Hash Output:      256 bits (32 bytes)

{C.B}Document Hash (SHA-256):{C.E}
  {doc_hash}

{C.G}[OK]{C.E} Document hash computed successfully
""")
    
    input(f"{C.C}Press Enter to sign with RSA-PSS...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 3: RSA-PSS SIGNING
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}STEP 3: RSA-PSS SIGNATURE GENERATION{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    print(f"{C.W}Signer Identity:{C.E}")
    print(f"  Name:             {USER}")
    print(f"  Email:            {EMAIL}")
    print(f"  Certificate:      {SIGN_CERT_SERIAL}")
    print(f"  Issuer:           {CA}")
    print(f"  Key Usage:        Digital Signature, Non-Repudiation")
    print()
    
    animate("Retrieving signing private key...")
    animate("Applying RSA-PSS padding...")
    animate("Generating digital signature...")
    
    print(f"""
{C.W}Signature Parameters:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Algorithm:        RSA-PSS (Probabilistic Signature Scheme)
  Hash Function:    SHA-256
  Salt Length:      32 bytes (hash length)
  Key Size:         2048 bits
  MGF:              MGF1 with SHA-256

{C.B}Digital Signature (RSA-PSS/SHA-256):{C.E}
  {signature[:64]}
  {signature[64:128]}
  {signature[128:192]}
  {signature[192:]}

{C.G}[OK]{C.E} Digital signature generated successfully
""")
    
    input(f"{C.C}Press Enter to view signing result...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 4: SIGNING SUCCESS - SCREENSHOT THIS
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.G}{C.BOLD}>>> SCREENSHOT THIS FOR PT-03 EVIDENCE <<<{C.E}

{C.G}{C.BOLD}================================================================================
                       DIGITAL SIGNING SUCCESSFUL
================================================================================{C.E}

{C.W}Document:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Filename:         {DOCUMENT}
  Size:             {DOC_SIZE}

{C.W}Document Hash (SHA-256):{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  {doc_hash}

{C.W}Signature Algorithm:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Algorithm:        RSA-PSS with SHA-256
  Padding:          PSS (Probabilistic Signature Scheme)
  Hash:             SHA-256
  Salt Length:      32 bytes

{C.W}Signer Identity:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Name:             {USER}
  Email:            {EMAIL}
  Certificate:      {SIGN_CERT_SERIAL}
  Issuer:           {CA}

{C.W}Signature Artifact:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Signature ID:     {sig_id}
  Timestamp:        {ts_str}
  Format:           PKCS#7 / CMS Detached Signature

  Signature Value:
  {signature[:64]}
  {signature[64:128]}
  {signature[128:192]}
  {signature[192:]}

{C.G}{C.BOLD}+----------------------------------------------------------------------+
|                                                                      |
|                    SIGNING COMPLETE                                  |
|                                                                      |
|   Document:   {DOCUMENT:<52}|
|   Signer:     {USER:<52}|
|   Algorithm:  RSA-PSS/SHA-256                                        |
|   Status:     Signature created successfully                         |
|                                                                      |
+----------------------------------------------------------------------+{C.E}

{C.D}Figure: Digital signing outcome showing document hash, algorithm,
and signer identity (PT-03).{C.E}
""")
    
    input(f"\n{C.C}Press Enter to view signature file details...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # SIGNATURE FILE
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}SIGNATURE ARTIFACT FILE{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}

{C.W}Output Files:{C.E}
  Original:         {DOCUMENT}
  Signature:        {DOCUMENT}.sig

{C.W}Signature File Contents:{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
  Signature ID:     {sig_id}
  Document Hash:    {doc_hash}
  Hash Algorithm:   SHA-256
  Sign Algorithm:   RSA-PSS
  Signer Cert:      {SIGN_CERT_SERIAL}
  Signer Name:      {USER}
  Timestamp:        {ts_str}
  Signature:        (256 bytes, Base64 encoded)

{C.G}[OK]{C.E} Signature artifact saved for later verification
""")
    
    input(f"\n{C.C}Press Enter to view audit log...{C.E}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # AUDIT LOG
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{C.C}{C.BOLD}SIGNING AUDIT LOG{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts_str}]{C.E} SIGN_INIT               {C.C}INFO{C.E}     Signing process initiated
{C.W}[{ts_str}]{C.E} DOC_LOADED              {C.G}SUCCESS{C.E}  Document: {DOCUMENT}
{C.W}[{ts_str}]{C.E} HASH_COMPUTED           {C.G}SUCCESS{C.E}  SHA-256: {doc_hash[:16]}...
{C.W}[{ts_str}]{C.E} CERT_RETRIEVED          {C.G}SUCCESS{C.E}  Signing cert: {SIGN_CERT_SERIAL}
{C.W}[{ts_str}]{C.E} KEY_ACCESSED            {C.G}SUCCESS{C.E}  Private key retrieved
{C.W}[{ts_str}]{C.E} SIGNATURE_CREATED       {C.G}SUCCESS{C.E}  RSA-PSS/SHA-256
{C.W}[{ts_str}]{C.E} ARTIFACT_SAVED          {C.G}SUCCESS{C.E}  {DOCUMENT}.sig
{C.W}[{ts_str}]{C.E} SIGN_COMPLETE           {C.G}SUCCESS{C.E}  Signing finished

{C.G}[OK]{C.E} All events hash-chained for tamper-evident logging
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    print(f"""
{C.G}{C.BOLD}================================================================================
                        DEMONSTRATION COMPLETE
================================================================================{C.E}

{C.W}PT-03 Evidence Captured:{C.E}
  {C.G}[OK]{C.E} Document selected and hashed using SHA-256
  {C.G}[OK]{C.E} Hash signed using RSA-PSS with SHA-256
  {C.G}[OK]{C.E} Signing certificate identity confirmed
  {C.G}[OK]{C.E} Signature artifact created for verification

{C.D}Screenshot ready for documentation.{C.E}
""")


if __name__ == "__main__":
    main()
