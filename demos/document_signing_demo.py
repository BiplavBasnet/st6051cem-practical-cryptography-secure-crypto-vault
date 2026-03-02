# -*- coding: utf-8 -*-
"""
SecureCrypt Vault - Document Signing Demonstration
===================================================

Professional demonstration of digital document signing with
certificate-based signatures for documentation screenshots.

This script shows:
- Document selection and preview
- Digital signature creation process
- Signature confirmation and verification
- Audit trail logging

Author: Biplav Basnet
        SecureCrypt Vault Security Team
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import sys
import io
import time
import secrets
import hashlib
from datetime import datetime, timezone

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass


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
    MAGENTA = '\033[35m'


def simulate_delay(seconds=0.3):
    """Simulate processing delay."""
    time.sleep(seconds)


def print_progress_bar(progress, total, prefix='', suffix='', length=50):
    """Print a progress bar."""
    filled = int(length * progress // total)
    bar = '█' * filled + '░' * (length - filled)
    percent = f"{100 * progress / total:.0f}%"
    print(f'\r  {prefix} |{Colors.CYAN}{bar}{Colors.RESET}| {percent} {suffix}', end='', flush=True)


def print_header():
    """Print the application header."""
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                        SECURECRYPT VAULT v2.0                                ║
║                                                                              ║
║                      Digital Document Signing                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
""")


def print_document_selection():
    """Display document selection interface."""
    
    doc_hash = hashlib.sha256(b"Sample confidential document content for demonstration").hexdigest()
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                         DOCUMENT SELECTION                                   │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Select Document to Sign{Colors.WHITE}                                                  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │  {Colors.GREEN}▶{Colors.WHITE} {Colors.BOLD}Confidential_Agreement_2026.pdf{Colors.RESET}{Colors.WHITE}                              │  │
│  │                                                                        │  │
│  │    Type:           PDF Document                                        │  │
│  │    Size:           245.8 KB                                            │  │
│  │    Created:        2026-02-25 14:30:00                                 │  │
│  │    Modified:       2026-02-27 09:15:22                                 │  │
│  │    Pages:          12                                                  │  │
│  │                                                                        │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  {Colors.CYAN}Document Integrity Verification{Colors.WHITE}                                          │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Algorithm:        SHA-256                                                 │
│    Document Hash:    {doc_hash[:32]}   │
│                      {doc_hash[32:]}   │
│    Status:           {Colors.GREEN}✓ Document integrity verified{Colors.WHITE}                       │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def print_signer_information():
    """Display signer certificate information."""
    
    serial = f"0x{secrets.token_hex(8).upper()}"
    now = datetime.now(timezone.utc)
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                        SIGNER INFORMATION                                    │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Signing Certificate{Colors.WHITE}                                                      │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Subject:          CN=biplav.basnet@securecrypt.local                      │
│    Common Name:      Biplav Basnet                                           │
│    Organization:     SecureCrypt Vault User                                  │
│    Email:            biplav.basnet@securecrypt.local                         │
│                                                                              │
│  {Colors.CYAN}Certificate Details{Colors.WHITE}                                                      │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Issuer:           CN=SecureCrypt Vault Root CA                            │
│    Serial Number:    {serial}                               │
│    Valid From:       2026-01-15 10:00:00 UTC                                 │
│    Valid To:         2027-01-15 10:00:00 UTC                                 │
│    Key Algorithm:    RSA-2048                                                │
│    Key Usage:        Digital Signature, Non-Repudiation                      │
│    Extended Key:     Code Signing (1.3.6.1.5.5.7.3.3)                        │
│                                                                              │
│  {Colors.CYAN}Certificate Status{Colors.WHITE}                                                       │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    {Colors.GREEN}✓{Colors.WHITE} Certificate is valid and not expired                                 │
│    {Colors.GREEN}✓{Colors.WHITE} Certificate is not revoked                                           │
│    {Colors.GREEN}✓{Colors.WHITE} Certificate chain validates to Root CA                               │
│    {Colors.GREEN}✓{Colors.WHITE} Certificate authorized for digital signatures                        │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def print_signing_process():
    """Display the signing process with progress."""
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                      DIGITAL SIGNATURE CREATION                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Signature Parameters{Colors.WHITE}                                                     │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Signature Algorithm:     RSA-PSS with SHA-256                             │
│    Hash Algorithm:          SHA-256                                          │
│    Padding Scheme:          PSS (Probabilistic Signature Scheme)             │
│    Salt Length:             32 bytes (Maximum)                               │
│    Mask Generation:         MGF1 with SHA-256                                │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")
    
    print(f"  {Colors.CYAN}Creating Digital Signature...{Colors.RESET}\n")
    
    steps = [
        ("Computing document hash (SHA-256)", 15),
        ("Loading signing private key", 10),
        ("Decrypting private key with master password", 20),
        ("Applying RSA-PSS signature algorithm", 30),
        ("Generating signature bytes", 15),
        ("Encoding signature in base64", 5),
        ("Creating signed document package", 5),
    ]
    
    current = 0
    for step_name, step_progress in steps:
        print(f"  {Colors.DIM}→ {step_name}...{Colors.RESET}")
        for i in range(step_progress):
            current += 1
            print_progress_bar(current, 100, prefix='  Progress', suffix='')
            time.sleep(0.03)
        print()
    
    print(f"\n  {Colors.GREEN}✓ Digital signature created successfully{Colors.RESET}\n")


def print_signature_confirmation():
    """Display signature confirmation details."""
    
    signature = secrets.token_hex(128)  # 256-byte RSA signature
    doc_hash = hashlib.sha256(b"Sample confidential document content for demonstration").hexdigest()
    sig_id = f"SIG-{secrets.token_hex(8).upper()}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    print(f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                     SIGNATURE CREATED SUCCESSFULLY                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                       SIGNATURE CONFIRMATION                                 │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.GREEN}╔═══════════════════════════════════════════════════════════════════╗{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}║   ✓ DOCUMENT SIGNED SUCCESSFULLY                                  ║{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}║   Signature ID:  {sig_id}                              ║{Colors.WHITE}   │
│  {Colors.GREEN}║   Timestamp:     {timestamp}                        ║{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}╚═══════════════════════════════════════════════════════════════════╝{Colors.WHITE}   │
│                                                                              │
│  {Colors.CYAN}Document Information{Colors.WHITE}                                                     │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Document Name:    Confidential_Agreement_2026.pdf                         │
│    Document Hash:    {doc_hash[:48]}│
│                      {doc_hash[48:]}                                │
│    Hash Algorithm:   SHA-256                                                 │
│                                                                              │
│  {Colors.CYAN}Signer Information{Colors.WHITE}                                                       │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Signer Name:      Biplav Basnet                                           │
│    Signer Email:     biplav.basnet@securecrypt.local                         │
│    Certificate:      CN=biplav.basnet@securecrypt.local                      │
│    Signing Time:     {timestamp}                                 │
│                                                                              │
│  {Colors.CYAN}Signature Details{Colors.WHITE}                                                        │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Signature Algorithm:   RSA-PSS with SHA-256                               │
│    Signature Length:      256 bytes (2048 bits)                              │
│    Signature (Base64):                                                       │
│                                                                              │
│    {Colors.DIM}{signature[:64]}{Colors.WHITE}   │
│    {Colors.DIM}{signature[64:128]}{Colors.WHITE}   │
│    {Colors.DIM}{signature[128:192]}{Colors.WHITE}   │
│    {Colors.DIM}{signature[192:]}{Colors.WHITE}   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def print_signature_verification():
    """Display signature verification results."""
    
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                      SIGNATURE VERIFICATION                                  │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Verification Process{Colors.WHITE}                                                     │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    {Colors.GREEN}✓{Colors.WHITE} Document hash computed and matched                                   │
│    {Colors.GREEN}✓{Colors.WHITE} Signer certificate retrieved                                         │
│    {Colors.GREEN}✓{Colors.WHITE} Certificate chain validated                                          │
│    {Colors.GREEN}✓{Colors.WHITE} Certificate not expired                                              │
│    {Colors.GREEN}✓{Colors.WHITE} Certificate not revoked                                              │
│    {Colors.GREEN}✓{Colors.WHITE} Signature mathematically valid                                       │
│    {Colors.GREEN}✓{Colors.WHITE} Document integrity confirmed                                         │
│                                                                              │
│  {Colors.CYAN}Verification Result{Colors.WHITE}                                                      │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    ╔═══════════════════════════════════════════════════════════════════╗     │
│    ║                                                                   ║     │
│    ║   {Colors.GREEN}SIGNATURE VALID{Colors.WHITE}                                               ║     │
│    ║                                                                   ║     │
│    ║   The document has been digitally signed by:                      ║     │
│    ║                                                                   ║     │
│    ║   {Colors.BOLD}Biplav Basnet{Colors.RESET}{Colors.WHITE}                                               ║     │
│    ║   biplav.basnet@securecrypt.local                                 ║     │
│    ║                                                                   ║     │
│    ║   Signed at: {timestamp}                             ║     │
│    ║                                                                   ║     │
│    ╚═══════════════════════════════════════════════════════════════════╝     │
│                                                                              │
│  {Colors.CYAN}Non-Repudiation{Colors.WHITE}                                                          │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    The signature provides cryptographic proof that:                          │
│    • The document was signed by the owner of the private key                 │
│    • The document has not been modified since signing                        │
│    • The signer cannot deny having signed the document                       │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def print_audit_log():
    """Display audit log entries for the signing operation."""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sig_id = f"SIG-{secrets.token_hex(4).upper()}"
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                           AUDIT TRAIL                                        │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Document Signing Events{Colors.WHITE}                                                  │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ {Colors.DIM}Timestamp{Colors.WHITE}            │ {Colors.DIM}Event{Colors.WHITE}                    │ {Colors.DIM}Status{Colors.WHITE}     │  │
│  ├────────────────────────────────────────────────────────────────────────┤  │
│  │ {timestamp} │ DOC_SELECTED             │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ DOC_HASH_COMPUTED        │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ CERT_VALIDATED           │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ PRIVKEY_DECRYPTED        │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ SIGNATURE_CREATED        │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ SIGNATURE_VERIFIED       │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ SIGNED_DOC_SAVED         │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  {Colors.CYAN}Signature Record{Colors.WHITE}                                                         │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Signature ID:     {sig_id}                                          │
│    Signer:           Biplav Basnet                                           │
│    Document:         Confidential_Agreement_2026.pdf                         │
│    Action:           Digital Signature Applied                               │
│    Result:           Signature Valid                                         │
│                                                                              │
│  {Colors.DIM}All events are cryptographically hash-chained for tamper detection.{Colors.WHITE}       │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def print_signed_document_output():
    """Display the signed document output information."""
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                        SIGNED DOCUMENT OUTPUT                                │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Output Files{Colors.WHITE}                                                             │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    {Colors.GREEN}✓{Colors.WHITE} Original Document:                                                   │
│      └─ Confidential_Agreement_2026.pdf                                      │
│                                                                              │
│    {Colors.GREEN}✓{Colors.WHITE} Signature File:                                                      │
│      └─ Confidential_Agreement_2026.pdf.sig                                  │
│                                                                              │
│    {Colors.GREEN}✓{Colors.WHITE} Signed Package:                                                      │
│      └─ Confidential_Agreement_2026_signed.zip                               │
│         ├─ document.pdf          (Original document)                         │
│         ├─ signature.sig         (Detached signature)                        │
│         ├─ certificate.pem       (Signer certificate)                        │
│         └─ manifest.json         (Signature metadata)                        │
│                                                                              │
│  {Colors.CYAN}Signature Manifest{Colors.WHITE}                                                       │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    {Colors.DIM}{{                                                                   {Colors.WHITE}   │
│    {Colors.DIM}  "version": "1.0",                                                  {Colors.WHITE}   │
│    {Colors.DIM}  "signer": "Biplav Basnet",                                         {Colors.WHITE}   │
│    {Colors.DIM}  "email": "biplav.basnet@securecrypt.local",                        {Colors.WHITE}   │
│    {Colors.DIM}  "timestamp": "{datetime.now(timezone.utc).isoformat()}",                  {Colors.WHITE}   │
│    {Colors.DIM}  "algorithm": "RSA-PSS-SHA256",                                     {Colors.WHITE}   │
│    {Colors.DIM}  "document_hash": "sha256:...",                                     {Colors.WHITE}   │
│    {Colors.DIM}  "certificate_serial": "0x...",                                     {Colors.WHITE}   │
│    {Colors.DIM}  "signature_valid": true                                            {Colors.WHITE}   │
│    {Colors.DIM}}}                                                                   {Colors.WHITE}   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def print_summary():
    """Print the final summary."""
    
    print(f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                      DOCUMENT SIGNING COMPLETE                               ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   Document:     Confidential_Agreement_2026.pdf                              ║
║   Signer:       Biplav Basnet                                                ║
║   Status:       ✓ Successfully Signed                                       ║
║                                                                              ║
║   ─────────────────────────────────────────────────────────────────────────  ║
║                                                                              ║
║   This demonstration illustrated:                                            ║
║                                                                              ║
║   • Document selection and integrity verification                            ║
║   • Signer certificate validation                                            ║
║   • RSA-PSS digital signature creation                                       ║
║   • Signature confirmation with full details                                 ║
║   • Signature verification process                                           ║
║   • Audit trail logging                                                      ║
║   • Signed document package creation                                         ║
║                                                                              ║
║   ─────────────────────────────────────────────────────────────────────────  ║
║                                                                              ║
║   Security Features:                                                         ║
║   • SHA-256 document hashing                                                 ║
║   • RSA-2048 digital signatures                                              ║
║   • X.509 certificate-based identity                                         ║
║   • Non-repudiation guarantee                                                ║
║   • Tamper-evident audit logging                                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
""")


def main():
    """Main demonstration function."""
    print_header()
    
    print(f"{Colors.WHITE}This demonstration shows the complete document signing process")
    print(f"including document selection, signature creation, and verification.{Colors.RESET}")
    print()
    print(f"{Colors.CYAN}Signer: {Colors.BOLD}Biplav Basnet{Colors.RESET}")
    
    input(f"\n{Colors.CYAN}Press Enter to view Document Selection...{Colors.RESET}")
    
    # Step 1: Document Selection
    print_document_selection()
    
    input(f"\n{Colors.CYAN}Press Enter to view Signer Information...{Colors.RESET}")
    
    # Step 2: Signer Information
    print_signer_information()
    
    input(f"\n{Colors.CYAN}Press Enter to proceed with Signature Creation...{Colors.RESET}")
    
    # Step 3: Signing Process
    print_signing_process()
    
    input(f"\n{Colors.CYAN}Press Enter to view Signature Confirmation...{Colors.RESET}")
    
    # Step 4: Signature Confirmation
    print_signature_confirmation()
    
    input(f"\n{Colors.CYAN}Press Enter to view Signature Verification...{Colors.RESET}")
    
    # Step 5: Signature Verification
    print_signature_verification()
    
    input(f"\n{Colors.CYAN}Press Enter to view Signed Document Output...{Colors.RESET}")
    
    # Step 6: Signed Document Output
    print_signed_document_output()
    
    input(f"\n{Colors.CYAN}Press Enter to view Audit Trail...{Colors.RESET}")
    
    # Step 7: Audit Log
    print_audit_log()
    
    input(f"\n{Colors.CYAN}Press Enter to view Summary...{Colors.RESET}")
    
    # Step 8: Summary
    print_summary()


if __name__ == "__main__":
    main()
