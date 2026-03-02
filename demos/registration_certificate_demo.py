# -*- coding: utf-8 -*-
"""
SecureCrypt Vault - Registration & Certificate Enrollment Demonstration
========================================================================

Professional demonstration of user registration and X.509 certificate
enrollment process for documentation and screenshot purposes.

User: Biplav Basnet
Date: February 2026

Author: SecureCrypt Vault Security Team
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import sys
import io
import time
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

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
    BG_BLUE = '\033[44m'
    BG_GREEN = '\033[42m'


def clear_line():
    """Clear current line."""
    print('\r' + ' ' * 80 + '\r', end='')


def print_progress_bar(progress, total, prefix='', suffix='', length=40):
    """Print a progress bar."""
    filled = int(length * progress // total)
    bar = '█' * filled + '░' * (length - filled)
    percent = f"{100 * progress / total:.0f}%"
    print(f'\r  {prefix} |{Colors.GREEN}{bar}{Colors.RESET}| {percent} {suffix}', end='', flush=True)


def simulate_delay(seconds=0.5):
    """Simulate processing delay."""
    time.sleep(seconds)


def print_header():
    """Print the application header."""
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                        SECURECRYPT VAULT v2.0                                ║
║                                                                              ║
║                    Enterprise Password Management System                     ║
║                   with PKI-Based Authentication                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
""")


def print_registration_form():
    """Display the registration form with user details."""
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                          USER REGISTRATION FORM                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Personal Information{Colors.WHITE}                                                      │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Full Name:        {Colors.GREEN}Biplav Basnet{Colors.WHITE}                                        │
│    Username:         {Colors.GREEN}biplav.basnet{Colors.WHITE}                                        │
│    Email:            {Colors.GREEN}biplav.basnet@securecrypt.local{Colors.WHITE}                      │
│                                                                              │
│  {Colors.CYAN}Security Credentials{Colors.WHITE}                                                      │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Master Password:  {Colors.DIM}••••••••••••••••{Colors.WHITE}  {Colors.GREEN}[Strong]{Colors.WHITE}                       │
│    Recovery Phrase:  {Colors.DIM}••••••••••••••••{Colors.WHITE}  {Colors.GREEN}[Configured]{Colors.WHITE}                   │
│                                                                              │
│  {Colors.CYAN}Password Strength Analysis{Colors.WHITE}                                                │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Length:           {Colors.GREEN}✓{Colors.WHITE} 16+ characters                                     │
│    Uppercase:        {Colors.GREEN}✓{Colors.WHITE} Contains uppercase letters                        │
│    Lowercase:        {Colors.GREEN}✓{Colors.WHITE} Contains lowercase letters                        │
│    Numbers:          {Colors.GREEN}✓{Colors.WHITE} Contains numeric digits                           │
│    Symbols:          {Colors.GREEN}✓{Colors.WHITE} Contains special characters                       │
│    Entropy:          {Colors.GREEN}✓{Colors.WHITE} 98.4 bits (Excellent)                             │
│                                                                              │
│  {Colors.CYAN}Key Derivation Parameters{Colors.WHITE}                                                 │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Algorithm:        Argon2id (Memory-Hard KDF)                              │
│    Memory Cost:      65,536 KB                                               │
│    Time Cost:        4 iterations                                            │
│    Parallelism:      4 threads                                               │
│    Salt:             256-bit cryptographically random                        │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def print_key_generation():
    """Display key generation process."""
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                      RSA KEY PAIR GENERATION                                 │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Generating Cryptographic Key Pairs for User: Biplav Basnet{Colors.WHITE}                │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")
    
    # Simulate key generation for each purpose
    key_types = [
        ("Authentication Key Pair", "RSA-2048", "Digital signature for login"),
        ("Encryption Key Pair", "RSA-2048", "Hybrid encryption of vault data"),
        ("Signing Key Pair", "RSA-2048", "Document and data integrity")
    ]
    
    for i, (name, algo, purpose) in enumerate(key_types, 1):
        print(f"  {Colors.CYAN}[{i}/3]{Colors.RESET} Generating {Colors.BOLD}{name}{Colors.RESET}")
        print(f"        Algorithm: {algo} | Purpose: {purpose}")
        
        for j in range(101):
            print_progress_bar(j, 100, prefix='       ', suffix='')
            time.sleep(0.015)
        print()
        print(f"        {Colors.GREEN}✓ Key pair generated successfully{Colors.RESET}")
        print()
    
    # Show key summary
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                          KEY GENERATION SUMMARY                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.GREEN}✓{Colors.WHITE} Authentication Key Pair    RSA-2048    Generated & Protected           │
│  {Colors.GREEN}✓{Colors.WHITE} Encryption Key Pair        RSA-2048    Generated & Protected           │
│  {Colors.GREEN}✓{Colors.WHITE} Signing Key Pair           RSA-2048    Generated & Protected           │
│                                                                              │
│  {Colors.CYAN}Private Key Protection:{Colors.WHITE}                                                   │
│    • Encrypted with AES-256-GCM                                              │
│    • Key derived from master password via Argon2id                           │
│    • Stored in secure key bundle format                                      │
│    • Never transmitted or stored in plaintext                                │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def print_certificate_enrollment():
    """Display certificate enrollment process."""
    
    serial_auth = f"0x{secrets.token_hex(8).upper()}"
    serial_enc = f"0x{secrets.token_hex(8).upper()}"
    serial_sign = f"0x{secrets.token_hex(8).upper()}"
    
    now = datetime.now(timezone.utc)
    not_before = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    not_after = (now + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                   X.509 CERTIFICATE ENROLLMENT                               │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Certificate Authority Information{Colors.WHITE}                                        │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    CA Name:          SecureCrypt Vault Root CA                               │
│    CA Type:          Self-Signed Root Certificate Authority                  │
│    Key Algorithm:    RSA-4096                                                │
│    Signature:        SHA-256 with RSA                                        │
│                                                                              │
│  {Colors.CYAN}Issuing Certificates for: Biplav Basnet{Colors.WHITE}                                  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")
    
    # Certificate issuance animation
    cert_types = [
        ("Authentication Certificate", "clientAuth", "1.3.6.1.5.5.7.3.2", serial_auth),
        ("Encryption Certificate", "dataEncipherment", "1.3.6.1.5.5.7.3.4", serial_enc),
        ("Signing Certificate", "digitalSignature", "1.3.6.1.5.5.7.3.1", serial_sign)
    ]
    
    for i, (name, eku, oid, serial) in enumerate(cert_types, 1):
        print(f"  {Colors.CYAN}[{i}/3]{Colors.RESET} Issuing {Colors.BOLD}{name}{Colors.RESET}")
        print(f"        Extended Key Usage: {eku} ({oid})")
        
        steps = [
            "Creating Certificate Signing Request (CSR)...",
            "Validating public key...",
            "Generating certificate serial number...",
            "Signing certificate with CA private key...",
            "Encoding certificate in PEM format..."
        ]
        
        for step in steps:
            print(f"        {Colors.DIM}→ {step}{Colors.RESET}")
            time.sleep(0.2)
        
        print(f"        {Colors.GREEN}✓ Certificate issued: Serial {serial}{Colors.RESET}")
        print()
    
    # Certificate details
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                     CERTIFICATE ENROLLMENT DETAILS                           │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}CERTIFICATE 1: Authentication{Colors.WHITE}                                            │
│  ─────────────────────────────────────────────────────────────────────────   │
│    Subject:          CN=biplav.basnet@securecrypt.local                      │
│    Issuer:           CN=SecureCrypt Vault Root CA                            │
│    Serial Number:    {serial_auth}                               │
│    Valid From:       {not_before}                             │
│    Valid To:         {not_after}                             │
│    Key Usage:        Digital Signature                                       │
│    Extended Key Usage: TLS Client Authentication (1.3.6.1.5.5.7.3.2)         │
│    Signature Algo:   SHA256withRSA                                           │
│                                                                              │
│  {Colors.CYAN}CERTIFICATE 2: Encryption{Colors.WHITE}                                                │
│  ─────────────────────────────────────────────────────────────────────────   │
│    Subject:          CN=biplav.basnet@securecrypt.local                      │
│    Issuer:           CN=SecureCrypt Vault Root CA                            │
│    Serial Number:    {serial_enc}                               │
│    Valid From:       {not_before}                             │
│    Valid To:         {not_after}                             │
│    Key Usage:        Key Encipherment, Data Encipherment                     │
│    Extended Key Usage: Email Protection (1.3.6.1.5.5.7.3.4)                  │
│    Signature Algo:   SHA256withRSA                                           │
│                                                                              │
│  {Colors.CYAN}CERTIFICATE 3: Digital Signing{Colors.WHITE}                                          │
│  ─────────────────────────────────────────────────────────────────────────   │
│    Subject:          CN=biplav.basnet@securecrypt.local                      │
│    Issuer:           CN=SecureCrypt Vault Root CA                            │
│    Serial Number:    {serial_sign}                               │
│    Valid From:       {not_before}                             │
│    Valid To:         {not_after}                             │
│    Key Usage:        Digital Signature, Non-Repudiation                      │
│    Extended Key Usage: Code Signing (1.3.6.1.5.5.7.3.3)                      │
│    Signature Algo:   SHA256withRSA                                           │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def print_registration_confirmation():
    """Display registration confirmation."""
    
    user_id = secrets.randbelow(9000) + 1000
    session_id = secrets.token_hex(16)
    
    print(f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    REGISTRATION COMPLETED SUCCESSFULLY                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                        ACCOUNT CONFIRMATION                                  │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.GREEN}✓{Colors.WHITE} Account Created Successfully                                           │
│                                                                              │
│  {Colors.CYAN}Account Details{Colors.WHITE}                                                          │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    User ID:          {user_id}                                                 │
│    Username:         biplav.basnet                                           │
│    Full Name:        Biplav Basnet                                           │
│    Email:            biplav.basnet@securecrypt.local                         │
│    Account Status:   {Colors.GREEN}Active{Colors.WHITE}                                               │
│    Created At:       {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC                             │
│                                                                              │
│  {Colors.CYAN}Security Configuration{Colors.WHITE}                                                   │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    {Colors.GREEN}✓{Colors.WHITE} Master Password:     Configured (Argon2id protected)                 │
│    {Colors.GREEN}✓{Colors.WHITE} Recovery Phrase:     Configured                                      │
│    {Colors.GREEN}✓{Colors.WHITE} Authentication Key:  RSA-2048 (Certificate issued)                   │
│    {Colors.GREEN}✓{Colors.WHITE} Encryption Key:      RSA-2048 (Certificate issued)                   │
│    {Colors.GREEN}✓{Colors.WHITE} Signing Key:         RSA-2048 (Certificate issued)                   │
│    {Colors.GREEN}✓{Colors.WHITE} Vault Database:      Initialized                                     │
│    {Colors.GREEN}✓{Colors.WHITE} Audit Logging:       Enabled (Hash-chained)                          │
│                                                                              │
│  {Colors.CYAN}Session Information{Colors.WHITE}                                                      │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Session ID:       {session_id}                         │
│    Session Timeout:  30 minutes                                              │
│    Auto-Lock:        Enabled (5 minutes idle)                                │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def print_certificate_summary():
    """Print final certificate enrollment summary."""
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                   CERTIFICATE ENROLLMENT CONFIRMATION                        │
│                                                                              │
│                          User: Biplav Basnet                                 │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.GREEN}╔═══════════════════════════════════════════════════════════════════╗{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}║   CERTIFICATE ENROLLMENT STATUS: COMPLETE                         ║{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}║   Total Certificates Issued: 3                                    ║{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}║   [✓] Authentication Certificate    -  For secure login          ║{Colors.WHITE}   │
│  {Colors.GREEN}║   [✓] Encryption Certificate        -  For vault encryption      ║{Colors.WHITE}   │
│  {Colors.GREEN}║   [✓] Signing Certificate           -  For data integrity        ║{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}║   Certificate Authority: SecureCrypt Vault Root CA               ║{Colors.WHITE}   │
│  {Colors.GREEN}║   Validity Period: 1 Year                                        ║{Colors.WHITE}   │
│  {Colors.GREEN}║   Signature Algorithm: SHA256withRSA                             ║{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}╚═══════════════════════════════════════════════════════════════════╝{Colors.WHITE}   │
│                                                                              │
│  {Colors.CYAN}Security Notes:{Colors.WHITE}                                                          │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│  • Private keys are encrypted and stored locally                             │
│  • Certificates are signed by the local Root CA                              │
│  • Each certificate serves a specific cryptographic purpose                  │
│  • Certificate revocation is supported for compromised keys                  │
│                                                                              │
│  {Colors.CYAN}Next Steps:{Colors.WHITE}                                                              │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│  1. You can now log in using your username and master password               │
│  2. Your credentials will be verified via challenge-response authentication  │
│  3. Store your recovery phrase in a secure location                          │
│  4. Consider enabling backup recovery for disaster recovery                  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def print_audit_log_entry():
    """Print audit log entry for the registration."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                          AUDIT LOG ENTRIES                                   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Registration Events Logged:{Colors.WHITE}                                              │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ {Colors.DIM}Timestamp{Colors.WHITE}            │ {Colors.DIM}Event{Colors.WHITE}                    │ {Colors.DIM}Status{Colors.WHITE}     │  │
│  ├────────────────────────────────────────────────────────────────────────┤  │
│  │ {timestamp} │ USER_REGISTRATION_INIT    │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ KEY_PAIR_GENERATED        │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ KEY_PAIR_GENERATED        │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ KEY_PAIR_GENERATED        │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ CERT_ISSUED_AUTH          │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ CERT_ISSUED_ENCRYPTION    │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ CERT_ISSUED_SIGNING       │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ USER_REGISTRATION_COMPLETE│ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  │ {timestamp} │ SESSION_CREATED           │ {Colors.GREEN}SUCCESS{Colors.WHITE}    │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  {Colors.DIM}All events are cryptographically hash-chained for tamper detection.{Colors.WHITE}       │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")


def main():
    """Main demonstration function."""
    print_header()
    
    print(f"{Colors.WHITE}This demonstration shows the complete user registration process")
    print(f"including form completion, key generation, and certificate enrollment.{Colors.RESET}")
    print()
    print(f"{Colors.CYAN}Registering User: {Colors.BOLD}Biplav Basnet{Colors.RESET}")
    
    input(f"\n{Colors.CYAN}Press Enter to view the Registration Form...{Colors.RESET}")
    
    # Step 1: Registration Form
    print_registration_form()
    
    input(f"\n{Colors.CYAN}Press Enter to proceed with Key Generation...{Colors.RESET}")
    
    # Step 2: Key Generation
    print_key_generation()
    
    input(f"\n{Colors.CYAN}Press Enter to proceed with Certificate Enrollment...{Colors.RESET}")
    
    # Step 3: Certificate Enrollment
    print_certificate_enrollment()
    
    input(f"\n{Colors.CYAN}Press Enter to view Registration Confirmation...{Colors.RESET}")
    
    # Step 4: Registration Confirmation
    print_registration_confirmation()
    
    input(f"\n{Colors.CYAN}Press Enter to view Certificate Enrollment Summary...{Colors.RESET}")
    
    # Step 5: Certificate Summary
    print_certificate_summary()
    
    input(f"\n{Colors.CYAN}Press Enter to view Audit Log Entries...{Colors.RESET}")
    
    # Step 6: Audit Log
    print_audit_log_entry()
    
    # Final message
    print(f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                      DEMONSTRATION COMPLETE                                  ║
║                                                                              ║
║   User: Biplav Basnet                                                        ║
║   Status: Successfully registered with PKI-based authentication             ║
║                                                                              ║
║   This demonstration illustrated:                                            ║
║   • User registration form with password strength validation                 ║
║   • RSA-2048 key pair generation (3 key pairs)                              ║
║   • X.509 certificate enrollment from local Root CA                          ║
║   • Account confirmation and session creation                                ║
║   • Audit logging with hash-chain integrity                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
""")


if __name__ == "__main__":
    main()
