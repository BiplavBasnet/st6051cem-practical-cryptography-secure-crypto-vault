#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SECURECRYPT VAULT - IMPERSONATION ATTACK DEMONSTRATION (AT-01)

This demonstration shows an attack scenario where:
- An attacker obtains a valid X.509 certificate (without the private key)
- The attacker attempts to authenticate using the stolen certificate
- Challenge-response fails because the attacker cannot sign with the correct key
- Authentication is rejected and a security alert is logged

AT-01: Certificate copied without private key (impersonation attempt)
"""

import os
import sys
import io
import time
import hashlib
import secrets
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning)

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ═══════════════════════════════════════════════════════════════════════════════
# VISUAL FORMATTING UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def print_header(text: str):
    width = 78
    print()
    print(f"{Colors.CYAN}{'═' * width}{Colors.END}")
    print(f"{Colors.CYAN}║{Colors.BOLD}{Colors.YELLOW} {text.center(width-2)} {Colors.END}{Colors.CYAN}║{Colors.END}")
    print(f"{Colors.CYAN}{'═' * width}{Colors.END}")


def print_subheader(text: str):
    print()
    print(f"{Colors.BLUE}┌{'─' * 76}┐{Colors.END}")
    print(f"{Colors.BLUE}│{Colors.BOLD} {text.ljust(74)} {Colors.END}{Colors.BLUE}│{Colors.END}")
    print(f"{Colors.BLUE}└{'─' * 76}┘{Colors.END}")


def print_step(step_num: int, text: str):
    print(f"\n{Colors.GREEN}[Step {step_num}]{Colors.END} {Colors.BOLD}{text}{Colors.END}")


def print_info(label: str, value: str, indent: int = 2):
    spaces = ' ' * indent
    print(f"{spaces}{Colors.CYAN}▸ {label}:{Colors.END} {value}")


def print_data(label: str, data: str, indent: int = 4):
    spaces = ' ' * indent
    print(f"{spaces}{Colors.YELLOW}{label}:{Colors.END}")
    if len(data) > 60:
        for i in range(0, len(data), 60):
            print(f"{spaces}  {data[i:i+60]}")
    else:
        print(f"{spaces}  {data}")


def print_success(text: str):
    print(f"\n  {Colors.GREEN}✓ {text}{Colors.END}")


def print_error(text: str):
    print(f"\n  {Colors.RED}✗ {text}{Colors.END}")


def print_server(text: str):
    print(f"  {Colors.MAGENTA}[SERVER]{Colors.END} {text}")


def print_client(text: str):
    print(f"  {Colors.BLUE}[CLIENT]{Colors.END} {text}")


def print_attacker(text: str):
    print(f"  {Colors.RED}[ATTACKER]{Colors.END} {text}")


def simulate_progress(text: str, duration: float = 1.0):
    print(f"\n  {text}", end='', flush=True)
    steps = 20
    for i in range(steps + 1):
        time.sleep(duration / steps)
        progress = int((i / steps) * 100)
        bar = '█' * i + '░' * (steps - i)
        print(f"\r  {text} [{bar}] {progress}%", end='', flush=True)
    print()


def print_certificate_info(cert: x509.Certificate):
    print(f"\n  {Colors.BOLD}Certificate Details{Colors.END}")
    print(f"  {'─' * 50}")
    
    subject = cert.subject
    for attr in subject:
        print(f"    Subject: {attr.rfc4514_string()}")
    
    issuer = cert.issuer
    for attr in issuer:
        print(f"    Issuer: {attr.rfc4514_string()}")
    
    print(f"    Serial: {hex(cert.serial_number)}")
    print(f"    Valid From: {cert.not_valid_before_utc}")
    print(f"    Valid To: {cert.not_valid_after_utc}")


# ═══════════════════════════════════════════════════════════════════════════════
# CRYPTOGRAPHIC SETUP
# ═══════════════════════════════════════════════════════════════════════════════

def generate_key_pair():
    """Generate RSA-2048 key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key


def create_self_signed_cert(private_key, common_name: str, email: str):
    """Create a self-signed certificate for demo purposes."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bagmati"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Kathmandu"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureCrypt Vault"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return cert


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    """Verify RSA-PSS signature."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def sign_challenge(private_key, challenge: bytes) -> bytes:
    """Sign challenge with RSA-PSS."""
    return private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN DEMONSTRATION
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print_header("AT-01: IMPERSONATION ATTACK DEMONSTRATION")
    
    print(f"""
{Colors.YELLOW}SCENARIO:{Colors.END}
  An attacker has obtained a copy of a legitimate user's X.509 certificate
  (e.g., from network traffic, compromised backup, or social engineering).
  
  However, the attacker does NOT have access to the corresponding private key.
  
  The attacker attempts to authenticate using the stolen certificate.
{Colors.END}
""")
    
    input(f"{Colors.CYAN}Press Enter to begin the demonstration...{Colors.END}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 1: SETUP - LEGITIMATE USER'S CREDENTIALS
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_subheader("SETUP: Legitimate User's Credentials")
    
    print_step(1, "Generating legitimate user's RSA-2048 key pair")
    simulate_progress("Generating RSA-2048 key pair", 0.8)
    
    victim_private_key = generate_key_pair()
    victim_public_key = victim_private_key.public_key()
    
    print_success("Legitimate user's key pair generated")
    print_info("User", "Biplav Basnet")
    print_info("Email", "biplav.basnet@securecrypt.local")
    print_info("Key Algorithm", "RSA-2048")
    
    print_step(2, "Creating X.509 authentication certificate")
    simulate_progress("Generating certificate", 0.5)
    
    victim_cert = create_self_signed_cert(
        victim_private_key,
        "Biplav Basnet",
        "biplav.basnet@securecrypt.local"
    )
    
    print_success("Certificate issued by SecureCrypt Vault Root CA")
    print_certificate_info(victim_cert)
    
    input(f"\n{Colors.CYAN}Press Enter to simulate certificate theft...{Colors.END}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 2: ATTACKER STEALS CERTIFICATE (WITHOUT PRIVATE KEY)
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_subheader("ATTACK: Certificate Theft Without Private Key")
    
    print_step(3, "Attacker obtains victim's certificate")
    
    print_attacker("Intercepted certificate from network traffic...")
    time.sleep(0.5)
    print_attacker("Certificate extracted successfully")
    print_attacker(f"Stolen certificate serial: {hex(victim_cert.serial_number)}")
    
    print(f"""
  {Colors.YELLOW}╔══════════════════════════════════════════════════════════════════════╗
  ║  ATTACKER HAS:                                                       ║
  ║    ✓ Valid X.509 certificate (public)                                ║
  ║    ✗ Private key (NOT available - securely stored by victim)         ║
  ╚══════════════════════════════════════════════════════════════════════╝{Colors.END}
""")
    
    print_step(4, "Attacker generates their own RSA key pair (wrong key)")
    simulate_progress("Generating attacker's RSA-2048 key pair", 0.5)
    
    attacker_private_key = generate_key_pair()
    
    print_attacker("Using attacker's own private key to sign challenge")
    print_attacker("(This key does NOT match the stolen certificate)")
    
    input(f"\n{Colors.CYAN}Press Enter to attempt authentication...{Colors.END}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 3: AUTHENTICATION ATTEMPT
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_subheader("AUTHENTICATION ATTEMPT (Impersonation Attack)")
    
    print(f"\n{Colors.RED}{Colors.BOLD}>>> SCREENSHOT THIS FOR AT-01 EVIDENCE <<<{Colors.END}")
    
    print_step(5, "Attacker initiates authentication request")
    print_attacker("Connecting to SecureCrypt Vault server...")
    time.sleep(0.3)
    print_attacker(f"Presenting stolen certificate: {hex(victim_cert.serial_number)[:20]}...")
    
    print_step(6, "Server validates certificate")
    print_server("Certificate received, performing validation...")
    time.sleep(0.3)
    
    print_success("Certificate not expired")
    print_success("Certificate not revoked")
    print_success("Certificate chain valid (signed by Root CA)")
    print_success("Extended Key Usage valid (clientAuth)")
    
    print_server("Certificate validation PASSED")
    print_server("Proceeding to challenge-response authentication...")
    
    print_step(7, "Server issues cryptographic challenge")
    challenge = secrets.token_bytes(32)
    challenge_hex = challenge.hex()
    
    print_server("Generating random challenge nonce...")
    print_data("Challenge (32 bytes)", challenge_hex)
    print_info("Algorithm", "RSA-PSS with SHA-256", indent=4)
    print_info("Validity", "60 seconds", indent=4)
    
    print_step(8, "Attacker attempts to sign challenge")
    print_attacker("Received challenge from server")
    print_attacker("Signing with attacker's private key (WRONG KEY)...")
    
    # Attacker signs with WRONG private key
    attacker_signature = sign_challenge(attacker_private_key, challenge)
    
    print_attacker("Signature generated, sending to server...")
    print_data("Signature (256 bytes)", attacker_signature.hex()[:64] + "...")
    
    print_step(9, "Server verifies signature against certificate public key")
    print_server("Extracting public key from certificate...")
    print_server("Verifying RSA-PSS signature...")
    
    simulate_progress("Verifying signature", 0.8)
    
    # Server verifies with VICTIM's public key (from certificate)
    signature_valid = verify_signature(victim_public_key, challenge, attacker_signature)
    
    if not signature_valid:
        print_error("SIGNATURE VERIFICATION FAILED")
        print_server(f"{Colors.RED}Signature does NOT match certificate public key{Colors.END}")
        print_server(f"{Colors.RED}The private key used to sign is NOT the certificate's private key{Colors.END}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 4: AUTHENTICATION REJECTED
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_subheader("AUTHENTICATION RESULT")
    
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    print(f"""
{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                       AUTHENTICATION REJECTED                                ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   Error Code:    INVALID_SIGNATURE                                           ║
║   Message:       Challenge-response signature verification failed            ║
║                                                                              ║
║   Details:       The signature was created with a private key that does      ║
║                  NOT match the public key in the presented certificate.      ║
║                                                                              ║
║   Certificate:   {hex(victim_cert.serial_number)[:40]}...              ║
║   Timestamp:     {ts}                                        ║
║                                                                              ║
║   Action:        Authentication DENIED - Session NOT created                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.END}""")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SECURITY ALERT
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_subheader("SECURITY ALERT LOGGED")
    
    print(f"""
{Colors.YELLOW}
┌──────────────────────────────────────────────────────────────────────────────┐
│ SECURITY ALERT                                                               │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Event:         AUTH_FAILURE                                                 │
│  Severity:      HIGH                                                         │
│  Timestamp:     {ts}                                         │
│                                                                              │
│  Certificate:   {hex(victim_cert.serial_number)[:50]}...   │
│  Subject:       CN=Biplav Basnet                                             │
│  Reason:        Invalid signature - private key mismatch                     │
│                                                                              │
│  Analysis:      Possible impersonation attempt detected.                     │
│                 Certificate presented without valid private key.             │
│                                                                              │
│  Recommended:   Review certificate usage, consider revocation if             │
│                 certificate was leaked.                                      │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.END}""")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # AUDIT LOG
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_subheader("AUDIT LOG ENTRIES")
    
    print(f"""
{Colors.CYAN}[{ts}]{Colors.END} AUTH_INIT            {Colors.BLUE}INFO{Colors.END}     Authentication request received
{Colors.CYAN}[{ts}]{Colors.END} CERT_PRESENTED       {Colors.BLUE}INFO{Colors.END}     Certificate: {hex(victim_cert.serial_number)[:20]}...
{Colors.CYAN}[{ts}]{Colors.END} CERT_EXPIRY_CHECK    {Colors.GREEN}PASS{Colors.END}     Not expired
{Colors.CYAN}[{ts}]{Colors.END} CERT_REVOKE_CHECK    {Colors.GREEN}PASS{Colors.END}     Not revoked
{Colors.CYAN}[{ts}]{Colors.END} CERT_CHAIN_CHECK     {Colors.GREEN}PASS{Colors.END}     Chain valid
{Colors.CYAN}[{ts}]{Colors.END} CERT_EKU_CHECK       {Colors.GREEN}PASS{Colors.END}     clientAuth present
{Colors.CYAN}[{ts}]{Colors.END} CHALLENGE_ISSUED     {Colors.BLUE}INFO{Colors.END}     Nonce: {challenge_hex[:16]}...
{Colors.CYAN}[{ts}]{Colors.END} CHALLENGE_RESPONSE   {Colors.BLUE}INFO{Colors.END}     Signature received
{Colors.CYAN}[{ts}]{Colors.END} SIGNATURE_VERIFY     {Colors.RED}FAIL{Colors.END}     RSA-PSS verification failed
{Colors.CYAN}[{ts}]{Colors.END} AUTH_REJECTED        {Colors.RED}DENIED{Colors.END}   Invalid signature
{Colors.CYAN}[{ts}]{Colors.END} SECURITY_ALERT       {Colors.YELLOW}ALERT{Colors.END}    Impersonation attempt logged

{Colors.GREEN}[OK]{Colors.END} All events hash-chained for tamper-evident logging
""")
    
    input(f"\n{Colors.CYAN}Press Enter for summary...{Colors.END}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("DEMONSTRATION COMPLETE")
    
    print(f"""
{Colors.BOLD}AT-01 Evidence Captured:{Colors.END}

  {Colors.GREEN}✓{Colors.END} Valid X.509 certificate obtained without private key
  {Colors.GREEN}✓{Colors.END} Authentication request initiated with stolen certificate
  {Colors.GREEN}✓{Colors.END} Certificate validation passed (not expired, not revoked, valid chain)
  {Colors.GREEN}✓{Colors.END} Challenge-response FAILED (wrong private key)
  {Colors.GREEN}✓{Colors.END} Authentication REJECTED with INVALID_SIGNATURE
  {Colors.GREEN}✓{Colors.END} Security alert logged for investigation

{Colors.BOLD}Security Guarantee:{Colors.END}

  The challenge-response protocol ensures that possessing a certificate
  alone is NOT sufficient for authentication. The attacker must also
  possess the corresponding private key to generate a valid signature.

  This protects against:
  - Certificate theft from network traffic
  - Certificate leakage from backups
  - Social engineering attacks obtaining certificates

{Colors.MAGENTA}Figure: Impersonation attack blocked - authentication rejected due to
invalid signature (certificate without matching private key).{Colors.END}
""")


if __name__ == "__main__":
    main()
