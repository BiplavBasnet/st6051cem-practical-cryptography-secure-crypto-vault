#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SECURECRYPT VAULT - REGISTRATION DEMO

This demonstration shows the complete user registration process including:
- RSA-2048 Key Pair Generation
- CA-Signed Certificate Issuance for Three Key Purposes
- Argon2id Key Derivation for Master Password Protection

REGISTRATION - USER ENTERS CREDENTIALS TO TRIGGER RSA-2048 KEY PAIR GENERATION 
AND CA-SIGNED CERTIFICATE ISSUANCE FOR ALL THREE KEY PURPOSES.
"""

import os
import sys
import io
import warnings

# Suppress deprecation warnings for cleaner output
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Fix Windows console encoding for Unicode characters
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import time
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import argon2

# ═══════════════════════════════════════════════════════════════════════════════
# VISUAL FORMATTING UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    @staticmethod
    def disable():
        Colors.HEADER = ''
        Colors.BLUE = ''
        Colors.CYAN = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
        Colors.END = ''


def print_header(text: str):
    """Print a formatted header."""
    width = 78
    print()
    print(f"{Colors.CYAN}{'═' * width}{Colors.END}")
    print(f"{Colors.CYAN}║{Colors.BOLD}{Colors.YELLOW} {text.center(width-2)} {Colors.END}{Colors.CYAN}║{Colors.END}")
    print(f"{Colors.CYAN}{'═' * width}{Colors.END}")


def print_subheader(text: str):
    """Print a formatted subheader."""
    print()
    print(f"{Colors.BLUE}┌{'─' * 76}┐{Colors.END}")
    print(f"{Colors.BLUE}│{Colors.BOLD} {text.ljust(74)} {Colors.END}{Colors.BLUE}│{Colors.END}")
    print(f"{Colors.BLUE}└{'─' * 76}┘{Colors.END}")


def print_step(step_num: int, text: str):
    """Print a numbered step."""
    print(f"\n{Colors.GREEN}[Step {step_num}]{Colors.END} {Colors.BOLD}{text}{Colors.END}")


def print_info(label: str, value: str, indent: int = 2):
    """Print labeled information."""
    spaces = ' ' * indent
    print(f"{spaces}{Colors.CYAN}▸ {label}:{Colors.END} {value}")


def print_data(label: str, data: str, indent: int = 4):
    """Print data with label."""
    spaces = ' ' * indent
    print(f"{spaces}{Colors.YELLOW}{label}:{Colors.END}")
    # Split long data into multiple lines
    if len(data) > 60:
        for i in range(0, len(data), 60):
            print(f"{spaces}  {data[i:i+60]}")
    else:
        print(f"{spaces}  {data}")


def print_success(text: str):
    """Print success message."""
    print(f"\n  {Colors.GREEN}✓ {text}{Colors.END}")


def print_certificate_info(cert: x509.Certificate, purpose: str):
    """Print certificate details in a formatted way."""
    print(f"\n  {Colors.BOLD}Certificate for: {purpose}{Colors.END}")
    print(f"  {'─' * 50}")
    
    # Subject
    subject = cert.subject
    for attr in subject:
        print(f"    {Colors.CYAN}Subject {attr.oid._name}:{Colors.END} {attr.value}")
    
    # Issuer
    issuer = cert.issuer
    for attr in issuer:
        print(f"    {Colors.CYAN}Issuer {attr.oid._name}:{Colors.END} {attr.value}")
    
    # Validity
    print(f"    {Colors.CYAN}Valid From:{Colors.END} {cert.not_valid_before_utc}")
    print(f"    {Colors.CYAN}Valid Until:{Colors.END} {cert.not_valid_after_utc}")
    
    # Serial Number
    print(f"    {Colors.CYAN}Serial Number:{Colors.END} {cert.serial_number}")
    
    # Fingerprint
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    print(f"    {Colors.CYAN}SHA-256 Fingerprint:{Colors.END}")
    print(f"      {fingerprint[:32]}")
    print(f"      {fingerprint[32:]}")


def simulate_progress(text: str, duration: float = 1.0):
    """Simulate a progress bar."""
    print(f"\n  {text}", end='', flush=True)
    steps = 20
    for i in range(steps + 1):
        time.sleep(duration / steps)
        progress = int((i / steps) * 100)
        bar = '█' * i + '░' * (steps - i)
        print(f"\r  {text} [{bar}] {progress}%", end='', flush=True)
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# CRYPTOGRAPHIC OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def generate_rsa_keypair(key_size: int = 2048) -> tuple:
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def derive_key_argon2(password: str, salt: bytes = None) -> tuple:
    """Derive a key using Argon2id."""
    if salt is None:
        salt = secrets.token_bytes(16)
    
    # Argon2id parameters (tuned for security)
    hasher = argon2.PasswordHasher(
        time_cost=3,
        memory_cost=65536,  # 64 MB
        parallelism=4,
        hash_len=32,
        salt_len=16,
        type=argon2.Type.ID
    )
    
    # For demonstration, we'll use low-level API to show the derived key
    from argon2.low_level import hash_secret_raw, Type
    
    derived_key = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    
    return derived_key, salt


def create_root_ca() -> tuple:
    """Create a self-signed Root CA certificate."""
    # Generate CA key pair
    ca_private_key, ca_public_key = generate_rsa_keypair(2048)
    
    # CA subject/issuer
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureCrypt Vault"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureCrypt Root CA"),
    ])
    
    # Create self-signed CA certificate
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )
    
    return ca_private_key, ca_cert


def issue_certificate(
    ca_private_key,
    ca_cert: x509.Certificate,
    user_public_key,
    username: str,
    purpose: str
) -> x509.Certificate:
    """Issue a CA-signed certificate for a specific purpose."""
    
    # Map purpose to key usage and extended key usage
    if purpose == "authentication":
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extended_key_usage = x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH
        ])
        cn_suffix = "Auth"
        
    elif purpose == "signing":
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,  # Non-repudiation
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extended_key_usage = x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CODE_SIGNING,
            ExtendedKeyUsageOID.EMAIL_PROTECTION
        ])
        cn_suffix = "Signing"
        
    elif purpose == "encryption":
        key_usage = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extended_key_usage = x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.EMAIL_PROTECTION
        ])
        cn_suffix = "Encryption"
    else:
        raise ValueError(f"Unknown purpose: {purpose}")
    
    # User subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureCrypt Vault"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{username} - {cn_suffix}"),
    ])
    
    # Create and sign certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(key_usage, critical=True)
        .add_extension(extended_key_usage, critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(user_public_key),
            critical=False
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )
    
    return cert


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN DEMONSTRATION
# ═══════════════════════════════════════════════════════════════════════════════

def run_registration_demo():
    """Run the complete registration demonstration."""
    
    # Check if terminal supports colors
    if os.name == 'nt':
        os.system('')  # Enable ANSI on Windows
    
    print("\n" * 2)
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                                                                              ║")
    print("║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗ ██████╗██████╗ ██╗   ██╗ ║")
    print("║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝ ║")
    print("║   ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║     ██████╔╝ ╚████╔╝  ║")
    print("║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║     ██╔══██╗  ╚██╔╝   ║")
    print("║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗╚██████╗██║  ██║   ██║    ║")
    print("║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝    ║")
    print("║                                                                              ║")
    print("║                         VAULT REGISTRATION DEMO                              ║")
    print("║                                                                              ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.END}")
    
    print(f"\n{Colors.BOLD}{Colors.YELLOW}REGISTRATION — USER ENTERS CREDENTIALS TO TRIGGER RSA-2048 KEY PAIR GENERATION")
    print(f"AND CA-SIGNED CERTIFICATE ISSUANCE FOR ALL THREE KEY PURPOSES.{Colors.END}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 1: USER CREDENTIALS INPUT
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 1: USER CREDENTIAL INPUT")
    
    print(f"""
  The user provides their credentials to begin the registration process.
  These credentials will be used to derive cryptographic keys.
    """)
    
    # Simulated user input
    username = "alice_demo"
    email = "alice@example.com"
    master_password = "SecureP@ssw0rd!2024"
    
    print_info("Username", username)
    print_info("Email", email)
    print_info("Master Password", "••••••••••••••••••" + f" ({len(master_password)} characters)")
    
    print_success("Credentials received")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 2: MASTER PASSWORD KEY DERIVATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 2: ARGON2ID KEY DERIVATION")
    
    print(f"""
  The master password is processed through Argon2id, a memory-hard key
  derivation function that protects against GPU/ASIC cracking attacks.
    """)
    
    print_subheader("Argon2id Parameters")
    print_info("Algorithm", "Argon2id (hybrid of Argon2i and Argon2d)")
    print_info("Time Cost", "3 iterations")
    print_info("Memory Cost", "65,536 KB (64 MB)")
    print_info("Parallelism", "4 threads")
    print_info("Output Length", "256 bits (32 bytes)")
    print_info("Salt Length", "128 bits (16 bytes)")
    
    simulate_progress("Deriving key from master password...", 2.0)
    
    derived_key, salt = derive_key_argon2(master_password)
    
    print_data("Salt (hex)", salt.hex())
    print_data("Derived Key (hex)", derived_key.hex())
    
    print_success("Master key derived successfully")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 3: ROOT CA GENERATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 3: ROOT CA CERTIFICATE GENERATION")
    
    print(f"""
  A self-signed Root Certificate Authority (CA) is created for this
  installation. All user certificates will be signed by this CA.
    """)
    
    simulate_progress("Generating Root CA RSA-2048 key pair...", 1.5)
    
    ca_private_key, ca_cert = create_root_ca()
    
    print_subheader("Root CA Certificate Details")
    print_certificate_info(ca_cert, "Root Certificate Authority")
    
    print_success("Root CA created successfully")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 4: USER KEY PAIRS GENERATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 4: RSA-2048 KEY PAIR GENERATION (×3)")
    
    print(f"""
  Three separate RSA-2048 key pairs are generated for the user:
  
    1. AUTHENTICATION KEY  - For challenge-response login
    2. SIGNING KEY         - For document digital signatures  
    3. ENCRYPTION KEY      - For hybrid encryption of secrets
    """)
    
    key_purposes = ["authentication", "signing", "encryption"]
    user_keys = {}
    
    for i, purpose in enumerate(key_purposes, 1):
        print_subheader(f"Key Pair {i}/3: {purpose.upper()}")
        
        simulate_progress(f"Generating RSA-2048 key pair for {purpose}...", 1.0)
        
        private_key, public_key = generate_rsa_keypair(2048)
        user_keys[purpose] = (private_key, public_key)
        
        # Show key details
        pub_numbers = public_key.public_numbers()
        print_info("Key Size", "2048 bits")
        print_info("Public Exponent", str(pub_numbers.e))
        print_info("Modulus (first 64 hex chars)", hex(pub_numbers.n)[:66] + "...")
        
        # Show public key fingerprint
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashlib.sha256(pub_bytes).hexdigest()
        print_info("Public Key Fingerprint (SHA-256)", fingerprint[:32] + "...")
        
        print_success(f"{purpose.capitalize()} key pair generated")
        time.sleep(0.5)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 5: CERTIFICATE ISSUANCE
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 5: CA-SIGNED CERTIFICATE ISSUANCE (×3)")
    
    print(f"""
  The Root CA issues X.509 certificates for each of the user's public keys.
  Each certificate includes specific Key Usage extensions for its purpose.
    """)
    
    user_certs = {}
    
    for i, purpose in enumerate(key_purposes, 1):
        print_subheader(f"Certificate {i}/3: {purpose.upper()}")
        
        private_key, public_key = user_keys[purpose]
        
        simulate_progress(f"Issuing CA-signed certificate for {purpose}...", 0.8)
        
        cert = issue_certificate(
            ca_private_key=ca_private_key,
            ca_cert=ca_cert,
            user_public_key=public_key,
            username=username,
            purpose=purpose
        )
        user_certs[purpose] = cert
        
        print_certificate_info(cert, purpose.upper())
        
        # Show key usage
        try:
            key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
            print(f"\n    {Colors.CYAN}Key Usage:{Colors.END}")
            ku = key_usage.value
            usages = []
            if ku.digital_signature: usages.append("digitalSignature")
            if ku.content_commitment: usages.append("contentCommitment (nonRepudiation)")
            if ku.key_encipherment: usages.append("keyEncipherment")
            if ku.data_encipherment: usages.append("dataEncipherment")
            if ku.key_agreement: usages.append("keyAgreement")
            if ku.key_cert_sign: usages.append("keyCertSign")
            if ku.crl_sign: usages.append("cRLSign")
            for usage in usages:
                print(f"      • {usage}")
        except x509.ExtensionNotFound:
            pass
        
        # Show extended key usage
        try:
            ext_key_usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            print(f"\n    {Colors.CYAN}Extended Key Usage:{Colors.END}")
            for eku in ext_key_usage.value:
                print(f"      • {eku._name}")
        except x509.ExtensionNotFound:
            pass
        
        print_success(f"{purpose.capitalize()} certificate issued and signed by CA")
        time.sleep(0.5)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 6: PRIVATE KEY PROTECTION
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 6: PRIVATE KEY PROTECTION")
    
    print(f"""
  All three private keys are encrypted using AES-256-GCM with the key
  derived from the master password. This creates a secure key bundle.
    """)
    
    print_subheader("Key Bundle Structure")
    print(f"""
    ┌─────────────────────────────────────────────────────────────────┐
    │                     ENCRYPTED KEY BUNDLE                        │
    ├─────────────────────────────────────────────────────────────────┤
    │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
    │  │  AUTHENTICATION │  │    SIGNING      │  │   ENCRYPTION    │  │
    │  │   PRIVATE KEY   │  │  PRIVATE KEY    │  │  PRIVATE KEY    │  │
    │  │   (encrypted)   │  │   (encrypted)   │  │   (encrypted)   │  │
    │  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
    ├─────────────────────────────────────────────────────────────────┤
    │  Encryption: AES-256-GCM                                        │
    │  Key Source: Argon2id(master_password, salt)                    │
    │  Nonce: Random 96-bit per key                                   │
    │  Auth Tag: 128-bit per key                                      │
    └─────────────────────────────────────────────────────────────────┘
    """)
    
    simulate_progress("Encrypting private keys with AES-256-GCM...", 1.0)
    
    print_success("All private keys encrypted and stored securely")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("REGISTRATION COMPLETE - SUMMARY")
    
    print(f"""
  {Colors.GREEN}✓{Colors.END} User credentials validated
  {Colors.GREEN}✓{Colors.END} Master key derived using Argon2id (64 MB memory-hard)
  {Colors.GREEN}✓{Colors.END} Root CA certificate generated (RSA-2048, SHA-256)
  {Colors.GREEN}✓{Colors.END} Authentication key pair generated (RSA-2048)
  {Colors.GREEN}✓{Colors.END} Signing key pair generated (RSA-2048)
  {Colors.GREEN}✓{Colors.END} Encryption key pair generated (RSA-2048)
  {Colors.GREEN}✓{Colors.END} Authentication certificate issued (digitalSignature, clientAuth)
  {Colors.GREEN}✓{Colors.END} Signing certificate issued (digitalSignature, nonRepudiation)
  {Colors.GREEN}✓{Colors.END} Encryption certificate issued (keyEncipherment, dataEncipherment)
  {Colors.GREEN}✓{Colors.END} All private keys encrypted with AES-256-GCM
    """)
    
    print_subheader("Certificate Chain")
    print(f"""
                    ┌─────────────────────────────┐
                    │     SecureCrypt Root CA     │
                    │      (Self-Signed, 10yr)    │
                    └──────────────┬──────────────┘
                                   │
           ┌───────────────────────┼───────────────────────┐
           │                       │                       │
           ▼                       ▼                       ▼
    ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
    │    Auth     │         │   Signing   │         │ Encryption  │
    │ Certificate │         │ Certificate │         │ Certificate │
    │  (1 year)   │         │  (1 year)   │         │  (1 year)   │
    └─────────────┘         └─────────────┘         └─────────────┘
    
    Purpose:            Purpose:            Purpose:
    • Login             • Documents         • Secrets
    • Challenge-        • Code signing      • Hybrid
      Response          • Email             • encryption
    """)
    
    print(f"\n{Colors.BOLD}{Colors.GREEN}")
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                    REGISTRATION SUCCESSFULLY COMPLETED                        ║")
    print("║                                                                              ║")
    print("║  The user now has a complete PKI setup with three purpose-specific           ║")
    print("║  certificates, all signed by the local Root CA and protected by the          ║")
    print("║  master password through Argon2id key derivation.                            ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.END}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        run_registration_demo()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Demo interrupted by user.{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
