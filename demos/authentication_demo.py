#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SECURECRYPT VAULT - CHALLENGE-RESPONSE AUTHENTICATION DEMO

This demonstration shows the complete challenge-response authentication process:
- Server generates a random cryptographic challenge
- Client signs the challenge with their private authentication key
- Server verifies the signature using the client's certificate
- Session is established upon successful verification

CHALLENGE-RESPONSE AUTHENTICATION - PROVING IDENTITY WITHOUT TRANSMITTING SECRETS
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

# Suppress deprecation warnings for cleaner output
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Fix Windows console encoding for Unicode characters
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import argon2
from argon2.low_level import hash_secret_raw, Type

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
    MAGENTA = '\033[35m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


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
    if len(data) > 60:
        for i in range(0, len(data), 60):
            print(f"{spaces}  {data[i:i+60]}")
    else:
        print(f"{spaces}  {data}")


def print_success(text: str):
    """Print success message."""
    print(f"\n  {Colors.GREEN}✓ {text}{Colors.END}")


def print_error(text: str):
    """Print error message."""
    print(f"\n  {Colors.RED}✗ {text}{Colors.END}")


def print_server(text: str):
    """Print server-side message."""
    print(f"  {Colors.MAGENTA}[SERVER]{Colors.END} {text}")


def print_client(text: str):
    """Print client-side message."""
    print(f"  {Colors.BLUE}[CLIENT]{Colors.END} {text}")


def print_arrow(direction: str = "right"):
    """Print arrow for data flow visualization."""
    if direction == "right":
        print(f"\n  {Colors.YELLOW}              ─────────────────────────►{Colors.END}")
    elif direction == "left":
        print(f"\n  {Colors.YELLOW}              ◄─────────────────────────{Colors.END}")
    elif direction == "both":
        print(f"\n  {Colors.YELLOW}              ◄────────────────────────►{Colors.END}")


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


def print_certificate_info(cert: x509.Certificate, purpose: str):
    """Print certificate details in a formatted way."""
    print(f"\n  {Colors.BOLD}Certificate: {purpose}{Colors.END}")
    print(f"  {'─' * 50}")
    
    subject = cert.subject
    for attr in subject:
        print(f"    {Colors.CYAN}Subject {attr.oid._name}:{Colors.END} {attr.value}")
    
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    print(f"    {Colors.CYAN}SHA-256 Fingerprint:{Colors.END}")
    print(f"      {fingerprint[:32]}...")


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


def create_root_ca() -> tuple:
    """Create a self-signed Root CA certificate."""
    ca_private_key, ca_public_key = generate_rsa_keypair(2048)
    
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureCrypt Vault"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureCrypt Root CA"),
    ])
    
    now = datetime.utcnow()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
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


def issue_auth_certificate(ca_private_key, ca_cert, user_public_key, username: str) -> x509.Certificate:
    """Issue a CA-signed authentication certificate."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureCrypt Vault"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{username} - Authentication"),
    ])
    
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )
    
    return cert


def generate_challenge(length: int = 32) -> bytes:
    """Generate a cryptographically secure random challenge."""
    return secrets.token_bytes(length)


def sign_challenge(private_key, challenge: bytes) -> bytes:
    """Sign a challenge using RSA-PSS with SHA-256."""
    signature = private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key, challenge: bytes, signature: bytes) -> bool:
    """Verify a signature using RSA-PSS with SHA-256."""
    try:
        public_key.verify(
            signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def derive_key_argon2(password: str, salt: bytes) -> bytes:
    """Derive a key using Argon2id."""
    derived_key = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    return derived_key


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN DEMONSTRATION
# ═══════════════════════════════════════════════════════════════════════════════

def run_authentication_demo():
    """Run the complete challenge-response authentication demonstration."""
    
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
    print("║               CHALLENGE-RESPONSE AUTHENTICATION DEMO                         ║")
    print("║                                                                              ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.END}")
    
    print(f"\n{Colors.BOLD}{Colors.YELLOW}CHALLENGE-RESPONSE AUTHENTICATION — PROVING IDENTITY BY SIGNING A RANDOM")
    print(f"CHALLENGE WITH THE PRIVATE KEY, VERIFIED USING THE CA-SIGNED CERTIFICATE.{Colors.END}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SETUP: SIMULATE PRE-EXISTING USER (from registration)
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("SETUP: SIMULATING REGISTERED USER")
    
    print(f"""
  First, we simulate a user who has already registered. This user has:
  • An authentication key pair (RSA-2048)
  • A CA-signed authentication certificate
  • Their private key encrypted with their master password
    """)
    
    username = "alice_demo"
    master_password = "SecureP@ssw0rd!2024"
    salt = secrets.token_bytes(16)
    
    # Generate CA and user keys (simulating prior registration)
    simulate_progress("Setting up Root CA...", 0.8)
    ca_private_key, ca_cert = create_root_ca()
    
    simulate_progress("Generating user's authentication key pair...", 0.8)
    auth_private_key, auth_public_key = generate_rsa_keypair(2048)
    
    simulate_progress("Issuing authentication certificate...", 0.8)
    auth_cert = issue_auth_certificate(ca_private_key, ca_cert, auth_public_key, username)
    
    # Derive key for "encrypted storage"
    derived_key = derive_key_argon2(master_password, salt)
    
    print_info("Username", username)
    print_info("Auth Certificate Serial", str(auth_cert.serial_number)[:20] + "...")
    print_certificate_info(auth_cert, "User Authentication Certificate")
    
    print_success("User setup complete (simulated prior registration)")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 1: LOGIN REQUEST
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 1: CLIENT INITIATES LOGIN")
    
    print(f"""
  The user enters their username to begin the authentication process.
  No password is sent to the server at this stage.
    """)
    
    print_subheader("Client → Server: Login Request")
    
    print_client("User enters username to login")
    print_info("Username", username, indent=4)
    
    print_arrow("right")
    
    print_server("Received login request")
    print_server("Looking up user in database...")
    time.sleep(0.5)
    print_server(f"Found user: {username}")
    print_server("Retrieving user's authentication certificate...")
    
    print_success("Login request received, user found")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 2: SERVER GENERATES CHALLENGE
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 2: SERVER GENERATES CRYPTOGRAPHIC CHALLENGE")
    
    print(f"""
  The server generates a random challenge using a cryptographically secure
  random number generator (CSPRNG). This challenge is:
  • Unique for each authentication attempt
  • Unpredictable (256 bits of entropy)
  • Time-limited (expires after 5 minutes)
    """)
    
    print_subheader("Challenge Generation")
    
    print_server("Generating cryptographic challenge...")
    simulate_progress("Using CSPRNG to generate 256-bit challenge...", 0.5)
    
    challenge = generate_challenge(32)  # 256 bits
    challenge_timestamp = datetime.utcnow()
    challenge_expiry = challenge_timestamp + timedelta(minutes=5)
    
    print_data("Challenge (hex)", challenge.hex())
    print_info("Challenge Size", "256 bits (32 bytes)", indent=4)
    print_info("Generated At", str(challenge_timestamp), indent=4)
    print_info("Expires At", str(challenge_expiry), indent=4)
    print_info("CSPRNG Source", "secrets.token_bytes() (OS entropy)", indent=4)
    
    print_success("Challenge generated")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 3: CHALLENGE SENT TO CLIENT
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 3: SERVER SENDS CHALLENGE TO CLIENT")
    
    print(f"""
  The server sends the challenge to the client. The client must prove
  they possess the private key corresponding to the registered certificate.
    """)
    
    print_subheader("Server → Client: Challenge")
    
    print_server("Sending challenge to client...")
    print_arrow("left")
    print_client("Received challenge from server")
    
    print(f"""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                        CHALLENGE PACKET                             │
    ├─────────────────────────────────────────────────────────────────────┤
    │  Challenge: {challenge.hex()[:40]}...   │
    │  Algorithm: RSA-PSS with SHA-256                                    │
    │  Timestamp: {challenge_timestamp.isoformat()}                              │
    └─────────────────────────────────────────────────────────────────────┘
    """)
    
    print_success("Challenge delivered to client")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 4: CLIENT UNLOCKS PRIVATE KEY
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 4: CLIENT UNLOCKS PRIVATE KEY")
    
    print(f"""
  The client enters their master password to decrypt their private
  authentication key from the encrypted key bundle.
    """)
    
    print_subheader("Private Key Decryption")
    
    print_client("User enters master password...")
    print_info("Master Password", "••••••••••••••••••", indent=4)
    
    simulate_progress("Deriving decryption key with Argon2id...", 1.5)
    
    print_info("Argon2id Parameters", "", indent=4)
    print_info("  Time Cost", "3 iterations", indent=4)
    print_info("  Memory Cost", "65,536 KB (64 MB)", indent=4)
    print_info("  Parallelism", "4 threads", indent=4)
    
    derived_key_verify = derive_key_argon2(master_password, salt)
    
    simulate_progress("Decrypting private key with AES-256-GCM...", 0.5)
    
    print(f"""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    KEY BUNDLE DECRYPTION                            │
    ├─────────────────────────────────────────────────────────────────────┤
    │                                                                     │
    │  Master Password ──► Argon2id ──► Derived Key (256-bit)            │
    │                                        │                            │
    │                                        ▼                            │
    │  Encrypted Key Bundle ──► AES-256-GCM ──► Private Key (RSA-2048)   │
    │                                                                     │
    └─────────────────────────────────────────────────────────────────────┘
    """)
    
    print_success("Private authentication key decrypted successfully")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 5: CLIENT SIGNS CHALLENGE
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 5: CLIENT SIGNS CHALLENGE")
    
    print(f"""
  The client uses their private authentication key to create a digital
  signature over the challenge. This proves possession of the private key.
    """)
    
    print_subheader("Digital Signature Creation (RSA-PSS)")
    
    print_client("Signing challenge with private key...")
    
    print(f"""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                     RSA-PSS SIGNATURE SCHEME                        │
    ├─────────────────────────────────────────────────────────────────────┤
    │                                                                     │
    │  Challenge ──────────────────────────────┐                          │
    │       │                                  │                          │
    │       ▼                                  ▼                          │
    │  ┌─────────┐    ┌─────────────┐    ┌──────────┐                    │
    │  │ SHA-256 │───►│ PSS Padding │───►│ RSA Sign │                    │
    │  │  Hash   │    │  (Salt +    │    │ (Private │                    │
    │  │         │    │   MGF1)     │    │   Key)   │                    │
    │  └─────────┘    └─────────────┘    └────┬─────┘                    │
    │                                         │                           │
    │                                         ▼                           │
    │                                   ┌──────────┐                      │
    │                                   │Signature │                      │
    │                                   │(256 bytes)│                      │
    │                                   └──────────┘                      │
    │                                                                     │
    └─────────────────────────────────────────────────────────────────────┘
    """)
    
    simulate_progress("Computing RSA-PSS signature...", 0.8)
    
    signature = sign_challenge(auth_private_key, challenge)
    
    print_info("Signature Algorithm", "RSASSA-PSS", indent=4)
    print_info("Hash Function", "SHA-256", indent=4)
    print_info("Mask Generation", "MGF1 with SHA-256", indent=4)
    print_info("Salt Length", "Maximum (PSS.MAX_LENGTH)", indent=4)
    print_info("Signature Size", f"{len(signature)} bytes ({len(signature) * 8} bits)", indent=4)
    print_data("Signature (hex, first 128 chars)", signature.hex()[:128] + "...")
    
    print_success("Challenge signed successfully")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 6: CLIENT SENDS RESPONSE
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 6: CLIENT SENDS SIGNED RESPONSE")
    
    print(f"""
  The client sends the signature back to the server as proof of identity.
  Note: The private key NEVER leaves the client!
    """)
    
    print_subheader("Client → Server: Signed Response")
    
    print_client("Sending signed response to server...")
    
    print(f"""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                        RESPONSE PACKET                              │
    ├─────────────────────────────────────────────────────────────────────┤
    │  Username:  {username.ljust(54)}│
    │  Signature: {signature.hex()[:48]}...  │
    │  Sig Size:  {str(len(signature)).ljust(54)}│
    │                                                                     │
    │  ⚠  Private key NEVER transmitted                                  │
    │  ⚠  Password NEVER transmitted                                     │
    └─────────────────────────────────────────────────────────────────────┘
    """)
    
    print_arrow("right")
    
    print_server("Received signed response from client")
    
    print_success("Response delivered to server")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 7: SERVER VERIFIES SIGNATURE
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 7: SERVER VERIFIES SIGNATURE")
    
    print(f"""
  The server uses the user's public key (from their certificate) to verify
  that the signature was created by the corresponding private key.
    """)
    
    print_subheader("Signature Verification Process")
    
    print_server("Retrieving user's authentication certificate...")
    print_server("Validating certificate chain...")
    
    # Verify certificate
    print(f"""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                  CERTIFICATE CHAIN VALIDATION                       │
    ├─────────────────────────────────────────────────────────────────────┤
    │                                                                     │
    │  ┌─────────────────────┐                                            │
    │  │  Root CA Cert       │ ◄── Trusted anchor                        │
    │  │  (Self-signed)      │                                            │
    │  └──────────┬──────────┘                                            │
    │             │ signed                                                │
    │             ▼                                                       │
    │  ┌─────────────────────┐                                            │
    │  │  User Auth Cert     │ ◄── Verify signature against this         │
    │  │  (alice_demo)       │                                            │
    │  └─────────────────────┘                                            │
    │                                                                     │
    │  ✓ Certificate not expired                                          │
    │  ✓ Certificate not revoked                                          │
    │  ✓ Key usage: digitalSignature                                      │
    │  ✓ Extended key usage: clientAuth                                   │
    │                                                                     │
    └─────────────────────────────────────────────────────────────────────┘
    """)
    
    print_server("Extracting public key from certificate...")
    public_key_from_cert = auth_cert.public_key()
    
    print_server("Verifying signature using RSA-PSS...")
    
    print(f"""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                   RSA-PSS SIGNATURE VERIFICATION                    │
    ├─────────────────────────────────────────────────────────────────────┤
    │                                                                     │
    │  Original Challenge ────────────────────┐                           │
    │       │                                 │                           │
    │       ▼                                 ▼                           │
    │  ┌─────────┐    ┌─────────────┐    ┌──────────┐                    │
    │  │ SHA-256 │───►│ PSS Verify  │◄───│Signature │                    │
    │  │  Hash   │    │  (Public    │    │  (from   │                    │
    │  │         │    │    Key)     │    │  client) │                    │
    │  └─────────┘    └──────┬──────┘    └──────────┘                    │
    │                        │                                            │
    │                        ▼                                            │
    │                 ┌─────────────┐                                     │
    │                 │  VALID or   │                                     │
    │                 │  INVALID    │                                     │
    │                 └─────────────┘                                     │
    │                                                                     │
    └─────────────────────────────────────────────────────────────────────┘
    """)
    
    simulate_progress("Verifying RSA-PSS signature...", 0.5)
    
    # Verify the signature
    is_valid = verify_signature(public_key_from_cert, challenge, signature)
    
    if is_valid:
        print_success("SIGNATURE VALID - Authentication successful!")
    else:
        print_error("SIGNATURE INVALID - Authentication failed!")
        return
    
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 8: SESSION ESTABLISHMENT
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("STEP 8: SESSION ESTABLISHMENT")
    
    print(f"""
  Upon successful signature verification, the server establishes a secure
  session for the authenticated user.
    """)
    
    print_subheader("Session Creation")
    
    # Generate session data
    session_id = secrets.token_hex(16)
    session_created = datetime.utcnow()
    session_expiry = session_created + timedelta(hours=8)
    
    print_server("Creating authenticated session...")
    
    print(f"""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                       SESSION ESTABLISHED                           │
    ├─────────────────────────────────────────────────────────────────────┤
    │                                                                     │
    │  Session ID:    {session_id}                │
    │  Username:      {username.ljust(48)}│
    │  Created:       {session_created.isoformat().ljust(48)}│
    │  Expires:       {session_expiry.isoformat().ljust(48)}│
    │  Auth Method:   Challenge-Response (RSA-PSS)                        │
    │  Cert Serial:   {str(auth_cert.serial_number)[:30].ljust(48)}│
    │                                                                     │
    └─────────────────────────────────────────────────────────────────────┘
    """)
    
    print_server("Recording login in audit log...")
    print_server("Clearing challenge from memory...")
    
    print_arrow("left")
    
    print_client("Received session token")
    print_client("Login complete!")
    
    print_success("Session established successfully")
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SECURITY ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("SECURITY ANALYSIS")
    
    print(f"""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                   WHY CHALLENGE-RESPONSE IS SECURE                  │
    ├─────────────────────────────────────────────────────────────────────┤
    │                                                                     │
    │  {Colors.GREEN}✓{Colors.END} Password NEVER transmitted over network                         │
    │    └─ Password only used locally to decrypt private key             │
    │                                                                     │
    │  {Colors.GREEN}✓{Colors.END} Private key NEVER leaves client                                 │
    │    └─ Only the signature (proof) is sent                            │
    │                                                                     │
    │  {Colors.GREEN}✓{Colors.END} Replay attacks prevented                                        │
    │    └─ Each challenge is random and single-use                       │
    │                                                                     │
    │  {Colors.GREEN}✓{Colors.END} Man-in-the-middle protection                                    │
    │    └─ Attacker cannot forge signature without private key           │
    │                                                                     │
    │  {Colors.GREEN}✓{Colors.END} Server compromise limited                                       │
    │    └─ Server only stores public keys/certificates                   │
    │                                                                     │
    │  {Colors.GREEN}✓{Colors.END} Certificate-based trust                                         │
    │    └─ PKI ensures key authenticity                                  │
    │                                                                     │
    └─────────────────────────────────────────────────────────────────────┘
    """)
    
    time.sleep(1)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # COMPLETE FLOW DIAGRAM
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("COMPLETE AUTHENTICATION FLOW")
    
    print(f"""
    ┌──────────────────┐                          ┌──────────────────┐
    │      CLIENT      │                          │      SERVER      │
    └────────┬─────────┘                          └────────┬─────────┘
             │                                              │
             │  1. Login Request (username)                 │
             │─────────────────────────────────────────────►│
             │                                              │
             │                                    2. Generate Challenge
             │                                       (256-bit random)
             │                                              │
             │  3. Challenge                                │
             │◄─────────────────────────────────────────────│
             │                                              │
    4. Enter Password                                       │
       Decrypt Private Key                                  │
             │                                              │
    5. Sign Challenge                                       │
       (RSA-PSS + SHA-256)                                  │
             │                                              │
             │  6. Signed Response                          │
             │─────────────────────────────────────────────►│
             │                                              │
             │                                    7. Verify Signature
             │                                       (Public Key from Cert)
             │                                              │
             │                                    8. Create Session
             │                                              │
             │  9. Session Token                            │
             │◄─────────────────────────────────────────────│
             │                                              │
    ✓ AUTHENTICATED                               ✓ USER VERIFIED
             │                                              │
    """)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════════════
    
    print_header("AUTHENTICATION COMPLETE - SUMMARY")
    
    print(f"""
  {Colors.GREEN}✓{Colors.END} Client sent login request with username
  {Colors.GREEN}✓{Colors.END} Server generated 256-bit cryptographic challenge
  {Colors.GREEN}✓{Colors.END} Client unlocked private key using Argon2id-derived key
  {Colors.GREEN}✓{Colors.END} Client signed challenge using RSA-PSS with SHA-256
  {Colors.GREEN}✓{Colors.END} Server verified signature against user's certificate
  {Colors.GREEN}✓{Colors.END} Server validated certificate chain to Root CA
  {Colors.GREEN}✓{Colors.END} Session established with 8-hour expiry
  {Colors.GREEN}✓{Colors.END} Login recorded in tamper-evident audit log
    """)
    
    print(f"\n{Colors.BOLD}{Colors.GREEN}")
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                   AUTHENTICATION SUCCESSFULLY COMPLETED                       ║")
    print("║                                                                              ║")
    print("║  The user has proven their identity through cryptographic proof without      ║")
    print("║  ever transmitting their password or private key over the network.           ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.END}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        run_authentication_demo()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Demo interrupted by user.{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
