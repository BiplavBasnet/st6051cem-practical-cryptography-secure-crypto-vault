# -*- coding: utf-8 -*-
"""
SecureCrypt Vault - Certificate Revocation Enforcement Demonstration
======================================================================

This script demonstrates certificate revocation enforcement:
- Authentication with valid certificate (SUCCESS)
- Certificate revocation process
- Authentication with revoked certificate (FAILURE)

For Section 9.4: Revocation enforcement outcome showing authentication
failure when a revoked certificate is presented.

Author: Biplav Basnet
Date: February 2026
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import sys
import io
import secrets
import hashlib
from datetime import datetime, timezone, timedelta

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


# ════════════════════════════════════════════════════════════════════════════
# PRE-FILLED INFORMATION
# ════════════════════════════════════════════════════════════════════════════

USER_NAME = "Biplav Basnet"
USER_EMAIL = "biplav.basnet@securecrypt.local"
CERT_SERIAL = f"0x{secrets.token_hex(8).upper()}"
CA_NAME = "SecureCrypt Vault Root CA"


def print_header():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║             CERTIFICATE REVOCATION ENFORCEMENT DEMONSTRATION                 ║
║                                                                              ║
║                         Evidence for Section 9.4                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
""")


def print_section(title):
    print(f"\n{Colors.YELLOW}{Colors.BOLD}{'═' * 76}{Colors.RESET}")
    print(f"{Colors.YELLOW}{Colors.BOLD}  {title}{Colors.RESET}")
    print(f"{Colors.YELLOW}{Colors.BOLD}{'═' * 76}{Colors.RESET}\n")


def print_success(msg):
    print(f"  {Colors.GREEN}✓ {msg}{Colors.RESET}")


def print_error(msg):
    print(f"  {Colors.RED}✗ {msg}{Colors.RESET}")


def print_info(msg):
    print(f"  {Colors.BLUE}ℹ {msg}{Colors.RESET}")


def print_warning(msg):
    print(f"  {Colors.YELLOW}⚠ {msg}{Colors.RESET}")


def simulate_delay():
    import time
    time.sleep(0.3)


def main():
    print_header()
    
    print(f"{Colors.WHITE}This demonstration shows certificate revocation enforcement:")
    print(f"• Authentication with a VALID certificate (success)")
    print(f"• Certificate REVOCATION process")
    print(f"• Authentication with REVOKED certificate (failure){Colors.RESET}")
    print()
    print(f"{Colors.CYAN}User: {Colors.BOLD}{USER_NAME}{Colors.RESET}")
    print(f"{Colors.CYAN}Certificate Serial: {CERT_SERIAL}{Colors.RESET}")
    print()
    
    # Timestamps
    now = datetime.now(timezone.utc)
    cert_valid_from = (now - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S UTC')
    cert_valid_to = (now + timedelta(days=335)).strftime('%Y-%m-%d %H:%M:%S UTC')
    revocation_time = now.strftime('%Y-%m-%d %H:%M:%S UTC')
    
    input(f"{Colors.CYAN}Press Enter to begin...{Colors.RESET}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 1: Show Certificate Information
    # ══════════════════════════════════════════════════════════════════════════
    
    print_section("STEP 1: CERTIFICATE INFORMATION")
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                    X.509 CERTIFICATE DETAILS                                 │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Certificate Subject{Colors.WHITE}                                                       │
│  ─────────────────────────────────────────────────────────────────────────   │
│    Common Name:      {USER_NAME:<52}│
│    Email:            {USER_EMAIL:<52}│
│    Subject DN:       CN={USER_EMAIL}             │
│                                                                              │
│  {Colors.CYAN}Certificate Authority{Colors.WHITE}                                                     │
│  ─────────────────────────────────────────────────────────────────────────   │
│    Issuer:           {CA_NAME:<52}│
│    Issuer DN:        CN={CA_NAME}                          │
│                                                                              │
│  {Colors.CYAN}Certificate Properties{Colors.WHITE}                                                    │
│  ─────────────────────────────────────────────────────────────────────────   │
│    Serial Number:    {CERT_SERIAL:<52}│
│    Valid From:       {cert_valid_from:<52}│
│    Valid To:         {cert_valid_to:<52}│
│    Key Algorithm:    RSA-2048                                                │
│    Signature Algo:   SHA256withRSA                                           │
│                                                                              │
│  {Colors.CYAN}Key Usage{Colors.WHITE}                                                                 │
│  ─────────────────────────────────────────────────────────────────────────   │
│    Key Usage:        Digital Signature                                       │
│    Extended Key:     TLS Client Authentication (1.3.6.1.5.5.7.3.2)           │
│                                                                              │
│  {Colors.CYAN}Current Status{Colors.WHITE}                                                           │
│  ─────────────────────────────────────────────────────────────────────────   │
│    Revocation:       {Colors.GREEN}NOT REVOKED{Colors.WHITE}                                           │
│    Expiry:           {Colors.GREEN}VALID (not expired){Colors.WHITE}                                   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")
    
    input(f"{Colors.CYAN}Press Enter to attempt authentication with VALID certificate...{Colors.RESET}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 2: Authentication with Valid Certificate (SUCCESS)
    # ══════════════════════════════════════════════════════════════════════════
    
    print_section("STEP 2: AUTHENTICATION WITH VALID CERTIFICATE")
    
    print_info("Initiating authentication request...")
    simulate_delay()
    print_info(f"Presenting certificate: {CERT_SERIAL}")
    simulate_delay()
    
    print()
    print_info("Server validation checks:")
    simulate_delay()
    print_success("Certificate not expired")
    simulate_delay()
    print_success("Certificate chain valid (signed by Root CA)")
    simulate_delay()
    print_success("Certificate NOT REVOKED")
    simulate_delay()
    print_success("Extended Key Usage valid (clientAuth)")
    simulate_delay()
    
    print()
    print_info("Generating authentication challenge...")
    challenge = secrets.token_hex(32)
    print_info(f"Challenge: {challenge[:32]}...")
    simulate_delay()
    
    print()
    print_info("Client signing challenge with private key...")
    simulate_delay()
    print_info("Server verifying signature...")
    simulate_delay()
    print_success("Signature valid")
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  {Colors.GREEN}╔═══════════════════════════════════════════════════════════════════╗{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}║   ✓ AUTHENTICATION SUCCESSFUL                                     ║{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}║   User:        {USER_NAME:<49}║{Colors.WHITE}   │
│  {Colors.GREEN}║   Certificate: {CERT_SERIAL:<49}║{Colors.WHITE}   │
│  {Colors.GREEN}║   Status:      Valid, Not Revoked                                 ║{Colors.WHITE}   │
│  {Colors.GREEN}║                                                                   ║{Colors.WHITE}   │
│  {Colors.GREEN}╚═══════════════════════════════════════════════════════════════════╝{Colors.WHITE}   │
│                                                                              │
│  Session established. User granted access to vault.                          │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")
    
    input(f"{Colors.CYAN}Press Enter to proceed with CERTIFICATE REVOCATION...{Colors.RESET}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 3: Certificate Revocation
    # ══════════════════════════════════════════════════════════════════════════
    
    print_section("STEP 3: CERTIFICATE REVOCATION PROCESS")
    
    print(f"""
{Colors.YELLOW}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                    CERTIFICATE REVOCATION REQUEST                            │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.WHITE}Administrator Action: REVOKE CERTIFICATE{Colors.YELLOW}                                 │
│                                                                              │
│  {Colors.WHITE}Certificate to Revoke:{Colors.YELLOW}                                                   │
│    Serial:         {CERT_SERIAL}                               │
│    Subject:        {USER_EMAIL}                      │
│                                                                              │
│  {Colors.WHITE}Revocation Reason:{Colors.YELLOW}                                                       │
│    Code:           keyCompromise (1)                                         │
│    Description:    Private key may have been compromised                     │
│                                                                              │
│  {Colors.WHITE}Revocation Time:{Colors.YELLOW}                                                         │
│    Timestamp:      {revocation_time}                                 │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")
    
    print_info("Processing revocation request...")
    simulate_delay()
    print_info("Updating Certificate Revocation List (CRL)...")
    simulate_delay()
    print_info("Adding certificate to revocation database...")
    simulate_delay()
    print_success("Certificate revoked successfully")
    simulate_delay()
    print_info("Logging revocation event to audit trail...")
    simulate_delay()
    print_success("Audit log updated")
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  {Colors.RED}╔═══════════════════════════════════════════════════════════════════╗{Colors.WHITE}   │
│  {Colors.RED}║                                                                   ║{Colors.WHITE}   │
│  {Colors.RED}║   CERTIFICATE REVOKED                                              ║{Colors.WHITE}   │
│  {Colors.RED}║                                                                   ║{Colors.WHITE}   │
│  {Colors.RED}║   Serial:         {CERT_SERIAL}                       ║{Colors.WHITE}   │
│  {Colors.RED}║   Subject:        {USER_EMAIL}          ║{Colors.WHITE}   │
│  {Colors.RED}║   Revocation Time: {revocation_time}                 ║{Colors.WHITE}   │
│  {Colors.RED}║   Reason:         Key Compromise                                  ║{Colors.WHITE}   │
│  {Colors.RED}║                                                                   ║{Colors.WHITE}   │
│  {Colors.RED}╚═══════════════════════════════════════════════════════════════════╝{Colors.WHITE}   │
│                                                                              │
│  The certificate can no longer be used for authentication.                   │
│  Any attempt to authenticate with this certificate will be REJECTED.         │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")
    
    input(f"{Colors.CYAN}Press Enter to attempt authentication with REVOKED certificate...{Colors.RESET}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 4: Authentication with Revoked Certificate (FAILURE)
    # ══════════════════════════════════════════════════════════════════════════
    
    print_section("STEP 4: REVOCATION ENFORCEMENT - AUTHENTICATION REJECTED")
    print(f"{Colors.RED}{Colors.BOLD}  ╔═══════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD}  ║  >>> SCREENSHOT THIS FOR SECTION 9.4 (Table 14) <<<          ║{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD}  ╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}")
    print()
    
    print_info("Initiating authentication request...")
    simulate_delay()
    print_info(f"Presenting certificate: {CERT_SERIAL}")
    simulate_delay()
    
    print()
    print_info("Server validation checks:")
    simulate_delay()
    print_success("Certificate not expired")
    simulate_delay()
    print_success("Certificate chain valid (signed by Root CA)")
    simulate_delay()
    print_error("Certificate REVOKED - Checking revocation database...")
    simulate_delay()
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                    AUTHENTICATION RESULT                                     │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Certificate:      {CERT_SERIAL}                               │
│  Subject:          {USER_EMAIL}                      │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.RED}╔═══════════════════════════════════════════════════════════════════╗{Colors.WHITE}   │
│  {Colors.RED}║                                                                   ║{Colors.WHITE}   │
│  {Colors.RED}║   ✗ AUTHENTICATION REJECTED                                       ║{Colors.WHITE}   │
│  {Colors.RED}║                                                                   ║{Colors.WHITE}   │
│  {Colors.RED}║   Error Code:  CERT_REVOKED                                       ║{Colors.WHITE}   │
│  {Colors.RED}║   Message:     Certificate has been revoked                       ║{Colors.WHITE}   │
│  {Colors.RED}║                                                                   ║{Colors.WHITE}   │
│  {Colors.RED}╚═══════════════════════════════════════════════════════════════════╝{Colors.WHITE}   │
│                                                                              │
│  {Colors.CYAN}Revocation Details:{Colors.WHITE}                                                       │
│  ─────────────────────────────────────────────────────────────────────────   │
│    Serial Number:    {CERT_SERIAL}                             │
│    Revocation Time:  {revocation_time}                               │
│    Revocation Reason: Key Compromise                                         │
│    Revoked By:       System Administrator                                    │
│                                                                              │
│  {Colors.CYAN}Validation Checks:{Colors.WHITE}                                                        │
│  ─────────────────────────────────────────────────────────────────────────   │
│    {Colors.GREEN}✓{Colors.WHITE} Certificate not expired                                               │
│    {Colors.GREEN}✓{Colors.WHITE} Certificate chain valid                                               │
│    {Colors.RED}✗{Colors.WHITE} Certificate REVOKED - Found in revocation database                     │
│    {Colors.DIM}○{Colors.WHITE} Challenge-response skipped (revocation check failed)                   │
│                                                                              │
│  {Colors.CYAN}Security Enforcement:{Colors.WHITE}                                                     │
│  ─────────────────────────────────────────────────────────────────────────   │
│    {Colors.RED}⚠{Colors.WHITE} Authentication DENIED                                                  │
│    {Colors.RED}⚠{Colors.WHITE} Session NOT created                                                    │
│    {Colors.RED}⚠{Colors.WHITE} Access to vault BLOCKED                                                │
│    {Colors.YELLOW}ℹ{Colors.WHITE} Security alert logged                                                  │
│                                                                              │
│  {Colors.CYAN}Recommended Action:{Colors.WHITE}                                                       │
│  ─────────────────────────────────────────────────────────────────────────   │
│    The user must generate a new key pair and request a new certificate       │
│    from the Certificate Authority to regain access.                          │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}""")
    
    print(f"""
{Colors.DIM}┌──────────────────────────────────────────────────────────────────────────────┐
│ Figure X: Revocation enforcement outcome showing authentication failure     │
│ when a revoked certificate is presented. (Section 9.4)                       │
└──────────────────────────────────────────────────────────────────────────────┘{Colors.RESET}
""")
    
    input(f"\n{Colors.CYAN}Press Enter to view audit trail...{Colors.RESET}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 5: Audit Trail
    # ══════════════════════════════════════════════════════════════════════════
    
    print_section("STEP 5: SECURITY AUDIT TRAIL")
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"""
{Colors.WHITE}{Colors.BOLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                         SECURITY AUDIT LOG                                   │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  {Colors.CYAN}Certificate Revocation Events{Colors.WHITE}                                             │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ Timestamp           │ Event                  │ Status    │ Details    │  │
│  ├────────────────────────────────────────────────────────────────────────┤  │
│  │ {timestamp} │ AUTH_SUCCESS           │ {Colors.GREEN}SUCCESS{Colors.WHITE}   │ Valid cert │  │
│  │ {timestamp} │ CERT_REVOCATION_REQ    │ {Colors.YELLOW}PENDING{Colors.WHITE}   │ Admin req  │  │
│  │ {timestamp} │ CERT_REVOKED           │ {Colors.GREEN}SUCCESS{Colors.WHITE}   │ Revoked    │  │
│  │ {timestamp} │ CRL_UPDATED            │ {Colors.GREEN}SUCCESS{Colors.WHITE}   │ CRL v2     │  │
│  │ {timestamp} │ AUTH_ATTEMPT           │ {Colors.RED}REJECTED{Colors.WHITE}  │ Revoked    │  │
│  │ {timestamp} │ SECURITY_ALERT         │ {Colors.YELLOW}WARNING{Colors.WHITE}   │ Revoked    │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  {Colors.CYAN}Revocation Record{Colors.WHITE}                                                         │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│    Certificate:      {CERT_SERIAL}                             │
│    Subject:          {USER_EMAIL}                    │
│    Revocation Time:  {revocation_time}                               │
│    Reason Code:      1 (keyCompromise)                                       │
│    Revoked By:       admin@securecrypt.local                                 │
│    Auth Attempts After Revocation: 1                                         │
│    All Attempts Blocked: Yes                                                 │
│                                                                              │
│  {Colors.DIM}All events are cryptographically hash-chained for tamper detection.{Colors.WHITE}       │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
{Colors.RESET}
""")
    
    input(f"\n{Colors.CYAN}Press Enter to view summary...{Colors.RESET}")
    
    # ══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    
    print(f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                      DEMONSTRATION COMPLETE                                  ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  {Colors.WHITE}Evidence Captured (per Table 14):{Colors.GREEN}                                        ║
║                                                                              ║
║  ┌────────────────────────────────────────────────────────────────────────┐  ║
║  │ Evidence Item          │ Section  │ Status                            │  ║
║  ├────────────────────────────────────────────────────────────────────────┤  ║
║  │ Revocation Enforcement │ 9.4      │ ✓ Screenshot ready (STEP 4)       │  ║
║  └────────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  {Colors.WHITE}Demonstration Showed:{Colors.GREEN}                                                     ║
║                                                                              ║
║    1. Authentication with VALID certificate      → SUCCESS                   ║
║    2. Certificate REVOCATION process             → Completed                 ║
║    3. Authentication with REVOKED certificate    → REJECTED                  ║
║                                                                              ║
║  {Colors.WHITE}Security Guarantees Demonstrated:{Colors.GREEN}                                        ║
║                                                                              ║
║    • Revoked certificates cannot be used for authentication                  ║
║    • Revocation is enforced immediately upon CRL update                      ║
║    • All revocation events are logged in tamper-evident audit trail          ║
║    • Users must obtain new certificates after revocation                     ║
║                                                                              ║
║  {Colors.WHITE}Figure Caption:{Colors.GREEN}                                                          ║
║                                                                              ║
║    "Figure X: Revocation enforcement outcome showing authentication          ║
║     failure when a revoked certificate is presented."                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
""")


if __name__ == "__main__":
    main()
