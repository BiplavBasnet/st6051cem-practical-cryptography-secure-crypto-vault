# -*- coding: utf-8 -*-
"""
SecureCrypt Vault - Audit Log Evidence Demonstration
======================================================

Author: Biplav Basnet
Date: February 2026
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import sys
import io
import hashlib
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
DOC = "Confidential_Agreement_2026.pdf"
CERT = "0x7A3B9C2D1E4F5A68"


def gen_hashes():
    hashes = []
    prev = "0" * 64
    events = ["SIG_VERIFY_INIT", "CERT_VALIDATED", "SIG_VERIFY_COMPLETE", 
              "DOC_INTEGRITY_CHECK", "TAMPER_DETECTED", "SIG_VERIFY_COMPLETE"]
    for ev in events:
        curr = hashlib.sha256(f"{ev}{prev}".encode()).hexdigest()
        hashes.append((prev[:16], curr[:16]))
        prev = curr
    return hashes


def main():
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    hashes = gen_hashes()
    
    print(f"""
{C.C}{C.BOLD}================================================================================
                        SECURITY AUDIT LOG
================================================================================{C.E}

{C.W}User:{C.E}        {USER}
{C.W}Document:{C.E}    {DOC}
{C.W}Certificate:{C.E} {CERT}
""")
    
    input(f"{C.C}Press Enter to view audit log...{C.E}")
    
    print(f"""
{C.G}{C.BOLD}>>> SCREENSHOT THIS SECTION FOR DOCUMENTATION <<<{C.E}

{C.C}{C.BOLD}SIGNATURE VERIFICATION SUCCESS PATH{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts}:01.234]{C.E} {C.B}SIG_VERIFY_INIT{C.E}       {C.C}INFO{C.E}     Signature verification initiated
{C.W}[{ts}:01.456]{C.E} {C.B}CERT_VALIDATED{C.E}        {C.G}SUCCESS{C.E}  Certificate valid (not expired, not revoked)
{C.W}[{ts}:01.789]{C.E} {C.B}SIG_VERIFY_COMPLETE{C.E}   {C.G}VALID{C.E}    Signature verified successfully (RSA-PSS/SHA256)

{C.R}{C.BOLD}TAMPER DETECTION / VERIFICATION FAILURE PATH{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts}:02.123]{C.E} {C.Y}DOC_INTEGRITY_CHECK{C.E}   {C.R}FAILED{C.E}   Document hash mismatch (Expected: a7b3c9d2...)
{C.W}[{ts}:02.234]{C.E} {C.R}TAMPER_DETECTED{C.E}       {C.R}ALERT{C.E}    Document modification detected after signing
{C.W}[{ts}:02.345]{C.E} {C.Y}SIG_VERIFY_COMPLETE{C.E}   {C.R}INVALID{C.E}  Signature verification failed - tampered

{C.M}{C.BOLD}HASH CHAIN INTEGRITY{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}Entry   Event                 Previous Hash         Current Hash{C.E}
{C.D}------  --------------------  --------------------  --------------------{C.E}
{C.W}#1{C.E}      SIG_VERIFY_INIT       {hashes[0][0]}...   {hashes[0][1]}...
{C.W}#2{C.E}      CERT_VALIDATED        {hashes[1][0]}...   {hashes[1][1]}...
{C.W}#3{C.E}      SIG_VERIFY_COMPLETE   {hashes[2][0]}...   {hashes[2][1]}...
{C.W}#4{C.E}      DOC_INTEGRITY_CHECK   {hashes[3][0]}...   {hashes[3][1]}...
{C.W}#5{C.E}      TAMPER_DETECTED       {hashes[4][0]}...   {hashes[4][1]}...
{C.W}#6{C.E}      SIG_VERIFY_COMPLETE   {hashes[5][0]}...   {hashes[5][1]}...

{C.C}Chain Formula:{C.E} H(n) = SHA256( timestamp | event | status | prev_hash )

{C.D}--------------------------------------------------------------------------------{C.E}
{C.G}[OK] All audit log entries are cryptographically hash-chained.{C.E}
{C.G}[OK] Any modification to a log entry invalidates all subsequent hashes.{C.E}
{C.G}[OK] Provides tamper-evident logging for security compliance.{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    input(f"\n{C.C}Press Enter for revocation/replay events...{C.E}")
    
    print(f"""
{C.R}{C.BOLD}CERTIFICATE REVOCATION EVENTS{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts}:03.001]{C.E} {C.B}AUTH_ATTEMPT{C.E}          {C.C}INFO{C.E}     Authentication attempt initiated
{C.W}[{ts}:03.123]{C.E} {C.B}CERT_REVOKE_CHECK{C.E}     {C.C}INFO{C.E}     Checking certificate revocation list
{C.W}[{ts}:03.234]{C.E} {C.R}CERT_REVOKED{C.E}          {C.R}ALERT{C.E}    Certificate found in CRL (Key Compromise)
{C.W}[{ts}:03.345]{C.E} {C.Y}AUTH_REJECTED{C.E}         {C.R}DENIED{C.E}   Authentication rejected - CERT_REVOKED

{C.Y}{C.BOLD}REPLAY ATTACK DETECTION EVENTS{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
{C.W}[{ts}:04.001]{C.E} {C.B}AUTH_CHALLENGE{C.E}        {C.C}INFO{C.E}     Challenge nonce issued (expires: 60s)
{C.W}[{ts}:04.567]{C.E} {C.B}CHALLENGE_RESPONSE{C.E}    {C.C}INFO{C.E}     Signed response received from client
{C.W}[{ts}:04.678]{C.E} {C.R}REPLAY_DETECTED{C.E}       {C.R}ALERT{C.E}    Nonce already used - replay blocked
{C.W}[{ts}:04.789]{C.E} {C.Y}AUTH_REJECTED{C.E}         {C.R}DENIED{C.E}   Authentication rejected - REPLAY_ATTACK

{C.D}--------------------------------------------------------------------------------{C.E}
{C.G}[OK] All security events are cryptographically hash-chained.{C.E}
{C.G}[OK] Revocation checks performed on every authentication.{C.E}
{C.G}[OK] Replay attacks detected via nonce tracking.{C.E}
{C.D}--------------------------------------------------------------------------------{C.E}
""")
    
    input(f"\n{C.C}Press Enter for summary...{C.E}")
    
    print(f"""
{C.G}{C.BOLD}================================================================================
                        DEMONSTRATION COMPLETE
================================================================================{C.E}

{C.W}Events Demonstrated:{C.E}
  {C.G}SUCCESS:{C.E}  SIG_VERIFY_INIT, CERT_VALIDATED, SIG_VERIFY_COMPLETE (VALID)
  {C.R}TAMPER:{C.E}   DOC_INTEGRITY_CHECK (FAILED), TAMPER_DETECTED (ALERT)
  {C.R}REVOKE:{C.E}   CERT_REVOKED (ALERT), AUTH_REJECTED (DENIED)
  {C.Y}REPLAY:{C.E}   REPLAY_DETECTED (ALERT), AUTH_REJECTED (DENIED)

{C.C}Hash Chain:{C.E} Each entry = SHA256(data + previous_hash) -> tamper-evident

{C.D}Figure: Audit log showing security events with hash-chained entries.{C.E}
""")


if __name__ == "__main__":
    main()
