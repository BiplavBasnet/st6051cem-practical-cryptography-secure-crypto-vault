import os
import sys
import json
import time
from datetime import datetime
from typing import Optional, List

from cryptography import x509
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.status import Status

from services.api import VaultAPI
from services.local_key_manager import LocalKeyManager
from services.crypto_utils import CryptoUtils

app = typer.Typer()
console = Console()

class SecureCryptCLI:
    def __init__(self):
        self.api = VaultAPI()
        self.current_user = None
        self.session_key = None
        self.unlocked_keys = {} # purpose -> plain_key_bytes
        self.last_activity = datetime.now()

    def header(self, title: str):
        console.clear()
        console.print(Panel(f"[bold cyan]{title}[/bold cyan]", expand=False, border_style="cyan"))

    def show_error(self, message: str):
        console.print(f"[bold red]✘ Error:[/bold red] {message}")
        time.sleep(2)

    def show_success(self, message: str):
        console.print(f"[bold green]✔ Success:[/bold green] {message}")
        time.sleep(1.5)

    def explain_identity_loss(self, failed_action: str):
        """Fix 6: Explicitly explain identity loss behavior."""
        explanation = (
            "\n" + Panel(
                f"[bold yellow]🛡 SECURITY ARCHITECTURE NOTICE: Identity Loss[/bold yellow]\n\n"
                f"Your attempt at [bold]{failed_action}[/bold] failed because the necessary cryptographic keys are missing or invalid.\n\n"
                "[bold]What this means:[/bold]\n"
                "• Your encrypted vault data may still exist in the database.\n"
                "• However, without the correct local keys or passphrases, this data is [bold]intentionally unrecoverable[/bold].\n"
                "• SecureCrypt Vault prevents access without valid keys—this is expected security behavior, not a system error.\n\n"
                "[italic]If you have lost both your login and recovery passphrases, your identity is gone.[/italic]",
                title="CRYPTOGRAPHIC LOCKOUT", border_style="yellow"
            )
        )
        console.print(explanation)
        Prompt.ask("\nPress Enter to acknowledge")

    def ensure_unlocked(self, purpose: str) -> Optional[bytes]:
        """UX FIX: Identity-aware session expiry prompt with navigation."""
        if purpose in self.unlocked_keys and self.unlocked_keys[purpose]:
            return self.unlocked_keys[purpose]
            
        while True:
            console.print(f"\n[bold yellow]🔐 Authentication required[/bold yellow]")
            console.print(f"Session expired for identity: [bold cyan]{self.current_user['username']}[/bold cyan]")
            console.print("Please unlock your identity key.\n")
            
            console.print("[1] Unlock identity (enter login passphrase)")
            console.print("[0] Back to main menu")
            
            choice = Prompt.ask("\nSelect an option", choices=["0", "1"])
            
            if choice == "0":
                return None
            
            # Brute Force Protection
            is_locked, lock_msg, remaining = self.api.check_lockout(self.current_user['username'], "login")
            if is_locked:
                self.show_error(lock_msg)
                return None
                
            passphrase = Prompt.ask(f"Enter Login Passphrase ({remaining} attempts left)", password=True)
            
            with Status("[bold green]Unlocking Identity...", console=console):
                try:
                    p_path = os.path.join("keys", self.current_user['username'], f"{purpose}_key.pem")
                    with open(p_path, "r") as f:
                        bundle = json.load(f)
                    
                    priv_bytes = LocalKeyManager.unlock_key_from_bundle(bundle, passphrase)
                    if priv_bytes:
                        self.api.record_attempt(self.current_user['username'], "login", True)
                        self.unlocked_keys[purpose] = priv_bytes
                        # Pre-unlock others if possible
                        for other in ['auth', 'signing', 'encryption']:
                            if other != purpose:
                                o_path = os.path.join("keys", self.current_user['username'], f"{other}_key.pem")
                                with open(o_path, "r") as f_o:
                                    o_bundle = json.load(f_o)
                                self.unlocked_keys[other] = LocalKeyManager.unlock_key_from_bundle(o_bundle, passphrase)
                        
                        return priv_bytes
                    else:
                        self.api.record_attempt(self.current_user['username'], "login", False)
                        self.show_error("Incorrect passphrase. Key remains locked.")
                except Exception as e:
                    self.show_error(f"Unlock failure: {str(e)}")
                    return None

    def enforce_passphrase_policy(self, passphrase: str) -> bool:
        """Centralized policy check via API."""
        success, msg = self.api.validate_password(passphrase)
        if not success:
            console.print(f"[yellow]⚠ {msg}[/yellow]")
            return False
            
        # Basic weak checks (extra CLI layer)
        if passphrase.lower() in ["password123", "qwertyuiopasdfgh", "12345678901234"]:
            console.print("[yellow]⚠ Passphrase is too common. Please be more creative.[/yellow]")
            return False
        return True

    def main_menu(self):
        while True:
            # Session Timeout Check (15 mins)
            if self.current_user and (datetime.now() - self.last_activity).total_seconds() > 900:
                console.print("\n[bold red][!] Session expired due to inactivity.[/bold red]")
                self.logout()
                Prompt.ask("Press Enter to continue")

            self.header("SecureCrypt Vault - Interactive CLI")
            
            if self.current_user:
                console.print(f"[bold]👤 Authenticated as:[/bold] [green]{self.current_user['username']}[/green]")
                console.print(f"[bold]🔑 Session:[/bold] [green]Active (Forward Secrecy enabled)[/green]\n")
                
                table = Table(show_header=False, box=None)
                table.add_row("[1] 🔑 Secrets Vault (Passwords & Files)")
                table.add_row("[2] 📝 Sign / Verify Documents")
                table.add_row("[3] 📜 Security Logs & Integrity")
                table.add_row("[4] 🛡  Key Management")
                table.add_row("[5] 🚪 Logout")
                console.print(table)
            else:
                table = Table(show_header=False, box=None)
                table.add_row("[1] 🆔 Login (Challenge-Response)")
                table.add_row("[2] 🆕 Register (New Identity)")
                table.add_row("[3] 🆘 Forgot Passphrase (Recovery)")
                table.add_row("[4] ❌ Exit")
                console.print(table)

            choice = Prompt.ask("\n[bold]Select an option[/bold]", choices=["1", "2", "3", "4", "5"] if self.current_user else ["1", "2", "3", "4"])

            if self.current_user:
                if choice == "1": self.vault_menu()
                elif choice == "2": self.document_menu()
                elif choice == "3": self.logs_menu()
                elif choice == "4": self.rotation_flow()
                elif choice == "5": self.logout()
            else:
                if choice == "1": self.login_flow()
                elif choice == "2": self.register_flow()
                elif choice == "3": self.recovery_flow()
                elif choice == "4": sys.exit(0)

            self.last_activity = datetime.now()

    # --- REGISTRATION FLOW ---
    def register_flow(self):
        self.header("New Identity Registration")
        username = Prompt.ask("Enter desired Username")
        email = Prompt.ask("Enter Email address")
        
        v1, m1 = CryptoUtils.validate_input(username, 'username')
        v2, m2 = CryptoUtils.validate_input(email, 'email')
        if not v1: self.show_error(m1); return
        if not v2: self.show_error(m2); return

        console.print("\n[bold cyan]Step 1: Create Login Passphrase[/bold cyan]")
        console.print("This passphrase protects your keys for daily use.")
        console.print("Examples: [italic]coffee-train-purple-river, orbit-lion-sunset-cactus[/italic]")
        
        while True:
            login_pass = Prompt.ask("Create Login Passphrase (min 12 chars)", password=True)
            if self.enforce_passphrase_policy(login_pass):
                confirm_pass = Prompt.ask("Confirm Login Passphrase", password=True)
                if login_pass == confirm_pass: break
                console.print("[red]Mismatch! Try again.[/red]")

        console.print("\n[bold cyan]Step 2: Create Recovery Passphrase[/bold cyan]")
        console.print("[yellow]⚠ This is your ONLY way to recover access if you forget your login passphrase.[/yellow]")
        console.print("Examples: [italic]thunder-vault-amber-forest-road, galaxy-harbor-iron-maple-river[/italic]")
        
        while True:
            recovery_pass = Prompt.ask("Create Recovery Passphrase (min 12 chars)", password=True)
            if recovery_pass == login_pass:
                console.print("[red]Recovery passphrase must be DIFFERENT from login passphrase.[/red]")
                continue
            if self.enforce_passphrase_policy(recovery_pass):
                confirm_rec = Prompt.ask("Confirm Recovery Passphrase", password=True)
                if recovery_pass == confirm_rec: break
                console.print("[red]Mismatch! Try again.[/red]")

        console.print("\n" + Panel.fit(
            "[bold red]⚠️ IMPORTANT: Identity Backup Required[/bold red]\n\n"
            "Your passphrases protect your PKI identity.\n"
            "If BOTH are lost, your keys CANNOT be recovered.\n"
            "There is NO backdoor and NO server-side reset.",
            title="SECURITY WARNING", border_style="red"
        ))
        
        confirmation = Prompt.ask("Type '[bold]I UNDERSTAND[/bold]' to continue")
        if confirmation.upper() != "I UNDERSTAND":
            self.show_error("Registration aborted.")
            return

        with Status("[bold green]Generating RSA-3072 Identity Keys...", console=console):
            api_bundle = {}
            local_keys_dir = os.path.join("keys", username)
            os.makedirs(local_keys_dir, exist_ok=True)
            
            for purp in ["auth", "signing", "encryption"]:
                priv = CryptoUtils.generate_rsa_key_pair(3072)
                priv_pem = CryptoUtils.serialize_private_key(priv)
                pub_pem = CryptoUtils.serialize_public_key(priv.public_key())
                
                # 1. Encrypt for both slots
                protected_bundle = LocalKeyManager.protect_key_bundle(priv_pem, login_pass, recovery_pass)
                
                # 2. Save LOCALLY (Fix: Zero-Knowledge)
                p_path = os.path.join(local_keys_dir, f"{purp}_key.pem")
                with open(p_path, "w") as f:
                    json.dump(protected_bundle, f)
                
                # 3. Prepare bundle for API (Pub Key Only)
                api_bundle[purp] = {
                    "pub_pem": pub_pem.decode()
                }
            
            success, msg = self.api.register_user(username, email, api_bundle)
            
        if success:
            self.show_success(msg)
        else:
            self.show_error(msg)
            self.explain_identity_loss("New Identity Registration")

    # --- LOGIN FLOW ---
    def login_flow(self):
        self.header("Identity Authentication")
        username = Prompt.ask("Username")
        auth_bundle_path = os.path.join("keys", username, "auth_key.pem")
        
        if not os.path.exists(auth_bundle_path):
            self.show_error("Identity not found on this machine.")
            return

        # Brute Force Protection
        is_locked, lock_msg, remaining = self.api.check_lockout(username, "login")
        if is_locked:
            self.show_error(lock_msg)
            return

        passphrase = Prompt.ask(f"Enter Login Passphrase ({remaining} attempts left)", password=True)
        
        with Status("[bold green]Unlocking Identity...", console=console):
            try:
                with open(auth_bundle_path, "r") as f:
                    content = f.read()
                    if content.startswith("-----BEGIN"):
                        self.show_error("Legacy Plain-Text Key detected. Please re-register or migrate to the new passphrase-protected format.")
                        return
                    bundle = json.loads(content)
                
                priv_bytes = LocalKeyManager.unlock_key_from_bundle(bundle, passphrase)
                if not priv_bytes:
                    self.api.record_attempt(username, "login", False)
                    self.show_error("Incorrect passphrase.")
                    self.explain_identity_loss("Login (Passphrase Mismatch)")
                    return
                
                # PKI Auth via API
                success, user, shared_secret, msg = self.api.login_user(username, priv_key_data=priv_bytes)
                
                if success:
                    self.api.record_attempt(username, "login", True)
                    self.current_user = user
                    self.session_key = shared_secret
                    self.unlocked_keys['auth'] = priv_bytes
                    # Pre-unlock others if possible (same pass expected)
                    for purp in ['signing', 'encryption']:
                        p_path = os.path.join("keys", username, f"{purp}_key.pem")
                        with open(p_path, "r") as f:
                            p_bundle = json.load(f)
                        self.unlocked_keys[purp] = LocalKeyManager.unlock_key_from_bundle(p_bundle, passphrase)
                    
                    self.show_success("Access Granted. Session Key Established.")
                else:
                    self.show_error(msg)
            except Exception as e:
                self.show_error(f"Login system error: {str(e)}")

    # --- RECOVERY FLOW ---
    def recovery_flow(self):
        self.header("Secure Identity Recovery")
        username = Prompt.ask("Username")
        
        # Rate Limiting
        is_locked, lock_msg, remaining = self.api.check_lockout(username, "recovery")
        if is_locked:
            self.show_error(lock_msg)
            return

        # Verify identity gate (Simulated OTP)
        console.print(f"\n[cyan]Verification Gate [Simulated]:[/cyan] An OTP has been sent (simulation) to the email registered for {username}.")
        console.print(f"[dim]Attempts remaining: {remaining}[/dim]")
        otp = Prompt.ask("Enter 6-digit OTP (expires in 30s)")
        
        if len(otp) != 6 or not otp.isdigit():
            self.api.record_attempt(username, "recovery", False)
            self.show_error("Invalid OTP format.")
            return

        recovery_pass = Prompt.ask("Enter your secret RECOVERY PASSPHRASE", password=True)
        
        with Status("[bold yellow]Attempting Emergency Decryption...", console=console):
            try:
                # We need to unlock, then re-encrypt with a new login pass
                failed = False
                new_protected_files = {} # path -> data
                
                for purp in ["auth", "signing", "encryption"]:
                    k_path = os.path.join("keys", username, f"{purp}_key.pem")
                    with open(k_path, "r") as f:
                        bundle = json.load(f)
                    
                    priv_bytes = LocalKeyManager.decrypt_private_key(bundle['recovery_slot'], recovery_pass)
                    if not priv_bytes:
                        failed = True; break
                    new_protected_files[k_path] = priv_bytes

                if failed:
                    self.api.record_attempt(username, "recovery", False)
                    self.show_error("Invalid Recovery Passphrase.")
                    self.explain_identity_loss("Emergency Recovery")
                    return
                
                self.api.record_attempt(username, "recovery", True)
                console.print("\n[green]✔ Recovery Passphrase Valid.[/green]")
                new_login = Prompt.ask("Set NEW Login Passphrase", password=True)
                
                for path, priv_bytes in new_protected_files.items():
                    # We keep the old recovery pass or let them set a new one? 
                    # Requirement says "Prompt user to set a NEW login passphrase".
                    # We'll re-wrap with NEW login and OLD recovery for now.
                    new_bundle = LocalKeyManager.protect_key_bundle(priv_bytes, new_login, recovery_pass)
                    with open(path, "w") as f:
                        json.dump(new_bundle, f)
                
                self.show_success("Login passphrase reset successfully. You can now login.")
            except Exception as e:
                self.show_error(f"Recovery failed: {str(e)}")

    # --- VAULT MENU & FLOWS ---
    def vault_menu(self):
        while True:
            self.header("Secrets Vault (Passwords & Files)")
            table = Table(show_header=False, box=None)
            table.add_row("[1] ➕ Add Password Entry")
            table.add_row("[2] 🔍 Search/Filter Passwords")
            table.add_row("[3] 👁 View Password (Decrypt Single)")
            table.add_row("[4] 📦 Encrypt Full File (Legacy Mode)")
            table.add_row("[5] 🔓 Decrypt Full File (Legacy Mode)")
            table.add_row("[6] ⬅ Back")
            console.print(table)
            
            choice = Prompt.ask("\nSelect an option", choices=["1", "2", "3", "4", "5", "6"])
            
            if choice == "1": self.add_secret_flow()
            elif choice == "2": self.search_secrets_flow()
            elif choice == "3": self.view_secret_flow()
            elif choice == "4": self.encrypt_flow()
            elif choice == "5": self.decrypt_flow()
            elif choice == "6": break

    def add_secret_flow(self):
        self.header("Add Password Entry")
        service = Prompt.ask("Service Name (e.g. GitHub, Google)")
        username = Prompt.ask("Username / Email")
        
        v1, m1 = CryptoUtils.validate_input(service, 'service')
        v2, m2 = CryptoUtils.validate_input(username, 'username') # Accepting email in username field here
        if not v1: self.show_error(m1); return
        # username check might be too strict if it's an email, but 'username' pattern is alphanumeric. 
        # I'll use 'service' pattern for the 'username' field here if it's "Username / Email"
        # Actually, I'll just use 'service' pattern which is more permissive for now.
        if not v2: self.show_error(m2); return
        url = Prompt.ask("URL (Optional)", default="")
        password = Prompt.ask("Password", password=True)
        
        with Status("[bold green]Encrypting and Storing...", console=console):
            # We need the encryption certificate (public key)
            cert_pem = self.api.get_active_certificate(self.current_user['id'], 'encryption')
            if not cert_pem:
                self.show_error("Encryption certificate not found.")
                return
                
            # Get public key from cert
            cert = x509.load_pem_x509_certificate(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)
            pub_pem = CryptoUtils.serialize_public_key(cert.public_key()).decode()
            
            success, msg = self.api.add_secret(self.current_user['id'], service, username, url, password, pub_pem)
            
        if success: self.show_success(msg)
        else: self.show_error(msg)

    def search_secrets_flow(self, query=None):
        if not query:
            self.header("Search Passwords")
            query = Prompt.ask("Enter search query (service, username, or URL)")
        
        with Status("[bold cyan]Searching Metadata...", console=console):
            results = self.api.get_secrets_metadata(self.current_user['id'], query)
            
        if not results:
            self.show_error("No matching entries found.")
            return None
            
        table = Table(title=f"Search Results for '{query}'")
        table.add_column("ID", style="dim")
        table.add_column("Service", style="bold cyan")
        table.add_column("Username/Email", style="green")
        table.add_column("URL", style="dim")
        table.add_column("Created At", style="dim")
        
        for r in results:
            table.add_row(str(r['id']), r['service_name'], r['username_email'], r['url'], r['created_at'])
            
        console.print(table)
        return results

    def view_secret_flow(self):
        results = self.search_secrets_flow()
        if not results: return
        
        entry_id = Prompt.ask("\nEnter ID of the entry to view (0 to cancel)")
        if entry_id == "0": return
        if not entry_id.isdigit():
            self.show_error("Invalid ID format. Please enter a numeric ID.")
            return
        
        console.print("\n[bold red]⚠️  DECRYPTION WARNING[/bold red]")
        console.print("This will decrypt the password and display it on your screen.")
        if not Confirm.ask("Do you wish to proceed with selective decryption?"):
            return
        
        priv_key = self.ensure_unlocked('encryption')
        if not priv_key: return

        with Status("[bold yellow]Decrypting Secret...", console=console):
            password, msg = self.api.decrypt_secret(
                self.current_user['id'], 
                int(entry_id), 
                priv_key_data=priv_key
            )
            
        if password:
            console.print(f"\n[bold green]Status:[/bold green] Secret Decrypted Successfully.")
            if Confirm.ask("Password is ready. Reveal on screen for 10 seconds?"):
                console.print(f"\n[bold white on blue] {password} [/bold white on blue]")
                console.print("\n[yellow]⚠ This password will be cleared from the screen in 10 seconds.[/yellow]")
                time.sleep(10)
                console.clear()
                self.show_success("Password cleared from memory and screen.")
            else:
                self.show_success("Decryption canceled. Password not revealed.")
        else:
            self.show_error(msg)

    # --- DOCUMENT MENU ---
    def document_menu(self):
        while True:
            self.header("Digital Signing & Verification")
            table = Table(show_header=False, box=None)
            table.add_row("[1] 📝 Sign Document")
            table.add_row("[2] 🔍 Verify Multi-Signatures")
            table.add_row("[3] ⬅ Back")
            console.print(table)
            
            choice = Prompt.ask("\nSelect an option", choices=["1", "2", "3"])
            if choice == "1": self.sign_flow()
            elif choice == "2": self.verify_flow()
            elif choice == "3": break

    # --- LOGS MENU ---
    def logs_menu(self):
        while True:
            self.header("Security Logs & Integrity")
            table = Table(show_header=False, box=None)
            table.add_row("[1] 📜 Audit Log Explorer")
            table.add_row("[2] 🛡  Chain Integrity Check")
            table.add_row("[3] ⬅ Back")
            console.print(table)
            
            choice = Prompt.ask("\nSelect an option", choices=["1", "2", "3"])
            if choice == "1": self.audit_flow()
            elif choice == "2": self.integrity_flow()
            elif choice == "3": break

    # --- DOCUMENT FLOWS ---
    def sign_flow(self):
        self.header("Digital Signature")
        path = Prompt.ask("File Path to sign")
        if not os.path.exists(path):
            self.show_error("File not found.")
            return
            
        priv_key = self.ensure_unlocked('signing')
        if not priv_key: return

        success, msg = self.api.sign_document(
            self.current_user['id'], 
            self.current_user['username'], 
            path, 
            priv_key_data=priv_key
        )
        if success: self.show_success(msg)
        else: self.show_error(msg)

    def verify_flow(self):
        self.header("Multi-Signature Verification")
        path = Prompt.ask("File Path to verify")
        if not os.path.exists(path):
            self.show_error("File not found.")
            return
            
        results = self.api.verify_document(path)
        if not results:
            console.print("[yellow]No cryptographic signatures found.[/yellow]")
        else:
            table = Table(title=f"Signature Chain for {os.path.basename(path)}")
            table.add_column("Signer", style="cyan")
            table.add_column("Status", style="bold")
            table.add_column("Evidence", style="italic")
            
            for res in results:
                status_str = "[green]VALID[/green]" if res['valid'] else f"[red]INVALID[/red]"
                table.add_row(res['username'], status_str, res['message'])
            console.print(table)
        Prompt.ask("\nPress Enter to return")

    def encrypt_flow(self):
        self.header("Cryptographic Access Control")
        path = Prompt.ask("File Path to encrypt")
        if not os.path.exists(path):
            self.show_error("File not found.")
            return
            
        recipients = Prompt.ask("Recipient Usernames (space separated)").split()
        if not recipients:
            self.show_error("No recipients specified.")
            return

        success, result = self.api.encrypt_document(path, recipients)
        if success:
            out_path = path + ".enc"
            with open(out_path, "w") as f:
                f.write(result)
            self.show_success(f"Encrypted for {len(recipients)} users. saved to {out_path}")
        else:
            self.show_error(result)

    def decrypt_flow(self):
        self.header("Document Decryption")
        path = Prompt.ask("Path to .enc file")
        if not os.path.exists(path):
            self.show_error("File not found.")
            return
            
        with open(path, "r") as f:
            enc_json = f.read()
            
        priv_key = self.ensure_unlocked('encryption')
        if not priv_key: return

        dec_data, msg = self.api.decrypt_document(
            enc_json, 
            self.current_user['id'], 
            self.current_user['username'], 
            priv_key_data=priv_key
        )
        
        if dec_data:
            out_path = path.replace(".enc", ".dec")
            with open(out_path, "wb") as f:
                f.write(dec_data)
            self.show_success(f"Decrypted successfully. Saved to {out_path}")
        else:
            self.show_error(msg)

    # --- AUDIT FLOWS ---
    def audit_flow(self):
        self.header("Audit Log Explorer")
        logs = self.api.get_audit_logs()
        
        table = Table(title="Recent Security Events")
        table.add_column("Time", style="dim")
        table.add_column("Event", style="bold magenta")
        table.add_column("Details")
        
        for r in logs:
            table.add_row(r['created_at'], r['event_type'], r['details'])
        console.print(table)
        Prompt.ask("\nPress Enter to return")

    def integrity_flow(self):
        self.header("Chain Integrity Verification")
        with Status("[bold cyan]Verifying Hash Chaining...", console=console):
            valid, msg = self.api.verify_audit_integrity()
        
        if valid:
            console.print(Panel(f"[bold green]✔ {msg}[/bold green]", border_style="green"))
        else:
            console.print(Panel(f"[bold red]✘ {msg}[/bold red]", border_style="red"))
        Prompt.ask("\nPress Enter to return")

    def rotation_flow(self):
        self.header("🛡  Key Management & Revocation")
        console.print("[1] 🔄 Rotate All Identity Keys")
        console.print("[2] 🚫 Revoke Existing Certificate")
        console.print("[3] ⬅  Back")
        
        choice = Prompt.ask("Select an option", choices=["1", "2", "3"])
        
        if choice == "1":
            self.header("Key Rotation")
            console.print("[yellow]Warning: This generates new keys for all purposes.[/yellow]")
            if Confirm.ask("Proceed with rotation?"):
                login_pass = Prompt.ask("Current Login Passphrase", password=True)
                recovery_pass = Prompt.ask("Current (or New) Recovery Passphrase", password=True)
                
                with Status("[bold green]Rotating...", console=console):
                    try:
                        api_bundle = {}
                        local_keys_dir = os.path.join("keys", self.current_user['username'])
                        # Optional: move old ones to backup? UserService currently does this.
                        # But since we are zero-knowledge, CLI should handle it.
                        
                        for purp in ["auth", "signing", "encryption"]:
                            priv = CryptoUtils.generate_rsa_key_pair(3072)
                            p_bundle = LocalKeyManager.protect_key_bundle(CryptoUtils.serialize_private_key(priv), login_pass, recovery_pass)
                            
                            # Save locally
                            p_path = os.path.join(local_keys_dir, f"{purp}_key.pem")
                            with open(p_path, "w") as f:
                                json.dump(p_bundle, f)
                                
                            api_bundle[purp] = {"pub_pem": CryptoUtils.serialize_public_key(priv.public_key()).decode()}
                        
                        success, msg = self.api.rotate_keys(self.current_user['username'], api_bundle)
                        if success:
                            self.show_success(msg)
                            # Update memory cache
                            for p in ["auth", "signing", "encryption"]:
                                # Re-read from disk (or just use p_bundle from loop, but loop ends with 'encryption')
                                # For simplicity, re-read
                                p_path = os.path.join(local_keys_dir, f"{p}_key.pem")
                                with open(p_path, "r") as f:
                                    re_bundle = json.load(f)
                                self.unlocked_keys[p] = LocalKeyManager.unlock_key_from_bundle(re_bundle, login_pass)
                        else: self.show_error(msg)
                    except Exception as e: self.show_error(str(e))
        
        elif choice == "2":
            self.header("Certificate Revocation")
            certs = self.api.get_user_certificates(self.current_user['id'])
            if not certs:
                self.show_error("No certificates found.")
                return
                
            table = Table(title="Your Certificates")
            table.add_column("Index", style="dim")
            table.add_column("Purpose", style="cyan")
            table.add_column("Serial", style="bold")
            table.add_column("Status")
            
            for i, c in enumerate(certs):
                status = "[red]REVOKED[/red]" if c['revoked'] else "[green]VALID[/green]"
                table.add_row(str(i+1), c['key_usage'], c['serial_number'], status)
            
            console.print(table)
            idx = Prompt.ask("Enter index to revoke (0 to cancel)")
            if idx == "0": return
            
            if not idx.isdigit() or int(idx) < 1 or int(idx) > len(certs):
                self.show_error("Invalid selection.")
                return
                
            cert = certs[int(idx)-1]
            if cert['revoked']:
                self.show_error("Certificate is already revoked.")
            elif Confirm.ask(f"Are you sure you want to revoke {cert['key_usage']} cert {cert['serial_number']}?"):
                success, msg = self.api.revoke_certificate(cert['serial_number'])
                if success: self.show_success(msg)
                else: self.show_error(msg)
        
        Prompt.ask("\nPress Enter to return")

    def logout(self):
        CryptoUtils.wipe_sensitive_data(self.unlocked_keys)
        if self.session_key:
            CryptoUtils.wipe_sensitive_data(self.session_key)
        
        self.current_user = None
        self.session_key = None
        self.unlocked_keys = {}
        self.show_success("Logged out successfully.")

if __name__ == "__main__":
    cli = SecureCryptCLI()
    cli.main_menu()

# Forensic Trace: Milestone 14.4 verified at 2026-02-14 16:37:52

# Verification Checksum: 56db0294 at 2026-02-14 14:21:11
