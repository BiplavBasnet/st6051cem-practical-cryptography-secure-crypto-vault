# SecureCrypt Vault

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![Security](https://img.shields.io/badge/Security-Hardened-success)](https://github.com)
[![Cryptography](https://img.shields.io/badge/Crypto-AES--256--GCM-blue)](https://github.com)
[![PKI](https://img.shields.io/badge/PKI-X.509-orange)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

A forensic-grade, enterprise-level password manager and secure document vault built with advanced cryptographic principles. Designed for **ST6051CEM Practical Cryptography** coursework, demonstrating real-world implementation of modern security protocols.

---

## Table of Contents

- [Features](#features)
- [Security Architecture](#security-architecture)
- [Technologies Used](#technologies-used)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Running Tests](#running-tests)
- [Screenshots](#screenshots)
- [API Reference](#api-reference)
- [Contributing](#contributing)

---

## Features

### Core Functionality
- **Password Vault**: Securely store, organize, and retrieve credentials
- **Password Generator**: Cryptographically secure random password generation
- **Password Health Analysis**: Detect weak, reused, and compromised passwords
- **CSV Import/Export**: Migrate from other password managers
- **Encrypted Backups**: Create and restore encrypted vault backups

### Security Features
- **Multi-Factor Authentication**: TOTP-based two-factor authentication
- **Session Management**: Configurable idle lock and session expiry
- **Brute-Force Protection**: Progressive backoff with lockout controls
- **Audit Logging**: Tamper-evident, hash-chained security logs
- **Digital Signatures**: Sign and verify documents with PKI

### Advanced Cryptography
- **Zero-Knowledge Architecture**: Master password never stored
- **Forward Secrecy**: ECDH key agreement for session keys
- **Certificate-Based Auth**: X.509 PKI with challenge-response
- **Key Rotation**: Seamless credential re-encryption

---

## Security Architecture

### Cryptographic Primitives

| Purpose | Algorithm | Details |
|---------|-----------|---------|
| **Encryption** | AES-256-GCM | Authenticated encryption with 96-bit nonce |
| **Key Derivation** | Argon2id | Memory-hard KDF with auto-tuned parameters |
| **Asymmetric** | RSA-2048/4096 | OAEP padding for encryption, PSS for signatures |
| **Hashing** | SHA-256 | HMAC for integrity, hash chains for audit |
| **Key Exchange** | ECDH (P-256) | Perfect forward secrecy for sessions |
| **TOTP** | HMAC-SHA1 | RFC 6238 compliant, 30-second window |

### Public Key Infrastructure (PKI)

```
┌─────────────────────────────────────────────────────────────┐
│                      Root CA (Self-Signed)                   │
│                  Generated per installation                  │
└─────────────────────────┬───────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│ Auth Cert     │ │ Signing Cert  │ │ Encryption    │
│ (Challenge-   │ │ (Document     │ │ Cert (Hybrid  │
│  Response)    │ │  Signatures)  │ │  Encryption)  │
└───────────────┘ └───────────────┘ └───────────────┘
```

### Data Protection Layers

1. **Master Password** → Argon2id → **Derived Key**
2. **Derived Key** → AES-GCM → **Protected Private Keys**
3. **Private Keys** → RSA/ECDH → **Session/Data Keys**
4. **Data Keys** → AES-GCM → **Encrypted Secrets**

---

## Technologies Used

### Core Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `cryptography` | ≥41.0.0 | Core cryptographic operations (AES, RSA, X.509) |
| `argon2-cffi` | ≥23.1.0 | Argon2id key derivation function |
| `typer` | ≥0.9.0 | CLI interface framework |
| `rich` | ≥13.0.0 | Terminal formatting and progress bars |
| `winotify` | ≥1.1.0 | Windows desktop notifications |

### Built-in Libraries

| Library | Purpose |
|---------|---------|
| `tkinter` | Desktop GUI framework |
| `sqlite3` | Local encrypted database |
| `hashlib` | SHA-256 hashing |
| `hmac` | Message authentication codes |
| `secrets` | Cryptographically secure random numbers |
| `threading` | Concurrent operations |

### Development Tools

| Tool | Purpose |
|------|---------|
| `pytest` | Test framework |
| `pytest-cov` | Code coverage |
| `pytest-mock` | Mocking utilities |

---

## Project Structure

```
SecureCrypt-Vault/
├── run_tk_desktop.py          # GUI entry point
├── secure_crypt_cli.py        # CLI entry point
├── desktop_tkinter_app.py     # Main GUI application
├── requirements.txt           # Python dependencies
├── README.md                  # This file
│
├── config/
│   ├── __init__.py
│   ├── design_tokens.py       # UI theming and colors
│   └── state.py               # Application state management
│
├── services/
│   ├── __init__.py
│   ├── api.py                 # Main API facade
│   ├── app_paths.py           # Platform-specific paths
│   ├── audit_log.py           # Hash-chained audit logging
│   ├── audit_log_normalizer.py# Log sanitization
│   ├── auth_service.py        # Challenge-response auth
│   ├── backup_service.py      # Encrypted backup/restore
│   ├── crypto_utils.py        # Cryptographic primitives
│   ├── database.py            # SQLite database manager
│   ├── document_service.py    # Document signing/verification
│   ├── extension_server.py    # Browser extension API
│   ├── local_key_manager.py   # Key bundle protection
│   ├── pki_service.py         # X.509 certificate management
│   ├── platform_utils.py      # OS-specific utilities
│   ├── secret_service.py      # Password CRUD operations
│   ├── security_alert_service.py # Security notifications
│   ├── security_service.py    # Brute-force protection
│   ├── session_manager.py     # Session lifecycle
│   ├── session_security_service.py # Session security
│   ├── sharing_service.py     # Secure sharing
│   ├── structured_logger.py   # Logging infrastructure
│   ├── sync_service.py        # Data synchronization
│   ├── totp_service.py        # TOTP 2FA
│   └── user_service.py        # User management
│
├── scripts/
│   ├── __init__.py
│   ├── cleanup_local_artifacts.py # Cleanup utility
│   └── smoke_check.py         # Quick validation tests
│
└── tests/
    ├── __init__.py
    ├── test_vault.py          # Core vault tests
    ├── test_hardening.py      # Security hardening tests
    ├── test_audit_log.py      # Audit chain tests
    ├── test_fuzz.py           # Fuzz/negative tests
    └── test_ui_services.py    # UI integration tests
```

---

## Installation

### Prerequisites

- **Python 3.10 or higher**
- **pip** (Python package manager)
- **Windows 10/11** (for desktop notifications)

### Step-by-Step Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/BiplavBasnet/ST6051CEM-practical-cryptography-secure-crypto-vault.git
   cd ST6051CEM-practical-cryptography-secure-crypto-vault
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   ```

3. **Activate the virtual environment**
   
   **Windows (PowerShell):**
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   
   **Windows (Command Prompt):**
   ```cmd
   .venv\Scripts\activate.bat
   ```
   
   **Linux/macOS:**
   ```bash
   source .venv/bin/activate
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

### Running the Desktop Application (GUI)

```bash
python run_tk_desktop.py
```

This launches the full graphical interface with:
- User registration/login
- Password vault management
- Settings and preferences
- Backup and restore

### Running the Command-Line Interface (CLI)

```bash
python secure_crypt_cli.py --help
```

Available CLI commands:
```bash
# Register a new user
python secure_crypt_cli.py register

# Add a new secret
python secure_crypt_cli.py add-secret

# List all secrets
python secure_crypt_cli.py list-secrets

# Generate a secure password
python secure_crypt_cli.py generate-password

# Create a backup
python secure_crypt_cli.py backup

# Restore from backup
python secure_crypt_cli.py restore
```

### Quick Smoke Test

Verify the installation is working:
```bash
python scripts/smoke_check.py
```

Expected output:
```
  PASS: imports
  PASS: app_paths
  PASS: api_init
  PASS: register_add_secret
  PASS: backup_create_validate

Smoke check: 5/5 passed
```

---

## Running Tests

### Run All Tests

```bash
python -m pytest tests/ -v
```

### Run Specific Test Files

```bash
# Core vault functionality
python -m pytest tests/test_vault.py -v

# Security hardening tests
python -m pytest tests/test_hardening.py -v

# Audit log integrity
python -m pytest tests/test_audit_log.py -v

# Fuzz/negative testing
python -m pytest tests/test_fuzz.py -v

# UI service integration
python -m pytest tests/test_ui_services.py -v
```

### Test Coverage Report

```bash
python -m pytest tests/ --cov=services --cov-report=html
```

---

## API Reference

### VaultAPI (Main Interface)

```python
from services.api import VaultAPI

api = VaultAPI()

# User Management
api.register_user(username, email, key_bundle)
api.authenticate_user(username, challenge_response)

# Secrets Management
api.add_secret(user_id, service_name, username, url, password, cert)
api.get_secret(user_id, secret_id, private_key)
api.list_secrets(user_id)
api.delete_secret(user_id, secret_id)

# Backup Operations
api.export_vault_backup(user_id, private_key, passphrase)
api.import_vault_backup(user_id, cert, backup_data, passphrase)

# Security Features
api.get_password_health(user_id, private_key)
api.rotate_keys(user_id, old_key_bundle, new_key_bundle)
```

### CryptoUtils (Cryptographic Operations)

```python
from services.crypto_utils import CryptoUtils

# Key Generation
key_pair = CryptoUtils.generate_rsa_key_pair(key_size=2048)

# Encryption/Decryption
ciphertext = CryptoUtils.encrypt_aes_gcm(plaintext, key)
plaintext = CryptoUtils.decrypt_aes_gcm(ciphertext, key)

# Digital Signatures
signature = CryptoUtils.sign_data(data, private_key)
is_valid = CryptoUtils.verify_signature(data, signature, public_key)

# Hybrid Encryption
encrypted = CryptoUtils.hybrid_encrypt(data, public_key)
decrypted = CryptoUtils.hybrid_decrypt(encrypted, private_key)
```

---

## Security Considerations

### What This Application Does

- Encrypts all sensitive data before storage
- Never stores the master password (zero-knowledge)
- Uses industry-standard cryptographic algorithms
- Implements defense-in-depth security layers
- Provides tamper-evident audit logging

### What Users Should Do

- Use a strong, unique master password
- Enable two-factor authentication (TOTP)
- Create regular encrypted backups
- Keep the recovery key in a safe location
- Update the application regularly

---

## License

This project is developed for educational purposes as part of **ST6051CEM Practical Cryptography** coursework.

---

## Author

**Biplav Basnet**

- GitHub: [@BiplavBasnet](https://github.com/BiplavBasnet)
- Course: ST6051CEM Practical Cryptography

---

## Acknowledgments

- Cryptography library maintainers
- Argon2 specification authors
- NIST cryptographic standards
