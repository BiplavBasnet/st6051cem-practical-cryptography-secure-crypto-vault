# SecureCrypt Vault: Advanced Practical Cryptography Portfolio

![Security](https://img.shields.io/badge/Security-Hardened-success)
![Cryptography](https://img.shields.io/badge/Crypto-C6.1%20Compliant-blue)
![Docker](https://img.shields.io/badge/Deployment-Dockerized-cyan)
![Build](https://img.shields.io/badge/Build-Passing-green)

SecureCrypt Vault is a forensic-grade, multi-layered security application designed for the secure management of credentials and sensitive documentation. This project demonstrates advanced implementation of modern cryptographic primitives, identity management, and tamper-evident logging.

---

## 🛡️ Security Architecture & Engineering

The vault is engineered with a **Defense-in-Depth** philosophy, ensuring that no single failure can compromise the integrity of the user's identity or data.

### 1. Cryptographic Foundation
- **Data-at-Rest**: All secrets and documents are encrypted using **AES-256-GCM** (Galois/Counter Mode), providing both confidentiality and built-in authenticity verification (AEAD).
- **Key Derivation**: Passphrases are transmuted into high-entropy master keys using **PBKDF2-HMAC-SHA256** with **600,000 iterations**, providing high resistance to GPU-accelerated brute-force attacks.
- **Hybrid Encryption**: Employs a robust hybrid model where data is encrypted with random 256-bit Data Encryption Keys (DEKs), which are then asymmetrically wrapped via **RSA-4096-OAEP**.

### 2. Public Key Infrastructure (PKI)
- **Identity Assurance**: Every user is issued a unique set of X.509 certificates (Auth, Signing, Encryption) upon registration, issued by the system's internal **Root CA**.
- **Challenge-Response**: Authentication bypasses traditional database password comparisons, instead utilizing a cryptographic challenge-response protocol to prove possession of the private key.
- **Forward Secrecy**: Temporary session keys are derived for operations, minimizing the impact of any potential session compromise.

### 3. Tamper-Evident Forensic Logging
- **Hash-Chaining**: Audit logs are structured as a cryptographic chain. Every event contains a SHA-256 digest of the previous event's hash, making it mathematically impossible to alter or delete logs without detection.
- **Global Consistency**: The system performs a full integrity check of the audit chain on every startup.

---

## 🚀 Key Features

- **Structured Secret Vault**: Securely store service credentials with PKI-backed isolation.
- **Signed Document Wallet**: Protect PDF and sensitive files with digital signatures and timestamped integrity proofs.
- **Brute-Force Protection**: Adaptive rate-limiting and account lockout mechanisms with exponential backoff.
- **Forensic Audit Utility**: Administrative tools to verify the integrity of the entire system history.
- **Zero-Trust Local Key Management**: Sensitive private key material is stored in partitioned local vaults with per-operation passphrase prompts.

---

## 🛠️ Technology Stack

| Component | Technology |
| :--- | :--- |
| **Language** | Python 3.13+ |
| **Cryptography** | `cryptography` (OpenSSL Backend) |
| **Database** | SQLite3 (C6.1 Hardened Schema) |
| **CLI Framework** | Typer & Rich (Professional UI) |
| **Containerization** | Docker & Docker-Compose |

---

## 📥 Installation & Setup

### Docker Deployment (Recommended)
The project is fully containerized for high-security isolation.
```bash
# Start the secure vault
docker-compose up --build
```

### Local Environment Setup
```bash
# Initialize virtual environment
python -m venv venv
source venv/bin/activate  # venv\Scripts\activate on Windows

# Install high-security dependencies
pip install -r requirements.txt

# Launch CLI
python secure_crypt_cli.py
```

---

## 🏁 Academic & Professional Context
This repository was developed as part of a high-security practical cryptography module, demonstrating end-to-end security hardening, cryptographic lifecycle management, and forensic transparency.

**State**: Production - Hardened  
**Verification**: All cryptographic modules verified against NIST standards.
