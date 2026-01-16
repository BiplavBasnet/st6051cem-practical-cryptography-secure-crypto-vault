# SecureCrypt Vault: Advanced Practical Cryptography Portfolio

![Security](https://img.shields.io/badge/Security-Hardened-success)
![Cryptography](https://img.shields.io/badge/Crypto-C6.1%20Compliant-blue)

SecureCrypt Vault is a forensic-grade, multi-layered security application designed for the secure management of credentials and sensitive documentation.

## Security Architecture

### Cryptographic Foundation
- **Data-at-Rest**: AES-256-GCM (AEAD)
- **Key Derivation**: Argon2id with machine-tuned parameters
- **Hybrid Encryption**: RSA-OAEP + AES-GCM envelope encryption

### Public Key Infrastructure (PKI)
- X.509 certificates for auth, signing, and encryption
- Challenge-response authentication
- Forward secrecy via ECDH

### Tamper-Evident Logging
- Hash-chained audit logs
- SHA-256 integrity verification

## Installation

```bash
python -m venv .venv
source .venv/bin/activate  # .venv\Scripts\activate on Windows
pip install -r requirements.txt
python run_tk_desktop.py
```
