# services/security.py
from cryptography.fernet import Fernet
import hashlib
import re
import base64
import os
import socket  # Added for IP address functionality

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive Fernet-compatible key from password"""
    raw_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        600000,
        dklen=32  # Explicit 32-byte output
    )
    return base64.urlsafe_b64encode(raw_key)  # Proper Fernet encoding

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Generate 16-byte salt
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000), salt

def encrypt_data(data, key):
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key).encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key).decrypt(encrypted_data).decode()

def validate_password(password):
    if len(password) < 8:
        return False, "Minimum 12 characters required"
    if not re.search(r'[A-Z]', password):
        return False, "Requires uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Requires lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Requires number"
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Requires special character"
    return True, "Strong password"

def calculate_password_strength(password):
    """Calculate password strength score (0-4 scale)"""
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r'[A-Z]', password): score += 1
    if re.search(r'[a-z]', password): score += 1
    if re.search(r'[0-9]', password): score += 1
    if re.search(r'[^A-Za-z0-9]', password): score += 1
    return min(score, 4)  # Cap at 4 for consistency

def detect_reused_passwords(passwords):
    """Detect duplicate passwords in a list"""
    seen = set()
    duplicates = []
    for pwd in passwords:
        if pwd in seen:
            duplicates.append(pwd)
        seen.add(pwd)
    return duplicates

def get_client_ip():
    """Get actual client IP address (works for local network)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google DNS server
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception:
        return "127.0.0.1"