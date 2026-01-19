"""
Centralized app path helpers with env override support.

Environment variables (when set) override default paths for tests:
- SECURECRYPT_DATA_DIR
- SECURECRYPT_CONFIG_DIR
- SECURECRYPT_LOG_DIR
- SECURECRYPT_BACKUP_DIR
- SECURECRYPT_BASE_DIR (overrides base; keys/pki go under base if not overridden)
"""

import os
from pathlib import Path

APP_NAME = "SecureCryptVault"


def _base_dir() -> Path:
    """
    Return a per-user application data directory.
    - Windows: %APPDATA%/SecureCryptVault
    - Others: ~/.securecrypt-vault
    - Env SECURECRYPT_BASE_DIR overrides when set.
    """
    env_base = os.environ.get("SECURECRYPT_BASE_DIR")
    if env_base:
        return Path(env_base).resolve()
    if os.name == "nt":
        root = Path(os.environ.get("APPDATA", str(Path.home())))
        return root / APP_NAME
    return Path.home() / ".securecrypt-vault"


def _resolve_path(env_var: str, default: Path) -> Path:
    """If env_var is set, return that path; else default. Create dirs if missing."""
    val = os.environ.get(env_var)
    if val:
        p = Path(val).resolve()
    else:
        p = default
    p.mkdir(parents=True, exist_ok=True)
    return p


def app_dir() -> Path:
    p = _base_dir()
    p.mkdir(parents=True, exist_ok=True)
    return p


def ensure_dirs() -> dict[str, Path]:
    base = app_dir()
    dirs = {
        "base": base,
        "config": _resolve_path("SECURECRYPT_CONFIG_DIR", base / "config"),
        "keys": base / "keys",
        "pki": base / "pki",
        "logs": _resolve_path("SECURECRYPT_LOG_DIR", base / "logs"),
        "data": _resolve_path("SECURECRYPT_DATA_DIR", base / "data"),
        "backups": _resolve_path("SECURECRYPT_BACKUP_DIR", base / "backups"),
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def backups_dir() -> Path:
    """Base directory for versioned local backups (Phase 2)."""
    return ensure_dirs()["backups"]


def backups_dir_for_user(username: str) -> Path:
    """Per-user backup directory. Use only safe usernames (no path traversal)."""
    import re
    safe = re.sub(r"[^\w\-.]", "_", (username or "unknown").strip())[:64] or "user"
    path = backups_dir() / safe
    path.mkdir(parents=True, exist_ok=True)
    return path

def config_path(name: str) -> Path:
    return ensure_dirs()["config"] / name

def keys_dir() -> Path:
    return ensure_dirs()["keys"]

def pki_dir() -> Path:
    return ensure_dirs()["pki"]

def logs_dir() -> Path:
    return ensure_dirs()["logs"]

def data_dir() -> Path:
    return ensure_dirs()["data"]

def db_path(name: str = "securevault.db") -> Path:
    # Keep the DB in data/ to avoid cluttering the repo folder
    return data_dir() / name
