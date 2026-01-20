"""
Cross-platform utilities: app data dir, temp dir, open folder/file, console clear, env detection.
Uses pathlib and os.environ only; no external libs. Safe on Windows and Linux.
"""

import os
import subprocess
import sys
from pathlib import Path

APP_NAME = "SecureCryptVault"


def is_windows() -> bool:
    return os.name == "nt"


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def is_darwin() -> bool:
    return sys.platform == "darwin"


def get_app_data_base() -> Path:
    """
    Cross-platform base directory for app data (read/write safe).
    - Windows: %APPDATA%/<AppName> or %LOCALAPPDATA%/<AppName>
    - Linux: $XDG_DATA_HOME/<AppName> if set, else ~/.local/share/<AppName>
    - Env SECURECRYPT_BASE_DIR overrides when set.
    """
    env_base = os.environ.get("SECURECRYPT_BASE_DIR")
    if env_base:
        return Path(env_base).resolve()
    if is_windows():
        root = Path(os.environ.get("APPDATA", os.environ.get("LOCALAPPDATA", str(Path.home()))))
        return root / APP_NAME
    # Linux and other Unix
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).resolve() / APP_NAME
    return Path.home() / ".local" / "share" / APP_NAME


def get_temp_dir() -> Path:
    """Safe temp directory; uses system default (e.g. TMPDIR, TEMP)."""
    import tempfile
    return Path(tempfile.gettempdir())


def open_folder(path: Path | str) -> tuple[bool, str]:
    """
    Open a folder in the system file manager. Cross-platform.
    Returns (success, error_message). Message is empty on success.
    """
    p = Path(path).resolve() if path else None
    if not p or not p.exists():
        return False, "Path does not exist"
    if not p.is_dir():
        return False, "Not a directory"
    try:
        if is_windows():
            os.startfile(str(p))
            return True, ""
        if is_darwin():
            subprocess.run(["open", str(p)], check=False, timeout=5)
            return True, ""
        # Linux and others: xdg-open if available
        subprocess.run(["xdg-open", str(p)], check=False, timeout=5)
        return True, ""
    except FileNotFoundError:
        if is_linux():
            return False, "xdg-open not found. Install xdg-utils or open the folder manually."
        return False, "Could not open folder"
    except Exception as e:
        return False, str(e)


def open_file(path: Path | str) -> tuple[bool, str]:
    """
    Open a file with the system default application. Cross-platform.
    Returns (success, error_message).
    """
    p = Path(path).resolve() if path else None
    if not p or not p.exists():
        return False, "Path does not exist"
    try:
        if is_windows():
            os.startfile(str(p))
            return True, ""
        if is_darwin():
            subprocess.run(["open", str(p)], check=False, timeout=5)
            return True, ""
        subprocess.run(["xdg-open", str(p)], check=False, timeout=5)
        return True, ""
    except FileNotFoundError:
        if is_linux():
            return False, "xdg-open not found. Install xdg-utils or open the file manually."
        return False, "Could not open file"
    except Exception as e:
        return False, str(e)


def clear_console() -> None:
    """Clear the terminal (if used). Cross-platform; no-op in GUI."""
    if is_windows():
        try:
            subprocess.run(["cmd", "/c", "cls"], check=False)
        except Exception:
            pass
    else:
        try:
            subprocess.run(["clear"], check=False)
        except Exception:
            pass


def get_project_root() -> Path:
    """
    Resolve project root from run_tk_desktop.py or this file's location.
    Prefer RUN_TK_DESKTOP_DIR if set (for bundled apps).
    """
    env = os.environ.get("RUN_TK_DESKTOP_DIR")
    if env:
        return Path(env).resolve()
    # From this file: .../services/platform_utils.py -> .../
    this = Path(__file__).resolve()
    if "services" in this.parts:
        return this.parent.parent
    return this.parent
