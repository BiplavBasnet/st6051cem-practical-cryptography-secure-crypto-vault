#!/usr/bin/env python3
"""Remove local runtime artifacts only (not source).

Safe cleanup: refuse if inside system path, dry-run by default, require --yes to delete.
Removes: .venv/, venv/, env/, __pycache__/ (recursively), .pytest_cache/,
logs/, data/, backups/, tsa/, pki/, keys/, *.db, *.db-wal, *.db-shm
"""

import argparse
import os
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Directories to remove (relative to repo root)
REMOVE_DIRS = [
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    "logs",
    "data",
    "backups",
    "tsa",
    "pki",
    "keys",
]

# Glob patterns for DB files
REMOVE_DB_GLOBS = ["*.db", "*.db-wal", "*.db-shm"]

# Paths that indicate we're inside a system/installation directory (refuse to run)
SYSTEM_INDICATORS = [
    os.path.expanduser("~/.local"),
    "/usr/",
    "/opt/",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
]


def _is_system_path() -> bool:
    """Refuse if project root is inside a system path (basic guard)."""
    root = PROJECT_ROOT.resolve()
    root_str = str(root).lower()
    for ind in SYSTEM_INDICATORS:
        try:
            p_str = str(Path(ind).resolve()).lower()
            if p_str and root_str.startswith(p_str):
                return True
        except Exception:
            pass
    return False


def collect_artifacts() -> list[Path]:
    """Collect all paths that would be removed."""
    collected = []
    for name in REMOVE_DIRS:
        p = PROJECT_ROOT / name
        if p.exists():
            collected.append(p)
    for d in PROJECT_ROOT.rglob("__pycache__"):
        if d.is_dir() and d not in collected:
            collected.append(d)
    for pattern in REMOVE_DB_GLOBS:
        for f in PROJECT_ROOT.glob(pattern):
            if f.is_file() and f not in collected:
                collected.append(f)
    return collected


def main():
    parser = argparse.ArgumentParser(
        description="Remove local runtime artifacts. Dry-run by default; use --yes to actually delete."
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Actually delete artifacts. Without this, only lists what would be removed.",
    )
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)

    if _is_system_path():
        print("Refusing to run: project appears to be inside a system path.", file=sys.stderr)
        return 1

    artifacts = collect_artifacts()
    if not artifacts:
        print("No local artifacts to remove.")
        return 0

    print("Would remove:" if not args.yes else "Removing:")
    for p in sorted(artifacts, key=lambda x: str(x)):
        print(f"  {p}")

    if not args.yes:
        print("\nDry-run. To actually delete, run: python scripts/cleanup_local_artifacts.py --yes")
        return 0

    removed = []
    for p in artifacts:
        try:
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            removed.append(p)
        except Exception as e:
            print(f"  [SKIP] {p}: {e}", file=sys.stderr)

    print(f"\nRemoved {len(removed)} items.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
