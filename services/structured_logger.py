"""Structured application logger with rotation and secret-scrubbing.

Provides a singleton logger that:
  - Writes JSON-formatted log lines to logs/app.log
  - Rotates logs at 5 MB (keeps 3 backups)
  - Scrubs known secret patterns (PEM keys, long hex, passwords)
  - Never logs raw secrets
"""

import logging
import logging.handlers
import os
import re
import json
from pathlib import Path


_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"-----BEGIN[A-Z ]*KEY-----[\s\S]*?-----END[A-Z ]*KEY-----"), "[REDACTED_KEY]"),
    (re.compile(r"(?i)(password|passphrase|secret|token|key)\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"[0-9a-fA-F]{64,}"), "[REDACTED_HEX]"),
]


class _SecretScrubFilter(logging.Filter):
    """Scrub known secret patterns from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pattern, replacement in _SECRET_PATTERNS:
            msg = pattern.sub(replacement, msg)
        record.msg = msg
        record.args = ()
        return True


class _JsonFormatter(logging.Formatter):
    """Emit structured JSON log lines."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def get_logger(name: str = "securecrypt") -> logging.Logger:
    """Return the application-wide logger (singleton per name)."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    try:
        from services.app_paths import logs_dir
        log_dir = logs_dir()
    except Exception:
        log_dir = Path("logs")
        log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "app.log"

    handler = logging.handlers.RotatingFileHandler(
        str(log_file),
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(_JsonFormatter())
    handler.addFilter(_SecretScrubFilter())

    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    return logger
