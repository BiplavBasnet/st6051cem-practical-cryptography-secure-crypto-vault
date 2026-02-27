"""Tests for audit log hash chain and thread-safety."""

import os
import shutil
import sys
import tempfile
import threading
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from services.database import DBManager
from services.audit_log import AuditLog


@pytest.fixture
def audit_env():
    base = tempfile.mkdtemp(prefix="audit_test_")
    old = os.environ.pop("SECURECRYPT_BASE_DIR", None)
    os.environ["SECURECRYPT_BASE_DIR"] = base
    try:
        db_path = Path(base) / "data"
        db_path.mkdir(parents=True, exist_ok=True)
        db = DBManager(str(db_path / "test.db"))
        db.setup_database()
        audit = AuditLog(db)
        yield audit
    finally:
        os.environ.pop("SECURECRYPT_BASE_DIR", None)
        if old:
            os.environ["SECURECRYPT_BASE_DIR"] = old
        shutil.rmtree(base, ignore_errors=True)


def test_audit_chain_integrity(audit_env):
    audit = audit_env
    audit.log_event("TEST_A", {"a": 1})
    audit.log_event("TEST_B", {"b": 2})
    ok, msg = audit.verify_integrity()
    assert ok, msg


def test_audit_chain_thread_safe(audit_env):
    audit = audit_env
    errors = []
    n_threads = 50

    def worker(i):
        try:
            audit.log_event("THREAD_EVENT", {"thread_id": i, "seq": i})
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    ok, msg = audit.verify_integrity()
    assert ok, msg
