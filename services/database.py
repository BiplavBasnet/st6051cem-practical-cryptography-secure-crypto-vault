import os
import sqlite3
from pathlib import Path

from services.app_paths import db_path as app_db_path


class DBManager:
    def __init__(self, db_name: str = "securevault.db"):
        # If a relative path is provided, store the DB in the per-user app data directory.
        p = Path(db_name)
        self.db_path = (app_db_path(p.name) if not p.is_absolute() else p).resolve()

    def get_connection(self):
        conn = sqlite3.connect(str(self.db_path), detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    @staticmethod
    def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
        cur = conn.cursor()
        cur.execute(f"PRAGMA table_info({table})")
        return {str(r[1]) for r in cur.fetchall()}

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, name: str, col_def: str):
        cols = DBManager._table_columns(conn, table)
        if name not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {col_def}")

    def setup_database(self):
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                auth_cert_serial TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                serial_number TEXT UNIQUE,
                subject TEXT,
                issuer TEXT,
                valid_from DATETIME,
                valid_to DATETIME,
                revoked BOOLEAN DEFAULT 0,
                cert_data TEXT,
                key_usage TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                file_hash TEXT,
                signature BLOB,
                signed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        # v2 table used by enhanced document signing flow (multi-sign + bound cert serial + TSA token)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS signed_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                cert_serial TEXT,
                file_name TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                signature BLOB NOT NULL,
                timestamp_token BLOB,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS encrypted_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                recipient_id INTEGER,
                filename TEXT,
                encrypted_key BLOB,
                encrypted_data BLOB,
                nonce BLOB,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(recipient_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT,
                details TEXT,
                prev_hash TEXT,
                event_hash TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                attempt_type TEXT,
                successful BOOLEAN,
                client_fingerprint TEXT DEFAULT 'global',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                nonce BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        # Vault table includes upgraded crypto/index metadata.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                service_name TEXT NOT NULL,
                username_email TEXT NOT NULL,
                url TEXT,
                canonical_url TEXT DEFAULT '',
                encrypted_password BLOB NOT NULL,
                encrypted_dek BLOB NOT NULL,
                nonce BLOB NOT NULL,
                encrypted_totp BLOB,
                totp_nonce BLOB,
                encrypted_totp_dek BLOB,
                duplicate_token TEXT,
                reuse_token TEXT,
                crypto_version TEXT DEFAULT 'v3-aead-envelope-aad',
                password_updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        # Backup/export event history (metadata only, no secret content)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                summary TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_recovery_config (
                user_id INTEGER PRIMARY KEY,
                backup_enabled INTEGER NOT NULL DEFAULT 0,
                backup_mode TEXT NOT NULL DEFAULT 'recovery_key',
                verifier_salt TEXT NOT NULL,
                verifier_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_backup_at DATETIME,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_settings (
                user_id INTEGER PRIMARY KEY,
                backup_auto_enabled INTEGER NOT NULL DEFAULT 0,
                backup_on_change_enabled INTEGER NOT NULL DEFAULT 0,
                schedule_interval_hours REAL NOT NULL DEFAULT 24.0,
                keep_last_n_backups INTEGER NOT NULL DEFAULT 10,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                device_name TEXT,
                created_at TEXT NOT NULL,
                last_active TEXT NOT NULL,
                revoked INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS share_packages (
                id TEXT PRIMARY KEY,
                sender_user_id INTEGER NOT NULL,
                recipient_fingerprint TEXT,
                encrypted_payload BLOB NOT NULL,
                encrypted_dek BLOB NOT NULL,
                nonce BLOB NOT NULL,
                burn_after_read INTEGER DEFAULT 0,
                expires_at TEXT,
                opened INTEGER DEFAULT 0,
                opened_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (sender_user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # ---- Safe migrations for existing DBs ----
        self._ensure_column(conn, "vault_secrets", "canonical_url", "TEXT DEFAULT ''")
        self._ensure_column(conn, "vault_secrets", "duplicate_token", "TEXT")
        self._ensure_column(conn, "vault_secrets", "reuse_token", "TEXT")
        self._ensure_column(conn, "vault_secrets", "crypto_version", "TEXT DEFAULT 'v3-aead-envelope-aad'")
        self._ensure_column(conn, "vault_secrets", "password_updated_at", "DATETIME DEFAULT CURRENT_TIMESTAMP")
        self._ensure_column(conn, "vault_secrets", "encrypted_totp", "BLOB")
        self._ensure_column(conn, "vault_secrets", "totp_nonce", "BLOB")
        self._ensure_column(conn, "vault_secrets", "encrypted_totp_dek", "BLOB")
        # Phase 5: backup health (validation status, staleness threshold)
        self._ensure_column(conn, "backup_settings", "latest_validation_ok", "INTEGER")
        self._ensure_column(conn, "backup_settings", "latest_validation_at", "DATETIME")
        self._ensure_column(conn, "backup_settings", "stale_warning_days", "INTEGER DEFAULT 7")
        self._ensure_column(conn, "backup_settings", "on_change_debounce_seconds", "INTEGER DEFAULT 60")
        # Per-user activity log: actor_username for display (user_id already exists as actor)
        self._ensure_column(conn, "audit_logs", "actor_username", "TEXT")

        # Useful indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cert_user_usage_revoked ON certificates(user_id, key_usage, revoked)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_challenges_user_nonce_used_exp ON challenges(user_id, nonce, used, expires_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_attempts_lookup ON security_attempts(username, attempt_type, client_fingerprint, successful, created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created ON audit_logs(user_id, created_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_signed_docs_hash ON signed_documents(file_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_signed_docs_user ON signed_documents(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_owner_search ON vault_secrets(owner_id, service_name, username_email, url)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_owner_duplicate ON vault_secrets(owner_id, duplicate_token)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_owner_reuse ON vault_secrets(owner_id, reuse_token)")

        conn.commit()
        conn.close()

    def clear_all_data(self):
        conn = self.get_connection()
        cursor = conn.cursor()

        # Order matters due FK constraints
        cursor.execute("DELETE FROM challenges")
        cursor.execute("DELETE FROM encrypted_documents")
        cursor.execute("DELETE FROM signed_documents")
        cursor.execute("DELETE FROM documents")
        cursor.execute("DELETE FROM certificates")
        cursor.execute("DELETE FROM vault_secrets")
        cursor.execute("DELETE FROM backup_events")
        cursor.execute("DELETE FROM backup_recovery_config")
        cursor.execute("DELETE FROM backup_settings")
        cursor.execute("DELETE FROM security_attempts")
        cursor.execute("DELETE FROM audit_logs")
        cursor.execute("DELETE FROM users")

        conn.commit()
        conn.close()

    def test_connection(self):
        try:
            conn = self.get_connection()
            conn.close()
            return True
        except Exception:
            return False


if __name__ == "__main__":
    db = DBManager()
    db.setup_database()
    print("Database and tables created successfully.")
