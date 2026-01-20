import os
import sqlite3
from pathlib import Path

from services.app_paths import db_path as app_db_path


class DBManager:
    def __init__(self, db_name: str = "securevault.db"):
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

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                auth_cert_serial TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

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
    print("Database created successfully.")
