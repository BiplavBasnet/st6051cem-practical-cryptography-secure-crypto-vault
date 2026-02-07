import sqlite3
import os
import logging

class DBManager:
    _instance_conn = None

    def __init__(self, db_path="data/vault.db"):
        self.db_path = os.path.abspath(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Disable WAL mode for now to ensure absolute consistency on Windows
        # cursor.execute("PRAGMA journal_mode=WAL")

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                auth_cert_serial TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Certificates table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                serial_number TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                valid_from DATETIME NOT NULL,
                valid_to DATETIME NOT NULL,
                revoked INTEGER DEFAULT 0,
                key_usage TEXT,
                cert_data TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Challenges table for authentication
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                nonce BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Signed documents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS signed_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                cert_serial TEXT, -- Link to the certificate used
                file_name TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                signature BLOB NOT NULL,
                timestamp_token BLOB,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Structured Secrets Vault
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                service_name TEXT NOT NULL,
                username_email TEXT NOT NULL,
                url TEXT,
                encrypted_password BLOB NOT NULL,
                encrypted_dek BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Audit logs with hash chaining
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                details TEXT,
                prev_hash TEXT,
                current_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Rate limiting and lockouts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                attempt_type TEXT NOT NULL, -- 'login' or 'recovery'
                successful INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()
        logging.info("Database initialized successfully.")
# Forensic Integrity: f27f5d8a verified at 2026-02-07 20:55:09
