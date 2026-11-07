
import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "investigations.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                verdict TEXT NOT NULL,
                iocs TEXT,
                file_hash TEXT
            )
        """)

        # Migration for databases created with the older schema.
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(investigations)"
            ).fetchall()
        }

        if "file_hash" not in columns:
            connection.execute(
                "ALTER TABLE investigations ADD COLUMN file_hash TEXT"
            )

        connection.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_investigations_file_hash
            ON investigations(file_hash)
            WHERE file_hash IS NOT NULL
        """)


def save_investigation(
    filename,
    risk_score,
    risk_level,
    verdict,
    iocs,
    file_hash
):
    with get_connection() as connection:

        # Insert the investigation only once per email hash.
        connection.execute("""
            INSERT OR IGNORE INTO investigations
            (filename, risk_score, risk_level, verdict, iocs, file_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            filename,
            risk_score,
            risk_level,
            verdict,
            json.dumps(iocs),
            file_hash
        ))

        # Update the verdict when the AI investigation becomes available.
        if verdict != "Not determined":
            connection.execute("""
                UPDATE investigations
                SET verdict = ?
                WHERE file_hash = ?
            """, (verdict, file_hash))


def get_all_investigations():
    with get_connection() as connection:
        return connection.execute("""
            SELECT id, filename, analyzed_at,
                   risk_score, risk_level, verdict, iocs
            FROM investigations
            ORDER BY analyzed_at DESC
        """).fetchall()
