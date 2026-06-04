import sqlite3
from datetime import datetime
from pathlib import Path

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at TEXT NOT NULL,
    url TEXT NOT NULL,
    score INTEGER NOT NULL,
    level TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    notes TEXT
);
"""


def initialize_database(db_path: str = "history.db") -> None:
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(DB_SCHEMA)
        conn.commit()


def save_url_check(db_path: str, url: str, score: int, level: str, confidence: int, notes: str | None = None) -> None:
    checked_at = datetime.utcnow().isoformat(sep=" ", timespec="seconds")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO history (checked_at, url, score, level, confidence, notes) VALUES (?, ?, ?, ?, ?, ?)",
            (checked_at, url, score, level, confidence, notes or ""),
        )
        conn.commit()


def get_history(db_path: str, limit: int = 20) -> list[dict]:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            "SELECT checked_at, url, score, level, confidence, notes FROM history ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = cursor.fetchall()
    return [
        {
            "checked_at": row[0],
            "url": row[1],
            "score": row[2],
            "level": row[3],
            "confidence": row[4],
            "notes": row[5],
        }
        for row in rows
    ]
