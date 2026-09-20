"""Storage layer. SQLite for local runs; the same SQL works on PostgreSQL/MySQL (e.g. AWS RDS)."""
import json
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL,
    phone       TEXT NOT NULL,
    address     TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,      -- DB-level guarantee: no exact duplicates, ever
    name_block  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email ON records(email);
CREATE INDEX IF NOT EXISTS idx_phone ON records(phone);
CREATE INDEX IF NOT EXISTS idx_block ON records(name_block);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    input_json TEXT NOT NULL,
    status     TEXT NOT NULL,
    reason     TEXT,
    matched_id INTEGER,
    created_at TEXT NOT NULL
);
"""


class Repository:
    def __init__(self, path: str = "records.db"):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def find_by_fingerprint(self, fp: str):
        return self.conn.execute("SELECT * FROM records WHERE fingerprint=?", (fp,)).fetchone()

    def find_candidates(self, norm: dict, block: str):
        return self.conn.execute(
            "SELECT * FROM records WHERE email=? OR phone=? OR name_block=?",
            (norm["email"], norm["phone"], block),
        ).fetchall()

    def insert(self, norm: dict, fp: str, block: str) -> int:
        """Raises sqlite3.IntegrityError if the fingerprint already exists (race-safe)."""
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO records(name,email,phone,address,fingerprint,name_block,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (norm["name"], norm["email"], norm["phone"], norm["address"], fp, block, _now()),
            )
        return cur.lastrowid

    def log(self, raw: dict, status: str, reason: str, matched_id=None):
        with self.conn:
            self.conn.execute(
                "INSERT INTO audit_log(input_json,status,reason,matched_id,created_at) VALUES(?,?,?,?,?)",
                (json.dumps(raw), status, reason, matched_id, _now()),
            )

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]

    def close(self):
        self.conn.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
