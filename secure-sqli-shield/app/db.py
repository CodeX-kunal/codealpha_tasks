"""Layer 2 - the data layer. Even if Layer 1 were bypassed, this still holds:

1. Only catalogued, parameterised statements can run (no raw SQL from callers).
2. Each statement demands a capability the caller must hold.
3. Parameter count and types are checked before binding.
4. The SQLite authoriser (least privilege) denies DROP/ALTER/CREATE/ATTACH/PRAGMA/DELETE and
   any read of sqlite_* system tables, so a hypothetical injection could not exfiltrate the schema
   or destroy data.
5. sqlite3 refuses stacked statements ("SELECT 1; DROP TABLE ...").
"""
import os
import sqlite3
import threading

from .queries import CATALOG

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    email_enc    TEXT NOT NULL,          -- AES-256-GCM
    email_bidx   TEXT NOT NULL UNIQUE,   -- HMAC blind index (duplicate check only)
    phone_enc    TEXT NOT NULL,          -- AES-256-GCM
    password_enc TEXT NOT NULL,          -- AES-256-GCM(scrypt hash)
    role         TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_events (
    id     INTEGER PRIMARY KEY,
    ts     TEXT NOT NULL,
    ip     TEXT NOT NULL,
    kind   TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""

# sqlite3 authoriser action codes (hard-coded so this works on every Python version)
_INSERT, _READ, _SELECT, _TRANSACTION, _UPDATE, _FUNCTION = 18, 20, 21, 22, 23, 31
_ALLOWED_ACTIONS = {_INSERT, _READ, _SELECT, _TRANSACTION, _UPDATE, _FUNCTION}
_OK, _DENY = 0, 1


def _authorizer(action, arg1, arg2, dbname, source):
    if action not in _ALLOWED_ACTIONS:
        return _DENY
    if action == _READ and str(arg1).startswith("sqlite_"):
        return _DENY
    return _OK


class CapabilityDenied(PermissionError):
    pass


class UnknownQuery(KeyError):
    pass


class BadParameters(ValueError):
    pass


class SecureDB:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._conn.executescript(SCHEMA)
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        self._conn.set_authorizer(_authorizer)  # lock the connection down AFTER setup

    def run(self, name: str, params: tuple, caps):
        query = CATALOG.get(name)
        if query is None:
            raise UnknownQuery(name)
        if query.capability not in caps:
            raise CapabilityDenied(f"'{query.capability}' capability required for {name}")
        if len(params) != len(query.params) or any(
                type(p) is not t for p, t in zip(params, query.params)):
            raise BadParameters(f"wrong parameters for {name}")
        with self._lock, self._conn:
            cur = self._conn.execute(query.sql, params)  # values are BOUND, never concatenated
            if query.fetch == "one":
                row = cur.fetchone()
                return dict(row) if row else None
            if query.fetch == "all":
                return [dict(r) for r in cur.fetchall()]
            return cur.rowcount
