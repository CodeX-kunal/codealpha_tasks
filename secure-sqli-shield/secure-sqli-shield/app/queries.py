"""The ONLY SQL this application can run.

Callers never pass SQL text. They pass a query *name*, parameters and their capabilities.
Each statement is a fixed template with '?' placeholders, tagged with the capability required
to run it and the exact parameter types it accepts.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Query:
    sql: str
    capability: str
    params: tuple
    fetch: str  # "one" | "all" | "none"


CATALOG: dict[str, Query] = {
    "user.create": Query(
        "INSERT INTO users(username, email_enc, email_bidx, phone_enc, password_enc, role, created_at) "
        "VALUES(?, ?, ?, ?, ?, ?, ?)",
        "auth:register", (str, str, str, str, str, str, str), "none"),
    "user.email_exists": Query(
        "SELECT 1 AS present FROM users WHERE email_bidx = ?",
        "auth:register", (str,), "one"),
    "user.by_username": Query(
        "SELECT id, username, password_enc, role FROM users WHERE username = ?",
        "auth:login", (str,), "one"),
    "profile.get": Query(
        "SELECT id, username, email_enc, phone_enc, created_at FROM users WHERE id = ?",
        "profile:read", (int,), "one"),
    "profile.email_taken": Query(
        "SELECT 1 AS present FROM users WHERE email_bidx = ? AND id != ?",
        "profile:write", (str, int), "one"),
    "profile.update": Query(
        "UPDATE users SET email_enc = ?, email_bidx = ?, phone_enc = ? WHERE id = ?",
        "profile:write", (str, str, str, int), "none"),
    "users.search": Query(
        "SELECT id, username, role, created_at FROM users "
        "WHERE username LIKE ? ESCAPE '\\' ORDER BY username LIMIT 50",
        "users:search", (str,), "all"),
    "audit.write": Query(
        "INSERT INTO security_events(ts, ip, kind, detail) VALUES(?, ?, ?, ?)",
        "audit:write", (str, str, str, str), "none"),
    "audit.recent": Query(
        "SELECT id, ts, ip, kind, detail FROM security_events ORDER BY id DESC LIMIT 100",
        "audit:read", (), "all"),
}
