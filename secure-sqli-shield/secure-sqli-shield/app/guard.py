"""Layer 1 - the gateway guard: strict input validation, SQLi detection, rate limiting."""
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


class ValidationError(ValueError):
    pass


class SQLiSuspected(Exception):
    def __init__(self, field: str, pattern: str, sample: str):
        super().__init__(f"{field}: {pattern}")
        self.field, self.pattern, self.sample = field, pattern, sample


_SQLI = {
    "union_select": r"\bunion\b\W+(all\W+)?select\b",
    "boolean_tautology": r"\b(or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
    "quote_then_logic": r"['\"]\s*(or|and)\b",
    "comment_sequence": r"(--|/\*|\*/)",
    "stacked_statement": r";\s*(drop|alter|create|insert|update|delete|select|attach|pragma)\b",
    "time_based": r"\b(sleep|benchmark|pg_sleep|randomblob|waitfor|load_extension)\s*[\(\s]",
    "schema_probe": r"\b(sqlite_master|sqlite_schema|information_schema|pg_catalog)\b",
    "destructive": r"\b(drop|truncate)\s+(table|database)\b",
    "select_from": r"\bselect\b.+\bfrom\b",
}
_SQLI_RE = {name: re.compile(rx, re.IGNORECASE) for name, rx in _SQLI.items()}


def detect_sqli(value: str) -> str | None:
    for name, rx in _SQLI_RE.items():
        if rx.search(value):
            return name
    return None


@dataclass(frozen=True)
class Rule:
    pattern: re.Pattern | None = None
    min_len: int = 1
    max_len: int = 128
    required: bool = True
    scan: bool = True  # run the SQLi detector (passwords are hashed, never placed in SQL text)


USERNAME = Rule(re.compile(r"^[A-Za-z0-9_.-]{3,32}$"), 3, 32)
EMAIL = Rule(re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$"), 6, 254)
PHONE = Rule(re.compile(r"^\+?[0-9 ()\-]{7,20}$"), 7, 21, required=False)
PASSWORD = Rule(None, 10, 128, scan=False)
LOGIN_PASSWORD = Rule(None, 1, 128, scan=False)
PREFIX = Rule(re.compile(r"^[A-Za-z0-9_.-]{0,32}$"), 0, 32, required=False)

REGISTER = {"username": USERNAME, "email": EMAIL, "phone": PHONE, "password": PASSWORD}
LOGIN = {"username": USERNAME, "password": LOGIN_PASSWORD}
PROFILE_UPDATE = {"email": Rule(EMAIL.pattern, 6, 254, required=False), "phone": PHONE}
SEARCH = {"prefix": PREFIX}


def screen_and_validate(body, spec: dict) -> dict:
    if not isinstance(body, dict):
        raise ValidationError("a JSON object is required")
    # 1) detection pass (also over unexpected fields)
    for key, value in body.items():
        rule = spec.get(key)
        if isinstance(value, str) and (rule is None or rule.scan):
            hit = detect_sqli(value)
            if hit:
                raise SQLiSuspected(str(key)[:32], hit, value[:80])
    # 2) strict allow-list validation
    unknown = set(body) - set(spec)
    if unknown:
        raise ValidationError("unexpected field(s)")
    clean = {}
    for name, rule in spec.items():
        value = body.get(name)
        if value is None:
            if rule.required:
                raise ValidationError(f"{name} is required")
            continue
        if not isinstance(value, str):
            raise ValidationError(f"{name} must be a string")
        if not (rule.min_len <= len(value) <= rule.max_len):
            raise ValidationError(f"{name} has invalid length")
        if rule.pattern is not None and not rule.pattern.match(value):
            raise ValidationError(f"{name} has invalid format")
        clean[name] = value
    return clean


def escape_like(prefix: str) -> str:
    return prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class SlidingWindow:
    """Tiny in-memory rate limiter (one process). Use API Gateway / WAF / Redis when scaling out."""

    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _trim(self, key):
        q, cutoff = self._hits[key], time.monotonic() - self.window
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def count(self, key: str) -> int:
        with self._lock:
            return len(self._trim(key))

    def add(self, key: str) -> None:
        with self._lock:
            self._trim(key).append(time.monotonic())

    def allow(self, key: str) -> bool:
        with self._lock:
            q = self._trim(key)
            if len(q) >= self.limit:
                return False
            q.append(time.monotonic())
            return True

    def clear(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)
