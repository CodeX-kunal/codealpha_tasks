"""Capability tokens: signed, short-lived, scoped grants (HMAC-SHA256).

A capability is a named permission such as 'profile:read'. The server checks it twice:
once at the route, and again inside the database layer before any SQL is executed.
"""
import base64
import hashlib
import hmac
import json
import time

ROLE_CAPS = {
    "user": {"profile:read", "profile:write"},
    "admin": {"profile:read", "profile:write", "users:search", "audit:read"},
}
ISSUABLE = set().union(*ROLE_CAPS.values())


class TokenError(Exception):
    pass


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class CapabilityAuthority:
    def __init__(self, key: bytes, ttl: int = 900):
        self._key = key
        self._ttl = ttl

    def _sign(self, payload_b64: str) -> bytes:
        return hmac.new(self._key, b"cap-token:" + payload_b64.encode(), hashlib.sha256).digest()

    def issue(self, user_id: int, role: str) -> tuple[str, list[str]]:
        caps = sorted(ROLE_CAPS.get(role, set()))
        payload = {"sub": int(user_id), "caps": caps, "exp": int(time.time()) + self._ttl}
        payload_b64 = _b64(json.dumps(payload, separators=(",", ":")).encode())
        return f"{payload_b64}.{_b64(self._sign(payload_b64))}", caps

    def verify(self, token: str) -> dict:
        if not token or len(token) > 2048:
            raise TokenError("malformed")
        try:
            payload_b64, sig_b64 = token.split(".")
            given = _unb64(sig_b64)
        except Exception as exc:  # noqa: BLE001
            raise TokenError("malformed") from exc
        if not hmac.compare_digest(self._sign(payload_b64), given):
            raise TokenError("bad signature")
        try:
            claims = json.loads(_unb64(payload_b64))
        except Exception as exc:  # noqa: BLE001
            raise TokenError("malformed") from exc
        if (not isinstance(claims, dict) or type(claims.get("sub")) is not int
                or type(claims.get("exp")) is not int or not isinstance(claims.get("caps"), list)):
            raise TokenError("malformed")
        if claims["exp"] < int(time.time()):
            raise TokenError("expired")
        claims["caps"] = sorted(set(map(str, claims["caps"])) & ISSUABLE)
        return claims
