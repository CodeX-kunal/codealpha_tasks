"""Configuration. Secrets come from environment variables, never from source code."""
import base64
import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


def _key_from_env(name: str) -> bytes:
    raw = os.environ.get(name)
    if not raw:
        raise ConfigError(f"{name} is not set. Generate keys with: python scripts/gen_keys.py")
    try:
        key = base64.urlsafe_b64decode(raw.encode())
    except Exception as exc:  # noqa: BLE001
        raise ConfigError(f"{name} is not valid urlsafe-base64") from exc
    if len(key) != 32:
        raise ConfigError(f"{name} must decode to exactly 32 bytes (256 bits)")
    return key


@dataclass(frozen=True)
class Config:
    enc_key: bytes                 # AES-256 key (data at rest)
    mac_key: bytes                 # HMAC key (capability tokens + blind index)
    db_path: str = "secure_app.db"
    token_ttl: int = 900           # capability token lifetime in seconds

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            enc_key=_key_from_env("APP_ENC_KEY"),
            mac_key=_key_from_env("APP_TOKEN_KEY"),
            db_path=os.environ.get("DB_PATH", "secure_app.db"),
            token_ttl=int(os.environ.get("TOKEN_TTL_SECONDS", "900")),
        )
