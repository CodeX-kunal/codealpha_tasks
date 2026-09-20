"""Print fresh 256-bit keys:  export $(python scripts/gen_keys.py | xargs)"""
import base64
import os

for name in ("APP_ENC_KEY", "APP_TOKEN_KEY"):
    print(f"{name}={base64.urlsafe_b64encode(os.urandom(32)).decode()}")
