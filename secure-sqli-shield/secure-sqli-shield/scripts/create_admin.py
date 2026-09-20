"""Create an admin account (admins cannot self-register over the API).

    python scripts/create_admin.py <username> <email>
"""
import getpass
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import guard  # noqa: E402
from app.config import Config  # noqa: E402
from app.crypto import Crypto  # noqa: E402
from app.db import SecureDB  # noqa: E402


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    username, email = sys.argv[1], sys.argv[2].lower()
    password = getpass.getpass("Admin password (min 10 chars): ")
    fields = guard.screen_and_validate(
        {"username": username, "email": email, "password": password}, guard.REGISTER)
    cfg = Config.from_env()
    crypto, db = Crypto(cfg.enc_key, cfg.mac_key), SecureDB(cfg.db_path)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    db.run("user.create", (
        fields["username"], crypto.encrypt(email, "email"), crypto.blind_index(email),
        crypto.encrypt("", "phone"), crypto.protect_password(fields["password"]), "admin", now),
        {"auth:register"})
    print(f"admin '{username}' created")


if __name__ == "__main__":
    main()
