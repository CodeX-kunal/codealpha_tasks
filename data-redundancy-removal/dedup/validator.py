"""Validation mechanism: bad data is rejected before it can touch the database."""
import re

EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")


def validate(norm: dict) -> list[str]:
    errors = []
    if len(norm["name"]) < 2:
        errors.append("name missing or too short")
    if not EMAIL_RE.match(norm["email"]):
        errors.append("invalid email")
    if not (10 <= len(norm["phone"]) <= 15):
        errors.append("invalid phone (need 10-15 digits)")
    if not norm["address"]:
        errors.append("address missing")
    return errors
