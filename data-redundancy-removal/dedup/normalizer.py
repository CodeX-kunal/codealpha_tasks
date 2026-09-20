"""Normalisation + fingerprinting: makes 'John  SMITH' and 'john smith' identical."""
import hashlib
import re
import unicodedata


def _clean(text) -> str:
    text = unicodedata.normalize("NFKC", str(text or "")).strip().lower()
    return re.sub(r"\s+", " ", text)


def _strip_punct(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", text)).strip()


def normalize_record(rec: dict) -> dict:
    phone = re.sub(r"\D", "", str(rec.get("phone") or ""))
    phone = phone[-10:] if len(phone) > 10 else phone  # drop country code
    return {
        "name": _strip_punct(_clean(rec.get("name"))),
        "email": _clean(rec.get("email")),
        "phone": phone,
        "address": _strip_punct(_clean(rec.get("address"))),
    }


def fingerprint(norm: dict) -> str:
    """SHA-256 of the canonical record -> O(1) exact-duplicate lookup."""
    payload = "|".join(norm[k] for k in ("name", "email", "phone", "address"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def name_block(norm: dict) -> str:
    """Cheap blocking key so fuzzy matching only compares a few candidates, not the whole table."""
    return norm["name"][:3]
