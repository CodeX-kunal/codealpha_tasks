"""Classifies an incoming record against candidate rows already in the database.

UNIQUE          - nothing similar exists.
REDUNDANT       - true duplicate (exact match, or same person re-entered).
FALSE_POSITIVE  - *looks* like a duplicate (similar name / shared phone) but the
                  identifying details conflict, so it is a different real-world entity.
"""
from difflib import SequenceMatcher

NAME_SAME = 0.85      # names considered "the same person"
NAME_SIMILAR = 0.90   # names similar enough to raise a flag
ADDR_SAME = 0.90


def sim(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio() if a and b else 0.0


def compare(new: dict, existing: dict) -> tuple[str, str]:
    """Return ('REDUNDANT' | 'FALSE_POSITIVE' | 'NONE', reason)."""
    same_email = new["email"] == existing["email"]
    same_phone = bool(new["phone"]) and new["phone"] == existing["phone"]
    n_sim = sim(new["name"], existing["name"])
    a_sim = sim(new["address"], existing["address"])

    if same_email or same_phone:
        key = "email" if same_email else "phone"
        if n_sim >= NAME_SAME:
            return "REDUNDANT", f"same {key} and similar name ({n_sim:.2f})"
        return "FALSE_POSITIVE", f"shares {key} but name differs ({n_sim:.2f})"

    if n_sim >= NAME_SIMILAR:
        if a_sim >= ADDR_SAME:
            return "REDUNDANT", f"same name and address, contact changed ({n_sim:.2f}/{a_sim:.2f})"
        return "FALSE_POSITIVE", f"similar name but different email/phone/address ({n_sim:.2f}/{a_sim:.2f})"

    return "NONE", ""
