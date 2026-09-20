"""Validation -> exact check -> fuzzy check -> append only unique, verified data."""
import sqlite3
from dataclasses import dataclass
from enum import Enum

from .classifier import compare
from .normalizer import fingerprint, name_block, normalize_record
from .repository import Repository
from .validator import validate


class Status(str, Enum):
    UNIQUE = "UNIQUE"                  # inserted
    FALSE_POSITIVE = "FALSE_POSITIVE"  # flagged, verified as different entity, inserted
    REDUNDANT = "REDUNDANT"            # duplicate, NOT inserted
    INVALID = "INVALID"                # failed validation, NOT inserted


@dataclass
class Decision:
    status: Status
    reason: str
    inserted: bool
    matched_id: int | None = None


class DedupPipeline:
    def __init__(self, repo: Repository):
        self.repo = repo

    def process(self, raw: dict) -> Decision:
        norm = normalize_record(raw)

        # 1. Validation
        errors = validate(norm)
        if errors:
            return self._finish(raw, Decision(Status.INVALID, "; ".join(errors), False))

        # 2. Exact-duplicate check (hash lookup, O(1))
        fp, block = fingerprint(norm), name_block(norm)
        hit = self.repo.find_by_fingerprint(fp)
        if hit:
            return self._finish(raw, Decision(Status.REDUNDANT, "exact duplicate", False, hit["id"]))

        # 3. Fuzzy check against a small candidate set only
        redundant, false_pos = None, None
        for row in self.repo.find_candidates(norm, block):
            verdict, reason = compare(norm, dict(row))
            if verdict == "REDUNDANT":
                redundant = (reason, row["id"])
                break
            if verdict == "FALSE_POSITIVE" and false_pos is None:
                false_pos = (reason, row["id"])

        if redundant:
            return self._finish(raw, Decision(Status.REDUNDANT, redundant[0], False, redundant[1]))

        # 4. Append (unique and verified). UNIQUE index on fingerprint is the last line of defence.
        try:
            self.repo.insert(norm, fp, block)
        except sqlite3.IntegrityError:
            return self._finish(raw, Decision(Status.REDUNDANT, "exact duplicate (race)", False))

        if false_pos:
            return self._finish(raw, Decision(Status.FALSE_POSITIVE, false_pos[0], True, false_pos[1]))
        return self._finish(raw, Decision(Status.UNIQUE, "no similar record found", True))

    def process_batch(self, rows: list[dict]) -> list[Decision]:
        return [self.process(r) for r in rows]

    def _finish(self, raw, decision: Decision) -> Decision:
        self.repo.log(raw, decision.status.value, decision.reason, decision.matched_id)
        return decision
