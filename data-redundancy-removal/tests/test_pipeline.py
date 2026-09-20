import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dedup import DedupPipeline, Status
from dedup.repository import Repository

BASE = {"name": "John Smith", "email": "john@example.com", "phone": "5551234567", "address": "12 Park Ave NY"}


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repository(":memory:")
        self.p = DedupPipeline(self.repo)

    def test_unique_is_inserted(self):
        d = self.p.process(BASE)
        self.assertEqual(d.status, Status.UNIQUE)
        self.assertEqual(self.repo.count(), 1)

    def test_exact_duplicate_after_normalisation(self):
        self.p.process(BASE)
        d = self.p.process({**BASE, "name": "  JOHN   smith ", "phone": "(555) 123-4567"})
        self.assertEqual(d.status, Status.REDUNDANT)
        self.assertEqual(self.repo.count(), 1)

    def test_typo_same_email_is_redundant(self):
        self.p.process(BASE)
        d = self.p.process({**BASE, "name": "Jon Smith", "address": "other"})
        self.assertEqual(d.status, Status.REDUNDANT)

    def test_same_name_different_person_is_false_positive_and_inserted(self):
        self.p.process(BASE)
        d = self.p.process({"name": "John Smith", "email": "js2@work.com",
                            "phone": "5559998888", "address": "400 Market St SF"})
        self.assertEqual(d.status, Status.FALSE_POSITIVE)
        self.assertTrue(d.inserted)
        self.assertEqual(self.repo.count(), 2)

    def test_shared_phone_different_name_is_false_positive(self):
        self.p.process(BASE)
        d = self.p.process({**BASE, "name": "Mary Jones", "email": "mary@example.com"})
        self.assertEqual(d.status, Status.FALSE_POSITIVE)

    def test_invalid_rejected(self):
        d = self.p.process({**BASE, "email": "bad"})
        self.assertEqual(d.status, Status.INVALID)
        self.assertEqual(self.repo.count(), 0)

    def test_no_duplicates_in_db_after_repeat_runs(self):
        for _ in range(5):
            self.p.process(BASE)
        self.assertEqual(self.repo.count(), 1)


if __name__ == "__main__":
    unittest.main()
