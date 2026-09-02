import json
import unittest
from pathlib import Path

from E0C_EXACT12_SPLIT_OR_MORE_EVIDENCE_RESOLUTION_DESIGN_R2.validate_e0c_r2 import load_json, validate_record


PACKAGE_DIR = Path(__file__).parent


class E0CR2ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crosswalk_path = PACKAGE_DIR / "EXACT12_RESOLUTION_CROSSWALK.jsonl"
        cls.crosswalk_text = cls.crosswalk_path.read_text(encoding="utf-8")
        cls.crosswalk_rows = [
            json.loads(line)
            for line in cls.crosswalk_text.splitlines()
            if line.strip()
        ]

    def test_valid_fixture_is_accepted(self):
        result = validate_record(
            load_json(PACKAGE_DIR / "fixtures" / "VALID_SPLIT_PROPOSAL_FIXTURE.json"),
            self.crosswalk_rows,
        )
        self.assertTrue(result.valid, result.errors)

    def test_negative_fixtures_are_rejected(self):
        fixture_dir = PACKAGE_DIR / "fixtures"
        negative_paths = sorted(fixture_dir.glob("NEGATIVE_*.json"))
        self.assertGreaterEqual(len(negative_paths), 7)
        for path in negative_paths:
            with self.subTest(fixture=path.name):
                result = validate_record(load_json(path), self.crosswalk_rows)
                self.assertFalse(result.valid, path.name)
                self.assertTrue(result.errors, path.name)

    def test_exact12_baseline_is_preserved(self):
        self.assertEqual(len(self.crosswalk_rows), 12)
        self.assertEqual(
            sum(row["frozen_identity"]["member_count"] for row in self.crosswalk_rows),
            203,
        )
        for row in self.crosswalk_rows:
            self.assertEqual(
                row["current_state"]["source_human_decision"],
                "REQUEST_SPLIT_OR_MORE_EVIDENCE",
            )
            self.assertEqual(
                row["current_state"]["resolution_state"],
                "REQUEST_MORE_EVIDENCE",
            )
            self.assertFalse(row["current_state"]["applied_split"])
            self.assertEqual(row["current_state"]["status_mutations"], 0)


if __name__ == "__main__":
    unittest.main()
