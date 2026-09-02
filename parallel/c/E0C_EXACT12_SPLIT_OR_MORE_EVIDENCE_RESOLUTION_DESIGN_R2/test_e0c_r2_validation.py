import json
import unittest
from pathlib import Path

from E0C_EXACT12_SPLIT_OR_MORE_EVIDENCE_RESOLUTION_DESIGN_R2.validate_e0c_r2 import (
    load_json,
    parse_json_text,
    validate_fixture_directory,
    validate_record,
)


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
        results = validate_fixture_directory(self.crosswalk_rows, fixture_dir)
        self.assertGreaterEqual(len(results["negative_fixtures"]), 13)
        self.assertTrue(results["all_negative_rejected"])
        self.assertTrue(results["all_expected_failure_reasons_satisfied"])

    def test_governance_reference_negatives_fail_closed(self):
        fixture_dir = PACKAGE_DIR / "fixtures"
        expected = {
            "NEGATIVE_NULL_EVIDENCE_MANIFEST_REFERENCE.json": "C1_GOVERNANCE_EVIDENCE_MANIFEST_REFERENCE_REQUIRED",
            "NEGATIVE_NULL_INDEPENDENT_REVIEW_REFERENCE.json": "C1_GOVERNANCE_INDEPENDENT_REVIEW_REFERENCE_REQUIRED",
            "NEGATIVE_MISSING_GOVERNANCE_REFERENCE.json": "C1_GOVERNANCE_EVIDENCE_MANIFEST_REFERENCE_REQUIRED",
            "NEGATIVE_MALFORMED_GOVERNANCE_REFERENCE.json": "C1_GOVERNANCE_EVIDENCE_MANIFEST_REFERENCE_MALFORMED",
        }
        for filename, code in expected.items():
            with self.subTest(fixture=filename):
                result = validate_record(load_json(fixture_dir / filename), self.crosswalk_rows)
                self.assertFalse(result.valid)
                self.assertTrue(any(error.startswith(code + ":") for error in result.errors), result.errors)

    def test_false_conservation_claim_is_semantically_isolated(self):
        fixture_dir = PACKAGE_DIR / "fixtures"
        false_claim = fixture_dir / "NEGATIVE_FALSE_CONSERVATION_CLAIM.json"
        incomplete = fixture_dir / "NEGATIVE_INCOMPLETE_CHILD_PARTITION.json"
        self.assertNotEqual(false_claim.read_bytes(), incomplete.read_bytes())

        result = validate_record(load_json(false_claim), self.crosswalk_rows)
        self.assertFalse(result.valid)
        self.assertTrue(
            any(error.startswith("C2_FALSE_CONSERVATION_CLAIM:") for error in result.errors),
            result.errors,
        )
        self.assertFalse(
            any(error.startswith("R2_INCOMPLETE_CHILD_PARTITION:") for error in result.errors),
            result.errors,
        )

    def test_duplicate_json_object_keys_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            parse_json_text('{"duplicate": 1, "duplicate": 2}')

    def test_schema_meta_validation_passes(self):
        from jsonschema import Draft202012Validator

        Draft202012Validator.check_schema(
            load_json(PACKAGE_DIR / "TEMPLATE_LEVEL_RESOLUTION_SCHEMA.json")
        )

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
