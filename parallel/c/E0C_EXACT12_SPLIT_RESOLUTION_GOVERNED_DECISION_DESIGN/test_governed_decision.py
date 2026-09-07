import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from E0C_EXACT12_SPLIT_RESOLUTION_GOVERNED_DECISION_DESIGN.validate_governed_decision import (
    EXPECTED_UNION_HASH,
    load_json,
    validate_manifest,
    validate_record,
    validate_schema_pair,
    validate_state_machine,
)


PACKAGE_DIR = Path(__file__).parent
FIXTURE_DIR = PACKAGE_DIR / "fixtures"


class GovernedDecisionValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.subject_manifest = load_json(PACKAGE_DIR / "EXACT12_SUBJECT_MANIFEST.json")
        cls.decision_schema = load_json(PACKAGE_DIR / "GOVERNED_DECISION_SCHEMA.json")
        cls.envelope_schema = load_json(PACKAGE_DIR / "SPLIT_PROPOSAL_ENVELOPE_SCHEMA.json")
        cls.fixture_manifest = load_json(FIXTURE_DIR / "FIXTURE_MANIFEST.json")

    def test_schema_meta_validation_passes(self):
        Draft202012Validator.check_schema(self.decision_schema)
        Draft202012Validator.check_schema(self.envelope_schema)

    def test_schema_reference_grammars_are_identical(self):
        self.assertEqual(
            self.decision_schema["$defs"]["governanceReference"]["pattern"],
            self.envelope_schema["$defs"]["governanceReference"]["pattern"],
        )
        self.assertTrue(validate_schema_pair())

    def test_decision_state_machine_is_design_only_and_excludes_applied(self):
        self.assertTrue(validate_state_machine())
        machine = load_json(PACKAGE_DIR / "DECISION_STATE_MACHINE.json")
        self.assertNotIn("SPLIT_APPLIED", machine["states"])

    def test_exact12_manifest_is_authenticated_and_frozen(self):
        result = validate_manifest(self.subject_manifest)
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(12, result.checks["template_count"])
        self.assertEqual(203, result.checks["unique_raw_member_count"])
        self.assertEqual(0, result.checks["blocked31_overlap"])
        self.assertEqual(EXPECTED_UNION_HASH, result.checks["union_hash"])
        self.assertEqual(0, result.checks["crosswalk_byte_drift"])

    def test_positive_fixtures_are_accepted(self):
        positive_names = {
            "POSITIVE_PENDING_GOVERNANCE_VALID_PROPOSAL.json",
            "POSITIVE_DEFERRED_DECISION.json",
            "POSITIVE_REJECTED_PROPOSAL.json",
            "POSITIVE_APPROVED_FOR_FUTURE_TRANSACTION.json",
        }
        self.assertEqual(positive_names, set(self.fixture_manifest["positive_fixtures"]))
        for filename in sorted(positive_names):
            with self.subTest(fixture=filename):
                result = validate_record(
                    load_json(FIXTURE_DIR / filename),
                    self.subject_manifest,
                    self.decision_schema,
                    self.envelope_schema,
                )
                self.assertTrue(result.valid, result.errors)

    def test_negative_fixtures_are_rejected_with_declared_codes(self):
        negative_names = set(self.fixture_manifest["negative_fixtures"])
        self.assertEqual(14, len(negative_names))
        for filename in sorted(negative_names):
            expected_codes = self.fixture_manifest["expected_error_codes"][filename]
            with self.subTest(fixture=filename):
                result = validate_record(
                    load_json(FIXTURE_DIR / filename),
                    self.subject_manifest,
                    self.decision_schema,
                    self.envelope_schema,
                )
                self.assertFalse(result.valid)
                self.assertTrue(
                    all(
                        any(error.startswith(code + ":") for error in result.errors)
                        for code in expected_codes
                    ),
                    result.errors,
                )

    def test_decision_schema_is_strict_at_root(self):
        record = load_json(FIXTURE_DIR / "POSITIVE_DEFERRED_DECISION.json")
        record["unauthorized_field"] = True
        result = validate_record(
            record,
            self.subject_manifest,
            self.decision_schema,
            self.envelope_schema,
        )
        self.assertFalse(result.valid)
        self.assertTrue(any(error.startswith("SCHEMA_UNAUTHORIZED_FIELD:") for error in result.errors))

    def test_approved_fixture_is_still_non_operational(self):
        record = load_json(FIXTURE_DIR / "POSITIVE_APPROVED_FOR_FUTURE_TRANSACTION.json")
        self.assertEqual("APPROVED_FOR_FUTURE_TRANSACTION", record["decision_status"])
        self.assertFalse(record["downstream_eligibility"]["eligible_for_split_execution"])
        self.assertFalse(record["downstream_eligibility"]["eligible_for_status_mutation"])
        self.assertFalse(record["downstream_eligibility"]["eligible_for_denominator_change"])
        self.assertEqual(0, record["zero_mutation_assertions"]["human_decisions_created"])
        self.assertEqual("NO", record["zero_mutation_assertions"]["formal_1796_experiment_executed"])


if __name__ == "__main__":
    unittest.main()
