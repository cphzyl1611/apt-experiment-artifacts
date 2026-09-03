import json
import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2.validate_e0c_r2 import (
    GOVERNANCE_REFERENCE_PATTERN,
    load_json,
    parse_json_text,
    validate_governance_reference_syntax_domain,
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

    def test_governance_reference_colon_path_witness_is_accepted_by_both_layers(self):
        from jsonschema import Draft202012Validator

        record = load_json(PACKAGE_DIR / "fixtures" / "VALID_SPLIT_PROPOSAL_FIXTURE.json")
        record["future_resolution"]["evidence_manifest_reference"] = "foo/bar:baz"
        record["future_resolution"]["independent_review_reference"] = "foo/bar:baz"
        schema = load_json(PACKAGE_DIR / "TEMPLATE_LEVEL_RESOLUTION_SCHEMA.json")

        schema_errors = list(Draft202012Validator(schema).iter_errors(record))
        semantic_result = validate_record(record, self.crosswalk_rows, schema=schema)

        self.assertEqual([], schema_errors)
        self.assertTrue(semantic_result.valid, semantic_result.errors)

    def test_governance_reference_syntax_domain_stays_aligned(self):
        schema = load_json(PACKAGE_DIR / "TEMPLATE_LEVEL_RESOLUTION_SCHEMA.json")
        syntax_fixture = load_json(
            PACKAGE_DIR / "fixtures" / "GOVERNANCE_REFERENCE_SYNTAX_WITNESSES.json"
        )
        results = validate_governance_reference_syntax_domain(syntax_fixture, schema)

        self.assertEqual(schema["$defs"]["reference"]["pattern"], GOVERNANCE_REFERENCE_PATTERN)
        self.assertTrue(results["patterns_identical"])
        self.assertTrue(
            all(item["schema_accepts"] and item["semantic_accepts"] for item in results["accepted"]),
            results,
        )
        self.assertTrue(
            all(item["schema_rejects"] and item["semantic_rejects"] for item in results["rejected"]),
            results,
        )

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

    def test_materialization_manifest_is_built_from_a_passing_package(self):
        from E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2.materialize_e0c_r2r2 import (
            build_materialization_manifest,
        )

        manifest = build_materialization_manifest(PACKAGE_DIR)

        self.assertEqual(
            "E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2_MATERIALIZATION_MANIFEST",
            manifest["manifest_type"],
        )
        self.assertEqual(
            "PASS_READY_FOR_INDEPENDENT_REVIEW",
            manifest["validation_terminal"]["E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2"],
        )
        self.assertEqual("PASS", manifest["validation_terminal"]["GOVERNANCE_REFERENCE_SYNTAX_ALIGNMENT"])
        self.assertEqual(0, manifest["zero_mutation_boundary"]["APPLIED_SPLITS"])
        self.assertEqual(0, manifest["zero_mutation_boundary"]["STATUS_MUTATIONS"])
        self.assertEqual(0, manifest["zero_mutation_boundary"]["EXECUTION_AUTHORIZATIONS"])
        self.assertEqual("NO", manifest["zero_mutation_boundary"]["DENOMINATOR_CHANGE"])
        self.assertEqual(12, manifest["frozen_scope"]["template_count"])
        self.assertEqual(203, manifest["frozen_scope"]["raw_coverage"])
        self.assertEqual(
            "ffeb2704a1c971b89129e1959ae721bbc9ef159153a5f0a20f8abda13edb441a",
            manifest["frozen_scope"]["union_member_key_sha256"],
        )
        payload_paths = {entry["relative_path"] for entry in manifest["payload_files"]}
        self.assertNotIn("MATERIALIZATION_MANIFEST.json", payload_paths)
        self.assertFalse(
            any("__pycache__" in path or path.endswith(".pyc") for path in payload_paths)
        )
        for entry in manifest["payload_files"]:
            path = PACKAGE_DIR / entry["relative_path"]
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(),
                entry["sha256"],
            )


if __name__ == "__main__":
    unittest.main()
