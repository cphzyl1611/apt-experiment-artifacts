import json
from pathlib import Path
import unittest


PACKAGE = Path(__file__).resolve().parents[1]


class DecisionMaterializationTests(unittest.TestCase):
    def test_bounded_package_contains_the_approved_v2_decision_record(self):
        record_path = PACKAGE / "FIRST_TRANCHE24_GOVERNANCE_DECISION_RECORD_V2.json"
        self.assertTrue(record_path.is_file())
        record = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(record["decision"], "APPROVE_BOTH_G1_AND_G2")
        self.assertEqual(record["scope"]["governance_scope_id"], "FIRST_TRANCHE24_ONLY")
        self.assertEqual(record["scope"]["scope_cardinality"], 24)
        self.assertEqual(len(set(record["scope"]["frozen_target_order"])), 24)

    def test_materialization_validator_accepts_the_bounded_record_and_evidence(self):
        validator_path = PACKAGE / "tools" / "validate_materialization.py"
        self.assertTrue(validator_path.is_file())
        import importlib.util

        spec = importlib.util.spec_from_file_location("validate_materialization", validator_path)
        validator = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(validator)
        result = validator.validate_package(PACKAGE)

        self.assertEqual(result["overall_status"], "PASS_READY_FOR_MATERIALIZATION")
        self.assertEqual(result["decision_record_id_recomputation"], "PASS")
        self.assertEqual(result["transaction_hash_recomputation"], "PASS")
        self.assertEqual(result["v2_governance_schema_validation"], "PASS")
        self.assertEqual(result["zero_operational_effect"], "PASS")


class DecisionMaterializationBoundaryTests(unittest.TestCase):
    def test_validator_reports_no_operational_effect(self):
        validator_path = PACKAGE / "tools" / "validate_materialization.py"
        self.assertTrue(validator_path.is_file())
        import importlib.util

        spec = importlib.util.spec_from_file_location("validate_materialization_boundary", validator_path)
        validator = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(validator)
        result = validator.validate_package(PACKAGE)

        self.assertEqual(result["new_source_authority_id_created"], 0)
        self.assertEqual(result["source_authority_activated"], "NO")
        self.assertEqual(result["source_acquisition"], "NO")
        self.assertEqual(result["source_auth_executed"], "NO")
        self.assertEqual(result["stage_a_admissions"], 0)
        self.assertEqual(result["stage_b_exposures"], 0)
        self.assertEqual(result["field_pins"], 0)
        self.assertEqual(result["operative_records"], 0)
        self.assertEqual(result["formal_1796_experiment_executed"], "NO")


if __name__ == "__main__":
    unittest.main()
