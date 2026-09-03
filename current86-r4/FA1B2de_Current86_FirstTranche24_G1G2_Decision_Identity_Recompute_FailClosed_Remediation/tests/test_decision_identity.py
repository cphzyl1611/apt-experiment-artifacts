import importlib.util
import json
from copy import deepcopy
from pathlib import Path
import unittest


PACKAGE = Path(__file__).resolve().parents[1]
TOOL_PATH = PACKAGE / "tools" / "decision_identity.py"
RECORD_PATH = PACKAGE / "fixtures" / "valid_record.json"


def _load_tool():
    spec = importlib.util.spec_from_file_location("decision_identity", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DecisionIdentityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = _load_tool()
        cls.record = json.loads(RECORD_PATH.read_text(encoding="utf-8"))

    def test_same_input_recomputes_both_declared_identities(self):
        decision_id, transaction_hash = self.tool.compute_identities(self.record)

        self.assertEqual(decision_id, self.record["decision_identity"]["decision_record_id"])
        self.assertEqual(transaction_hash, self.record["decision_identity"]["decision_transaction_hash"])

    def test_any_identity_basis_change_changes_the_corresponding_hash(self):
        original_id, original_tx = self.tool.compute_identities(self.record)
        strict_boundary_paths = {
            "record_type",
            "schema_version",
            "scope.governance_scope_id",
            "scope.scope_cardinality",
            "scope.frozen_target_order",
        }
        for path in self.tool.IDENTITY_BASIS_PATHS:
            candidate = deepcopy(self.record)
            self.tool.mutate_path_for_test(candidate, path)
            try:
                changed_id, changed_tx = self.tool.compute_identities(candidate)
            except self.tool.IdentityContractError:
                self.assertIn(path, strict_boundary_paths, path)
                continue
            self.assertNotEqual(changed_id, original_id, path)
            self.assertNotEqual(changed_tx, original_tx, path)

    def test_timestamp_random_and_reviewer_metadata_are_excluded(self):
        candidate = deepcopy(self.record)
        candidate["decision_timestamp_metadata"]["decided_at_utc"] = "2099-01-01T00:00:00Z"
        candidate["decision_timestamp_metadata"]["recorded_by"] = "randomized-recorder"
        candidate["decision_timestamp_metadata"]["reviewer_metadata_is_identity_bearing"] = False
        candidate["reviewer_metadata"] = {"random": "nonce", "reviewer": "not-in-contract"}

        self.assertEqual(self.tool.compute_identities(candidate), self.tool.compute_identities(self.record))

    def test_reordered_object_fields_are_canonicalization_equivalent(self):
        reordered = json.loads(json.dumps(self.record, sort_keys=False))
        reordered["scope"] = {
            "scope_extension_requested": reordered["scope"]["scope_extension_requested"],
            "r1r1_crosswalk_sha256": reordered["scope"]["r1r1_crosswalk_sha256"],
            "frozen_target_order": reordered["scope"]["frozen_target_order"],
            "scope_cardinality": reordered["scope"]["scope_cardinality"],
            "governance_scope_id": reordered["scope"]["governance_scope_id"],
        }

        self.assertEqual(self.tool.compute_identities(reordered), self.tool.compute_identities(self.record))

    def test_negative_fixtures_fail_closed(self):
        for name, candidate in self.tool.negative_fixtures(self.record).items():
            with self.subTest(name=name):
                with self.assertRaises(self.tool.IdentityContractError):
                    self.tool.compute_identities(candidate)

    def test_collision_or_reuse_mismatch_is_rejected(self):
        with self.assertRaises(self.tool.IdentityContractError):
            self.tool.validate_reuse(self.record, "GOVDEC2-" + "0" * 64, self.record["decision_identity"]["decision_transaction_hash"])

    def test_zero_mutation_state_is_exactly_preserved(self):
        zero_path = PACKAGE / "fixtures" / "zero_operational_effect.json"
        zero_state = json.loads(zero_path.read_text(encoding="utf-8"))
        result = self.tool.verify_zero_mutation(zero_state)

        self.assertEqual(result["authority_activation"], "NO")
        self.assertEqual(result["source_acquisition"], "NO")
        self.assertEqual(result["stage_a_admission"], "NO")
        self.assertEqual(result["field_pins"], 0)
        self.assertEqual(result["operative_records"], 0)


if __name__ == "__main__":
    unittest.main()
