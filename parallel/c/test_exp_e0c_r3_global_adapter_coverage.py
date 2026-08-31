import json
from pathlib import Path
import unittest

from build_exp_e0c_r3_global_adapter_coverage import (
    GLOBAL_STATUSES,
    REMAINING_FAMILIES,
    TARGET_FAMILIES,
    build_r3_outputs,
    load_inputs,
)


ROOT = Path(".")


class R3GlobalCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = load_inputs(ROOT)
        cls.outputs = build_r3_outputs(cls.inputs)

    def test_reconciles_r2_without_double_counting(self):
        rec = self.outputs["r2_accounting_reconciliation"]
        self.assertEqual(rec["raw_denominator"], 1796)
        self.assertEqual(rec["r2_target_family_rows"], 1318)
        self.assertEqual(rec["r2_contract_covered_rows"], 945)
        self.assertEqual(rec["r2_manual_design_rows"], 589)
        self.assertEqual(rec["r2_unresolved_prerequisite_rows"], 4)
        self.assertEqual(rec["r2_authenticated_artifact_count"], 5)
        self.assertEqual(len(rec["r2_authenticated_artifacts"]), 5)
        self.assertTrue(all(item["status"] == "PASS" for item in rec["r2_authenticated_artifacts"]))
        self.assertTrue(rec["r1_conservation_audit_authenticated"])
        self.assertEqual(rec["r2_contract_rows_including_unresolved"], 945)
        self.assertEqual(rec["r2_manual_rows_outside_target_families"], 216)
        self.assertEqual(rec["r2_unresolved_is_subset_of_contract_rows"], True)
        self.assertIn("not", rec["explanation"].lower())

    def test_remaining_eight_contracts_conserve_exact_members(self):
        remaining = self.outputs["remaining_8_family_contracts"]
        self.assertEqual(set(remaining["families"]), set(REMAINING_FAMILIES))
        self.assertEqual(sum(item["raw_count"] for item in remaining["families"].values()), 478)
        all_keys = []
        required = {
            "adapter_id", "adapter_version", "raw_key_set_commitment", "raw_keys",
            "inputs", "roles", "preconditions", "fixtures", "result_schema",
            "run_id_raw_key_binding", "cleanup_reset", "evidence_artifacts",
            "timeout_error_semantics", "fail_closed_behavior", "defensive_equivalence",
            "provx_telemetry", "mininet_compatibility", "dependency_classification",
        }
        for family, item in remaining["families"].items():
            self.assertTrue(required.issubset(item), family)
            self.assertEqual(item["raw_count"], len(item["raw_keys"]))
            self.assertEqual(len(item["raw_keys"]), len(set(item["raw_keys"])))
            self.assertEqual(item["implementation_status"], "DESIGN_ONLY_NOT_IMPLEMENTED")
            self.assertFalse(item["formal_execution_authorized"])
            self.assertEqual(item["provx_telemetry"]["provx_phase1_observable"], "UNKNOWN")
            self.assertEqual(item["provx_telemetry"]["provx_phase2_core_edge_localizable"], "UNKNOWN")
            all_keys.extend(item["raw_keys"])
        self.assertEqual(len(all_keys), len(set(all_keys)))

    def test_global_status_is_complete_mutually_exclusive_and_preserves_r1_fidelity(self):
        rows = self.outputs["global_planning_status_rows"]
        self.assertEqual(len(rows), 1796)
        self.assertEqual(set(row["global_planning_status"] for row in rows), set(GLOBAL_STATUSES))
        counts = {status: sum(row["global_planning_status"] == status for row in rows) for status in GLOBAL_STATUSES}
        self.assertEqual(counts, {
            "CONTRACT_DESIGNED_READY_FOR_IMPLEMENTATION_PLANNING": 1196,
            "MANUAL_DESIGN_REQUIRED": 589,
            "BLOCKED_UNRESOLVED_PREREQUISITE": 11,
        })
        for row in rows:
            self.assertIn(row["r1_candidate_execution_mode"], {"NATIVE_CANDIDATE", "EMULATED_CANDIDATE", "SYNTHETIC_CANDIDATE", "REQUIRES_MANUAL_DESIGN"})
            self.assertFalse(row["formal_execution_authorized"])
            self.assertEqual(row["provx_phase1_observable"], "UNKNOWN")
            self.assertEqual(row["provx_phase2_core_edge_localizable"], "UNKNOWN")
            self.assertEqual(row["status_membership"], [row["global_planning_status"]])

    def test_priority_covers_all_thirteen_families_and_dependencies(self):
        priority = self.outputs["implementation_priority"]
        self.assertEqual(priority["family_count"], 13)
        self.assertEqual({item["primary_execution_archetype"] for item in priority["priority_order"]}, set(TARGET_FAMILIES) | set(REMAINING_FAMILIES))
        allowed = {
            "CAN_IMPLEMENT_BEFORE_PROVX_COLLECTOR",
            "WAIT_FOR_PROVX_SCHEMA",
            "WAIT_FOR_MININET_PROVENANCE_COLLECTOR",
            "WAIT_FOR_WINDOWS_OR_SERVICE_ENVIRONMENT",
            "MANUAL_ONLY",
        }
        self.assertTrue(all(item["dependency_classification"] in allowed for item in priority["priority_order"]))
        self.assertEqual(sorted(item["priority_rank"] for item in priority["priority_order"]), list(range(1, 14)))

    def test_coverage_audit_terminal_and_boundaries(self):
        audit = self.outputs["global_coverage_audit"]
        self.assertEqual(audit["raw_denominator"], 1796)
        self.assertEqual(audit["global_status_sum"], 1796)
        self.assertEqual(audit["global_status_overlap"], 0)
        self.assertEqual(audit["global_status_missing"], 0)
        self.assertEqual(audit["contract_designed_count"], 1196)
        self.assertEqual(audit["manual_design_required_count"], 589)
        self.assertEqual(audit["blocked_unresolved_prerequisite_count"], 11)
        self.assertEqual(audit["formal_experiment_executed"], "NO")
        self.assertEqual(audit["denominator_change"], "NO")
        self.assertEqual(audit["next_action"], "FRESH_REVIEW_OF_E0C_R3_GLOBAL_ADAPTER_COVERAGE")
        self.assertTrue(audit["stop"])
        self.assertIn("NEXT_ACTION = FRESH_REVIEW_OF_E0C_R3_GLOBAL_ADAPTER_COVERAGE", self.outputs["global_coverage_report"])
        self.assertIn("STOP = true", self.outputs["global_coverage_report"])


if __name__ == "__main__":
    unittest.main()
