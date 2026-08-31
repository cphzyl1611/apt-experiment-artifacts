import json
from pathlib import Path
import unittest

from build_exp_e0c_r2_adapter_contracts import (
    TARGET_FAMILIES,
    build_r2_outputs,
    load_r1_rows,
)


R1 = Path("EXP_E0C_R1_1796_ENRICHED_READINESS.jsonl")


class R2AdapterContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = load_r1_rows(R1)
        cls.outputs = build_r2_outputs(cls.rows)

    def test_target_family_manifests_conserve_exact_members(self):
        manifests = self.outputs["family_manifests"]["families"]
        self.assertEqual(set(manifests), set(TARGET_FAMILIES))
        expected = {
            "PROCESS_COMMAND_EXECUTION": 712,
            "NETWORK_SERVICE_INTERACTION": 232,
            "TRANSFER_DOWNLOAD_UPLOAD": 166,
            "EMAIL_DELIVERY": 105,
            "NETWORK_C2_BEACON": 103,
        }
        all_keys = []
        for family, count in expected.items():
            item = manifests[family]
            self.assertEqual(item["raw_count"], count)
            self.assertEqual(len(item["raw_keys"]), count)
            self.assertEqual(len(set(item["raw_keys"])), count)
            self.assertTrue(item["manual_design_raw_keys"] <= item["raw_keys"] if isinstance(item["manual_design_raw_keys"], set) else set(item["manual_design_raw_keys"]).issubset(item["raw_keys"]))
            self.assertIn("playbooks_covered", item)
            self.assertIn("stages_covered", item)
            self.assertIn("os_platform_hints", item)
            self.assertIn("service_or_protocol_prerequisites", item)
            all_keys.extend(item["raw_keys"])
        self.assertEqual(len(all_keys), len(set(all_keys)))

    def test_contract_schema_is_non_executable_and_complete(self):
        contracts = self.outputs["adapter_contracts"]["contracts"]
        self.assertEqual(set(contracts), set(TARGET_FAMILIES))
        required = {
            "adapter_id", "adapter_version", "applicable_raw_key_set_commitment",
            "input_parameters", "required_source_target_roles", "preconditions",
            "environment_service_fixtures", "execution_result_schema", "run_id_raw_key_binding",
            "cleanup_reset", "evidence_artifacts", "timeout_error_semantics",
            "fail_closed_behavior", "implementation_status", "mininet_compatibility",
        }
        for family, contract in contracts.items():
            self.assertTrue(required.issubset(contract), family)
            self.assertEqual(contract["implementation_status"], "DESIGN_ONLY_NOT_IMPLEMENTED")
            self.assertFalse(contract["formal_execution_authorized"])
            self.assertNotIn("commands", json.dumps(contract).lower())
            self.assertEqual(contract["applicable_raw_key_set_commitment"]["raw_count"], contract["raw_count"])

    def test_equivalence_and_telemetry_contracts_cover_modes_and_boundaries(self):
        eq = self.outputs["defensive_equivalence_contracts"]["contracts"]
        telemetry = self.outputs["provx_telemetry_contracts"]["contracts"]
        for family in TARGET_FAMILIES:
            self.assertIn(family, eq)
            self.assertIn(family, telemetry)
            self.assertIn("candidate_modes", eq[family])
            self.assertIn("what_may_safely_differ", eq[family])
            self.assertIn("process_events", telemetry[family])
            self.assertIn("file_events", telemetry[family])
            self.assertIn("socket_events", telemetry[family])
            self.assertIn("packet_events", telemetry[family])
            self.assertIn("logical_host_attribution", telemetry[family])
            self.assertIn("provenance_nodes_edges", telemetry[family])
            self.assertIn("raw_key_run_id_reversible_mapping", telemetry[family])
            self.assertEqual(telemetry[family]["provx_phase1_observable"], "UNKNOWN")
            self.assertEqual(telemetry[family]["provx_phase2_core_edge_localizable"], "UNKNOWN")

    def test_manual_blockers_cover_all_r1_manual_rows(self):
        blockers = self.outputs["manual_design_blockers"]
        self.assertEqual(blockers["manual_design_row_count"], 589)
        self.assertEqual(len(blockers["rows"]), 589)
        keys = [row["raw_key"] for row in blockers["rows"]]
        self.assertEqual(len(keys), len(set(keys)))
        allowed = set(blockers["allowed_blocker_taxonomy"])
        self.assertTrue(all(row["blockers"] for row in blockers["rows"]))
        self.assertTrue(all(set(row["blockers"]).issubset(allowed) for row in blockers["rows"]))
        self.assertEqual(sum(blockers["blocker_counts"].values()), 0 if not blockers["rows"] else sum(len(r["blockers"]) for r in blockers["rows"]))

    def test_coverage_audit_and_terminal_metadata(self):
        audit = self.outputs["coverage_audit"]
        self.assertEqual(audit["raw_denominator"], 1796)
        self.assertEqual(audit["target_family_member_conservation"], "PASS")
        self.assertEqual(audit["contract_covered_candidate_rows"], 945)
        self.assertEqual(audit["addressable_candidate_rows_excluding_unresolved_prerequisites"], 941)
        self.assertEqual(audit["manual_design_rows"], 589)
        self.assertEqual(audit["unresolved_prerequisite_rows"], 4)
        self.assertEqual(audit["formal_experiment_executed"], "NO")
        self.assertEqual(audit["denominator_change"], "NO")
        self.assertEqual(audit["next_action"], "FRESH_REVIEW_OF_E0C_R2_ADAPTER_CONTRACTS")
        self.assertTrue(audit["stop"])
        report = self.outputs["design_report"]
        self.assertIn("NEXT_ACTION = FRESH_REVIEW_OF_E0C_R2_ADAPTER_CONTRACTS", report)
        self.assertIn("STOP = true", report)


if __name__ == "__main__":
    unittest.main()
