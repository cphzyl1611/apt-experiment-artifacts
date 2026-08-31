import json
from pathlib import Path
import unittest

from build_exp_e0c_r4_manual_design_compression import (
    BLOCKED_DETAIL,
    CLASSIFICATIONS,
    EXPECTED_MANUAL_COUNT,
    RAW_SPECIFIC,
    SHARED_TEMPLATE,
    build_outputs,
)


ROOT = Path(".")


class R4ManualCompressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outputs = build_outputs(ROOT)

    def test_exact_manual_set_is_authenticated_and_conserved(self):
        exact = self.outputs["exact_manual_set"]
        self.assertEqual(exact["exact_manual_raw_count"], EXPECTED_MANUAL_COUNT)
        self.assertEqual(len(exact["raw_keys"]), EXPECTED_MANUAL_COUNT)
        self.assertEqual(len(set(exact["raw_keys"])), EXPECTED_MANUAL_COUNT)
        self.assertEqual(exact["source_status"], "MANUAL_DESIGN_REQUIRED")
        self.assertEqual(exact["human_decisions_created"], 0)
        r3 = [json.loads(line) for line in (ROOT / "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        expected = {row["raw_key"] for row in r3 if row["global_planning_status"] == "MANUAL_DESIGN_REQUIRED"}
        self.assertEqual(set(exact["raw_keys"]), expected)

    def test_dimensions_are_mechanical_and_embeddings_excluded(self):
        dimensions = self.outputs["clustering_dimensions"]
        self.assertTrue(all(item["mechanical"] for item in dimensions["dimensions"]))
        self.assertIn("embeddings", dimensions["excluded_methods"])
        self.assertIn("semantic similarity models", dimensions["excluded_methods"])

    def test_templates_have_exact_member_commitments_and_review_contract(self):
        data = self.outputs["shared_templates"]
        self.assertGreater(data["template_count"], 0)
        all_keys = []
        required = {
            "template_id", "template_version", "member_key_commitment", "common_blockers_environment",
            "allowed_candidate_fidelity_classes", "defensive_equivalence_invariants",
            "telemetry_equivalence_invariants", "cleanup_reset", "per_raw_parameters",
            "raw_specific_human_questions", "negative_cases", "human_decision_options",
        }
        for template in data["templates"]:
            self.assertTrue(required.issubset(template), template["template_id"])
            self.assertEqual(template["human_decision"], None)
            self.assertEqual(template["human_decision_options"], [
                "APPROVE_TEMPLATE_FOR_MEMBER_SET",
                "REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL",
                "REQUEST_SPLIT_OR_MORE_EVIDENCE",
            ])
            keys = template["member_keys"]
            self.assertEqual(len(keys), template["member_count"])
            self.assertEqual(len(keys), len(set(keys)))
            all_keys.extend(keys)
        self.assertEqual(len(all_keys), EXPECTED_MANUAL_COUNT)
        self.assertEqual(len(set(all_keys)), EXPECTED_MANUAL_COUNT)

    def test_every_manual_row_has_one_classification_and_template_mapping(self):
        mapped = [json.loads(line) for line in (ROOT / "E0C_R4_RAW_TO_TEMPLATE_MAP.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()] if (ROOT / "E0C_R4_RAW_TO_TEMPLATE_MAP.jsonl").exists() else self.outputs["raw_to_template_rows"]
        self.assertEqual(len(mapped), EXPECTED_MANUAL_COUNT)
        self.assertEqual(len({row["raw_key"] for row in mapped}), EXPECTED_MANUAL_COUNT)
        self.assertTrue(all(row["template_classification"] in CLASSIFICATIONS for row in mapped))
        self.assertTrue(all(row["human_decision_required"] and row["human_decision"] is None for row in mapped))
        self.assertTrue(all(row["r3_global_planning_status"] == "MANUAL_DESIGN_REQUIRED" and not row["formal_execution_authorized"] and row["provx_phase1_observable"] == "UNKNOWN" and row["provx_phase2_core_edge_localizable"] == "UNKNOWN" for row in mapped))

    def test_review_packets_and_outliers_are_non_decisional(self):
        packets = self.outputs["review_packets"]
        self.assertEqual(len(packets), self.outputs["shared_templates"]["template_count"])
        self.assertTrue(all(packet["decision"] is None and packet["human_decisions_created"] == 0 for packet in packets))
        outliers = self.outputs["outliers"]
        self.assertEqual(outliers["raw_specific_count"], self.outputs["audit"]["raw_specific_human_design_required"])
        self.assertEqual(outliers["blocked_need_more_source_detail_count"], self.outputs["audit"]["blocked_need_more_source_detail"])
        self.assertTrue(all(item["classification"] in {RAW_SPECIFIC, BLOCKED_DETAIL} for item in outliers["rows"]))
        for packet in packets:
            self.assertEqual(len(packet["member_keys"]), packet["member_count"])
            self.assertTrue(packet["representative_source_fields"])
            self.assertTrue(packet["unresolved_questions"])
            self.assertIsNone(packet["decision"])

    def test_audit_has_exact_partition_and_boundaries(self):
        audit = self.outputs["audit"]
        self.assertEqual(audit["exact_manual_raw_count"], EXPECTED_MANUAL_COUNT)
        self.assertEqual(audit["manual_set_conservation"], "PASS")
        self.assertEqual(audit["classification_sum"], EXPECTED_MANUAL_COUNT)
        self.assertEqual(audit["classification_overlap"], 0)
        self.assertEqual(audit["classification_missing"], 0)
        self.assertEqual(audit["human_decisions_created"], 0)
        self.assertEqual(audit["formal_experiment_executed"], "NO")
        self.assertEqual(audit["denominator_change"], "NO")
        self.assertEqual(audit["next_action"], "FRESH_REVIEW_OF_E0C_R4_MANUAL_DESIGN_COMPRESSION")
        self.assertTrue(audit["stop"])
        report = self.outputs["report"]
        self.assertIn("E0C_R4_MANUAL_DESIGN_COMPRESSION = READY_FOR_HUMAN_TEMPLATE_REVIEW", report)
        self.assertIn("NEXT_ACTION = FRESH_REVIEW_OF_E0C_R4_MANUAL_DESIGN_COMPRESSION", report)
        self.assertIn("STOP = true", report)


if __name__ == "__main__":
    unittest.main()
