import hashlib
import json
from pathlib import Path
import unittest

from build_exp_e0c_r5_human_template_review_batching import (
    EXPECTED_BLOCKED_COUNT,
    EXPECTED_RAW_SPECIFIC_COUNT,
    EXPECTED_SHARED_COVERED_ROWS,
    EXPECTED_SHARED_TEMPLATE_COUNT,
    build_outputs,
)


ROOT = Path(".")


def key_commitment(keys):
    return hashlib.sha256("\n".join(sorted(keys)).encode("utf-8")).hexdigest()


class R5HumanTemplateReviewBatchingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outputs = build_outputs(ROOT)

    def test_exact89_audit_authenticates_frozen_inputs_and_exact_members(self):
        audit = self.outputs["exact89_template_audit"]
        self.assertEqual(audit["shared_template_count"], EXPECTED_SHARED_TEMPLATE_COUNT)
        self.assertEqual(audit["shared_template_covered_rows"], EXPECTED_SHARED_COVERED_ROWS)
        self.assertEqual(audit["template_member_overlap"], 0)
        self.assertEqual(audit["template_member_missing"], 0)
        self.assertEqual(audit["human_decisions_created"], 0)
        self.assertEqual(audit["formal_experiment_executed"], "NO")
        self.assertEqual(audit["denominator_change"], "NO")
        self.assertEqual(len(audit["authenticated_inputs"]), 5)
        self.assertTrue(all(item["sha256"] for item in audit["authenticated_inputs"]))
        self.assertTrue(all(item["r3_global_planning_status"] == "MANUAL_DESIGN_REQUIRED" for item in audit["member_status_checks"]))

    def test_priorities_preserve_template_member_authority_and_unexecuted_boundaries(self):
        priority = self.outputs["template_priority"]
        templates = priority["templates"]
        self.assertEqual(len(templates), EXPECTED_SHARED_TEMPLATE_COUNT)
        self.assertEqual([item["priority_rank"] for item in templates], list(range(1, EXPECTED_SHARED_TEMPLATE_COUNT + 1)))
        members = []
        for item in templates:
            self.assertEqual(item["member_count"], len(item["member_keys"]))
            self.assertEqual(item["member_key_commitment"]["sha256"], key_commitment(item["member_keys"]))
            self.assertIsNone(item["human_decision"])
            self.assertFalse(item["formal_execution_authorized"])
            self.assertEqual(item["provx_phase1_observable"], "UNKNOWN")
            self.assertEqual(item["provx_phase2_core_edge_localizable"], "UNKNOWN")
            members.extend(item["member_keys"])
        self.assertEqual(len(members), EXPECTED_SHARED_COVERED_ROWS)
        self.assertEqual(len(set(members)), EXPECTED_SHARED_COVERED_ROWS)

    def test_batches_are_complete_non_overlapping_presentation_groups(self):
        batches = self.outputs["review_batches"]
        self.assertGreaterEqual(batches["review_batch_count"], 8)
        self.assertLessEqual(batches["review_batch_count"], 12)
        ids = []
        for batch in batches["batches"]:
            self.assertGreaterEqual(batch["template_count"], 8)
            self.assertLessEqual(batch["template_count"], 12)
            self.assertEqual(batch["template_count"], len(batch["template_ids"]))
            self.assertEqual(batch["human_decisions_created"], 0)
            ids.extend(batch["template_ids"])
        self.assertEqual(len(ids), EXPECTED_SHARED_TEMPLATE_COUNT)
        self.assertEqual(len(set(ids)), EXPECTED_SHARED_TEMPLATE_COUNT)

    def test_review_sheets_are_compact_non_decisional_packets(self):
        sheets = self.outputs["human_review_sheets"]
        self.assertIn("# E0C-R5 Human Template Review Sheets", sheets)
        self.assertEqual(sheets.count("### r4-template-"), EXPECTED_SHARED_TEMPLATE_COUNT)
        self.assertNotIn("Human Decision: APPROVE", sheets)
        self.assertIn("`APPROVE_TEMPLATE_FOR_MEMBER_SET`", sheets)
        self.assertIn("`REQUEST_SPLIT_OR_MORE_EVIDENCE`", sheets)

    def test_blocked_recovery_is_exact_source_detail_without_semantic_inference(self):
        recovery = self.outputs["blocked31_source_detail_recovery"]
        self.assertEqual(recovery["blocked_need_more_source_detail_count"], EXPECTED_BLOCKED_COUNT)
        rows = recovery["rows"]
        self.assertEqual(len(rows), EXPECTED_BLOCKED_COUNT)
        self.assertEqual(len({row["raw_key"] for row in rows}), EXPECTED_BLOCKED_COUNT)
        for row in rows:
            self.assertEqual(row["missing_fields"], ["named_protocols_or_services", "service_prerequisites"])
            self.assertIn(row["recovery_source_kind"], {"EXISTING_PLAYBOOK_TEXT", "AUTHENTICATED_ARTIFACT", "HUMAN_CLARIFICATION"})
            self.assertEqual(row["inferred_semantics"], False)
            self.assertTrue(row["r2_blocker_evidence"])

    def test_raw_specific_priority_is_complete_and_non_resolving(self):
        priority = self.outputs["raw_specific64_priority"]
        self.assertEqual(priority["raw_specific_count"], EXPECTED_RAW_SPECIFIC_COUNT)
        rows = priority["rows"]
        self.assertEqual(len(rows), EXPECTED_RAW_SPECIFIC_COUNT)
        self.assertEqual([row["priority_rank"] for row in rows], list(range(1, EXPECTED_RAW_SPECIFIC_COUNT + 1)))
        self.assertTrue(all(row["resolution"] is None and row["human_decision"] is None for row in rows))
        self.assertTrue(all(row["formal_execution_authorized"] is False for row in rows))

    def test_report_carries_required_terminal_block(self):
        report = self.outputs["report"]
        self.assertIn("E0C_R5_TEMPLATE_REVIEW_BATCHING = READY_FOR_HUMAN_REVIEW", report)
        self.assertIn("SHARED_TEMPLATE_COUNT = 89", report)
        self.assertIn("SHARED_TEMPLATE_COVERED_ROWS = 494", report)
        self.assertIn("TEMPLATE_MEMBER_OVERLAP = 0", report)
        self.assertIn("TEMPLATE_MEMBER_MISSING = 0", report)
        self.assertIn("BLOCKED31_RECOVERY_PLAN_READY = YES", report)
        self.assertIn("RAW_SPECIFIC64_PRIORITY_READY = YES", report)
        self.assertIn("HUMAN_DECISIONS_CREATED = 0", report)
        self.assertIn("FORMAL_EXPERIMENT_EXECUTED = NO", report)
        self.assertIn("DENOMINATOR_CHANGE = NO", report)
        self.assertIn("NEXT_ACTION = FRESH_REVIEW_OF_E0C_R5_TEMPLATE_REVIEW_BATCHING", report)
        self.assertIn("STOP = true", report)


if __name__ == "__main__":
    unittest.main()
