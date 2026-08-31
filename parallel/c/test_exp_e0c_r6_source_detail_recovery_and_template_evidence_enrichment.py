import hashlib
import json
from pathlib import Path
import unittest

from build_exp_e0c_r6_source_detail_recovery_and_template_evidence_enrichment import (
    EXPECTED_BLOCKED_COUNT,
    EXPECTED_MANUAL_COUNT,
    EXPECTED_RAW_SPECIFIC_COUNT,
    EXPECTED_SHARED_COVERED_ROWS,
    EXPECTED_SHARED_TEMPLATE_COUNT,
    build_outputs,
)


ROOT = Path(".")


def key_commitment(keys):
    return hashlib.sha256("\n".join(sorted(keys)).encode("utf-8")).hexdigest()


class R6SourceRecoveryAndEnrichmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outputs = build_outputs(ROOT)

    def test_input_authentication_covers_exact_sets_batches_and_commitments(self):
        auth = self.outputs["input_authentication"]
        self.assertEqual(auth["exact_manual_raw_count"], EXPECTED_MANUAL_COUNT)
        self.assertEqual(auth["shared_template_count"], EXPECTED_SHARED_TEMPLATE_COUNT)
        self.assertEqual(auth["shared_template_covered_rows"], EXPECTED_SHARED_COVERED_ROWS)
        self.assertEqual(auth["raw_specific_count"], EXPECTED_RAW_SPECIFIC_COUNT)
        self.assertEqual(auth["blocked_count"], EXPECTED_BLOCKED_COUNT)
        self.assertEqual(auth["review_batch_count"], 9)
        authenticated_names = {item["file"] for item in auth["authenticated_inputs"]}
        self.assertIn("E0C_R4_MANUAL_OUTLIERS.json", authenticated_names)
        self.assertIn("E0C_R5_REVIEW_BATCHING_REPORT.md", authenticated_names)
        self.assertEqual({item["file"] for item in auth["authenticated_supporting_inputs"]}, {
            "EXP_E0C_R1_1796_ENRICHED_READINESS.jsonl",
            "E0C_R2_MANUAL_DESIGN_BLOCKERS.json",
            "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl",
        })
        self.assertEqual(auth["template_member_overlap"], 0)
        self.assertEqual(auth["template_member_missing"], 0)
        self.assertEqual(auth["status_mutations"], 0)
        self.assertEqual(auth["human_decisions_created"], 0)
        self.assertEqual(auth["pinned_review_commit"], "90513ab76a2d392398fefd0456ad53a4660a3e8a")
        self.assertTrue(auth["shared_member_set_commitment"]["sha256"])
        self.assertTrue(auth["blocked_set_commitment"]["sha256"])
        self.assertTrue(auth["raw_specific_set_commitment"]["sha256"])

    def test_blocked_recovery_preserves_classification_and_reports_absent_detail(self):
        results = self.outputs["blocked31_source_recovery_results"]
        self.assertEqual(results["exact31_conservation"], "PASS")
        self.assertEqual(results["blocked_count"], EXPECTED_BLOCKED_COUNT)
        self.assertEqual(results["recovered_from_authenticated_existing_source"], 0)
        self.assertEqual(results["not_present_in_authenticated_existing_source"], EXPECTED_BLOCKED_COUNT)
        self.assertEqual(results["conflicting_existing_source_detail"], 0)
        self.assertEqual(results["advisory_reclassification"], "CANDIDATE_FOR_HUMAN_RECLASSIFICATION_AFTER_SOURCE_RECOVERY")
        rows = results["rows"]
        self.assertEqual(len(rows), EXPECTED_BLOCKED_COUNT)
        self.assertEqual(len({row["raw_key"] for row in rows}), EXPECTED_BLOCKED_COUNT)
        for row in rows:
            self.assertEqual(row["original_r4_classification"], "BLOCKED_NEED_MORE_SOURCE_DETAIL")
            self.assertEqual(row["classification"], "BLOCKED_NEED_MORE_SOURCE_DETAIL")
            self.assertEqual(row["recovery_status"], "NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE")
            self.assertEqual(row["resulting_classification"], "BLOCKED_NEED_MORE_SOURCE_DETAIL")
            self.assertEqual(row["r3_global_planning_status"], "MANUAL_DESIGN_REQUIRED")
            self.assertEqual(row["missing_fields"], ["named_protocols_or_services", "service_prerequisites"])
            self.assertTrue(row["searched_source_identities"])
            self.assertTrue(row["exact_source_evidence"]["source_locator"])
            self.assertTrue(row["evidence_hash"])
            self.assertEqual(row["evidence_sha256"], row["evidence_hash"])
            self.assertFalse(row["semantics_inferred"])
            self.assertTrue(row["validation_rule_evidence"]["source_file"].endswith(".json"))
            self.assertTrue(row["validation_rule_evidence"]["source_file_sha256"])
            self.assertIn("host_cli_action", row["validation_rule_evidence"]["exact_source_fields"])
            self.assertEqual(row["missing_field_search_results"]["named_protocols_or_services"]["validation_rule_field"], "ABSENT")

    def test_recovered_evidence_jsonl_matches_exact31_results(self):
        rows = self.outputs["blocked31_recovered_evidence_jsonl"]
        self.assertEqual(len(rows), EXPECTED_BLOCKED_COUNT)
        self.assertEqual(len({row["raw_key"] for row in rows}), EXPECTED_BLOCKED_COUNT)
        self.assertTrue(all(row["recovery_status"] == "NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE" for row in rows))
        self.assertTrue(all(row["recovered_source_fields"] for row in rows))
        self.assertTrue(all(row["missing_source_fields"] == ["named_protocols_or_services", "service_prerequisites"] for row in rows))

    def test_exact89_packets_are_enriched_with_source_fields_and_boundaries(self):
        packets = self.outputs["enriched_template_packets"]
        self.assertEqual(len(packets), EXPECTED_SHARED_TEMPLATE_COUNT)
        members = []
        for packet in packets:
            self.assertEqual(packet["classification"], "CANDIDATE_FOR_SHARED_HUMAN_TEMPLATE")
            self.assertEqual(packet["member_key_commitment"]["sha256"], key_commitment(packet["member_keys"]))
            self.assertEqual(packet["member_count"], len(packet["member_keys"]))
            self.assertEqual(len(packet["exact_source_evidence_references"]), packet["member_count"])
            self.assertEqual(len(packet["representative_raw_source_snippets"]), min(3, packet["member_count"]))
            self.assertTrue(all(ref["validation_rule_evidence_reference"]["source_file"].endswith(".json") for ref in packet["exact_source_evidence_references"]))
            self.assertTrue(packet["environment_prerequisites"])
            self.assertTrue(packet["unresolved_unknown_fields"])
            self.assertTrue(packet["defensive_equivalence_invariants"])
            self.assertTrue(packet["telemetry_equivalence_invariants"])
            self.assertTrue(packet["cleanup_reset_requirements"])
            self.assertTrue(packet["negative_cases"])
            self.assertIsNone(packet["human_decision"])
            self.assertEqual(packet["r3_global_planning_status"], "MANUAL_DESIGN_REQUIRED")
            self.assertFalse(packet["formal_execution_authorized"])
            self.assertEqual(packet["status_mutations"], 0)
            self.assertEqual(packet["denominator_change"], "NO")
            self.assertEqual(packet["provx_phase1_observable"], "UNKNOWN")
            self.assertEqual(packet["provx_phase2_core_edge_localizable"], "UNKNOWN")
            members.extend(packet["member_keys"])
        self.assertEqual(len(members), EXPECTED_SHARED_COVERED_ROWS)
        self.assertEqual(len(set(members)), EXPECTED_SHARED_COVERED_ROWS)

    def test_first_review_tranche_is_compact_non_decisional_and_complete(self):
        tranche = self.outputs["first_human_review_tranche"]
        self.assertGreaterEqual(tranche["template_count"], 10)
        self.assertLessEqual(tranche["template_count"], 15)
        self.assertEqual(len(tranche["template_ids"]), tranche["template_count"])
        self.assertEqual(len(set(tranche["template_ids"])), tranche["template_count"])
        self.assertEqual(tranche["raw_coverage"], sum(item["member_count"] for item in tranche["templates"]))
        self.assertTrue(all(item["human_decision"] is None for item in tranche["templates"]))
        self.assertTrue(all(item["consequences_of_approval"] for item in tranche["templates"]))
        self.assertEqual(tranche["human_decisions_created"], 0)
        self.assertEqual(tranche["formal_experiment_executed"], "NO")
        self.assertEqual(tranche["denominator_change"], "NO")
        self.assertTrue(all(item["r3_global_planning_status"] == "MANUAL_DESIGN_REQUIRED" for item in tranche["templates"]))

    def test_first_review_sheets_include_required_fields_and_unselected_actions(self):
        sheets = self.outputs["first_human_review_sheets"]
        tranche = self.outputs["first_human_review_tranche"]
        self.assertIn("# E0C-R6 First Human Review Sheets", sheets)
        self.assertEqual(sheets.count("### r4-template-"), tranche["template_count"])
        self.assertIn("Consequences of approval", sheets)
        self.assertIn("`APPROVE_TEMPLATE_FOR_MEMBER_SET`", sheets)
        self.assertIn("`REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`", sheets)
        self.assertIn("`REQUEST_SPLIT_OR_MORE_EVIDENCE`", sheets)
        self.assertNotIn("Decision: APPROVE", sheets)

    def test_raw_specific_fixture_analysis_is_support_only(self):
        analysis = self.outputs["raw_specific64_fixture_reuse_analysis"]
        self.assertEqual(analysis["raw_specific_count"], EXPECTED_RAW_SPECIFIC_COUNT)
        self.assertEqual(analysis["formal_experiment_executed"], "NO")
        self.assertEqual(analysis["denominator_change"], "NO")
        self.assertEqual(len(analysis["rows"]), EXPECTED_RAW_SPECIFIC_COUNT)
        self.assertEqual([row["priority_rank"] for row in analysis["rows"]], list(range(1, EXPECTED_RAW_SPECIFIC_COUNT + 1)))
        for row in analysis["rows"]:
            self.assertEqual(row["original_classification"], "RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED")
            self.assertTrue(row["shared_environment_fixture_reuse_candidate"] is not None)
            self.assertTrue(row["shared_template_conversion"] is False)
            self.assertIsNone(row["human_decision"])
            self.assertIsNone(row["semantic_resolution"])
            self.assertFalse(row["formal_execution_authorized"])
            self.assertEqual(row["status_mutations"], 0)
            self.assertEqual(row["denominator_change"], "NO")

    def test_report_contains_r6_terminal_block(self):
        report = self.outputs["report"]
        self.assertIn("E0C_R6_SOURCE_RECOVERY_AND_TEMPLATE_ENRICHMENT = READY_FOR_HUMAN_REVIEW", report)
        self.assertIn("EXACT31_CONSERVATION = PASS", report)
        self.assertIn("RECOVERED_FROM_AUTHENTICATED_EXISTING_SOURCE = 0", report)
        self.assertIn("NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE = 31", report)
        self.assertIn("CONFLICTING_EXISTING_SOURCE_DETAIL = 0", report)
        self.assertIn("EXACT89_TEMPLATE_ENRICHMENT = PASS", report)
        self.assertIn("HUMAN_DECISIONS_CREATED = 0", report)
        self.assertIn("STATUS_MUTATIONS = 0", report)
        self.assertIn("FORMAL_EXPERIMENT_EXECUTED = NO", report)
        self.assertIn("DENOMINATOR_CHANGE = NO", report)
        self.assertIn("NEXT_ACTION =\nFRESH_REVIEW_OF_E0C_R6_SOURCE_RECOVERY_AND_TEMPLATE_ENRICHMENT", report)
        self.assertIn("STOP = true", report)


if __name__ == "__main__":
    unittest.main()
