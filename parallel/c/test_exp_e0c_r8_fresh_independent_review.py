import json
import tempfile
import unittest
from pathlib import Path

from review_exp_e0c_r8_fresh_independent_review import (
    ALLOWED_DECISIONS,
    EXPECTED_MAIN_COMMIT,
    EXPECTED_TEMPLATE_IDS,
    build_review,
    write_review,
)


ROOT = Path(".")


class E0CR8FreshIndependentReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.review = build_review(ROOT, current_commit=EXPECTED_MAIN_COMMIT)

    def test_fresh_recomputation_authenticates_exact12_and_union(self):
        terminal = self.review["terminal"]
        self.assertEqual(terminal["current_repository_commit"], EXPECTED_MAIN_COMMIT)
        self.assertEqual(terminal["exact12_authentication"], "PASS")
        self.assertEqual(terminal["template_count"], 12)
        self.assertEqual(terminal["raw_coverage"], 203)
        self.assertEqual(terminal["member_overlap"], 0)
        self.assertEqual(terminal["member_set_drift"], 0)
        self.assertEqual(terminal["blocked31_overlap"], 0)
        self.assertEqual(terminal["all_members_manual_design_required"], "PASS")
        self.assertEqual(self.review["template_ids"], EXPECTED_TEMPLATE_IDS)

    def test_structured_recomputation_has_no_candidate_split_evidence(self):
        self.assertEqual(self.review["structured_heterogeneity_recomputation"], "PASS")
        self.assertEqual(self.review["templates_with_structured_split_evidence"], 0)
        self.assertEqual(self.review["templates_with_no_structured_split_evidence"], 12)
        for template in self.review["templates"]:
            self.assertEqual(template["candidate_split_status"], "NO_STRUCTURED_SPLIT_EVIDENCE")
            self.assertEqual(template["candidate_split_count"], 0)
            self.assertEqual(template["heterogeneous_fields"], [])

    def test_unknown_list_values_are_counted_as_unknown_and_match_remediated_publish(self):
        for template in self.review["templates"]:
            expected_unknown_fields = 3 if template["template_id"] in {
                "r4-template-048-network_c2_beacon",
                "r4-template-035-file_resource_operation",
            } else 5
            self.assertEqual(
                template["unknown_burden"]["unknown_cell_count"],
                template["member_count"] * expected_unknown_fields,
            )
        published = self.review["r8_published_output_audit"]
        self.assertEqual(published["status"], "PASS")
        self.assertTrue(published["structured_heterogeneity_matches_fresh_recompute"])
        self.assertEqual(published["structured_heterogeneity_mismatch_count"], 0)

    def test_policy_and_packet_audits_are_non_mutating_and_null(self):
        self.assertTrue(self.review["no_unauthorized_inference"])
        packet = self.review["human_decision_packet_audit"]
        self.assertEqual(packet["status"], "PASS")
        self.assertEqual(packet["allowed_decisions"], ALLOWED_DECISIONS)
        self.assertEqual(packet["human_decisions_created"], 0)
        self.assertEqual(packet["applied_splits"], 0)
        self.assertEqual(packet["status_mutations"], 0)
        self.assertTrue(packet["all_decisions_null"])
        self.assertTrue(packet["all_member_hashes_match_fresh_recompute"])

    def test_writer_emits_only_separate_fresh_review_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_review(output, self.review)
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "E0C_R8_FRESH_INDEPENDENT_REVIEW.json",
                    "E0C_R8_FRESH_INDEPENDENT_REVIEW.md",
                },
            )
            data = json.loads((output / "E0C_R8_FRESH_INDEPENDENT_REVIEW.json").read_text())
            self.assertEqual(data["terminal"]["next_action"], "EXPLICIT_HUMAN_TEMPLATE_DECISIONS")

    def test_historical_blocked_review_report_is_not_rewritten(self):
        historical = json.loads((ROOT / "E0C_R8_FRESH_INDEPENDENT_REVIEW.json").read_text())
        self.assertEqual(historical["terminal"]["status"], "BLOCKED")
        self.assertEqual(historical["terminal"]["next_action"], "REMEDIATE_E0C_R8")


if __name__ == "__main__":
    unittest.main()
