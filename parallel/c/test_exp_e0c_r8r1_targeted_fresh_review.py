import unittest
from pathlib import Path

from review_exp_e0c_r8r1_targeted_fresh_review import build_targeted_review


class E0CR8R1TargetedFreshReviewTests(unittest.TestCase):
    def test_targeted_review_passes_without_reconstructing_exact12(self):
        review = build_targeted_review(Path("."))
        terminal = review["terminal"]
        self.assertEqual(terminal["status"], "PASS_READY_FOR_EXPLICIT_HUMAN_TEMPLATE_DECISIONS")
        self.assertEqual(terminal["exact12_authentication"], "PASS")
        self.assertEqual(terminal["template_count"], 12)
        self.assertEqual(terminal["raw_coverage"], 203)
        self.assertEqual(terminal["member_overlap"], 0)
        self.assertEqual(terminal["member_set_drift"], 0)
        self.assertEqual(terminal["blocked31_overlap"], 0)
        self.assertEqual(terminal["unknown_normalization_review"], "PASS")
        self.assertEqual(terminal["structured_heterogeneity_match"], "PASS")
        self.assertEqual(terminal["review_complexity_match"], "PASS")
        self.assertEqual(terminal["templates_with_structured_split_evidence"], 0)
        self.assertEqual(terminal["templates_with_no_structured_split_evidence"], 12)
        self.assertEqual(terminal["targeted_review_reuse_of_prior_exact12_audit"], "YES")
        self.assertEqual(terminal["full_e0c_r8_fresh_review_required"], "NO")
        self.assertEqual(terminal["human_decisions_created"], 0)
        self.assertEqual(terminal["applied_splits"], 0)
        self.assertEqual(terminal["status_mutations"], 0)
        self.assertEqual(terminal["formal_experiment_executed"], "NO")
        self.assertEqual(terminal["denominator_change"], "NO")


if __name__ == "__main__":
    unittest.main()
