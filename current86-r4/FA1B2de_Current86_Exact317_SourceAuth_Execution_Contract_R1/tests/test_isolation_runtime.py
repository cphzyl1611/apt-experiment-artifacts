import unittest

from tools.sourceauth_isolation import run_synthetic_isolation_probe


class IsolationRuntimeTests(unittest.TestCase):
    def test_bwrap_verifier_cannot_see_primary_private_or_commitment(self):
        evidence = run_synthetic_isolation_probe()
        self.assertEqual(evidence["probe_mode"], "SYNTHETIC_NON_SEMANTIC_ONLY")
        self.assertTrue(evidence["primary_torn_down_before_verifier"])
        self.assertTrue(evidence["primary_commitment_frozen_before_verifier"])
        self.assertFalse(evidence["verifier_observed_primary_private"])
        self.assertFalse(evidence["verifier_observed_primary_commitment"])
        self.assertTrue(evidence["comparator_started_after_both_commitments_frozen"])
        self.assertNotEqual(evidence["PRIMARY_IMPLEMENTATION_ID"], evidence["VERIFIER_IMPLEMENTATION_ID"])
        self.assertNotEqual(evidence["PRIMARY_CONTEXT_ID"], evidence["VERIFIER_CONTEXT_ID"])
        self.assertNotEqual(evidence["PRIMARY_RUN_ID"], evidence["VERIFIER_RUN_ID"])


if __name__ == "__main__":
    unittest.main()
