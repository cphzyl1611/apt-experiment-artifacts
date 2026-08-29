import copy
import unittest

from tests.fixtures import comparison, commitment, with_id

try:
    from tools.transaction import authenticate_commitment, compare_commitments
    from tools.isolation import run_synthetic_commitment_transaction
    from tools.records import ContractError
except ImportError as import_error:
    _IMPORT_ERROR = import_error
    ContractError = ValueError
else:
    _IMPORT_ERROR = None


class CommitmentComparatorTests(unittest.TestCase):
    def setUp(self):
        if _IMPORT_ERROR is not None:
            self.fail(f"R2_TRANSACTION_NOT_IMPLEMENTED: {_IMPORT_ERROR}")

    def test_valid_equal_commitments_emit_schema_valid_comparison(self):
        primary = commitment()
        verifier = commitment("verifier_commitment", context="context-v", run="run-v")
        verifier["ordered_result_vector_sha256"] = primary["ordered_result_vector_sha256"]
        verifier["terminal_state_count_map"] = primary["terminal_state_count_map"]
        verifier["exact_target_id_set_sha256"] = primary["exact_target_id_set_sha256"]
        verifier = with_id(verifier, "commitment_id")
        result = compare_commitments(primary, verifier, both_frozen=True)
        self.assertTrue(result["comparison_equal"])
        self.assertEqual(result["affected_target_ids"], [])

    def test_wrong_schema_primary_fails(self):
        primary = commitment()
        primary["schema"] = "WRONG"
        primary = with_id(primary, "commitment_id")
        with self.assertRaisesRegex(ContractError, "WRONG_SCHEMA_DISCRIMINATOR"):
            authenticate_commitment(primary, "primary_commitment")

    def test_wrong_common_input_role_identity_or_stale_id_fails(self):
        primary = commitment()
        verifier = commitment("verifier_commitment", context="context-v", run="run-v")
        for field, value, reason in (
            ("common_input_set_id", "wrong-common", "COMMITMENT_COMMON_INPUT_MISMATCH"),
            ("role", "PRIMARY", "COMMITMENT_ROLE_MISMATCH"),
            ("commitment_id", "f" * 64, "STALE_OR_INVALID_IDENTITY"),
        ):
            candidate = copy.deepcopy(verifier)
            candidate[field] = value
            if field != "commitment_id":
                candidate = with_id(candidate, "commitment_id")
            with self.assertRaisesRegex(ContractError, reason):
                compare_commitments(primary, candidate, both_frozen=True)

    def test_equal_forbidden_identity_fails(self):
        primary = commitment()
        verifier = commitment("verifier_commitment", context="context-p", run="run-p")
        with self.assertRaisesRegex(ContractError, "ROLE_IDENTITY_NOT_DISTINCT"):
            compare_commitments(primary, verifier, both_frozen=True)

    def test_comparator_before_both_frozen_fails(self):
        with self.assertRaisesRegex(ContractError, "COMPARATOR_BEFORE_BOTH_COMMITMENTS_FROZEN"):
            compare_commitments(commitment(), commitment("verifier_commitment", context="context-v", run="run-v"), both_frozen=False)

    def test_disagreement_requires_exact_affected_targets(self):
        primary = commitment()
        verifier = commitment("verifier_commitment", result_hash="9" * 64, context="context-v", run="run-v")
        with self.assertRaisesRegex(ContractError, "AFFECTED_TARGET_LIST_INCONSISTENT"):
            compare_commitments(primary, verifier, both_frozen=True, affected_target_ids=[])

    def test_wrong_comparison_self_id_fails(self):
        primary = commitment()
        verifier = commitment("verifier_commitment", context="context-v", run="run-v")
        row = comparison(primary, verifier)
        row["comparison_record_id"] = "a" * 64
        with self.assertRaisesRegex(ContractError, "STALE_OR_INVALID_IDENTITY"):
            compare_commitments(primary, verifier, both_frozen=True, comparison_record=row)

    def test_bwrap_transaction_emits_and_compares_frozen_commitments(self):
        result = run_synthetic_commitment_transaction()
        self.assertEqual(result["mode"], "SYNTHETIC_NON_SEMANTIC_ONLY")
        self.assertTrue(result["primary_commitment_schema_valid"])
        self.assertTrue(result["verifier_commitment_schema_valid"])
        self.assertTrue(result["primary_frozen_before_verifier_start"])
        self.assertTrue(result["comparator_after_both_frozen"])
        self.assertFalse(result["verifier_observed_primary_private"])
        self.assertFalse(result["verifier_observed_primary_commitment"])


if __name__ == "__main__":
    unittest.main()
