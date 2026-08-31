import json
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]


class R7ActivationTests(unittest.TestCase):
    def test_r7_package_materializes_required_activation_records(self):
        required = {
            "R7_HUMAN_ACTIVATION_APPROVAL_AUTHENTICATION.json",
            "R7_PRE_ACTIVATION_STATE.json",
            "R7_ACTIVATION_PRECONDITION_VERIFICATION.json",
            "R7_STAGED_AUTHORITY_ROOTS.json",
            "R7_ACTIVATION_TRANSACTION_JOURNAL.jsonl",
            "R7_COMMIT_POINT.json",
            "R7_POST_ACTIVATION_STATE.json",
            "R7_INDEPENDENT_ACTIVATION_VERIFICATION.json",
            "R7_DOWNSTREAM_BOUNDARY_VERIFICATION.json",
            "R7_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION_REPORT.md",
            "FILE_LIST.txt",
            "SHA256SUMS.txt",
        }
        self.assertTrue(required.issubset({p.name for p in PACKAGE.iterdir()}))

    def test_approval_and_transaction_are_exact(self):
        approval = json.loads((PACKAGE / "R7_HUMAN_ACTIVATION_APPROVAL_AUTHENTICATION.json").read_text())
        self.assertEqual(approval["human_origin"], "USER_EXPLICIT_APPROVAL")
        self.assertEqual(approval["decision"], "APPROVE_EXACT_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION")
        self.assertEqual(
            approval["transaction_id"],
            "e8a0a97a33d47ac68c8ded4af1af109fa010d979acf9736fd5dffdebf96c5208",
        )

    def test_post_activation_preserves_exact317_and_downstream_zero_state(self):
        post = json.loads((PACKAGE / "R7_POST_ACTIVATION_STATE.json").read_text())
        self.assertEqual(post["exact317"]["total"], 317)
        self.assertEqual(post["exact317"]["raw"], 86)
        self.assertEqual(post["exact317"]["candidate"], 231)
        self.assertEqual(post["exact317"]["duplicates"], 0)
        self.assertEqual(post["exact317"]["cross_route_substitution"], 0)
        self.assertEqual(post["authority_boundary"]["source_auth_executed"], False)
        self.assertEqual(post["authority_boundary"]["field_pins_created"], 0)
        self.assertEqual(post["authority_boundary"]["p0_executed"], False)
        self.assertEqual(post["authority_boundary"]["p1_executed"], False)
        self.assertEqual(post["authority_boundary"]["binding_publication"], False)

    def test_consumer_pointer_is_complete_and_atomic(self):
        pointer = json.loads(
            (PACKAGE / "authority_store/r7-activation-consumer-pointer.json").read_text()
        )
        self.assertEqual(pointer["status"], "COMMITTED")
        self.assertEqual(pointer["visibility"], "ATOMIC_SINGLE_POINTER")
        self.assertEqual(
            set(pointer["post_state_root_ids"]),
            {
                "SOURCE_ADMISSION_REGISTRY_ROOT",
                "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT",
                "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST",
                "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION",
            },
        )


if __name__ == "__main__":
    unittest.main()
