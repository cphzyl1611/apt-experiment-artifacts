import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from materialize_r6 import (  # noqa: E402
    build_field_pin_packet,
    canonical_id,
    flatten_scalar_leaves,
    materialize,
)


class R6DesignTests(unittest.TestCase):
    def test_scalar_leaf_paths_are_rfc6901_and_deterministic(self):
        value = {"a/b": {"~key": "v"}, "items": [True, 3]}
        leaves = flatten_scalar_leaves(value, "/source_row")
        self.assertEqual(
            [(leaf["pointer"], leaf["value"]) for leaf in leaves],
            [("/source_row/a~1b/~0key", "v"), ("/source_row/items/0", True), ("/source_row/items/1", 3)],
        )

    def test_packet_is_evidence_only_and_has_no_selection(self):
        record = {
            "target_index": 1,
            "source_binding_target_id": "target",
            "source_side": "RAW",
            "route_rule_id": "R4_WRAPPER_RAW_LEGACY_26",
            "candidate_object_id": "candidate",
            "source_key": "6000002::S02::A001",
            "source_locator": "$.pipeline[1].actions[0]",
            "source_action": {"name": "example", "enabled": False},
        }
        packet = build_field_pin_packet(record)
        self.assertEqual(packet["evidence_status"], "EVIDENCE_ONLY_NOT_AUTHENTICATED")
        self.assertIsNone(packet["selected_canonical_pointer"])
        self.assertIsNone(packet["selected_scalar_leaf"])
        self.assertEqual(
            packet["allowed_future_human_actions"],
            [
                "APPROVE_EXACT_FIELD_PIN",
                "REJECT_FIELD_CANDIDATES_KEEP_BLOCKED",
                "REQUEST_MORE_EVIDENCE",
            ],
        )

    def test_materialize_produces_exact317_and_null_decision(self):
        output = materialize(ROOT)
        self.assertEqual(output["field_pin_packet_count"], 317)
        self.assertEqual(output["exact317_conservation"], "PASS")
        self.assertEqual(output["human_activation_decision"], None)
        self.assertTrue((ROOT / "R6_INPUT_AUTHENTICATION.json").exists())
        self.assertTrue((ROOT / "R6_ATOMICITY_AND_ROLLBACK_CONTRACT.json").exists())
        self.assertTrue((ROOT / "R6_INDEPENDENT_ACTIVATION_VERIFIER_CONTRACT.json").exists())

    def test_canonical_transaction_id_changes_when_a_bound_hash_changes(self):
        basis = {"root_hash": "a" * 64, "manifest_hash": "b" * 64}
        first = canonical_id("FA1B2DE_R6_TRANSACTION_V1", basis)
        basis["root_hash"] = "c" * 64
        second = canonical_id("FA1B2DE_R6_TRANSACTION_V1", basis)
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
