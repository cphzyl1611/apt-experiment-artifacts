from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]


class R8MaterializationTests(unittest.TestCase):

 def test_r8_materializer_module_exists_and_exports_contract(self) -> None:
    module_path = PACKAGE / "tools" / "materialize_r8.py"
    self.assertTrue(module_path.is_file())
    completed = subprocess.run(
        [sys.executable, str(module_path), "--help"],
        cwd=PACKAGE,
        capture_output=True,
        text=True,
    )
    self.assertEqual(completed.returncode, 0, completed.stderr)


 def test_materialized_package_conserves_exact317_and_keeps_field_pins_unselected(self) -> None:
    packets = PACKAGE / "R8_EXACT317_FIELD_PIN_CANDIDATE_PACKETS.jsonl"
    classification = PACKAGE / "R8_FIELD_PIN_CANDIDATE_CLASSIFICATION.json"
    self.assertTrue(packets.is_file())
    rows = [json.loads(line) for line in packets.read_text(encoding="utf-8").splitlines() if line]
    self.assertEqual(len(rows), 317)
    self.assertEqual(sum(row["source_side"] == "RAW" for row in rows), 86)
    self.assertEqual(sum(row["source_side"] == "CANDIDATE" for row in rows), 231)
    self.assertEqual(len({row["source_binding_target_id"] for row in rows}), 317)
    self.assertTrue(all(row["human_decision"] is None for row in rows))
    self.assertTrue(all(row["selected_canonical_pointer"] is None for row in rows))
    self.assertTrue(all(row["field_pin_created"] is False for row in rows))
    self.assertTrue(classification.is_file())


 def test_r8_outputs_have_no_authoritative_or_downstream_activation(self) -> None:
    auth = json.loads((PACKAGE / "R8_INPUT_AUTHENTICATION.json").read_text(encoding="utf-8"))
    bridge = json.loads((PACKAGE / "R8_SOURCE_AUTH_READINESS_BRIDGE.json").read_text(encoding="utf-8"))
    self.assertEqual(auth["authentication_status"], "PASS")
    self.assertEqual(auth["pinned_r8_review"]["commit"], "107ef9f69a734a10b320d552cfe18a6cb9a2ac0c")
    self.assertEqual(auth["pinned_r8_review"]["tree"], "26b5c3a56e86fb5c11d50fc86bd99d6b940239fc")
    self.assertEqual(auth["exact317"]["target_total"], 317)
    self.assertEqual(auth["exact317"]["raw_side_total"], 86)
    self.assertEqual(auth["exact317"]["candidate_side_total"], 231)
    self.assertEqual(auth["r7"]["consumer_pointer_sha256"], "02394a7fc7c5f337dfbfff521467759f80e14f8d5d27ca9e01653eec3f0d592c")
    self.assertTrue(bridge["design_only"])
    self.assertEqual(bridge["field_pin_authority_status"], "BLOCKED_UNTIL_EXPLICIT_APPROVAL")
    self.assertEqual(bridge["source_auth_execution_status"], "NOT_EXECUTED")


 def test_batches_and_first_tranche_are_exact_and_presentation_only(self) -> None:
    batches = json.loads((PACKAGE / "R8_FIELD_PIN_REVIEW_BATCHES.json").read_text(encoding="utf-8"))
    tranche = json.loads((PACKAGE / "R8_FIRST_HUMAN_FIELD_PIN_TRANCHE.json").read_text(encoding="utf-8"))
    self.assertTrue(20 <= batches["batch_count"] <= 30)
    batch_ids = [target for batch in batches["batches"] for target in batch["target_indices"]]
    self.assertEqual(batch_ids, list(range(1, 318)))
    self.assertEqual(len(set(batch_ids)), 317)
    self.assertTrue(batches["presentation_only"])
    self.assertLessEqual(len(tranche["target_indices"]), 24)
    self.assertEqual(tranche["human_decisions"], {})
    self.assertEqual(tranche["field_pins_created"], 0)


 def test_envelope_inventory_path_sets_are_exact_and_self_bound(self) -> None:
    file_list_paths = {
        line.strip()
        for line in (PACKAGE / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    checksum_paths = {
        line.split("  ./", 1)[1]
        for line in (PACKAGE / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    self.assertEqual(file_list_paths, checksum_paths)
    self.assertIn("FILE_LIST.txt", file_list_paths)
    self.assertIn("FILE_LIST.txt", checksum_paths)
    self.assertNotIn("SHA256SUMS.txt", file_list_paths)
    self.assertNotIn("SHA256SUMS.txt", checksum_paths)


if __name__ == "__main__":
    unittest.main()
