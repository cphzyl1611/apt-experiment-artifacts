import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from build_exp_e0c_r7_first_tranche_human_template_adjudication import (
    ALLOWED_DECISIONS,
    EXPECTED_RAW_COVERAGE,
    EXPECTED_TEMPLATE_COUNT,
    PINNED_REVIEW_COMMIT,
    build_outputs,
    write_outputs,
)


ROOT = Path(".")
EXPECTED_TEMPLATE_IDS = [
    "r4-template-120-process_command_execution",
    "r4-template-136-process_command_execution",
    "r4-template-107-process_command_execution",
    "r4-template-159-process_command_execution",
    "r4-template-130-process_command_execution",
    "r4-template-152-process_command_execution",
    "r4-template-069-persistence_configuration",
    "r4-template-009-credential_store_access",
    "r4-template-006-credential_store_access",
    "r4-template-048-network_c2_beacon",
    "r4-template-035-file_resource_operation",
    "r4-template-071-persistence_configuration",
]


def key_commitment(keys):
    return hashlib.sha256("\n".join(sorted(keys)).encode("utf-8")).hexdigest()


class R7FirstTrancheHumanTemplateAdjudicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outputs = build_outputs(ROOT)

    def test_input_authentication_is_exact_and_fail_closed(self):
        auth = self.outputs["input_authentication"]
        self.assertEqual(auth["template_count"], EXPECTED_TEMPLATE_COUNT)
        self.assertEqual(auth["raw_coverage"], EXPECTED_RAW_COVERAGE)
        self.assertEqual(auth["template_ids"], EXPECTED_TEMPLATE_IDS)
        self.assertEqual(auth["template_member_overlap"], 0)
        self.assertTrue(auth["no_member_overlap"])
        self.assertEqual(auth["member_set_drift"], 0)
        self.assertTrue(auth["no_member_set_drift"])
        self.assertEqual(auth["blocked_member_overlap"], 0)
        self.assertEqual(auth["human_decisions_created"], 0)
        self.assertEqual(auth["status_mutations"], 0)
        self.assertEqual(auth["formal_experiment_executed"], "NO")
        self.assertEqual(auth["denominator_change"], "NO")
        self.assertEqual(auth["pinned_review_commit"], PINNED_REVIEW_COMMIT)
        self.assertTrue(auth["authenticated_inputs"])
        self.assertTrue(all(item["sha256"] for item in auth["authenticated_inputs"]))
        self.assertEqual(len(auth["template_member_authentication"]), EXPECTED_TEMPLATE_COUNT)
        for item in auth["template_member_authentication"]:
            self.assertEqual(item["member_key_sha256"], key_commitment(item["member_keys"]))
            self.assertEqual(item["member_set_sha256"], item["member_key_sha256"])
            self.assertEqual(item["member_count"], len(item["member_keys"]))
            self.assertEqual(item["r3_global_planning_status"], "MANUAL_DESIGN_REQUIRED")
            self.assertEqual(item["status_mutations"], 0)
        all_keys = [key for item in auth["template_member_authentication"] for key in item["member_keys"]]
        self.assertEqual(len(all_keys), EXPECTED_RAW_COVERAGE)
        self.assertEqual(len(set(all_keys)), EXPECTED_RAW_COVERAGE)
        self.assertEqual(auth["union_member_key_sha256"], key_commitment(all_keys))

    def test_review_table_has_all_required_fields_for_exact_twelve(self):
        table = self.outputs["review_table"]
        self.assertIn("# E0C-R7 First-Tranche Human Template Review Table", table)
        self.assertEqual(table.count("| r4-template-"), EXPECTED_TEMPLATE_COUNT)
        for label in (
            "Template ID",
            "Member count",
            "Playbook count",
            "Representative raw keys",
            "Archetype / platform",
            "Exact source evidence summary",
            "Proposed reusable design contract",
            "Defensive-equivalence requirements",
            "Telemetry-equivalence requirements",
            "Environment prerequisites",
            "Unresolved UNKNOWN fields",
            "Cleanup/reset obligations",
            "Negative cases",
            "Member-set SHA256",
        ):
            self.assertIn(label, table)
        for decision in ALLOWED_DECISIONS:
            self.assertIn(f"`{decision}`", table)
        self.assertNotIn("Decision: APPROVE", table)
        self.assertNotIn("HUMAN_DECISIONS_CREATED = 1", table)
        self.assertIn("No human decision is selected", table)

    def test_decision_packet_is_explicit_only_and_hash_bound(self):
        packet = self.outputs["decision_packet"]
        self.assertEqual(packet["template_count"], EXPECTED_TEMPLATE_COUNT)
        self.assertEqual(packet["raw_coverage"], EXPECTED_RAW_COVERAGE)
        self.assertEqual(packet["allowed_decisions"], ALLOWED_DECISIONS)
        self.assertEqual(packet["human_decision_options"], ALLOWED_DECISIONS)
        self.assertEqual(packet["human_decisions_created"], 0)
        self.assertEqual(packet["status_mutations"], 0)
        self.assertEqual(packet["formal_experiment_executed"], "NO")
        self.assertEqual(packet["denominator_change"], "NO")
        self.assertTrue(packet["stop"])
        self.assertEqual(len(packet["templates"]), EXPECTED_TEMPLATE_COUNT)
        for item in packet["templates"]:
            self.assertIsNone(item["decision"])
            self.assertIsNone(item["human_origin"])
            self.assertFalse(item["member_expansion"])
            self.assertEqual(item["decision_options"], ALLOWED_DECISIONS)
            self.assertEqual(item["human_decision_options"], ALLOWED_DECISIONS)
            self.assertEqual(item["member_set_sha256"], key_commitment(item["member_keys"]))
            self.assertEqual(item["member_key_commitment"]["sha256"], item["member_set_sha256"])
            self.assertTrue(item["evidence_packet_hash"])
            self.assertIsNone(item["human_decision"])
            self.assertFalse(item["member_expansion_authorized"])
            self.assertEqual(item["r3_global_planning_status"], "MANUAL_DESIGN_REQUIRED")
            self.assertFalse(item["formal_execution_authorized"])
        with (ROOT / "E0C_R6_BLOCKED31_SOURCE_RECOVERY_RESULTS.json").open(encoding="utf-8") as handle:
            blocked = json.load(handle)
        blocked_keys = {row["raw_key"] for row in blocked["rows"]}
        packet_keys = {key for item in packet["templates"] for key in item["member_keys"]}
        self.assertTrue(blocked_keys.isdisjoint(packet_keys))

    def test_writer_emits_only_three_predecision_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory)
            write_outputs(output_root, self.outputs)
            self.assertEqual(
                {path.name for path in output_root.iterdir()},
                {
                    "E0C_R7_FIRST_TRANCHE_INPUT_AUTHENTICATION.json",
                    "E0C_R7_FIRST_TRANCHE_REVIEW_TABLE.md",
                    "E0C_R7_FIRST_TRANCHE_DECISION_PACKET.json",
                },
            )

    def _copy_authenticated_inputs(self, directory):
        for name in (
            "E0C_R6_FIRST_HUMAN_REVIEW_TRANCHE.json",
            "E0C_R6_EXACT89_ENRICHED_TEMPLATE_PACKETS.jsonl",
            "E0C_R6_INPUT_AUTHENTICATION.json",
            "E0C_R6_BLOCKED31_SOURCE_RECOVERY_RESULTS.json",
            "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl",
        ):
            shutil.copy2(ROOT / name, directory / name)

    def test_builder_rejects_valid_but_non_pinned_template_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_authenticated_inputs(root)
            tranche_path = root / "E0C_R6_FIRST_HUMAN_REVIEW_TRANCHE.json"
            tranche = json.loads(tranche_path.read_text(encoding="utf-8"))
            packets = [json.loads(line) for line in (root / "E0C_R6_EXACT89_ENRICHED_TEMPLATE_PACKETS.jsonl").read_text(encoding="utf-8").splitlines()]
            replacement = next(item for item in packets if item["template_id"] == "r4-template-105-process_command_execution")
            tranche["template_ids"][10] = replacement["template_id"]
            tranche["templates"][10] = replacement
            tranche_path.write_text(json.dumps(tranche, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_outputs(root)

    def test_builder_rejects_incomplete_or_misaligned_source_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_authenticated_inputs(root)
            packet_path = root / "E0C_R6_EXACT89_ENRICHED_TEMPLATE_PACKETS.jsonl"
            packets = [json.loads(line) for line in packet_path.read_text(encoding="utf-8").splitlines()]
            selected = next(item for item in packets if item["template_id"] == EXPECTED_TEMPLATE_IDS[0])
            selected["exact_source_evidence_references"][0]["raw_key"] = selected["member_keys"][1]
            packet_path.write_text(
                "".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in packets),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                build_outputs(root)


if __name__ == "__main__":
    unittest.main()
