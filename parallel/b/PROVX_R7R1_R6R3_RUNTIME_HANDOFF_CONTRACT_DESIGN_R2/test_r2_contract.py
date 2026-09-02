"""Safe, local contract tests for the R6R3 handoff R2 design bundle."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from r2_contract_validator import (
    ContractError,
    canonical_json_bytes,
    check_artifact_bindings,
    check_cleanup_recomputation,
    check_file_event_same_serial,
    check_join_roundtrip,
    check_path_reference,
    check_pcap_binding,
    check_record_hash_lineage,
    check_receipt,
    load_json_strict,
    load_jsonl_strict,
    validate_operator_registry_and_rules,
    validate_handoff_shape,
)


PACKAGE = Path(__file__).resolve().parent
FIXTURES = PACKAGE / "fixtures"
REQUIRED_ARTIFACT_IDS = json.loads(
    (PACKAGE / "R6R3_REQUIRED_ARTIFACT_PATH_BINDINGS_R2.json").read_text()
)["required_artifact_ids"]


def fixture(name: str) -> dict:
    return load_json_strict(FIXTURES / name)


class StrictJsonTests(unittest.TestCase):
    def test_duplicate_json_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "DUPLICATE_JSON_KEY"):
            load_json_strict(FIXTURES / "duplicate_key.json")

    def test_nonfinite_json_number_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "NONFINITE_JSON_NUMBER"):
            load_json_strict(FIXTURES / "nonfinite_number.json")

    def test_jsonl_requires_nonempty_objects(self) -> None:
        with self.assertRaisesRegex(ContractError, "MALFORMED_JSONL"):
            load_jsonl_strict(FIXTURES / "malformed_jsonl.jsonl")


class RegistryTests(unittest.TestCase):
    def test_unknown_operator_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "UNKNOWN_OPERATOR"):
            validate_handoff_shape(fixture("unknown_operator.json"))

    def test_every_referenced_operator_is_defined_once(self) -> None:
        result = validate_operator_registry_and_rules()
        self.assertEqual(result["status"], "PASS")
        self.assertGreaterEqual(result["known_operator_count"], 20)


class SchemaTests(unittest.TestCase):
    def test_all_r2_json_schemas_meta_validate(self) -> None:
        schema_paths = sorted(PACKAGE.glob("*.json"))
        self.assertGreaterEqual(len(schema_paths), 7)
        for path in schema_paths:
            document = load_json_strict(path)
            if "$schema" in document:
                Draft202012Validator.check_schema(document)

    def test_schema_and_binding_contracts_expose_all_twenty_ids(self) -> None:
        bindings = load_json_strict(PACKAGE / "R6R3_REQUIRED_ARTIFACT_PATH_BINDINGS_R2.json")
        schema = load_json_strict(PACKAGE / "R6R3_RUNTIME_HANDOFF_SCHEMA_R2.json")
        required = bindings["required_artifact_ids"]
        binding_required = bindings["binding_map_schema"]["required"]
        path_required = schema["$defs"]["selectedInputs"]["properties"]["path_bindings"]["required"]
        self.assertEqual(required, binding_required)
        self.assertEqual(required, path_required)
        self.assertEqual(len(required), 20)
        self.assertIn("hash_lineage", schema["required"])

    def test_each_runtime_artifact_has_an_exact_content_schema_pointer(self) -> None:
        bindings = load_json_strict(PACKAGE / "R6R3_REQUIRED_ARTIFACT_PATH_BINDINGS_R2.json")
        content = load_json_strict(PACKAGE / "R6R3_RUNTIME_ARTIFACT_CONTENT_SCHEMAS_R2.json")
        self.assertEqual(set(bindings["required_artifact_ids"]), set(content["artifact_schema_refs"]))
        for artifact_id, schema_ref in content["artifact_schema_refs"].items():
            if schema_ref.startswith("#/"):
                target = content
                for part in schema_ref[2:].split("/"):
                    target = target[part]
                self.assertEqual(target.get("type"), "object", artifact_id)

    def test_all_instance_object_schemas_are_closed(self) -> None:
        content = load_json_strict(PACKAGE / "R6R3_RUNTIME_ARTIFACT_CONTENT_SCHEMAS_R2.json")
        handoff = load_json_strict(PACKAGE / "R6R3_RUNTIME_HANDOFF_SCHEMA_R2.json")

        def walk(value: object) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object":
                    self.assertFalse(value.get("additionalProperties", True))
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(content["$defs"])
        walk(handoff["$defs"])


class ArtifactBindingTests(unittest.TestCase):
    def test_all_twenty_ids_are_required_and_bound_once(self) -> None:
        root = Path("/home/cph/experiment-parallel/e0-b")
        source_files = [path for path in sorted(root.rglob("*")) if path.is_file()]
        self.assertGreaterEqual(len(source_files), 20)
        entries = []
        for artifact_id, path in zip(REQUIRED_ARTIFACT_IDS, source_files[:20]):
            entries.append(
                {
                    "artifact_id": artifact_id,
                    "path": str(path),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "byte_length": path.stat().st_size,
                }
            )
        result = check_artifact_bindings(
            {"runtime_root": str(root), "entries": entries},
            required_ids=REQUIRED_ARTIFACT_IDS,
        )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(result["bound_artifact_ids"]), 20)

    def test_cross_root_artifact_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "CROSS_ROOT_ARTIFACT"):
            check_artifact_bindings(
                fixture("cross_root_artifact.json"),
                required_ids=REQUIRED_ARTIFACT_IDS,
            )


class CleanupTests(unittest.TestCase):
    def test_cleanup_false_claim_is_rejected_by_recomputation(self) -> None:
        with self.assertRaisesRegex(ContractError, "CLEANUP_RECOMPUTATION_MISMATCH"):
            check_cleanup_recomputation(fixture("cleanup_false_claim.json"))


class RecordLineageTests(unittest.TestCase):
    def test_raw_normalized_hash_lineage_is_recomputed(self) -> None:
        with self.assertRaisesRegex(ContractError, "SAME_SERIAL_BYTE_LINK_MISMATCH"):
            record = fixture("record_lineage_mismatch.json")
            check_record_hash_lineage(record["raw"], record["normalized"])

    def test_file_event_syscall_and_path_must_share_exact_serial(self) -> None:
        record = fixture("same_serial_audit_event_mismatch.json")
        with self.assertRaisesRegex(ContractError, "SAME_SERIAL_AUDIT_EVENT_MISMATCH"):
            check_file_event_same_serial(record["event"], record["raw_records"])


class PcapTests(unittest.TestCase):
    def test_pcap_hash_must_match_every_authenticated_source(self) -> None:
        with self.assertRaisesRegex(ContractError, "PCAP_HASH_MISMATCH"):
            check_pcap_binding(fixture("pcap_hash_mismatch.json"))


class ReceiptTests(unittest.TestCase):
    def test_multi_invocation_receipt_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "RECEIPT_INVOCATION_COUNT"):
            check_receipt(fixture("receipt_multi_invocation.json"))

    def test_unbound_manifest_receipt_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "RECEIPT_MANIFEST_BINDING"):
            check_receipt(fixture("receipt_unbound_manifest.json"))

    def test_malformed_receipt_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "RECEIPT_MALFORMED"):
            check_receipt(fixture("receipt_malformed.json"))


class JoinTests(unittest.TestCase):
    def test_ambiguous_join_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "AMBIGUOUS_JOIN"):
            check_join_roundtrip(fixture("ambiguous_join.json"))


class PathTests(unittest.TestCase):
    def test_dot_segment_traversal_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "PATH_DOT_SEGMENT"):
            path = fixture("path_traversal.json")
            check_path_reference(path["path"], path["runtime_root"])

    def test_symlink_substitution_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "PATH_SYMLINK"):
            path = fixture("symlink_substitution.json")
            check_path_reference(path["path"], path["runtime_root"], set(path["symlink_components"]))

    def test_noncanonical_runtime_root_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "PATH_NONCANONICAL"):
            check_path_reference("/run/root/file", "/run/root/")


class TemplateAndLineageTests(unittest.TestCase):
    def test_minimum_template_is_not_runtime_evidence(self) -> None:
        minimum = load_json_strict(
            PACKAGE.parent / "PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN" / "R6R3_RUNTIME_HANDOFF_MINIMUM_PACKAGE.json"
        )
        with self.assertRaisesRegex(ContractError, "TEMPLATE_NOT_RUNTIME_EVIDENCE"):
            validate_handoff_shape(minimum)

    def test_lineage_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "SOURCE_LINEAGE_NOT_AUTHENTICATED"):
            validate_handoff_shape(fixture("lineage_mismatch.json"))

    def test_current_producer_compatibility_prerequisite_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(ContractError, "PRODUCER_RECEIPT_EMISSION_NOT_IMPLEMENTED"):
            validate_handoff_shape(fixture("producer_receipt_unimplemented.json"))


class BoundaryTests(unittest.TestCase):
    def test_r7r1_adapter_and_frozen_encoder_match_recorded_baselines(self) -> None:
        expected = {
            "PROVX_R7_NORMALIZED_TO_GRAPH_ADAPTER.py": "d467359b5a54a1f6222e53f406153431e0223bc6a14d433fb492fc109ec6d1f5",
            "PROVX_R4_ENCODER_IMPLEMENTATION.py": "013d9b77297308843144ccfce4c3eec4b03dc3cc5172dabd6eb3320e7bc46547",
        }
        for name, digest in expected.items():
            actual = hashlib.sha256((PACKAGE.parent / name).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, name)

    def test_current_e0a_run_has_no_receipt_or_runtime_evidence(self) -> None:
        run_dir = Path("/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z")
        names = {path.name for path in run_dir.iterdir() if path.is_file()}
        self.assertEqual(
            names,
            {"mininet_e1c_r6_file_access_closure_smoke.py", "test_e1c_r6_harness.py"},
        )
        self.assertNotIn("r6_privileged_execution_receipt.json", names)


class CanonicalizationTests(unittest.TestCase):
    def test_canonical_json_is_sorted_and_compact(self) -> None:
        self.assertEqual(canonical_json_bytes({"b": 2, "a": 1}), b'{"a":1,"b":2}')


if __name__ == "__main__":
    unittest.main()
