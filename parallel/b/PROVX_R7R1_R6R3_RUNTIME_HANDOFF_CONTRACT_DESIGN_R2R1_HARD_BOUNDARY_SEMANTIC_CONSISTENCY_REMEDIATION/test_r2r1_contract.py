"""Safe, local contract tests for the R6R3 handoff R2R1 design bundle."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from r2r1_contract_validator import (
    ContractError,
    _check_manifest_completeness,
    _check_hard_boundaries,
    canonical_json_bytes,
    check_artifact_bindings,
    check_cleanup_recomputation,
    check_cleanup_recomputation_from_authenticated_artifacts,
    check_file_event_same_serial,
    check_join_roundtrip,
    check_path_reference,
    check_pcap_binding,
    check_record_hash_lineage,
    check_receipt,
    check_source_lineage,
    load_json_strict,
    load_jsonl_strict,
    validate_contract_static,
    validate_handoff,
    validate_operator_registry_and_rules,
    validate_handoff_shape,
)


PACKAGE = Path(__file__).resolve().parent
FIXTURES = PACKAGE / "fixtures"
REQUIRED_ARTIFACT_IDS = json.loads(
    (PACKAGE / "R6R3_REQUIRED_ARTIFACT_PATH_BINDINGS_R2R1.json").read_text()
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

    def test_static_validation_rejects_duplicate_operator_definition(self) -> None:
        registry = load_json_strict(PACKAGE / "R6R3_RUNTIME_HANDOFF_OPERATOR_SEMANTICS_R2R1.json")
        registry["operators"].append(dict(registry["operators"][0]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_bytes(canonical_json_bytes(registry))
            with patch("r2r1_contract_validator.REGISTRY_PATH", path):
                with self.assertRaisesRegex(ContractError, "DUPLICATE_OPERATOR_DEFINITION"):
                    validate_contract_static()

    def test_static_validation_rejects_incomplete_operator_definition(self) -> None:
        registry = load_json_strict(PACKAGE / "R6R3_RUNTIME_HANDOFF_OPERATOR_SEMANTICS_R2R1.json")
        del registry["operators"][0]["ambiguity_behavior"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_bytes(canonical_json_bytes(registry))
            with patch("r2r1_contract_validator.REGISTRY_PATH", path):
                with self.assertRaisesRegex(ContractError, "OPERATOR_SEMANTICS_INCOMPLETE"):
                    validate_contract_static()

    def test_static_validation_requires_exact_declared_rule_order(self) -> None:
        result = validate_contract_static()
        self.assertEqual(result["validated_rule_ids"], [f"H{i:03d}_{suffix}" for i, suffix in [
            (1, "PACKAGE_SHAPE_AND_SCHEMA"),
            (2, "MANIFEST_CANONICAL_HASH"),
            (3, "MANIFEST_ENTRY_UNIQUENESS_AND_COMPLETENESS"),
            (4, "EXACT_PATH_AND_FILE_HASH_BINDING"),
            (5, "SOURCE_COMMIT_AND_CONTRACT_LINEAGE"),
            (6, "EXPLICIT_PRIVILEGED_EXECUTION"),
            (7, "RUN_ID_CLOSURE"),
            (8, "RAW_RECORD_INTEGRITY"),
            (9, "NORMALIZED_RECORD_INTEGRITY"),
            (10, "RAW_NORMALIZED_SAME_SERIAL_AND_BYTE_LINK"),
            (11, "FILE_READ_OR_WRITE_STRICT_EVIDENCE"),
            (12, "PID_START_TICKS_NETNS_LOGICAL_HOST_JOIN"),
            (13, "EVENT_CLASS_COVERAGE_AND_LOSS_CLOSURE"),
            (14, "PCAP_AUTHENTICATION"),
            (15, "CLEANUP_INVERSE_RULE_AND_BASELINE_RESTORATION"),
            (16, "HARD_BOUNDARIES"),
            (17, "FINAL_CANONICAL_RECHECK"),
        ]])


class SchemaTests(unittest.TestCase):
    def test_all_r2_json_schemas_meta_validate(self) -> None:
        schema_paths = sorted(PACKAGE.glob("*.json"))
        self.assertGreaterEqual(len(schema_paths), 7)
        for path in schema_paths:
            document = load_json_strict(path)
            if "$schema" in document:
                Draft202012Validator.check_schema(document)

    def test_schema_and_binding_contracts_expose_all_twenty_ids(self) -> None:
        bindings = load_json_strict(PACKAGE / "R6R3_REQUIRED_ARTIFACT_PATH_BINDINGS_R2R1.json")
        schema = load_json_strict(PACKAGE / "R6R3_RUNTIME_HANDOFF_SCHEMA_R2R1.json")
        self.assertEqual(
            schema["$id"],
            "provx://r7r1/r6r3/authenticated-runtime-handoff/schema/r2r1",
        )
        required = bindings["required_artifact_ids"]
        binding_required = bindings["binding_map_schema"]["required"]
        path_required = schema["$defs"]["selectedInputs"]["properties"]["path_bindings"]["required"]
        self.assertEqual(required, binding_required)
        self.assertEqual(required, path_required)
        self.assertEqual(len(required), 20)
        self.assertIn("hash_lineage", schema["required"])

    def test_each_runtime_artifact_has_an_exact_content_schema_pointer(self) -> None:
        bindings = load_json_strict(PACKAGE / "R6R3_REQUIRED_ARTIFACT_PATH_BINDINGS_R2R1.json")
        content = load_json_strict(PACKAGE / "R6R3_RUNTIME_ARTIFACT_CONTENT_SCHEMAS_R2R1.json")
        handoff = load_json_strict(PACKAGE / "R6R3_RUNTIME_HANDOFF_SCHEMA_R2R1.json")
        self.assertEqual(set(bindings["required_artifact_ids"]), set(content["artifact_schema_refs"]))
        self.assertIn("content_schema", bindings["$defs"]["binding"]["required"])
        self.assertIn("content_schema", handoff["$defs"]["artifactBinding"]["required"])
        self.assertIn("operation_id", handoff["$defs"]["cleanupJournalEntry"]["required"])
        for artifact_id, schema_ref in content["artifact_schema_refs"].items():
            if schema_ref.startswith("#/"):
                target = content
                for part in schema_ref[2:].split("/"):
                    target = target[part]
                self.assertEqual(target.get("type"), "object", artifact_id)

    def test_all_instance_object_schemas_are_closed(self) -> None:
        content = load_json_strict(PACKAGE / "R6R3_RUNTIME_ARTIFACT_CONTENT_SCHEMAS_R2R1.json")
        handoff = load_json_strict(PACKAGE / "R6R3_RUNTIME_HANDOFF_SCHEMA_R2R1.json")

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


class HardBoundarySemanticConsistencyTests(unittest.TestCase):
    @staticmethod
    def _boundaries(*, pcap_is_not_graph_edge_source: bool) -> dict:
        return {
            "r7r1_adapter_changed": False,
            "frozen_32d_encoder_changed": False,
            "detector_trained": False,
            "provx_inference_executed": False,
            "formal_experiment_executed": False,
            "privileged_commands_executed_by_e0b": False,
            "runtime_data_fabricated": False,
            "pcap_is_not_graph_edge_source": pcap_is_not_graph_edge_source,
        }

    def test_inverse_pcap_guard_true_is_schema_and_validator_accepted(self) -> None:
        schema = load_json_strict(PACKAGE / "R6R3_RUNTIME_HANDOFF_SCHEMA_R2R1.json")
        boundaries = self._boundaries(pcap_is_not_graph_edge_source=True)
        errors = list(Draft202012Validator(schema["$defs"]["hardBoundaries"]).iter_errors(boundaries))
        self.assertEqual(errors, [])
        self.assertEqual(
            _check_hard_boundaries({
                "hard_boundaries": boundaries,
                "pcap_authentication": {"used_as_graph_edge_source": False},
            }),
            {"status": "PASS"},
        )

    def test_inverse_pcap_guard_false_remains_schema_invalid(self) -> None:
        schema = load_json_strict(PACKAGE / "R6R3_RUNTIME_HANDOFF_SCHEMA_R2R1.json")
        boundaries = self._boundaries(pcap_is_not_graph_edge_source=False)
        errors = list(Draft202012Validator(schema["$defs"]["hardBoundaries"]).iter_errors(boundaries))
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].validator, "const")
        self.assertEqual(errors[0].validator_value, True)
        with self.assertRaisesRegex(ContractError, "HANDOFF_SCOPE_BOUNDARY_VIOLATED"):
            _check_hard_boundaries({
                "hard_boundaries": boundaries,
                "pcap_authentication": {"used_as_graph_edge_source": False},
            })


class ArtifactBindingTests(unittest.TestCase):
    def _entry(self, artifact_id: str, path: Path, root: Path) -> dict:
        bindings = load_json_strict(PACKAGE / "R6R3_REQUIRED_ARTIFACT_PATH_BINDINGS_R2R1.json")
        stat_result = path.stat()
        return {
            "artifact_id": artifact_id,
            "role": bindings["artifact_roles"][artifact_id],
            "content_schema": bindings["parsed_artifact_schemas"][artifact_id],
            "path": str(path),
            "path_form": "ABSOLUTE_CANONICAL_NO_DOT_NO_SYMLINK",
            "runtime_root": str(root),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "byte_length": stat_result.st_size,
            "object_identity": {
                "device": stat_result.st_dev,
                "inode": stat_result.st_ino,
                "mode_type": "REGULAR_FILE",
                "lstat_matches_open_fstat": True,
            },
            "status": "BOUND_AND_HASHED",
        }

    def test_all_twenty_ids_are_required_and_bound_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = []
            for index, artifact_id in enumerate(REQUIRED_ARTIFACT_IDS):
                path = root / f"artifact-{index}.bin"
                path.write_bytes(f"artifact-{artifact_id}".encode("ascii"))
                entries.append(self._entry(artifact_id, path, root))
            result = check_artifact_bindings({"runtime_root": str(root), "entries": entries}, required_ids=REQUIRED_ARTIFACT_IDS)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(len(result["bound_artifact_ids"]), 20)

    def test_cross_root_artifact_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "CROSS_ROOT_ARTIFACT"):
            check_artifact_bindings(
                fixture("cross_root_artifact.json"),
                required_ids=REQUIRED_ARTIFACT_IDS,
            )

    def test_generic_artifact_binding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "a.json"
            path.write_text("{}")
            entry = self._entry(REQUIRED_ARTIFACT_IDS[0], path, root)
            del entry["role"]
            with self.assertRaisesRegex(ContractError, "ARTIFACT_BINDING_INCOMPLETE"):
                check_artifact_bindings({"runtime_root": str(root), "entries": [entry]}, required_ids=[REQUIRED_ARTIFACT_IDS[0]])

    def test_parent_symlink_and_path_alias_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            payload = outside / "a.json"
            payload.write_text("{}")
            os.symlink(outside, root / "linked")
            symlink_entry = self._entry(REQUIRED_ARTIFACT_IDS[0], root / "linked" / "a.json", root)
            with self.assertRaisesRegex(ContractError, "PATH_SYMLINK"):
                check_artifact_bindings({"runtime_root": str(root), "entries": [symlink_entry]}, required_ids=[REQUIRED_ARTIFACT_IDS[0]])

            normal = root / "normal.json"
            normal.write_text("{}")
            first = self._entry(REQUIRED_ARTIFACT_IDS[0], normal, root)
            second = self._entry(REQUIRED_ARTIFACT_IDS[1], normal, root)
            with self.assertRaisesRegex(ContractError, "DUPLICATE_ARTIFACT_PATH"):
                check_artifact_bindings({"runtime_root": str(root), "entries": [first, second]}, required_ids=REQUIRED_ARTIFACT_IDS[:2])

    def test_hard_link_object_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original.json"
            alias = root / "alias.json"
            original.write_text("{}")
            os.link(original, alias)
            first = self._entry(REQUIRED_ARTIFACT_IDS[0], original, root)
            second = self._entry(REQUIRED_ARTIFACT_IDS[1], alias, root)
            with self.assertRaisesRegex(ContractError, "DUPLICATE_ARTIFACT_OBJECT"):
                check_artifact_bindings({"runtime_root": str(root), "entries": [first, second]}, required_ids=REQUIRED_ARTIFACT_IDS[:2])

    def test_runtime_root_with_symlink_ancestor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            physical_parent = base / "physical-parent"
            physical_root = physical_parent / "runtime"
            physical_root.mkdir(parents=True)
            symlink_parent = base / "symlink-parent"
            os.symlink(physical_parent, symlink_parent)
            root = symlink_parent / "runtime"
            artifact = root / "artifact.json"
            artifact.write_text("{}")
            entry = self._entry(REQUIRED_ARTIFACT_IDS[0], artifact, root)
            with self.assertRaisesRegex(ContractError, "PATH_SYMLINK"):
                check_artifact_bindings({"runtime_root": str(root), "entries": [entry]}, required_ids=[REQUIRED_ARTIFACT_IDS[0]])

    def test_manifest_entries_must_equal_selected_path_bindings(self) -> None:
        root = "/runtime"
        bindings = {
            artifact_id: {"artifact_id": artifact_id, "runtime_root": root, "path": f"{root}/{index}"}
            for index, artifact_id in enumerate(REQUIRED_ARTIFACT_IDS)
        }
        entries = [dict(bindings[artifact_id]) for artifact_id in REQUIRED_ARTIFACT_IDS]
        entries[0]["path"] = f"{root}/unselected-alias"
        candidate = {
            "run_identity": {"runtime_root": root},
            "selected_inputs": {
                "runtime_root": root,
                "path_bindings": bindings,
                "parsed_bindings": [
                    {"artifact_id": artifact_id} for artifact_id in REQUIRED_ARTIFACT_IDS
                ],
            },
            "package_manifest": {"runtime_root": root, "runtime_entries": entries},
        }
        with self.assertRaisesRegex(ContractError, "MANIFEST_SELECTED_BINDING_MISMATCH"):
            _check_manifest_completeness(candidate)


class CleanupTests(unittest.TestCase):
    def test_cleanup_false_claim_is_rejected_by_recomputation(self) -> None:
        with self.assertRaisesRegex(ContractError, "CLEANUP_RECOMPUTATION_MISMATCH"):
            check_cleanup_recomputation(
                fixture("cleanup_false_claim.json"),
                authenticated_artifact_ids={
                    "r6_audit_pre_state",
                    "r6_rule_remediation_journal",
                    "r6_transient_rule_contract",
                    "r6_residual_remediation",
                    "r6_post_cleanup",
                },
            )

    def test_cleanup_requires_manifest_bound_evidence(self) -> None:
        with self.assertRaisesRegex(ContractError, "CLEANUP_EVIDENCE_UNBOUND"):
            check_cleanup_recomputation(fixture("cleanup_false_claim.json"))

    def test_cleanup_is_recomputed_from_authenticated_artifacts_not_candidate_claims(self) -> None:
        digest = "a" * 64
        artifacts = {
            "r6_audit_pre_state": {
                "baseline_rule_dump_sha256": digest,
                "persistent_rule_files_sha256": digest,
            },
            "r6_transient_rule_contract": {
                "allowed_rule_ids": ["rule-1"],
                "rules": [{"rule_id": "rule-1", "rule_sha256": digest}],
            },
            "r6_rule_remediation_journal": {
                "entries": [
                    {"operation_id": "add-1", "rule_id": "rule-1", "operation": "ADD", "result": "SUCCESS", "rule_sha256": digest},
                    {"operation_id": "delete-1", "rule_id": "rule-1", "operation": "DELETE", "result": "SUCCESS", "rule_sha256": digest},
                ],
                "successful_add_ids": ["rule-1"],
                "successful_delete_ids": ["rule-1"],
                "global_delete_observed": False,
            },
            "r6_residual_remediation": {
                "remaining_transient_rules": [],
                "baseline_rule_dump_sha256_after": digest,
                "persistent_rule_files_sha256_after": digest,
                "run_owned_children_remaining": 0,
                "reserved_test_interfaces_remaining": 0,
                "reserved_test_ovs_objects_remaining": 0,
                "tcpdump_process_remaining": 0,
                "topology_residue_zero": True,
                "child_residue_zero": True,
                "tcpdump_residue_zero": True,
            },
            "r6_post_cleanup": {
                "performed_after_all_reads": True,
                "audit_lost_events": 0,
                "audit_backlog": 0,
                "baseline_rule_dump_sha256_after": digest,
                "persistent_rule_files_sha256_after": digest,
            },
        }
        self.assertEqual(
            check_cleanup_recomputation_from_authenticated_artifacts(artifacts)["status"],
            "PASS",
        )
        artifacts["r6_rule_remediation_journal"]["entries"].pop()
        with self.assertRaisesRegex(ContractError, "CLEANUP_RECOMPUTATION_MISMATCH"):
            check_cleanup_recomputation_from_authenticated_artifacts(artifacts)


class RecordLineageTests(unittest.TestCase):
    def test_raw_normalized_hash_lineage_is_recomputed(self) -> None:
        with self.assertRaisesRegex(ContractError, "SAME_SERIAL_BYTE_LINK_MISMATCH"):
            record = fixture("record_lineage_mismatch.json")
            check_record_hash_lineage(record["raw"], record["normalized"])

    def test_file_event_syscall_and_path_must_share_exact_serial(self) -> None:
        record = fixture("same_serial_audit_event_mismatch.json")
        with self.assertRaisesRegex(ContractError, "SAME_SERIAL_AUDIT_EVENT_MISMATCH"):
            check_file_event_same_serial(record["event"], record["raw_records"])

    def test_file_event_rejects_raw_record_key_or_path_mismatch(self) -> None:
        event = {
            "raw_serial": 7,
            "syscall_record_serial": 7,
            "path_record_serial": 7,
            "same_serial_linkage": "PASS",
            "path": "/watched/file",
            "watched_path": "/watched/file",
            "file_identity_paths": ["/watched/file"],
            "underlying_syscall": "openat",
            "audit_key": "expected-key",
            "raw_bundle_assertions": {
                "contains_syscall_record": True,
                "contains_path_record": True,
                "syscall_success": True,
                "audit_key_exact": True,
                "path_exact": True,
            },
        }
        raw_records = [{
            "serial": 7,
            "record_types": ["SYSCALL", "PATH"],
            "audit_records": [
                {"serial": 7, "record_kind": "SYSCALL", "audit_key": "wrong-key", "path_name": None, "syscall_name": "openat", "syscall_success": True},
                {"serial": 7, "record_kind": "PATH", "audit_key": "wrong-key", "path_name": "/watched/file", "syscall_name": None, "syscall_success": None},
            ],
        }]
        with self.assertRaisesRegex(ContractError, "SAME_SERIAL_AUDIT_EVENT_MISMATCH"):
            check_file_event_same_serial(event, raw_records)


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

    def test_receipt_requires_full_schema_hash_and_summary_equality(self) -> None:
        receipt = {
            "schema": "R6R3_PRIVILEGED_EXECUTION_RECEIPT_R2R1",
            "manifest_binding": {
                "artifact_id": "r6_privileged_execution_receipt",
                "manifest_sha256": "a" * 64,
            },
            "run_binding": {"run_id": "run-1", "runtime_root": "/run/one", "binding_kind": "RUN_ID_AND_EXACT_RUNTIME_ROOT"},
            "producer_identity": {"producer_id": "producer", "program_path": "/run/one/producer.py", "producer_source_sha256": "b" * 64, "identity_kind": "EXACT_PROGRAM_PATH_AND_SOURCE_HASH"},
            "authorization": {"human_initiated": True, "authorization_reference": {"reference_type": "TICKET", "reference_value": "T-1"}},
            "invocation_count": 1,
            "invocation": {"invocation_id": "i1"},
            "receipt_hash": "c" * 64,
        }
        with self.assertRaisesRegex(ContractError, "RECEIPT_SCHEMA_INVALID"):
            check_receipt(receipt, {}, "a" * 64, "run-1", "/run/one")

    def test_receipt_rejects_pid_mismatch_with_privileged_summary(self) -> None:
        receipt = {
            "schema": "R6R3_PRIVILEGED_EXECUTION_RECEIPT_R2R1",
            "receipt_version": "2.1.0",
            "receipt_status": "AUTHENTICATED_EXECUTION_RECEIPT",
            "manifest_binding": {"artifact_id": "r6_privileged_execution_receipt", "manifest_sha256": "a" * 64, "binding_kind": "PACKAGE_MANIFEST_SHA256_EXACT"},
            "runtime_binding": {"run_id": "run-1", "runtime_root": "/run/one", "binding_kind": "RUN_ID_AND_EXACT_RUNTIME_ROOT"},
            "producer_identity": {"producer_id": "producer", "program_path": "/run/one/producer.py", "producer_source_sha256": "b" * 64, "identity_kind": "EXACT_PROGRAM_PATH_AND_SOURCE_HASH"},
            "authorization": {"human_initiated": True, "authorization_reference": {"reference_type": "TICKET", "reference_value": "T-1"}},
            "invocation_count": 1,
            "invocation": {
                "invocation_id": "i1", "exact_command": "python producer.py", "command_argv": ["python", "producer.py"], "program_path": "/run/one/producer.py", "uid": 0, "euid": 0,
                "start_time_utc": "2026-09-03T00:00:00Z", "end_time_utc": "2026-09-03T00:01:00Z", "pid": 42, "pid_start_time_ticks": 100, "netns_inode": 200,
                "exit_code": 0, "result_status": "COMPLETED", "classification": "PASS_READY_FOR_GRAPH_NORMALIZATION", "micro_probe_verdict": "PASS", "micro_probe_cleanup_state": "RULE_REMOVED_BASELINE_RESTORED", "mininet_executed": True,
            },
        }
        receipt["receipt_hash"] = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
        summary = {
            "human_initiated": True, "producer_id": "producer", "program_path": "/run/one/producer.py", "producer_source_sha256": "b" * 64,
            "authorization_reference": {"reference_type": "TICKET", "reference_value": "T-1"}, "exact_command": "python producer.py", "uid": 0, "effective_uid": 0,
            "pid": 99, "pid_start_time_ticks": 100, "netns_inode": 200, "exit_code": 0, "result_status": "COMPLETED",
            "classification": "PASS_READY_FOR_GRAPH_NORMALIZATION", "micro_probe_verdict": "PASS", "micro_probe_cleanup_state": "RULE_REMOVED_BASELINE_RESTORED", "mininet_executed": True,
        }
        with self.assertRaisesRegex(ContractError, "RECEIPT_SUMMARY_MISMATCH"):
            check_receipt(receipt, summary, "a" * 64, "run-1", "/run/one")


class JoinTests(unittest.TestCase):
    def test_ambiguous_join_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "AMBIGUOUS_JOIN"):
            check_join_roundtrip(fixture("ambiguous_join.json"))

    def test_join_rejects_zero_candidate_role_mismatch_and_type_coercion(self) -> None:
        normalized = [{"run_id": "run-1", "logical_host_id": "h1", "pid": 42, "pid_start_time_ticks": 100, "netns_inode": 200, "role": "child"}]
        with self.assertRaisesRegex(ContractError, "MISSING_JOIN"):
            check_join_roundtrip({"normalized_rows": normalized, "join_rows": []})
        role_mismatch = dict(normalized[0], role="shell", join_status="JOINED", captured_while_alive=True)
        with self.assertRaisesRegex(ContractError, "MISSING_JOIN"):
            check_join_roundtrip({"normalized_rows": normalized, "join_rows": [role_mismatch]})
        type_coercion = dict(normalized[0], pid="42", join_status="JOINED", captured_while_alive=True)
        with self.assertRaisesRegex(ContractError, "JOIN_KEY_TYPE_COERCION"):
            check_join_roundtrip({"normalized_rows": normalized, "join_rows": [type_coercion]})

    def test_join_rejects_compact_key_when_explicit_role_bearing_fields_are_absent(self) -> None:
        compact = {"join_key": ["run-1", "h1", 42, 100, 200, "child"]}
        joined = dict(compact, join_status="JOINED", captured_while_alive=True)
        with self.assertRaisesRegex(ContractError, "ROLE_NOT_ROUNDTRIPPABLE"):
            check_join_roundtrip({"normalized_rows": [compact], "join_rows": [joined]})


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

    def test_double_leading_slash_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "PATH_NONCANONICAL"):
            check_path_reference("//run/root/file", "//run/root")
        with self.assertRaisesRegex(ContractError, "PATH_NONCANONICAL"):
            check_path_reference("//run/root/file", "/run/root")


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

    def test_fabricated_committed_source_is_not_authenticated(self) -> None:
        lineage = {
            "disposition": "AUTHENTICATED_COMMITTED_SOURCE",
            "committed_source": {
                "resolved_commit": "0" * 40,
                "resolution_method": "INDEPENDENT_COMMITTED_STATE_RESOLUTION",
                "hashes_match": True,
                "source_files": [{"source_id": "harness", "repository_relative_path": "producer.py", "sha256": "a" * 64}],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ContractError, "SOURCE_LINEAGE_NOT_AUTHENTICATED"):
                check_source_lineage(lineage, Path(directory))

    def test_committed_source_schema_and_manifest_use_identical_relative_entries(self) -> None:
        repository = Path("/home/cph/fa1b2de-artifact-worktrees/e0-b")
        commit = "11a5692effd70ab5fbcf75b4574c7c27338e49af"
        relative_path = "parallel/b/PROVX_R7_NORMALIZED_TO_GRAPH_ADAPTER.py"
        digest = hashlib.sha256((repository / relative_path).read_bytes()).hexdigest()
        source = {
            "source_id": "r7r1_adapter",
            "repository_relative_path": relative_path,
            "sha256": digest,
            "file_role": "producer_contract_input",
        }
        handoff = load_json_strict(PACKAGE / "R6R3_RUNTIME_HANDOFF_SCHEMA_R2R1.json")
        committed_schema = {"$defs": handoff["$defs"], **handoff["$defs"]["committedSource"]}
        self.assertFalse(list(Draft202012Validator(committed_schema).iter_errors({
            "resolved_commit": commit,
            "resolution_method": "INDEPENDENT_COMMITTED_STATE_RESOLUTION",
            "source_files": [source],
            "hashes_match": True,
        })))
        lineage = {
            "disposition": "AUTHENTICATED_COMMITTED_SOURCE",
            "committed_source": {
                "resolved_commit": commit,
                "resolution_method": "INDEPENDENT_COMMITTED_STATE_RESOLUTION",
                "source_files": [source],
                "hashes_match": True,
            },
        }
        self.assertEqual(check_source_lineage(lineage, repository, [source])["status"], "PASS")
        mismatch = [dict(source, sha256="0" * 64)]
        with self.assertRaisesRegex(ContractError, "SOURCE_LINEAGE_NOT_AUTHENTICATED"):
            check_source_lineage(lineage, repository, mismatch)


class OrderedHandoffTests(unittest.TestCase):
    def test_handoff_never_returns_a_partial_success(self) -> None:
        with self.assertRaisesRegex(ContractError, "H001_PACKAGE_SHAPE_AND_SCHEMA"):
            validate_handoff({"schema": "PROVX_R7R1_R6R3_AUTHENTICATED_RUNTIME_HANDOFF_R2R1"}, source_repository=None)


class BoundaryTests(unittest.TestCase):
    def test_r7r1_adapter_and_frozen_encoder_match_recorded_baselines(self) -> None:
        frozen_artifact_root = Path("/home/cph/fa1b2de-artifact-worktrees/e0-b/parallel/b")
        expected = {
            "PROVX_R7_NORMALIZED_TO_GRAPH_ADAPTER.py": "7e33886b9ac628e8c4f312317127d95c181e40bebc2c5059cc9022ed4555ad6e",
            "PROVX_R4_ENCODER_IMPLEMENTATION.py": "013d9b77297308843144ccfce4c3eec4b03dc3cc5172dabd6eb3320e7bc46547",
        }
        for name, digest in expected.items():
            actual = hashlib.sha256((frozen_artifact_root / name).read_bytes()).hexdigest()
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
