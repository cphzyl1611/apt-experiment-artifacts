#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

from .canonical import (
    AUDIT_SCOPE_ID,
    SCALAR_FORMAT_ID,
    TARGET_MANIFEST_SHA256,
    ContractError,
    admission_tuple_id,
    authenticated_value_sha256,
    canonical_json_bytes,
    fail,
    pointer_sha256,
    require_sha256,
    self_excluding_id,
    sha256_hex,
)

EXACT_SCHEMA_NAME = {
    "common_input_entry": "FA1B2DE_CURRENT86_SOURCE_AUTH_COMMON_INPUT_ENTRY_R2",
    "common_input_manifest": "FA1B2DE_CURRENT86_SOURCE_AUTH_COMMON_INPUT_MANIFEST_R2",
    "authenticated_frozen_authority_record": "FA1B2DE_CURRENT86_AUTHENTICATED_FROZEN_AUTHORITY_RECORD_R2",
    "candidate_source_object_commitment": "FA1B2DE_CURRENT86_CANDIDATE_SOURCE_OBJECT_COMMITMENT_R2",
    "admission_record": "FA1B2DE_CURRENT86_SOURCE_ADMISSION_RECORD_V1",
    "source_admission_machine_zero_proof": "FA1B2DE_CURRENT86_SOURCE_ADMISSION_MACHINE_ZERO_PROOF_R2",
    "human_normative_admission_record": "FA1B2DE_CURRENT86_HUMAN_NORMATIVE_ADMISSION_RECORD_R2",
    "no_machine_field_pin_authority_proof_v2": "FA1B2DE_CURRENT86_NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF_V2",
    "human_field_pin_governance_record_v2": "FA1B2DE_CURRENT86_HUMAN_FIELD_PIN_GOVERNANCE_RECORD_V2",
    "field_pin_record": "FA1B2DE_CURRENT86_FIELD_PIN_RECORD_R2",
    "primary_commitment": "FA1B2DE_CURRENT86_SOURCE_AUTH_PRIMARY_COMMITMENT_R3",
    "verifier_commitment": "FA1B2DE_CURRENT86_SOURCE_AUTH_VERIFIER_COMMITMENT_R3",
    "comparison_record": "FA1B2DE_CURRENT86_SOURCE_AUTH_COMPARISON_RECORD_R3",
    "per_target_readiness_record": "FA1B2DE_CURRENT86_SOURCE_AUTH_READINESS_RECORD_R2",
    "terminal_conservation_record": "FA1B2DE_CURRENT86_SOURCE_AUTH_TERMINAL_CONSERVATION_RECORD_R2",
    "machine_authority_expansion_record": "FA1B2DE_CURRENT86_MACHINE_AUTHORITY_EXPANSION_RECORD_R3",
    "machine_authority_evaluation_evidence": "FA1B2DE_CURRENT86_MACHINE_AUTHORITY_EVALUATION_EVIDENCE_R3",
}


def fields(*names: str) -> frozenset[str]:
    return frozenset(names)


SCHEMA_FIELDS = {
    "common_input_entry": fields("schema", "logical_artifact_id", "logical_artifact_role", "exact_locator", "sha256_or_explicit_pinned_identity", "byte_length", "media_type", "schema_or_contract_id", "provenance_id", "authority_role", "governance_freeze_record_id", "read_mode", "available", "content_opened", "authenticated_artifact_bytes", "content_sha256_observed", "content_byte_length_observed", "common_input_entry_id"),
    "common_input_manifest": fields("schema", "audit_scope_id", "exact_target_manifest_sha256", "fixture_authority", "entries", "common_input_set_id"),
    "authenticated_frozen_authority_record": fields("schema", "audit_scope_id", "logical_artifact_id", "logical_artifact_role", "sha256_or_explicit_pinned_identity", "byte_length", "schema_or_contract_id", "provenance_id", "authority_role", "governance_freeze_record_id", "common_input_entry_id", "authority_record_id"),
    "candidate_source_object_commitment": fields("schema", "audit_scope_id", "candidate_corpus_id", "source_artifact_identity", "source_artifact_sha256_or_pinned_identity", "source_side", "bound_raw_key", "bound_candidate_scoring_id", "object_locator", "object_locator_canonical_sha256", "object_extraction_rule_id", "extracted_byte_span_sha256", "canonical_object_representation_sha256", "source_provenance_id", "candidate_object_id"),
    "admission_record": fields("schema", "audit_scope_id", "source_binding_target_id", "candidate_object_id", "canonical_intrinsic_field_semantics_id", "exact_RFC6901_pointer_utf8_sha256", "exact_RFC6901_pointer", "admission_authority_type", "admission_authority_artifact_id", "admission_authority_sha256_or_pinned_identity", "admission_authority_provenance_id", "admission_record_id"),
    "source_admission_machine_zero_proof": fields("schema", "audit_scope_id", "exact_target_manifest_sha256", "source_binding_target_id", "machine_authority_input_set_id", "source_admission_evaluation_contract_id", "machine_authority_evaluation_evidence_id", "registry_valid_tuple_ids", "rule_valid_tuple_ids", "machine_valid_admission_tuple_ids", "machine_valid_admission_tuple_count", "machine_conflict_count", "source_admission_machine_zero_proof_id"),
    "human_normative_admission_record": fields("schema", "audit_scope_id", "source_binding_target_id", "candidate_object_id", "canonical_intrinsic_field_semantics_id", "exact_RFC6901_pointer_utf8_sha256", "exact_RFC6901_pointer", "source_admission_machine_zero_proof_id", "human_native_decision_bytes_sha256", "human_origin_provenance_mode", "governance_event_id", "independent_capture_verification_id", "human_normative_admission_record_id"),
    "no_machine_field_pin_authority_proof_v2": fields("schema", "audit_scope_id", "exact_target_manifest_sha256", "source_binding_target_id", "candidate_object_id", "canonical_intrinsic_field_semantics_id", "admission_record_id", "admission_tuple_id", "admitted_exact_RFC6901_pointer_utf8_sha256", "machine_field_pin_authority_input_set_id", "exact_target_pointer_authority_set_id", "field_pin_registry_authority_set_id", "deterministic_corpus_schema_rule_authority_set_id", "field_pin_authority_evaluation_contract_id", "exact_target_valid_tuple_ids", "field_pin_registry_valid_tuple_ids", "deterministic_corpus_schema_rule_valid_tuple_ids", "machine_valid_field_pin_tuple_ids", "valid_exact_target_pointer_authority_count", "valid_field_pin_registry_tuple_count", "valid_deterministic_corpus_schema_rule_tuple_count", "machine_valid_field_pin_tuple_count", "machine_conflict_count", "machine_admission_tuple_mismatch_count", "machine_authority_evaluation_evidence_id", "no_machine_field_pin_authority_proof_id"),
    "human_field_pin_governance_record_v2": fields("schema", "audit_scope_id", "source_binding_target_id", "candidate_object_id", "canonical_intrinsic_field_semantics_id", "admission_record_id", "admission_tuple_id", "admitted_exact_RFC6901_pointer_utf8_sha256", "exact_RFC6901_pointer", "exact_RFC6901_pointer_utf8_sha256", "no_machine_field_pin_authority_proof_id", "human_native_decision_bytes_sha256", "human_origin_provenance_mode", "governance_event_id", "independent_capture_verification_id", "human_field_pin_governance_record_id"),
    "field_pin_record": fields("schema", "audit_scope_id", "source_binding_target_id", "candidate_object_id", "admission_record_id", "admission_tuple_id", "canonical_intrinsic_field_semantics_id", "exact_RFC6901_pointer", "exact_RFC6901_pointer_utf8_sha256", "parsed_scalar_type", "canonical_scalar_format_id", "authenticated_value_sha256", "provenance_id", "field_pin_id"),
    "primary_commitment": fields("schema", "role", "common_input_set_id", "implementation_id", "context_id", "run_id", "isolation_audit_id", "ordered_target_result_vector", "ordered_result_vector_sha256", "terminal_state_count_map", "exact_target_id_set_sha256", "private_output_manifest_sha256", "commitment_id"),
    "verifier_commitment": fields("schema", "role", "common_input_set_id", "implementation_id", "context_id", "run_id", "isolation_audit_id", "ordered_target_result_vector", "ordered_result_vector_sha256", "terminal_state_count_map", "exact_target_id_set_sha256", "private_output_manifest_sha256", "commitment_id"),
    "comparison_record": fields("schema", "audit_scope_id", "primary_commitment_id", "verifier_commitment_id", "common_input_set_id", "commitments_frozen_before_compare", "comparison_equal", "affected_target_ids", "comparison_record_id"),
    "per_target_readiness_record": fields("schema", "audit_scope_id", "source_binding_target_id", "terminal_state", "reason", "readiness_record_id"),
    "terminal_conservation_record": fields("schema", "audit_scope_id", "exact_target_manifest_sha256", "ordered_target_ids_sha256", "terminal_state_counts", "source_auth_target_count", "raw_side_target_count", "candidate_side_target_count", "exactly_one_state_per_target", "terminal_conservation_record_id"),
    "machine_authority_expansion_record": fields("schema", "audit_scope_id", "authority_record_id", "common_input_entry_id", "artifact_content_identity", "evaluator_implementation_id", "evaluator_implementation_sha256", "evaluator_configuration_id", "evaluation_contract_id", "evaluation_run_input_identity", "evaluation_evidence_id", "complete_input_open_audit_id", "expansion_complete", "ordered_tuple_ids", "tuples", "rejected_record_reason_codes", "ordered_set_commitment_id", "expansion_record_id"),
    "machine_authority_evaluation_evidence": fields("schema", "audit_scope_id", "machine_authority_input_set_id", "evaluation_contract_id", "evaluator_implementation_id", "evaluator_implementation_sha256", "evaluator_configuration_id", "evaluation_run_input_identity", "evaluation_evidence_id", "authority_record_ids", "ordered_expansion_record_ids", "complete_input_open_audit", "authority_authentication_results", "deterministic_expansion_outputs", "rejected_record_reason_codes", "ordered_set_commitments", "machine_authority_evaluation_evidence_id"),
}

IDENTITY_FIELDS = {
    "common_input_entry": "common_input_entry_id", "common_input_manifest": "common_input_set_id",
    "authenticated_frozen_authority_record": "authority_record_id", "candidate_source_object_commitment": "candidate_object_id",
    "admission_record": "admission_record_id", "source_admission_machine_zero_proof": "source_admission_machine_zero_proof_id",
    "human_normative_admission_record": "human_normative_admission_record_id", "no_machine_field_pin_authority_proof_v2": "no_machine_field_pin_authority_proof_id",
    "human_field_pin_governance_record_v2": "human_field_pin_governance_record_id", "field_pin_record": "field_pin_id",
    "primary_commitment": "commitment_id", "verifier_commitment": "commitment_id", "comparison_record": "comparison_record_id",
    "per_target_readiness_record": "readiness_record_id", "terminal_conservation_record": "terminal_conservation_record_id",
    "machine_authority_expansion_record": "expansion_record_id", "machine_authority_evaluation_evidence": "machine_authority_evaluation_evidence_id",
}

LIST_FIELDS = {"entries", "registry_valid_tuple_ids", "rule_valid_tuple_ids", "machine_valid_admission_tuple_ids", "exact_target_valid_tuple_ids", "field_pin_registry_valid_tuple_ids", "deterministic_corpus_schema_rule_valid_tuple_ids", "machine_valid_field_pin_tuple_ids", "affected_target_ids", "ordered_tuple_ids", "tuples", "ordered_target_result_vector", "authority_record_ids", "ordered_expansion_record_ids", "rejected_record_reason_codes", "complete_input_open_audit", "authority_authentication_results", "deterministic_expansion_outputs", "ordered_set_commitments"}
DICT_FIELDS = {"object_locator", "terminal_state_count_map", "terminal_state_counts"}
BOOL_FIELDS = {"available", "content_opened", "commitments_frozen_before_compare", "comparison_equal", "exactly_one_state_per_target", "expansion_complete"}
INT_FIELDS = {"byte_length", "content_byte_length_observed", "machine_valid_admission_tuple_count", "machine_conflict_count", "valid_exact_target_pointer_authority_count", "valid_field_pin_registry_tuple_count", "valid_deterministic_corpus_schema_rule_tuple_count", "machine_valid_field_pin_tuple_count", "machine_admission_tuple_mismatch_count", "source_auth_target_count", "raw_side_target_count", "candidate_side_target_count"}
NULLABLE_STRINGS = {"bound_raw_key", "bound_candidate_scoring_id"}

TERMINAL_STATES = frozenset({"SOURCE_AUTHENTICATED", "BLOCKED_NORMATIVE_ADMISSION", "BLOCKED_SOURCE_OBJECT", "BLOCKED_FIELD_PIN", "BLOCKED_PROVENANCE", "BLOCKED_INDEPENDENT_VERIFICATION"})


def validate_record(kind: str, record: Mapping[str, Any]) -> bool:
    if kind not in EXACT_SCHEMA_NAME:
        fail("UNKNOWN_SCHEMA_KIND", kind)
    if not isinstance(record, dict):
        fail("WRONG_TYPE", kind)
    if record.get("schema") != EXACT_SCHEMA_NAME[kind]:
        fail("WRONG_SCHEMA_DISCRIMINATOR", kind)
    missing = SCHEMA_FIELDS[kind] - record.keys()
    unknown = record.keys() - SCHEMA_FIELDS[kind]
    if missing:
        fail("MISSING_REQUIRED_FIELDS", ",".join(sorted(missing)))
    if unknown:
        fail("UNKNOWN_FIELDS", ",".join(sorted(unknown)))
    if "audit_scope_id" in record and record["audit_scope_id"] != AUDIT_SCOPE_ID:
        fail("WRONG_AUDIT_SCOPE")
    for key, value in record.items():
        if key in LIST_FIELDS:
            if not isinstance(value, list): fail("WRONG_TYPE", key)
        elif key in DICT_FIELDS:
            if not isinstance(value, dict): fail("WRONG_TYPE", key)
        elif key in BOOL_FIELDS:
            if type(value) is not bool: fail("WRONG_TYPE", key)
        elif key in INT_FIELDS or key.endswith("_count"):
            if type(value) is not int or value < 0: fail("WRONG_TYPE", key)
        elif key in NULLABLE_STRINGS:
            if value is not None and not isinstance(value, str): fail("WRONG_TYPE", key)
        elif not isinstance(value, str):
            fail("WRONG_TYPE", key)
        if key.endswith("_sha256") and isinstance(value, str):
            require_sha256(value, key)
    identity_field = IDENTITY_FIELDS[kind]
    if record[identity_field] != self_excluding_id(record, identity_field):
        fail("STALE_OR_INVALID_IDENTITY", identity_field)
    return True


def _validate_common_entry(entry: Mapping[str, Any]) -> bool:
    validate_record("common_input_entry", entry)
    if entry["read_mode"] != "READ_ONLY" or not entry["available"] or not entry["content_opened"]:
        fail("COMMON_INPUT_UNAVAILABLE_OR_UNREADABLE", entry["logical_artifact_id"])
    if entry["sha256_or_explicit_pinned_identity"] != entry["content_sha256_observed"] or entry["byte_length"] != entry["content_byte_length_observed"]:
        fail("COMMON_INPUT_CONTENT_IDENTITY_MISMATCH", entry["logical_artifact_id"])
    return True


def validate_common_input_manifest(manifest: Mapping[str, Any]) -> bool:
    validate_record("common_input_manifest", manifest)
    if manifest["exact_target_manifest_sha256"] != TARGET_MANIFEST_SHA256:
        fail("WRONG_TARGET_MANIFEST_IDENTITY")
    entries = manifest["entries"]
    for entry in entries: _validate_common_entry(entry)
    ids = [entry["logical_artifact_id"] for entry in entries]
    if ids != sorted(ids, key=lambda value: value.encode("utf-8")):
        fail("COMMON_INPUT_ORDER_INVALID")
    if len(ids) != len(set(ids)):
        fail("DUPLICATE_LOGICAL_ARTIFACT_ID")
    unique_roles = {"SOURCE_ADMISSION_REGISTRY", "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE", "EXACT_TARGET_POINTER_AUTHORITY", "FIELD_PIN_REGISTRY", "DETERMINISTIC_CORPUS_SCHEMA_FIELD_PIN_RULE"}
    roles = [entry["authority_role"] for entry in entries if entry["authority_role"] in unique_roles]
    if len(roles) != len(set(roles)):
        fail("DUPLICATE_UNIQUE_AUTHORITY_ROLE")
    return True


def validate_frozen_authority_record(record: Mapping[str, Any], manifest: Mapping[str, Any]) -> bool:
    validate_common_input_manifest(manifest)
    validate_record("authenticated_frozen_authority_record", record)
    matches = [entry for entry in manifest["entries"] if entry["common_input_entry_id"] == record["common_input_entry_id"]]
    if len(matches) != 1:
        fail("AUTHORITY_NOT_IN_COMMON_INPUT")
    entry = matches[0]
    matched_fields = ("logical_artifact_id", "logical_artifact_role", "sha256_or_explicit_pinned_identity", "byte_length", "schema_or_contract_id", "provenance_id", "authority_role", "governance_freeze_record_id")
    if any(record[field] != entry[field] for field in matched_fields):
        fail("AUTHORITY_COMMON_INPUT_MISMATCH")
    return True


def validate_candidate_source_object_commitment(record: Mapping[str, Any], target: Mapping[str, Any], manifest: Mapping[str, Any], extraction_authority: Mapping[str, Any]) -> bool:
    validate_common_input_manifest(manifest)
    validate_record("candidate_source_object_commitment", record)
    validate_frozen_authority_record(extraction_authority, manifest)
    corpus_matches = [entry for entry in manifest["entries"] if entry["logical_artifact_id"] == record["source_artifact_identity"]]
    if len(corpus_matches) != 1:
        fail("CANDIDATE_ARTIFACT_NOT_IN_COMMON_INPUT")
    corpus = corpus_matches[0]
    expected = (
        record["candidate_corpus_id"] == corpus["logical_artifact_id"],
        record["source_artifact_sha256_or_pinned_identity"] == corpus["sha256_or_explicit_pinned_identity"],
        record["source_provenance_id"] == corpus["provenance_id"],
        record["object_extraction_rule_id"] == extraction_authority["authority_record_id"],
        extraction_authority["authority_role"] == "CANDIDATE_OBJECT_EXTRACTION_RULE",
        record["source_side"] == target["source_side"],
        record["bound_raw_key"] == target["bound_raw_key"],
        record["bound_candidate_scoring_id"] == target["bound_candidate_scoring_id"],
        record["object_locator_canonical_sha256"] == sha256_hex(canonical_json_bytes(record["object_locator"])),
    )
    if not all(expected):
        fail("CANDIDATE_OBJECT_BINDING_MISMATCH")
    return True


def validate_admission_record(record: Mapping[str, Any]) -> bool:
    validate_record("admission_record", record)
    if record["exact_RFC6901_pointer_utf8_sha256"] != pointer_sha256(record["exact_RFC6901_pointer"]):
        fail("POINTER_HASH_MISMATCH")
    return True


def validate_field_pin_record(record: Mapping[str, Any], admission: Mapping[str, Any], scalar_value: Any) -> bool:
    validate_record("field_pin_record", record)
    validate_admission_record(admission)
    expected_tuple = admission_tuple_id(admission)
    tuple_fields = ("source_binding_target_id", "candidate_object_id", "canonical_intrinsic_field_semantics_id", "exact_RFC6901_pointer")
    if record["admission_record_id"] != admission["admission_record_id"] or record["admission_tuple_id"] != expected_tuple or any(record[field] != admission[field] for field in tuple_fields):
        fail("ADMISSION_FIELD_PIN_TUPLE_MISMATCH")
    if record["exact_RFC6901_pointer"].encode("utf-8") != admission["exact_RFC6901_pointer"].encode("utf-8") or record["exact_RFC6901_pointer_utf8_sha256"] != pointer_sha256(admission["exact_RFC6901_pointer"]):
        fail("ADMISSION_FIELD_PIN_TUPLE_MISMATCH")
    from .canonical import canonical_scalar
    scalar_type, _ = canonical_scalar(scalar_value)
    if record["parsed_scalar_type"] != scalar_type or record["canonical_scalar_format_id"] != SCALAR_FORMAT_ID:
        fail("FIELD_PIN_SCALAR_TYPE_OR_FORMAT_MISMATCH")
    if record["authenticated_value_sha256"] != authenticated_value_sha256(scalar_value):
        fail("FIELD_PIN_VALUE_HASH_MISMATCH")
    if not record["provenance_id"]:
        fail("FIELD_PIN_PROVENANCE_MISSING")
    return True


def validate_per_target_readiness_record(record: Mapping[str, Any], target_ids: set[str]) -> bool:
    validate_record("per_target_readiness_record", record)
    if record["source_binding_target_id"] not in target_ids:
        fail("READINESS_TARGET_NOT_IN_SCOPE")
    if record["terminal_state"] not in TERMINAL_STATES:
        fail("UNKNOWN_TERMINAL_STATE")
    return True


def validate_terminal_conservation_record(record: Mapping[str, Any], ordered_target_ids: Sequence[str], readiness_records: Sequence[Mapping[str, Any]], expected_side_counts: tuple[int, int]) -> bool:
    validate_record("terminal_conservation_record", record)
    if record["exact_target_manifest_sha256"] != TARGET_MANIFEST_SHA256:
        fail("WRONG_TARGET_MANIFEST_IDENTITY")
    if len(set(ordered_target_ids)) != len(ordered_target_ids):
        fail("DUPLICATE_TARGET_AUTHORITY")
    for item in readiness_records: validate_per_target_readiness_record(item, set(ordered_target_ids))
    seen = Counter(item["source_binding_target_id"] for item in readiness_records)
    if any(seen[target] != 1 for target in ordered_target_ids) or set(seen) != set(ordered_target_ids):
        fail("TARGET_STATE_NOT_EXACTLY_ONCE")
    counts = dict(Counter(item["terminal_state"] for item in readiness_records))
    raw_count, candidate_count = expected_side_counts
    expected = (
        record["ordered_target_ids_sha256"] == sha256_hex(canonical_json_bytes(list(ordered_target_ids))),
        record["terminal_state_counts"] == counts,
        record["source_auth_target_count"] == len(ordered_target_ids),
        record["raw_side_target_count"] == raw_count,
        record["candidate_side_target_count"] == candidate_count,
        raw_count + candidate_count == len(ordered_target_ids),
        record["exactly_one_state_per_target"] is True,
        sum(counts.values()) == len(ordered_target_ids),
    )
    if not all(expected): fail("TERMINAL_CONSERVATION_FAILED")
    return True
