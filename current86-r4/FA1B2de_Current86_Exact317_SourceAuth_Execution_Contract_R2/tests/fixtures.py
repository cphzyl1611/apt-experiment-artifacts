import hashlib
import json

AUDIT_SCOPE_ID = "34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306"
TARGET_MANIFEST_SHA256 = "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac"
TARGET_ID = "synthetic-non-production-target-r2-0001"
CANDIDATE_ID_PLACEHOLDER = "synthetic-non-production-candidate-r2-placeholder"
SEMANTICS_ID = "synthetic-field-semantics-r2"
POINTER = "/intrinsic/name"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def with_id(record, field):
    value = dict(record)
    value[field] = digest({key: item for key, item in value.items() if key != field})
    return value


def common_entry(logical_id="synthetic-artifact-a", role="FIELD_PIN_REGISTRY", content=b"synthetic-authority-bytes\n"):
    content_hash = hashlib.sha256(content).hexdigest()
    return with_id({
        "schema": "FA1B2DE_CURRENT86_SOURCE_AUTH_COMMON_INPUT_ENTRY_R2",
        "logical_artifact_id": logical_id,
        "logical_artifact_role": role,
        "exact_locator": f"synthetic://{logical_id}",
        "sha256_or_explicit_pinned_identity": content_hash,
        "byte_length": len(content),
        "media_type": "application/json",
        "schema_or_contract_id": "synthetic-schema-r2",
        "provenance_id": "synthetic-provenance-r2",
        "authority_role": role,
        "governance_freeze_record_id": "synthetic-governance-freeze-r2",
        "read_mode": "READ_ONLY",
        "available": True,
        "content_opened": True,
        "content_sha256_observed": content_hash,
        "content_byte_length_observed": len(content),
    }, "common_input_entry_id")


def common_manifest(entries=None):
    entries = entries or [common_entry()]
    entries = sorted(entries, key=lambda row: row["logical_artifact_id"].encode("utf-8"))
    return with_id({
        "schema": "FA1B2DE_CURRENT86_SOURCE_AUTH_COMMON_INPUT_MANIFEST_R2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "exact_target_manifest_sha256": TARGET_MANIFEST_SHA256,
        "fixture_authority": "NON_AUTHORITATIVE_SYNTHETIC_ONLY",
        "entries": entries,
    }, "common_input_set_id")


def frozen_authority(entry=None):
    entry = entry or common_entry()
    return with_id({
        "schema": "FA1B2DE_CURRENT86_AUTHENTICATED_FROZEN_AUTHORITY_RECORD_R2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "logical_artifact_id": entry["logical_artifact_id"],
        "logical_artifact_role": entry["logical_artifact_role"],
        "sha256_or_explicit_pinned_identity": entry["sha256_or_explicit_pinned_identity"],
        "byte_length": entry["byte_length"],
        "schema_or_contract_id": entry["schema_or_contract_id"],
        "provenance_id": entry["provenance_id"],
        "authority_role": entry["authority_role"],
        "governance_freeze_record_id": entry["governance_freeze_record_id"],
        "common_input_entry_id": entry["common_input_entry_id"],
    }, "authority_record_id")


def authority_expansion(authority, tuples=None, evaluation_contract_id="synthetic-evaluation-contract-r2", complete=True):
    tuples = tuples or []
    tuple_ids = sorted((digest(item) for item in tuples), key=lambda value: value.encode("utf-8"))
    ordered_tuples = sorted(tuples, key=lambda item: digest(item).encode("utf-8"))
    return with_id({
        "schema": "FA1B2DE_CURRENT86_MACHINE_AUTHORITY_EXPANSION_RECORD_R2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "authority_record_id": authority["authority_record_id"],
        "evaluation_contract_id": evaluation_contract_id,
        "complete_input_open_audit_id": "synthetic-complete-input-open-audit-r2",
        "expansion_complete": complete,
        "ordered_tuple_ids": tuple_ids,
        "tuples": ordered_tuples,
        "rejected_record_reason_codes": [],
        "ordered_set_commitment_id": digest(tuple_ids),
    }, "expansion_record_id")


def extraction_authority():
    entry = common_entry("synthetic-extraction-rule", "CANDIDATE_OBJECT_EXTRACTION_RULE", b"synthetic-extraction-rule\n")
    return entry, common_manifest([entry]), frozen_authority(entry)


def candidate_commitment(corpus_entry, extraction_record):
    locator = {"jsonl_line_index": 0, "match_key": "synthetic"}
    row = {
        "schema": "FA1B2DE_CURRENT86_CANDIDATE_SOURCE_OBJECT_COMMITMENT_R2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "candidate_corpus_id": corpus_entry["logical_artifact_id"],
        "source_artifact_identity": corpus_entry["logical_artifact_id"],
        "source_artifact_sha256_or_pinned_identity": corpus_entry["sha256_or_explicit_pinned_identity"],
        "source_side": "RAW",
        "bound_raw_key": "synthetic::raw::1",
        "bound_candidate_scoring_id": None,
        "object_locator": locator,
        "object_locator_canonical_sha256": digest(locator),
        "object_extraction_rule_id": extraction_record["authority_record_id"],
        "extracted_byte_span_sha256": "2" * 64,
        "canonical_object_representation_sha256": "3" * 64,
        "source_provenance_id": corpus_entry["provenance_id"],
    }
    return with_id(row, "candidate_object_id")


def target_for_candidate(candidate):
    return {
        "source_binding_target_id": TARGET_ID,
        "source_side": "RAW",
        "bound_raw_key": "synthetic::raw::1",
        "bound_candidate_scoring_id": None,
    }


def admission_record(candidate, pointer=POINTER):
    pointer_hash = hashlib.sha256(pointer.encode("utf-8")).hexdigest()
    return with_id({
        "schema": "FA1B2DE_CURRENT86_SOURCE_ADMISSION_RECORD_V1",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "source_binding_target_id": TARGET_ID,
        "candidate_object_id": candidate["candidate_object_id"],
        "canonical_intrinsic_field_semantics_id": SEMANTICS_ID,
        "exact_RFC6901_pointer_utf8_sha256": pointer_hash,
        "exact_RFC6901_pointer": pointer,
        "admission_authority_type": "SYNTHETIC_NON_AUTHORITATIVE_FIXTURE",
        "admission_authority_artifact_id": "synthetic-admission-authority-r2",
        "admission_authority_sha256_or_pinned_identity": "4" * 64,
        "admission_authority_provenance_id": "synthetic-admission-provenance-r2",
    }, "admission_record_id")


def admission_tuple_id(admission):
    return digest({
        "candidate_object_id": admission["candidate_object_id"],
        "canonical_intrinsic_field_semantics_id": admission["canonical_intrinsic_field_semantics_id"],
        "exact_RFC6901_pointer": admission["exact_RFC6901_pointer"],
        "source_binding_target_id": admission["source_binding_target_id"],
    })


def scalar_hash(value):
    payload = value.encode("utf-8")
    envelope = b"FA1B2DE_CANONICAL_INTRINSIC_SCALAR_V1\x00string\x00" + str(len(payload)).encode("ascii") + b"\x00" + payload
    return hashlib.sha256(envelope).hexdigest()


def field_pin_record(admission, value="synthetic-value"):
    pointer = admission["exact_RFC6901_pointer"]
    return with_id({
        "schema": "FA1B2DE_CURRENT86_FIELD_PIN_RECORD_R2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "source_binding_target_id": admission["source_binding_target_id"],
        "candidate_object_id": admission["candidate_object_id"],
        "admission_record_id": admission["admission_record_id"],
        "admission_tuple_id": admission_tuple_id(admission),
        "canonical_intrinsic_field_semantics_id": admission["canonical_intrinsic_field_semantics_id"],
        "exact_RFC6901_pointer": pointer,
        "exact_RFC6901_pointer_utf8_sha256": hashlib.sha256(pointer.encode("utf-8")).hexdigest(),
        "parsed_scalar_type": "string",
        "canonical_scalar_format_id": "FA1B2DE_CANONICAL_INTRINSIC_SCALAR_V1",
        "authenticated_value_sha256": scalar_hash(value),
        "provenance_id": "synthetic-field-pin-provenance-r2",
    }, "field_pin_id")


def source_admission_zero_proof(input_set_id="synthetic-authority-input-set-r2", contract_id="synthetic-admission-evaluation-contract-r2", evidence_id="synthetic-admission-evidence-r2"):
    return with_id({
        "schema": "FA1B2DE_CURRENT86_SOURCE_ADMISSION_MACHINE_ZERO_PROOF_R2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "exact_target_manifest_sha256": TARGET_MANIFEST_SHA256,
        "source_binding_target_id": TARGET_ID,
        "machine_authority_input_set_id": input_set_id,
        "source_admission_evaluation_contract_id": contract_id,
        "machine_authority_evaluation_evidence_id": evidence_id,
        "registry_valid_tuple_ids": [],
        "rule_valid_tuple_ids": [],
        "machine_valid_admission_tuple_ids": [],
        "machine_valid_admission_tuple_count": 0,
        "machine_conflict_count": 0,
    }, "source_admission_machine_zero_proof_id")


def field_pin_zero_proof(admission, input_set_id="synthetic-field-pin-input-set-r2", contract_id="synthetic-field-pin-evaluation-contract-r2", evidence_id="synthetic-field-pin-evidence-r2"):
    return with_id({
        "schema": "FA1B2DE_CURRENT86_NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF_V2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "exact_target_manifest_sha256": TARGET_MANIFEST_SHA256,
        "source_binding_target_id": admission["source_binding_target_id"],
        "candidate_object_id": admission["candidate_object_id"],
        "canonical_intrinsic_field_semantics_id": admission["canonical_intrinsic_field_semantics_id"],
        "admission_record_id": admission["admission_record_id"],
        "admission_tuple_id": admission_tuple_id(admission),
        "admitted_exact_RFC6901_pointer_utf8_sha256": admission["exact_RFC6901_pointer_utf8_sha256"],
        "machine_field_pin_authority_input_set_id": input_set_id,
        "field_pin_authority_evaluation_contract_id": contract_id,
        "machine_authority_evaluation_evidence_id": evidence_id,
        "exact_target_pointer_authority_set_id": "synthetic-set-target-r2",
        "field_pin_registry_authority_set_id": "synthetic-set-registry-r2",
        "deterministic_corpus_schema_rule_authority_set_id": "synthetic-set-rule-r2",
        "exact_target_valid_tuple_ids": [], "field_pin_registry_valid_tuple_ids": [],
        "deterministic_corpus_schema_rule_valid_tuple_ids": [], "machine_valid_field_pin_tuple_ids": [],
        "valid_exact_target_pointer_authority_count": 0, "valid_field_pin_registry_tuple_count": 0,
        "valid_deterministic_corpus_schema_rule_tuple_count": 0, "machine_valid_field_pin_tuple_count": 0,
        "machine_conflict_count": 0, "machine_admission_tuple_mismatch_count": 0,
    }, "no_machine_field_pin_authority_proof_id")


def readiness_record(target_id=TARGET_ID, state="BLOCKED_FIELD_PIN"):
    return with_id({
        "schema": "FA1B2DE_CURRENT86_SOURCE_AUTH_READINESS_RECORD_R2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "source_binding_target_id": target_id,
        "terminal_state": state,
        "reason": "SYNTHETIC_TEST_ONLY",
    }, "readiness_record_id")


def conservation_record(target_ids, records):
    counts = {}
    for row in records:
        counts[row["terminal_state"]] = counts.get(row["terminal_state"], 0) + 1
    return with_id({
        "schema": "FA1B2DE_CURRENT86_SOURCE_AUTH_TERMINAL_CONSERVATION_RECORD_R2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "exact_target_manifest_sha256": TARGET_MANIFEST_SHA256,
        "ordered_target_ids_sha256": digest(target_ids),
        "terminal_state_counts": counts,
        "source_auth_target_count": len(target_ids),
        "raw_side_target_count": len(target_ids),
        "candidate_side_target_count": 0,
        "exactly_one_state_per_target": True,
    }, "terminal_conservation_record_id")


def commitment(kind="primary_commitment", result_hash="1" * 64, common_id="synthetic-common-input-r2", role=None, context="context-p", run="run-p"):
    role = role or ("PRIMARY" if kind == "primary_commitment" else "VERIFIER")
    return with_id({
        "schema": "FA1B2DE_CURRENT86_SOURCE_AUTH_PRIMARY_COMMITMENT_R2" if kind == "primary_commitment" else "FA1B2DE_CURRENT86_SOURCE_AUTH_VERIFIER_COMMITMENT_R2",
        "role": role,
        "common_input_set_id": common_id,
        "implementation_id": "implementation-" + role.lower(),
        "context_id": context,
        "run_id": run,
        "isolation_audit_id": "synthetic-isolation-audit-r2",
        "ordered_result_vector_sha256": result_hash,
        "terminal_state_count_map": {"BLOCKED_FIELD_PIN": 1},
        "exact_target_id_set_sha256": "2" * 64,
        "private_output_manifest_sha256": "3" * 64,
    }, "commitment_id")


def comparison(primary, verifier, affected=None, frozen=True, equal=False):
    return with_id({
        "schema": "FA1B2DE_CURRENT86_SOURCE_AUTH_COMPARISON_RECORD_R2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "primary_commitment_id": primary["commitment_id"],
        "verifier_commitment_id": verifier["commitment_id"],
        "common_input_set_id": primary["common_input_set_id"],
        "commitments_frozen_before_compare": frozen,
        "comparison_equal": equal,
        "affected_target_ids": affected or [],
    }, "comparison_record_id")
