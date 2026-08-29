#!/usr/bin/env python3
"""Fail-closed executable rules for the contract; no production execution entry point."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence

AUDIT_SCOPE_ID = "34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306"
TARGET_MANIFEST_SHA256 = "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac"
SCALAR_DOMAIN = b"FA1B2DE_CANONICAL_INTRINSIC_SCALAR_V1"
TERMINAL_STATES = frozenset(
    {
        "SOURCE_AUTHENTICATED",
        "BLOCKED_NORMATIVE_ADMISSION",
        "BLOCKED_SOURCE_OBJECT",
        "BLOCKED_FIELD_PIN",
        "BLOCKED_PROVENANCE",
        "BLOCKED_INDEPENDENT_VERIFICATION",
    }
)
MACHINE_AUTHORITY_ROLES = (
    "EXACT_TARGET_POINTER_AUTHORITY",
    "FIELD_PIN_REGISTRY",
    "DETERMINISTIC_CORPUS_SCHEMA_FIELD_PIN_RULE",
)


class ContractError(ValueError):
    """A stable fail-closed contract error."""


def _fail(code: str, detail: str = "") -> None:
    raise ContractError(code + ((": " + detail) if detail else ""))


def _strict_text(value: str) -> str:
    if not isinstance(value, str):
        _fail("WRONG_TYPE", "expected string")
    try:
        value.encode("utf-8", "strict")
    except UnicodeError as exc:
        _fail("INVALID_UNICODE_SCALAR", str(exc))
    return value


def _parse_int(token: str) -> int:
    if not re.fullmatch(r"0|-?[1-9][0-9]*", token):
        _fail("INVALID_INTEGER_TOKEN", token)
    return int(token)


def _parse_float(token: str) -> Any:
    _fail("FLOAT_FORBIDDEN", token)


def _parse_constant(token: str) -> Any:
    _fail("NONFINITE_FORBIDDEN", token)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _strict_text(key)
        if key in result:
            _fail("DUPLICATE_JSON_KEY", key)
        result[key] = value
    return result


def _validate_strings(value: Any) -> None:
    if isinstance(value, str):
        _strict_text(value)
    elif isinstance(value, list):
        for item in value:
            _validate_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _strict_text(key)
            _validate_strings(item)


def parse_json_strict(data: bytes | str) -> Any:
    """Strict UTF-8 JSON: no BOM, duplicate key, float, nonfinite, or surrogate."""
    if isinstance(data, bytes):
        if data.startswith(b"\xef\xbb\xbf"):
            _fail("UTF8_BOM_FORBIDDEN")
        try:
            text = data.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            _fail("INVALID_UTF8", str(exc))
    elif isinstance(data, str):
        text = data
    else:
        _fail("WRONG_TYPE", "JSON input")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_parse_constant,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        _fail("STRICT_JSON_PARSE_FAILED", str(exc))
    _validate_strings(value)
    return value


def _canonical(value: Any) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if type(value) is int:
        return str(value).encode("ascii")
    if isinstance(value, float):
        _fail("FLOAT_FORBIDDEN")
    if isinstance(value, str):
        _strict_text(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(_canonical(item) for item in value) + b"]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            _fail("NON_STRING_JSON_KEY")
        keys = sorted(value, key=lambda key: _strict_text(key).encode("utf-8"))
        return b"{" + b",".join(_canonical(key) + b":" + _canonical(value[key]) for key in keys) + b"}"
    _fail("UNSUPPORTED_JSON_TYPE", type(value).__name__)


def canonical_json_bytes(value: Any) -> bytes:
    """PROJECT_CANONICAL_JSON_V1, including bytewise UTF-8 object-key order."""
    return _canonical(value)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def self_excluding_id(record: Mapping[str, Any], identity_field: str) -> str:
    return sha256_hex(canonical_json_bytes({k: v for k, v in record.items() if k != identity_field}))


def _decode_pointer_token(token: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(token):
        char = token[index]
        if char != "~":
            out.append(char)
            index += 1
            continue
        if index + 1 >= len(token) or token[index + 1] not in "01":
            _fail("INVALID_POINTER_ESCAPE")
        out.append("~" if token[index + 1] == "0" else "/")
        index += 2
    return "".join(out)


def resolve_rfc6901(document: Any, pointer: str) -> Any:
    """Exact RFC6901 string-form traversal with the inherited restrictions."""
    _strict_text(pointer)
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        _fail("INVALID_POINTER_FORM")
    current = document
    for encoded in pointer[1:].split("/"):
        token = _decode_pointer_token(encoded)
        if isinstance(current, dict):
            if token not in current:
                _fail("POINTER_MISSING")
            current = current[token]
        elif isinstance(current, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", token):
                _fail("INVALID_ARRAY_INDEX")
            index = int(token)
            if index >= len(current):
                _fail("POINTER_MISSING")
            current = current[index]
        else:
            _fail("SCALAR_BEFORE_FINAL_TOKEN")
    return current


def canonical_scalar_bytes(value: Any) -> bytes:
    if value is None:
        type_tag, payload = b"null", b""
    elif value is True:
        type_tag, payload = b"boolean", b"true"
    elif value is False:
        type_tag, payload = b"boolean", b"false"
    elif type(value) is int:
        type_tag, payload = b"integer", str(value).encode("ascii")
    elif isinstance(value, str):
        type_tag, payload = b"string", _strict_text(value).encode("utf-8")
    elif isinstance(value, float):
        _fail("FLOAT_FORBIDDEN")
    elif isinstance(value, (dict, list)):
        _fail("COMPOSITE_TERMINAL_FORBIDDEN")
    else:
        _fail("SCALAR_TYPE_FORBIDDEN")
    return SCALAR_DOMAIN + b"\x00" + type_tag + b"\x00" + str(len(payload)).encode("ascii") + b"\x00" + payload


def authenticated_value_sha256(value: Any) -> str:
    return sha256_hex(canonical_scalar_bytes(value))


def _fields(required: Sequence[str], optional: Sequence[str] = ()) -> dict[str, Any]:
    return {"required": frozenset(required), "optional": frozenset(optional)}


SCHEMAS = {
    "common_input_manifest": _fields(("schema", "audit_scope_id", "exact_target_manifest_sha256", "entries", "common_input_set_id")),
    "authenticated_frozen_authority_record": _fields(("schema", "audit_scope_id", "logical_artifact_role", "exact_locator", "sha256_or_explicit_pinned_identity", "byte_length", "media_type", "schema_or_contract_id", "provenance_id", "authority_role", "governance_freeze_record_id", "authority_record_id")),
    "candidate_source_object_commitment": _fields(("schema", "audit_scope_id", "candidate_corpus_id", "source_artifact_identity", "source_artifact_sha256_or_pinned_identity", "source_side", "bound_raw_key", "bound_candidate_scoring_id", "object_locator", "object_locator_canonical_sha256", "object_extraction_rule_id", "extracted_byte_span_sha256", "canonical_object_representation_sha256", "source_provenance_id", "candidate_object_id")),
    "admission_record": _fields(("schema", "audit_scope_id", "source_binding_target_id", "candidate_object_id", "canonical_intrinsic_field_semantics_id", "exact_RFC6901_pointer_utf8_sha256", "exact_RFC6901_pointer", "admission_authority_type", "admission_authority_artifact_id", "admission_authority_sha256_or_pinned_identity", "admission_authority_provenance_id", "admission_record_id")),
    "source_admission_machine_zero_proof": _fields(("schema", "audit_scope_id", "source_binding_target_id", "machine_authority_input_set_id", "registry_valid_tuple_ids", "rule_valid_tuple_ids", "machine_valid_admission_tuple_count", "evaluation_evidence_id", "source_admission_machine_zero_proof_id")),
    "human_normative_admission_record": _fields(("schema", "audit_scope_id", "source_binding_target_id", "candidate_object_id", "canonical_intrinsic_field_semantics_id", "exact_RFC6901_pointer_utf8_sha256", "exact_RFC6901_pointer", "source_admission_machine_zero_proof_id", "human_native_decision_bytes_sha256", "human_origin_provenance_mode", "governance_event_id", "independent_capture_verification_id", "human_normative_admission_record_id")),
    "no_machine_field_pin_authority_proof_v2": _fields(("schema", "audit_scope_id", "exact_target_manifest_sha256", "source_binding_target_id", "candidate_object_id", "canonical_intrinsic_field_semantics_id", "admission_record_id", "admission_tuple_id", "admitted_exact_RFC6901_pointer_utf8_sha256", "machine_field_pin_authority_input_set_id", "exact_target_pointer_authority_set_id", "field_pin_registry_authority_set_id", "deterministic_corpus_schema_rule_authority_set_id", "field_pin_authority_evaluation_contract_id", "exact_target_valid_tuple_ids", "field_pin_registry_valid_tuple_ids", "deterministic_corpus_schema_rule_valid_tuple_ids", "machine_valid_field_pin_tuple_ids", "valid_exact_target_pointer_authority_count", "valid_field_pin_registry_tuple_count", "valid_deterministic_corpus_schema_rule_tuple_count", "machine_valid_field_pin_tuple_count", "machine_conflict_count", "machine_admission_tuple_mismatch_count", "machine_authority_evaluation_evidence_id", "no_machine_field_pin_authority_proof_id")),
    "human_field_pin_governance_record_v2": _fields(("schema", "audit_scope_id", "source_binding_target_id", "candidate_object_id", "canonical_intrinsic_field_semantics_id", "admission_record_id", "admission_tuple_id", "admitted_exact_RFC6901_pointer_utf8_sha256", "exact_RFC6901_pointer", "exact_RFC6901_pointer_utf8_sha256", "no_machine_field_pin_authority_proof_id", "human_native_decision_bytes_sha256", "human_origin_provenance_mode", "governance_event_id", "independent_capture_verification_id", "human_field_pin_governance_record_id")),
    "field_pin_record": _fields(("schema", "audit_scope_id", "source_binding_target_id", "candidate_object_id", "admission_record_id", "admission_tuple_id", "canonical_intrinsic_field_semantics_id", "exact_RFC6901_pointer", "exact_RFC6901_pointer_utf8_sha256", "parsed_scalar_type", "canonical_scalar_format_id", "authenticated_value_sha256", "provenance_id", "field_pin_id")),
    "primary_commitment": _fields(("schema", "role", "common_input_set_id", "implementation_id", "context_id", "run_id", "isolation_audit_id", "ordered_result_vector_sha256", "terminal_state_count_map", "exact_target_id_set_sha256", "private_output_manifest_sha256", "commitment_id")),
    "verifier_commitment": _fields(("schema", "role", "common_input_set_id", "implementation_id", "context_id", "run_id", "isolation_audit_id", "ordered_result_vector_sha256", "terminal_state_count_map", "exact_target_id_set_sha256", "private_output_manifest_sha256", "commitment_id")),
    "comparison_record": _fields(("schema", "audit_scope_id", "primary_commitment_id", "verifier_commitment_id", "common_input_set_id", "commitments_frozen_before_compare", "comparison_equal", "affected_target_ids", "comparison_record_id")),
    "per_target_readiness_record": _fields(("schema", "audit_scope_id", "source_binding_target_id", "terminal_state", "reason", "readiness_record_id")),
    "terminal_conservation_record": _fields(("schema", "audit_scope_id", "exact_target_manifest_sha256", "ordered_target_ids_sha256", "terminal_state_counts", "source_auth_target_count", "raw_side_target_count", "candidate_side_target_count", "exactly_one_state_per_target", "terminal_conservation_record_id")),
}

IDENTITY_FIELDS = {
    "common_input_manifest": "common_input_set_id",
    "authenticated_frozen_authority_record": "authority_record_id",
    "candidate_source_object_commitment": "candidate_object_id",
    "admission_record": "admission_record_id",
    "source_admission_machine_zero_proof": "source_admission_machine_zero_proof_id",
    "human_normative_admission_record": "human_normative_admission_record_id",
    "no_machine_field_pin_authority_proof_v2": "no_machine_field_pin_authority_proof_id",
    "human_field_pin_governance_record_v2": "human_field_pin_governance_record_id",
    "field_pin_record": "field_pin_id",
    "primary_commitment": "commitment_id",
    "verifier_commitment": "commitment_id",
    "comparison_record": "comparison_record_id",
    "per_target_readiness_record": "readiness_record_id",
    "terminal_conservation_record": "terminal_conservation_record_id",
}

LIST_FIELDS = {
    "entries",
    "registry_valid_tuple_ids",
    "rule_valid_tuple_ids",
    "exact_target_valid_tuple_ids",
    "field_pin_registry_valid_tuple_ids",
    "deterministic_corpus_schema_rule_valid_tuple_ids",
    "machine_valid_field_pin_tuple_ids",
    "affected_target_ids",
}
OBJECT_FIELDS = {"object_locator", "terminal_state_count_map", "terminal_state_counts"}
BOOLEAN_FIELDS = {"commitments_frozen_before_compare", "comparison_equal", "exactly_one_state_per_target"}
INTEGER_FIELDS = {
    "byte_length",
    "machine_valid_admission_tuple_count",
    "valid_exact_target_pointer_authority_count",
    "valid_field_pin_registry_tuple_count",
    "valid_deterministic_corpus_schema_rule_tuple_count",
    "machine_valid_field_pin_tuple_count",
    "machine_conflict_count",
    "machine_admission_tuple_mismatch_count",
    "source_auth_target_count",
    "raw_side_target_count",
    "candidate_side_target_count",
}
NULLABLE_STRING_FIELDS = {"bound_raw_key", "bound_candidate_scoring_id"}


def validate_record(kind: str, record: Mapping[str, Any]) -> bool:
    if kind not in SCHEMAS:
        _fail("UNKNOWN_SCHEMA_KIND", kind)
    if not isinstance(record, dict):
        _fail("WRONG_TYPE", kind)
    allowed = SCHEMAS[kind]["required"] | SCHEMAS[kind]["optional"]
    missing = SCHEMAS[kind]["required"] - record.keys()
    unknown = record.keys() - allowed
    if missing:
        _fail("MISSING_REQUIRED_FIELDS", ",".join(sorted(missing)))
    if unknown:
        _fail("UNKNOWN_FIELDS", ",".join(sorted(unknown)))
    if record.get("audit_scope_id", AUDIT_SCOPE_ID) != AUDIT_SCOPE_ID:
        _fail("WRONG_AUDIT_SCOPE")
    for key, value in record.items():
        if key in LIST_FIELDS:
            if not isinstance(value, list):
                _fail("WRONG_TYPE", key)
            if key != "entries" and any(not isinstance(item, str) for item in value):
                _fail("WRONG_TYPE", key + "[]")
        elif key in OBJECT_FIELDS:
            if not isinstance(value, dict):
                _fail("WRONG_TYPE", key)
        elif key in BOOLEAN_FIELDS:
            if type(value) is not bool:
                _fail("WRONG_TYPE", key)
        elif key in INTEGER_FIELDS or key.endswith("_count"):
            if type(value) is not int or value < 0:
                _fail("WRONG_TYPE", key)
        elif key in NULLABLE_STRING_FIELDS:
            if value is not None and not isinstance(value, str):
                _fail("WRONG_TYPE", key)
        elif not isinstance(value, str):
            _fail("WRONG_TYPE", key)
        if key.endswith("_sha256") and isinstance(value, str) and not re.fullmatch(r"[0-9a-f]{64}", value):
            _fail("INVALID_SHA256", key)
    identity_field = IDENTITY_FIELDS[kind]
    if record[identity_field] != self_excluding_id(record, identity_field):
        _fail("STALE_OR_INVALID_IDENTITY", identity_field)
    return True


def _tuple_basis(record: Mapping[str, Any]) -> dict[str, Any]:
    required = (
        "source_binding_target_id",
        "candidate_object_id",
        "canonical_intrinsic_field_semantics_id",
        "exact_RFC6901_pointer",
    )
    if any(key not in record for key in required):
        _fail("MISSING_ADMISSION_TUPLE_COMPONENT")
    return {key: record[key] for key in sorted(required)}


def tuple_id(record: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(_tuple_basis(record)))


def admission_context(record: Mapping[str, Any]) -> dict[str, Any]:
    validate_record("admission_record", record)
    pointer = _strict_text(record["exact_RFC6901_pointer"])
    pointer_hash = sha256_hex(pointer.encode("utf-8"))
    if record["exact_RFC6901_pointer_utf8_sha256"] != pointer_hash:
        _fail("POINTER_HASH_MISMATCH")
    return {
        **_tuple_basis(record),
        "admission_record_id": record["admission_record_id"],
        "admission_tuple_id": tuple_id(record),
        "admitted_exact_RFC6901_pointer_utf8_sha256": pointer_hash,
    }


def machine_authority_input_set_id(roots: Sequence[Mapping[str, Any]]) -> str:
    basis = [
        {
            "authority_role": root.get("authority_role"),
            "authority_set_id": root.get("authority_set_id"),
            "available": root.get("available"),
            "authenticated": root.get("authenticated"),
            "provenance_valid": root.get("provenance_valid"),
            "evaluation_complete": root.get("evaluation_complete"),
            "tuples": root.get("tuples"),
        }
        for root in sorted(roots, key=lambda row: str(row.get("authority_role")))
    ]
    return sha256_hex(canonical_json_bytes(basis))


def _enumerate_machine(roots: Sequence[Mapping[str, Any]]) -> tuple[list[tuple[str, Mapping[str, Any]]], dict[str, Mapping[str, Any]]]:
    by_role: dict[str, Mapping[str, Any]] = {}
    for root in roots:
        role = root.get("authority_role")
        if role not in MACHINE_AUTHORITY_ROLES or role in by_role:
            _fail("DUPLICATE_OR_CONFLICTING_MACHINE_AUTHORITY")
        by_role[role] = root
    if set(by_role) != set(MACHINE_AUTHORITY_ROLES):
        _fail("MISSING_AUTHORITY_ROOT_NOT_ZERO")
    emitted: list[tuple[str, Mapping[str, Any]]] = []
    for role in MACHINE_AUTHORITY_ROLES:
        root = by_role[role]
        if not root.get("available"):
            _fail("MISSING_AUTHORITY_ROOT_NOT_ZERO", role)
        if not root.get("authenticated"):
            _fail("UNAUTHENTICATED_AUTHORITY_ROOT", role)
        if not root.get("provenance_valid"):
            _fail("INVALID_AUTHORITY_PROVENANCE", role)
        if not root.get("evaluation_complete"):
            _fail("INCOMPLETE_AUTHORITY_ENUMERATION", role)
        tuples = root.get("tuples")
        if not isinstance(tuples, list):
            _fail("WRONG_TYPE", role + ".tuples")
        seen: set[str] = set()
        for item in tuples:
            identity = tuple_id(item)
            if identity in seen:
                _fail("DUPLICATE_OR_CONFLICTING_MACHINE_AUTHORITY")
            seen.add(identity)
            emitted.append((role, item))
    return emitted, by_role


def _cross_bound(item: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    basis = _tuple_basis(item)
    return (
        basis["source_binding_target_id"] == context["source_binding_target_id"]
        and basis["candidate_object_id"] == context["candidate_object_id"]
        and basis["canonical_intrinsic_field_semantics_id"] == context["canonical_intrinsic_field_semantics_id"]
        and _strict_text(basis["exact_RFC6901_pointer"]).encode("utf-8")
        == _strict_text(context["exact_RFC6901_pointer"]).encode("utf-8")
        and tuple_id(item) == context["admission_tuple_id"]
    )


def validate_no_machine_field_pin_proof_v2(
    proof: Mapping[str, Any], context: Mapping[str, Any], roots: Sequence[Mapping[str, Any]]
) -> bool:
    validate_record("no_machine_field_pin_authority_proof_v2", proof)
    emitted, by_role = _enumerate_machine(roots)
    if emitted:
        _fail("NO_MACHINE_PROOF_NONZERO")
    expected = {
        "audit_scope_id": AUDIT_SCOPE_ID,
        "exact_target_manifest_sha256": TARGET_MANIFEST_SHA256,
        "source_binding_target_id": context["source_binding_target_id"],
        "candidate_object_id": context["candidate_object_id"],
        "canonical_intrinsic_field_semantics_id": context["canonical_intrinsic_field_semantics_id"],
        "admission_record_id": context["admission_record_id"],
        "admission_tuple_id": context["admission_tuple_id"],
        "admitted_exact_RFC6901_pointer_utf8_sha256": context["admitted_exact_RFC6901_pointer_utf8_sha256"],
        "machine_field_pin_authority_input_set_id": machine_authority_input_set_id(roots),
        "exact_target_pointer_authority_set_id": by_role[MACHINE_AUTHORITY_ROLES[0]]["authority_set_id"],
        "field_pin_registry_authority_set_id": by_role[MACHINE_AUTHORITY_ROLES[1]]["authority_set_id"],
        "deterministic_corpus_schema_rule_authority_set_id": by_role[MACHINE_AUTHORITY_ROLES[2]]["authority_set_id"],
    }
    if any(proof.get(key) != value for key, value in expected.items()):
        _fail("STALE_NO_MACHINE_PROOF")
    list_fields = (
        "exact_target_valid_tuple_ids",
        "field_pin_registry_valid_tuple_ids",
        "deterministic_corpus_schema_rule_valid_tuple_ids",
        "machine_valid_field_pin_tuple_ids",
    )
    count_fields = (
        "valid_exact_target_pointer_authority_count",
        "valid_field_pin_registry_tuple_count",
        "valid_deterministic_corpus_schema_rule_tuple_count",
        "machine_valid_field_pin_tuple_count",
        "machine_conflict_count",
        "machine_admission_tuple_mismatch_count",
    )
    if any(proof[field] != [] for field in list_fields) or any(proof[field] != 0 for field in count_fields):
        _fail("NO_MACHINE_PROOF_NONZERO")
    return True


def validate_human_field_pin_record_v2(
    record: Mapping[str, Any], context: Mapping[str, Any], proof: Mapping[str, Any]
) -> bool:
    validate_record("human_field_pin_governance_record_v2", record)
    expected = {
        "audit_scope_id": AUDIT_SCOPE_ID,
        "source_binding_target_id": context["source_binding_target_id"],
        "candidate_object_id": context["candidate_object_id"],
        "canonical_intrinsic_field_semantics_id": context["canonical_intrinsic_field_semantics_id"],
        "admission_record_id": context["admission_record_id"],
        "admission_tuple_id": context["admission_tuple_id"],
        "admitted_exact_RFC6901_pointer_utf8_sha256": context["admitted_exact_RFC6901_pointer_utf8_sha256"],
        "no_machine_field_pin_authority_proof_id": proof["no_machine_field_pin_authority_proof_id"],
    }
    if any(record.get(key) != value for key, value in expected.items()):
        _fail("ADMISSION_FIELD_PIN_TUPLE_MISMATCH")
    pointer = _strict_text(record["exact_RFC6901_pointer"])
    if pointer.encode("utf-8") != _strict_text(context["exact_RFC6901_pointer"]).encode("utf-8"):
        _fail("ADMISSION_FIELD_PIN_TUPLE_MISMATCH")
    pointer_hash = sha256_hex(pointer.encode("utf-8"))
    if record["exact_RFC6901_pointer_utf8_sha256"] != pointer_hash or pointer_hash != context["admitted_exact_RFC6901_pointer_utf8_sha256"]:
        _fail("ADMISSION_FIELD_PIN_TUPLE_MISMATCH")
    if tuple_id(record) != context["admission_tuple_id"]:
        _fail("ADMISSION_FIELD_PIN_TUPLE_MISMATCH")
    for field in ("human_native_decision_bytes_sha256", "human_origin_provenance_mode", "governance_event_id", "independent_capture_verification_id"):
        if not record.get(field):
            _fail("BAD_HUMAN_PROVENANCE_OR_CAPTURE", field)
    return True


def _blocked(reason: str) -> dict[str, Any]:
    return {
        "state": "BLOCKED_FIELD_PIN",
        "reason": reason,
        "human_fallback_allowed": False,
        "alternate_pointer_allowed": False,
    }


def evaluate_field_pin_authority(
    admission: Mapping[str, Any],
    roots: Sequence[Mapping[str, Any]],
    proof: Mapping[str, Any] | None = None,
    human_records: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    context = admission_context(admission)
    try:
        emitted, _ = _enumerate_machine(roots)
    except ContractError as exc:
        code = str(exc).split(":", 1)[0]
        return _blocked(code)
    for _, item in emitted:
        if not _cross_bound(item, context):
            return _blocked("ADMISSION_FIELD_PIN_TUPLE_MISMATCH")
    unique = {tuple_id(item) for _, item in emitted}
    if len(emitted) != len(unique) and len(emitted) > 1:
        # Identical confirmation across distinct roots is allowed; duplicate rows in one root
        # were already rejected by _enumerate_machine.
        pass
    if len(unique) > 1:
        return _blocked("DUPLICATE_OR_CONFLICTING_MACHINE_AUTHORITY")
    if len(unique) == 1:
        return {
            "state": "FIELD_PIN_AUTHORITY_ELIGIBLE_SYNTHETIC",
            "authority_path": "MACHINE_CONFIRMATION",
            "selected_field_pin_tuple_id": context["admission_tuple_id"],
            "human_fallback_allowed": False,
            "alternate_pointer_allowed": False,
        }
    if proof is None:
        return _blocked("NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF_REQUIRED")
    try:
        validate_no_machine_field_pin_proof_v2(proof, context, roots)
    except ContractError as exc:
        return _blocked(str(exc).split(":", 1)[0])
    if len(human_records) != 1:
        return _blocked("HUMAN_RECORD_COUNT_NOT_EXACTLY_ONE")
    try:
        validate_human_field_pin_record_v2(human_records[0], context, proof)
    except ContractError as exc:
        code = str(exc).split(":", 1)[0]
        if code in {"STALE_OR_INVALID_IDENTITY", "WRONG_AUDIT_SCOPE"}:
            code = "ADMISSION_FIELD_PIN_TUPLE_MISMATCH"
        return _blocked(code)
    return {
        "state": "FIELD_PIN_AUTHORITY_ELIGIBLE_SYNTHETIC",
        "authority_path": "HUMAN_RATIFICATION",
        "selected_field_pin_tuple_id": context["admission_tuple_id"],
        "human_fallback_allowed": True,
        "alternate_pointer_allowed": False,
    }


def validate_isolation_contract(contract: Mapping[str, Any]) -> bool:
    required = {
        "COMMON_INPUT_SET",
        "PRIMARY_PRIVATE_OUTPUT_SET",
        "VERIFIER_READABLE_SET",
        "PRIMARY_IMPLEMENTATION_ID",
        "VERIFIER_IMPLEMENTATION_ID",
        "PRIMARY_CONTEXT_ID",
        "VERIFIER_CONTEXT_ID",
        "PRIMARY_RUN_ID",
        "VERIFIER_RUN_ID",
    }
    if required - contract.keys():
        _fail("MISSING_ISOLATION_FIELDS")
    if set(contract["VERIFIER_READABLE_SET"]) & set(contract["PRIMARY_PRIVATE_OUTPUT_SET"]):
        _fail("VERIFIER_PRIMARY_SET_INTERSECTION")
    pairs = (
        ("PRIMARY_IMPLEMENTATION_ID", "VERIFIER_IMPLEMENTATION_ID"),
        ("PRIMARY_CONTEXT_ID", "VERIFIER_CONTEXT_ID"),
        ("PRIMARY_RUN_ID", "VERIFIER_RUN_ID"),
    )
    if any(contract[left] == contract[right] for left, right in pairs):
        _fail("ROLE_IDENTITY_NOT_DISTINCT")
    if not set(contract["COMMON_INPUT_SET"]).issubset(set(contract["VERIFIER_READABLE_SET"])):
        _fail("VERIFIER_COMMON_INPUT_INCOMPLETE")
    return True


def validate_conservation(target_ids: Sequence[str], records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    if len(set(target_ids)) != len(target_ids):
        _fail("DUPLICATE_TARGET_AUTHORITY")
    seen: dict[str, int] = {target_id: 0 for target_id in target_ids}
    counts = {state: 0 for state in TERMINAL_STATES}
    for record in records:
        target = record.get("source_binding_target_id")
        state = record.get("terminal_state")
        if target not in seen or state not in TERMINAL_STATES:
            _fail("UNKNOWN_TARGET_OR_TERMINAL_STATE")
        seen[target] += 1
        counts[state] += 1
    if any(count != 1 for count in seen.values()):
        _fail("TARGET_STATE_NOT_EXACTLY_ONCE")
    if sum(counts.values()) != len(target_ids):
        _fail("TERMINAL_CONSERVATION_FAILED")
    return counts


def validate_synthetic_fixture_manifest(manifest: Mapping[str, Any]) -> bool:
    if manifest.get("fixture_authority") != "NON_AUTHORITATIVE_SYNTHETIC_ONLY":
        _fail("FIXTURE_AUTHORITY_MARKER_MISSING")
    if manifest.get("real_source_auth_targets_executed") != 0:
        _fail("REAL_TARGET_EXECUTION_FORBIDDEN")
    synthetic = set(manifest.get("synthetic_target_ids", []))
    production = set(manifest.get("production_target_ids", []))
    if synthetic & production:
        _fail("SYNTHETIC_PRODUCTION_ID_INTERSECTION")
    if not synthetic or any(not value.startswith("synthetic-non-production-") for value in synthetic):
        _fail("INVALID_SYNTHETIC_TARGET_ID")
    return True
