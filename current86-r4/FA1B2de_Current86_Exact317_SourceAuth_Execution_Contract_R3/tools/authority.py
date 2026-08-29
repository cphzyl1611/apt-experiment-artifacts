from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from .canonical import ContractError, canonical_json_bytes, sha256_hex
from .records import validate_common_input_manifest, validate_frozen_authority_record, validate_record
from .frozen_authority_evaluator import evaluate_authority_bytes

R3_EVALUATOR_IMPLEMENTATION_ID = "FA1B2DE_FROZEN_MACHINE_AUTHORITY_EVALUATOR_R3"
R3_EVALUATOR_IMPLEMENTATION_SHA256 = sha256_hex((Path(__file__).with_name("frozen_authority_evaluator.py")).read_bytes())
R3_EVALUATOR_CONFIGURATION_ID = "FA1B2DE_MACHINE_AUTHORITY_EVALUATOR_CONFIG_R3"


class MachineAuthorityContext(dict):
    _TOKEN = object()

    def __init__(self, payload: Mapping[str, Any], token: object | None = None):
        if token is not self._TOKEN:
            raise TypeError("AUTHORITY_CONTEXT_MUST_BE_DERIVED")
        super().__init__(payload)

    @classmethod
    def _from_derived(cls, payload: Mapping[str, Any]) -> "MachineAuthorityContext":
        return cls(payload, cls._TOKEN)


def _artifact_bytes(entry: Mapping[str, Any]) -> bytes:
    if not entry.get("content_opened"):
        raise ContractError("AUTHORITY_ARTIFACT_BYTES_UNAVAILABLE")
    # Synthetic fixtures carry their authenticated bytes through this explicit field.
    content = entry.get("authenticated_artifact_bytes")
    if content is None:
        raise ContractError("AUTHORITY_ARTIFACT_BYTES_UNAVAILABLE")
    if not isinstance(content, str):
        raise ContractError("AUTHORITY_ARTIFACT_BYTES_UNAVAILABLE")
    raw = content.encode("utf-8")
    if sha256_hex(raw) != entry["sha256_or_explicit_pinned_identity"]:
        raise ContractError("AUTHORITY_ARTIFACT_IDENTITY_MISMATCH")
    if len(raw) != entry["byte_length"]:
        raise ContractError("AUTHORITY_ARTIFACT_IDENTITY_MISMATCH")
    return raw


def _derive_tuples(raw: bytes, entry: Mapping[str, Any]) -> list[dict[str, Any]]:
    return evaluate_authority_bytes(raw)


def derive_machine_authority_context(
    manifest: Mapping[str, Any],
    authority_records: Sequence[Mapping[str, Any]],
    expansion_records: Sequence[Mapping[str, Any]],
    required_roles: Sequence[str],
    evaluation_contract_id: str,
    evaluation_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if any(isinstance(row, dict) and set(row) <= {"authenticated", "available", "provenance_valid", "evaluation_complete"} for row in authority_records):
        raise ContractError("CALLER_TRUSTED_STATUS_REJECTED")
    validate_common_input_manifest(manifest)
    if len(authority_records) != len(required_roles) or len(set(required_roles)) != len(required_roles):
        raise ContractError("MISSING_AUTHORITY_ROOT_NOT_ZERO")
    by_role = {}
    for record in authority_records:
        validate_frozen_authority_record(record, manifest)
        role = record["authority_role"]
        if role not in required_roles or role in by_role:
            raise ContractError("DUPLICATE_OR_CONFLICTING_AUTHORITY_ROLE")
        by_role[role] = record
    if set(by_role) != set(required_roles):
        raise ContractError("MISSING_AUTHORITY_ROOT_NOT_ZERO")
    by_authority = {}
    for expansion in expansion_records:
        validate_record("machine_authority_expansion_record", expansion)
        if expansion["evaluation_contract_id"] != evaluation_contract_id:
            raise ContractError("EVALUATION_CONTRACT_ID_MISMATCH")
        if not expansion["expansion_complete"]:
            raise ContractError("INCOMPLETE_AUTHORITY_ENUMERATION")
        authority_id = expansion["authority_record_id"]
        if authority_id in by_authority:
            raise ContractError("DUPLICATE_EXPANSION_RECORD")
        by_authority[authority_id] = expansion
    if set(by_authority) != {record["authority_record_id"] for record in authority_records}:
        raise ContractError("MISSING_AUTHORITY_ROOT_NOT_ZERO")
    ordered = sorted(authority_records, key=lambda row: (row["authority_role"].encode("utf-8"), row["logical_artifact_id"].encode("utf-8")))
    if evaluation_evidence is None:
        raise ContractError("AUTHENTICATED_EVALUATION_EVIDENCE_REQUIRED")
    validate_record("machine_authority_evaluation_evidence", evaluation_evidence)
    if evaluation_evidence["evaluation_contract_id"] != evaluation_contract_id:
        raise ContractError("EVALUATION_CONTRACT_ID_MISMATCH")
    if evaluation_evidence["evaluator_implementation_id"] != R3_EVALUATOR_IMPLEMENTATION_ID or evaluation_evidence["evaluator_implementation_sha256"] != R3_EVALUATOR_IMPLEMENTATION_SHA256 or evaluation_evidence["evaluator_configuration_id"] != R3_EVALUATOR_CONFIGURATION_ID:
        raise ContractError("EVALUATOR_IDENTITY_MISMATCH")
    if not evaluation_evidence["complete_input_open_audit"] or len(evaluation_evidence["authority_authentication_results"]) != len(ordered) or any(result != "PASS" for result in evaluation_evidence["authority_authentication_results"]):
        raise ContractError("INCOMPLETE_EVALUATION_EVIDENCE")
    expected_expansion_ids = []
    for record in ordered:
        expansion = by_authority[record["authority_record_id"]]
        entry = next(item for item in manifest["entries"] if item["common_input_entry_id"] == record["common_input_entry_id"])
        raw = _artifact_bytes(entry)
        tuples = _derive_tuples(raw, entry)
        derived_ids = sorted((sha256_hex(canonical_json_bytes(item)) for item in tuples), key=lambda value: value.encode("utf-8"))
        if expansion["common_input_entry_id"] != entry["common_input_entry_id"] or expansion["artifact_content_identity"] != entry["sha256_or_explicit_pinned_identity"] or expansion["evaluator_implementation_id"] != R3_EVALUATOR_IMPLEMENTATION_ID or expansion["evaluator_implementation_sha256"] != R3_EVALUATOR_IMPLEMENTATION_SHA256 or expansion["evaluator_configuration_id"] != R3_EVALUATOR_CONFIGURATION_ID or expansion["evaluation_contract_id"] != evaluation_contract_id or expansion["evaluation_run_input_identity"] != evaluation_evidence["evaluation_run_input_identity"] or expansion["evaluation_evidence_id"] != evaluation_evidence["evaluation_evidence_id"]:
            raise ContractError("EVALUATOR_IDENTITY_MISMATCH")
        if expansion["tuples"] != tuples or expansion["ordered_tuple_ids"] != derived_ids or expansion["ordered_set_commitment_id"] != sha256_hex(canonical_json_bytes(derived_ids)):
            raise ContractError("EXPANSION_NOT_DERIVED_FROM_AUTHENTICATED_ARTIFACT")
        expected_expansion_ids.append(expansion["expansion_record_id"])
    if evaluation_evidence["authority_record_ids"] != [row["authority_record_id"] for row in ordered] or evaluation_evidence["ordered_expansion_record_ids"] != expected_expansion_ids:
        raise ContractError("EVALUATION_EVIDENCE_GRAPH_MISMATCH")
    input_basis = [{
        "logical_artifact_id": row["logical_artifact_id"],
        "authority_role": row["authority_role"],
        "sha256_or_explicit_pinned_identity": row["sha256_or_explicit_pinned_identity"],
        "byte_length": row["byte_length"],
        "schema_or_rule_id": row["schema_or_contract_id"],
        "provenance_id": row["provenance_id"],
        "common_input_membership": row["common_input_entry_id"],
    } for row in ordered]
    input_set_id = sha256_hex(canonical_json_bytes(input_basis))
    ordered_expansions = [by_authority[row["authority_record_id"]] for row in ordered]
    if evaluation_evidence["machine_authority_input_set_id"] != input_set_id:
        raise ContractError("EVALUATION_EVIDENCE_INPUT_SET_MISMATCH")
    if evaluation_evidence["ordered_set_commitments"] != [row["ordered_set_commitment_id"] for row in ordered_expansions]:
        raise ContractError("EVALUATION_EVIDENCE_EXPANSION_MISMATCH")
    if evaluation_evidence["deterministic_expansion_outputs"] != [row["ordered_tuple_ids"] for row in ordered_expansions]:
        raise ContractError("EVALUATION_EVIDENCE_EXPANSION_MISMATCH")
    return MachineAuthorityContext._from_derived({
        "manifest": manifest,
        "authority_records": list(authority_records),
        "expansion_records": list(expansion_records),
        "required_roles": list(required_roles),
        "machine_authority_input_set_id": input_set_id,
        "evaluation_contract_id": evaluation_contract_id,
        "ordered_artifact_records": ordered,
        "ordered_expansion_records": ordered_expansions,
        "valid_tuple_count": sum(len(by_authority[row["authority_record_id"]]["tuples"]) for row in ordered),
        "derived_available": all(row["available"] and row["content_opened"] for row in manifest["entries"]),
        "derived_authenticated": True,
        "derived_provenance_valid": True,
        "derived_evaluation_complete": True,
        "machine_authority_evaluation_evidence": evaluation_evidence,
        "derivation_graph_valid": True,
        "machine_field_pin_authority_input_set_id": input_set_id,
        "field_pin_authority_evaluation_contract_id": evaluation_contract_id,
    })
