from __future__ import annotations

from typing import Any, Mapping, Sequence

from .canonical import ContractError, canonical_json_bytes, sha256_hex
from .records import validate_common_input_manifest, validate_frozen_authority_record, validate_record


def derive_machine_authority_context(
    manifest: Mapping[str, Any],
    authority_records: Sequence[Mapping[str, Any]],
    expansion_records: Sequence[Mapping[str, Any]],
    required_roles: Sequence[str],
    evaluation_contract_id: str,
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
    for record in ordered:
        expansion = by_authority[record["authority_record_id"]]
        derived_ids = sorted((sha256_hex(canonical_json_bytes(item)) for item in expansion["tuples"]), key=lambda value: value.encode("utf-8"))
        if expansion["ordered_tuple_ids"] != derived_ids or expansion["ordered_set_commitment_id"] != sha256_hex(canonical_json_bytes(derived_ids)):
            raise ContractError("EXPANSION_IDENTITY_MISMATCH")
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
    return {
        "machine_authority_input_set_id": input_set_id,
        "evaluation_contract_id": evaluation_contract_id,
        "ordered_artifact_records": ordered,
        "ordered_expansion_records": [by_authority[row["authority_record_id"]] for row in ordered],
        "valid_tuple_count": sum(len(by_authority[row["authority_record_id"]]["tuples"]) for row in ordered),
        "derived_available": all(row["available"] and row["content_opened"] for row in manifest["entries"]),
        "derived_authenticated": True,
        "derived_provenance_valid": True,
        "derived_evaluation_complete": True,
    }
