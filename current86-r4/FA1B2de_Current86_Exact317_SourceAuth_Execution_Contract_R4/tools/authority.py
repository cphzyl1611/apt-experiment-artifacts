from __future__ import annotations

import copy
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, Sequence

from .canonical import ContractError, admission_tuple_id, canonical_json_bytes, pointer_sha256, sha256_hex
from .records import validate_common_input_manifest, validate_frozen_authority_record, validate_record
from .frozen_authority_evaluator import R4_EVALUATOR_CONFIGURATION_ID as EVALUATOR_CONFIGURATION_ID, evaluate_authority_bytes


R4_EVALUATOR_IMPLEMENTATION_ID = "FA1B2DE_FROZEN_MACHINE_AUTHORITY_EVALUATOR_R4"
R4_EVALUATOR_IMPLEMENTATION_SHA256 = sha256_hex((Path(__file__).with_name("frozen_authority_evaluator.py")).read_bytes())
R4_EVALUATOR_CONFIGURATION_ID = EVALUATOR_CONFIGURATION_ID


_CONTEXT_CREATION_TOKEN = object()
_CONTEXT_SEAL = object()


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return copy.deepcopy(value)


class MachineAuthorityContext(Mapping[str, Any]):
    """Read-only sealed result carrying the graph that produced it."""

    __slots__ = ("_payload", "_graph_inputs", "_seal")

    def __init__(self, payload: Mapping[str, Any], token: object | None = None):
        raise TypeError("AUTHORITY_CONTEXT_MUST_BE_DERIVED")

    def __setattr__(self, name: str, value: Any) -> None:
        if hasattr(self, name):
            raise TypeError("AUTHORITY_CONTEXT_IMMUTABLE")
        object.__setattr__(self, name, value)

    @classmethod
    def _from_derived(cls, payload: Mapping[str, Any]) -> "MachineAuthorityContext":
        raise ContractError("DIRECT_DERIVED_CONTEXT_FORBIDDEN")

    @classmethod
    def _seal_from_derived(
        cls,
        payload: Mapping[str, Any],
        graph_inputs: Mapping[str, Any],
        token: object,
    ) -> "MachineAuthorityContext":
        if token is not _CONTEXT_CREATION_TOKEN:
            raise ContractError("DIRECT_DERIVED_CONTEXT_FORBIDDEN")
        result = object.__new__(cls)
        object.__setattr__(result, "_payload", _freeze(copy.deepcopy(dict(payload))))
        object.__setattr__(result, "_graph_inputs", _freeze(copy.deepcopy(dict(graph_inputs))))
        object.__setattr__(result, "_seal", _CONTEXT_SEAL)
        return result

    def __getitem__(self, key: str) -> Any:
        return self._payload[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)

    def graph_inputs(self) -> dict[str, Any]:
        if self._seal is not _CONTEXT_SEAL:
            raise ContractError("CURRENT_DERIVATION_REQUIRED")
        return _thaw(self._graph_inputs)

    @staticmethod
    def extract_graph_inputs(context: Mapping[str, Any]) -> dict[str, Any]:
        """Extract only a sealed graph; authenticity is established by revalidation."""
        if not isinstance(context, Mapping) or getattr(context, "_seal", None) is not _CONTEXT_SEAL:
            raise ContractError("CURRENT_DERIVATION_REQUIRED")
        graph = getattr(context, "_graph_inputs", None)
        if not isinstance(graph, Mapping):
            raise ContractError("CURRENT_DERIVATION_REQUIRED")
        return _thaw(graph)


def _artifact_bytes(entry: Mapping[str, Any]) -> bytes:
    if not entry.get("content_opened"):
        raise ContractError("AUTHORITY_ARTIFACT_BYTES_UNAVAILABLE")
    content = entry.get("authenticated_artifact_bytes")
    if not isinstance(content, str):
        raise ContractError("AUTHORITY_ARTIFACT_BYTES_UNAVAILABLE")
    try:
        raw = content.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ContractError("INVALID_UTF8") from exc
    if sha256_hex(raw) != entry["sha256_or_explicit_pinned_identity"] or len(raw) != entry["byte_length"]:
        raise ContractError("AUTHORITY_ARTIFACT_IDENTITY_MISMATCH")
    return raw


def _derive_tuples(raw: bytes, entry: Mapping[str, Any]) -> list[dict[str, Any]]:
    return evaluate_authority_bytes(
        raw,
        authority_role=entry["authority_role"],
        schema_or_contract_id=entry["schema_or_contract_id"],
        evaluator_configuration_id=R4_EVALUATOR_CONFIGURATION_ID,
    )


def derive_machine_authority_context(
    manifest: Mapping[str, Any],
    authority_records: Sequence[Mapping[str, Any]],
    expansion_records: Sequence[Mapping[str, Any]],
    required_roles: Sequence[str],
    evaluation_contract_id: str,
    evaluation_evidence: Mapping[str, Any] | None = None,
    admission_record: Mapping[str, Any] | None = None,
) -> MachineAuthorityContext:
    if any(isinstance(row, dict) and set(row) <= {"authenticated", "available", "provenance_valid", "evaluation_complete"} for row in authority_records):
        raise ContractError("CALLER_TRUSTED_STATUS_REJECTED")
    validate_common_input_manifest(manifest)
    if len(authority_records) != len(required_roles) or len(set(required_roles)) != len(required_roles):
        raise ContractError("MISSING_AUTHORITY_ROOT_NOT_ZERO")
    by_role: dict[str, Mapping[str, Any]] = {}
    for record in authority_records:
        validate_frozen_authority_record(record, manifest)
        role = record["authority_role"]
        if role not in required_roles or role in by_role:
            raise ContractError("DUPLICATE_OR_CONFLICTING_AUTHORITY_ROLE")
        by_role[role] = record
    if set(by_role) != set(required_roles):
        raise ContractError("MISSING_AUTHORITY_ROOT_NOT_ZERO")
    by_authority: dict[str, Mapping[str, Any]] = {}
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
    if (
        evaluation_evidence["evaluator_implementation_id"] != R4_EVALUATOR_IMPLEMENTATION_ID
        or evaluation_evidence["evaluator_implementation_sha256"] != R4_EVALUATOR_IMPLEMENTATION_SHA256
        or evaluation_evidence["evaluator_configuration_id"] != R4_EVALUATOR_CONFIGURATION_ID
    ):
        raise ContractError("EVALUATOR_IDENTITY_MISMATCH")
    if not evaluation_evidence["complete_input_open_audit"] or len(evaluation_evidence["authority_authentication_results"]) != len(ordered) or any(result != "PASS" for result in evaluation_evidence["authority_authentication_results"]):
        raise ContractError("INCOMPLETE_EVALUATION_EVIDENCE")
    expected_expansion_ids: list[str] = []
    for record in ordered:
        expansion = by_authority[record["authority_record_id"]]
        entry = next(item for item in manifest["entries"] if item["common_input_entry_id"] == record["common_input_entry_id"])
        raw = _artifact_bytes(entry)
        tuples = _derive_tuples(raw, entry)
        derived_ids = sorted((sha256_hex(canonical_json_bytes(item)) for item in tuples), key=lambda value: value.encode("utf-8"))
        if (
            expansion["common_input_entry_id"] != entry["common_input_entry_id"]
            or expansion["artifact_content_identity"] != entry["sha256_or_explicit_pinned_identity"]
            or expansion["evaluator_implementation_id"] != R4_EVALUATOR_IMPLEMENTATION_ID
            or expansion["evaluator_implementation_sha256"] != R4_EVALUATOR_IMPLEMENTATION_SHA256
            or expansion["evaluator_configuration_id"] != R4_EVALUATOR_CONFIGURATION_ID
            or expansion["evaluation_contract_id"] != evaluation_contract_id
            or expansion["evaluation_run_input_identity"] != evaluation_evidence["evaluation_run_input_identity"]
            or expansion["evaluation_evidence_id"] != evaluation_evidence["evaluation_evidence_id"]
        ):
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
    if evaluation_evidence["ordered_set_commitments"] != [row["ordered_set_commitment_id"] for row in ordered_expansions] or evaluation_evidence["deterministic_expansion_outputs"] != [row["ordered_tuple_ids"] for row in ordered_expansions]:
        raise ContractError("EVALUATION_EVIDENCE_EXPANSION_MISMATCH")
    payload: dict[str, Any] = {
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
    }
    graph_inputs: dict[str, Any] = {
        "manifest": manifest,
        "authority_records": list(authority_records),
        "expansion_records": list(expansion_records),
        "required_roles": list(required_roles),
        "evaluation_contract_id": evaluation_contract_id,
        "evaluation_evidence": evaluation_evidence,
        "admission_record": admission_record,
    }
    if admission_record is not None:
        validate_record("admission_record", admission_record)
        payload.update({
            "admission_record_id": admission_record["admission_record_id"],
            "admission_tuple_id": admission_tuple_id(admission_record),
            "admitted_exact_RFC6901_pointer_utf8_sha256": pointer_sha256(admission_record["exact_RFC6901_pointer"]),
        })
    return MachineAuthorityContext._seal_from_derived(payload, graph_inputs, _CONTEXT_CREATION_TOKEN)
