from __future__ import annotations

from typing import Any, Mapping, Sequence

from .canonical import AUDIT_SCOPE_ID, ContractError, self_excluding_id
from .records import validate_record


def authenticate_commitment(record: Mapping[str, Any], kind: str) -> bool:
    validate_record(kind, record)
    expected_role = "PRIMARY" if kind == "primary_commitment" else "VERIFIER"
    if record["role"] != expected_role:
        raise ContractError("COMMITMENT_ROLE_MISMATCH")
    return True


def compare_commitments(
    primary: Mapping[str, Any],
    verifier: Mapping[str, Any],
    both_frozen: bool,
    affected_target_ids: Sequence[str] | None = None,
    comparison_record: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not both_frozen:
        raise ContractError("COMPARATOR_BEFORE_BOTH_COMMITMENTS_FROZEN")
    authenticate_commitment(primary, "primary_commitment")
    authenticate_commitment(verifier, "verifier_commitment")
    if primary["common_input_set_id"] != verifier["common_input_set_id"]:
        raise ContractError("COMMITMENT_COMMON_INPUT_MISMATCH")
    if primary["implementation_id"] == verifier["implementation_id"] or primary["context_id"] == verifier["context_id"] or primary["run_id"] == verifier["run_id"]:
        raise ContractError("ROLE_IDENTITY_NOT_DISTINCT")
    equal = (
        primary["ordered_result_vector_sha256"] == verifier["ordered_result_vector_sha256"]
        and primary["terminal_state_count_map"] == verifier["terminal_state_count_map"]
        and primary["exact_target_id_set_sha256"] == verifier["exact_target_id_set_sha256"]
    )
    affected = list(affected_target_ids or [])
    if equal and affected:
        raise ContractError("AFFECTED_TARGET_LIST_INCONSISTENT")
    if not equal and not affected:
        raise ContractError("AFFECTED_TARGET_LIST_INCONSISTENT")
    row = {
        "schema": "FA1B2DE_CURRENT86_SOURCE_AUTH_COMPARISON_RECORD_R2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "primary_commitment_id": primary["commitment_id"],
        "verifier_commitment_id": verifier["commitment_id"],
        "common_input_set_id": primary["common_input_set_id"],
        "commitments_frozen_before_compare": True,
        "comparison_equal": equal,
        "affected_target_ids": affected,
    }
    row["comparison_record_id"] = self_excluding_id(row, "comparison_record_id")
    if comparison_record is not None:
        validate_record("comparison_record", comparison_record)
        if comparison_record != row:
            raise ContractError("COMPARISON_RECORD_MISMATCH")
    return row
