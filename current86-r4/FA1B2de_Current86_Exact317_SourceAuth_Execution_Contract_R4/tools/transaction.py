from __future__ import annotations

from typing import Any, Mapping, Sequence

from .canonical import AUDIT_SCOPE_ID, ContractError, canonical_json_bytes, self_excluding_id, sha256_hex
from .records import validate_record
from .target_universe import TARGET_MANIFEST_SHA256, frozen_exact317_target_ids, frozen_exact317_target_set_commitment


def authenticate_commitment(record: Mapping[str, Any], kind: str) -> bool:
    validate_record(kind, record)
    expected_role = "PRIMARY" if kind == "primary_commitment" else "VERIFIER"
    if record["role"] != expected_role:
        raise ContractError("COMMITMENT_ROLE_MISMATCH")
    return True


def _authenticated_target_universe(
    frozen_target_ids: Sequence[str] | None,
    frozen_target_manifest_sha256: str | None,
    frozen_target_set_commitment: str | None,
) -> list[str]:
    expected = list(frozen_exact317_target_ids())
    if frozen_target_ids is not None and list(frozen_target_ids) != expected:
        raise ContractError("FROZEN_EXACT317_TARGET_UNIVERSE_MISMATCH")
    if frozen_target_manifest_sha256 is not None and frozen_target_manifest_sha256 != TARGET_MANIFEST_SHA256:
        raise ContractError("FROZEN_EXACT317_TARGET_MANIFEST_MISMATCH")
    if frozen_target_set_commitment is not None and frozen_target_set_commitment != frozen_exact317_target_set_commitment():
        raise ContractError("FROZEN_EXACT317_TARGET_SET_COMMITMENT_MISMATCH")
    return expected


def compare_commitments(
    primary: Mapping[str, Any],
    verifier: Mapping[str, Any],
    both_frozen: bool,
    affected_target_ids: Sequence[str] | None = None,
    comparison_record: Mapping[str, Any] | None = None,
    *,
    frozen_target_ids: Sequence[str] | None = None,
    frozen_target_manifest_sha256: str | None = None,
    frozen_target_set_commitment: str | None = None,
) -> dict[str, Any]:
    if not both_frozen:
        raise ContractError("COMPARATOR_BEFORE_BOTH_COMMITMENTS_FROZEN")
    authenticate_commitment(primary, "primary_commitment")
    authenticate_commitment(verifier, "verifier_commitment")
    if primary["common_input_set_id"] != verifier["common_input_set_id"]:
        raise ContractError("COMMITMENT_COMMON_INPUT_MISMATCH")
    if primary["implementation_id"] == verifier["implementation_id"] or primary["context_id"] == verifier["context_id"] or primary["run_id"] == verifier["run_id"]:
        raise ContractError("ROLE_IDENTITY_NOT_DISTINCT")
    expected_targets = _authenticated_target_universe(frozen_target_ids, frozen_target_manifest_sha256, frozen_target_set_commitment)
    primary_vector = primary["ordered_target_result_vector"]
    verifier_vector = verifier["ordered_target_result_vector"]
    if not isinstance(primary_vector, list) or not isinstance(verifier_vector, list):
        raise ContractError("RESULT_VECTOR_INVALID")
    if any(not isinstance(row, dict) or set(row) != {"target_id", "result_commitment"} for row in primary_vector + verifier_vector):
        raise ContractError("TARGET_UNIVERSE_MISMATCH")
    primary_targets = [row["target_id"] for row in primary_vector]
    verifier_targets = [row["target_id"] for row in verifier_vector]
    if primary_targets != expected_targets or verifier_targets != expected_targets or primary_targets != verifier_targets:
        raise ContractError("FROZEN_EXACT317_TARGET_UNIVERSE_MISMATCH")
    if len(primary_targets) != len(set(primary_targets)) or len(verifier_targets) != len(set(verifier_targets)):
        raise ContractError("TARGET_UNIVERSE_MISMATCH")
    expected_target_set_hash = sha256_hex(canonical_json_bytes(expected_targets))
    for record, vector in ((primary, primary_vector), (verifier, verifier_vector)):
        if record["ordered_result_vector_sha256"] != sha256_hex(canonical_json_bytes(vector)) or record["exact_target_id_set_sha256"] != expected_target_set_hash:
            raise ContractError("RESULT_VECTOR_COMMITMENT_MISMATCH")
    derived_affected = [
        target for target, p_row, v_row in zip(primary_targets, primary_vector, verifier_vector)
        if p_row["result_commitment"] != v_row["result_commitment"]
    ]
    equal = (
        primary["ordered_result_vector_sha256"] == verifier["ordered_result_vector_sha256"]
        and primary["terminal_state_count_map"] == verifier["terminal_state_count_map"]
        and primary["exact_target_id_set_sha256"] == verifier["exact_target_id_set_sha256"]
    )
    if affected_target_ids is not None and list(affected_target_ids) != derived_affected:
        raise ContractError("AFFECTED_TARGET_LIST_INCONSISTENT")
    if equal != (not derived_affected):
        raise ContractError("AFFECTED_TARGET_LIST_INCONSISTENT")
    row = {
        "schema": "FA1B2DE_CURRENT86_SOURCE_AUTH_COMPARISON_RECORD_R3",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "primary_commitment_id": primary["commitment_id"],
        "verifier_commitment_id": verifier["commitment_id"],
        "common_input_set_id": primary["common_input_set_id"],
        "commitments_frozen_before_compare": True,
        "comparison_equal": equal,
        "affected_target_ids": derived_affected,
    }
    row["comparison_record_id"] = self_excluding_id(row, "comparison_record_id")
    if comparison_record is not None:
        validate_record("comparison_record", comparison_record)
        if comparison_record != row:
            raise ContractError("COMPARISON_RECORD_MISMATCH")
    return row
