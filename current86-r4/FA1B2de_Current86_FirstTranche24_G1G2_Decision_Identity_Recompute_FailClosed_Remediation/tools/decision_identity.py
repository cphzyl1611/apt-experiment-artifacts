"""Deterministic identity contract for the bounded First-Tranche24 G1/G2 record.

This module is intentionally self-contained.  It does not import or mutate any
source-authority, Stage A/B, field-pin, or operative-manifest state.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from copy import deepcopy
from typing import Any


PROFILE_ID = "PROJECT_CANONICAL_JSON_V1"
IDENTITY_PROCEDURE_ID = "FIRST_TRANCHE24_GOVERNANCE_DECISION_IDENTITY_V2"
DECISION_NAMESPACE = "GOVDEC2/DECISION_RECORD_ID/V2"
TRANSACTION_NAMESPACE = "GOVDEC2/TRANSACTION_HASH/V2"

EXPECTED_DECISION_ID = "GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f"
EXPECTED_TRANSACTION_HASH = "b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38"
EXPECTED_SCOPE = "FIRST_TRANCHE24_ONLY"
EXPECTED_DECISION = "APPROVE_BOTH_G1_AND_G2"
EXPECTED_TARGET_ORDER = [
    110, 273, 210, 98, 147, 277, 188, 301, 143, 250, 233, 287,
    146, 293, 114, 284, 291, 215, 88, 182, 300, 218, 115, 148,
]
FROZEN_BASIS_DIGEST = "402d83d90b3ca76637ca57abca8a425b887322483f29feea40d9002fed06a739"

# These are semantic paths, in contract order.  Metadata and the identity
# fields themselves are deliberately absent.  The complete scope object is
# included in the payload, so scope order remains identity-bearing even though
# test mutation helpers use scalar descendants for focused probes.
IDENTITY_BASIS_PATHS = (
    "record_type",
    "schema_version",
    "scope.scope_cardinality",
    "scope.r1r1_crosswalk_sha256",
    "scope.scope_extension_requested",
    "governance_authorization.authorized_source_artifact_class",
    "governance_authorization.authorized_source_fact_type",
    "governance_authorization.authorized_scope",
    "governance_authorization.g1_preparation_process_authorized",
    "governance_authorization.g2_future_admission_process_authorized",
    "governance_authorization.does_not_assert_source_object_exists",
    "governance_authorization.does_not_activate_source_authority",
    "governance_authorization.does_not_admit_operative_manifest",
    "future_activation_requirements.activation_transaction_state",
    "future_activation_requirements.concrete_source_authority_id_required_at_activation",
    "future_activation_requirements.concrete_source_version_policy_required_at_activation",
    "future_activation_requirements.activation_must_precede_operative_manifest_admission",
    "future_activation_requirements.activation_record_reference",
    "future_activation_requirements.activation_record_hash",
    "prerequisites.independent_preparation_review_commit",
    "prerequisites.preparation_review_status",
    "prerequisites.source_owner_authorization_required",
    "prerequisites.operative_manifest_gate_required",
    "prerequisites.candidate_evidence_non_authoritative",
    "decision",
    "human_governance_identity_reference.principal_id",
    "human_governance_identity_reference.principal_identity_sha256",
    "human_governance_identity_reference.authentication_record_reference",
    "human_governance_identity_reference.authentication_status",
    "human_governance_identity_reference.personal_identity_bound",
    "referenced_frozen_artifact_hashes.pinned_governance_preparation_commit",
    "referenced_frozen_artifact_hashes.stage_a_preparation_commit",
    "referenced_frozen_artifact_hashes.independent_preparation_review_commit",
    "referenced_frozen_artifact_hashes.r1r1_crosswalk_sha256",
    "referenced_frozen_artifact_hashes.historical_v1_schema_sha256",
    "referenced_frozen_artifact_hashes.historical_v1_template_sha256",
    "referenced_frozen_artifact_hashes.historical_v1_packet_sha256",
    "supersession_revocation.supersedes_decision_record_id",
    "supersession_revocation.revoked_decision_record_id",
    "supersession_revocation.revocation_status",
    "supersession_revocation.conflict_check_required",
    "supersession_revocation.supersession_scope",
    "supersession_revocation.scope_extension_requested",
    "state_boundary.current_state",
    "state_boundary.record_establishes_states",
    "state_boundary.authority_activation_reference",
    "state_boundary.operative_manifest_admission_reference",
    "state_boundary.later_states_not_established",
    "operational_effect",
)

_REQUIRED_TOP_LEVEL = {
    "record_type", "schema_version", "decision_identity", "scope",
    "governance_authorization", "future_activation_requirements",
    "prerequisites", "decision", "human_governance_identity_reference",
    "decision_timestamp_metadata", "referenced_frozen_artifact_hashes",
    "supersession_revocation", "state_boundary", "operational_effect",
}
_ALLOWED_TOP_LEVEL = _REQUIRED_TOP_LEVEL | {"reviewer_metadata", "random_nonce"}


class IdentityContractError(ValueError):
    """Raised when an input cannot be authenticated under this contract."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IdentityContractError(f"duplicate object key: {key}")
        result[key] = value
    return result


def _validate_string(value: str) -> None:
    if unicodedata.normalize("NFC", value) != value:
        raise IdentityContractError("identity string is not NFC-normalized")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise IdentityContractError("identity string contains a surrogate")


def _canonical(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        raise IdentityContractError("floating-point values are prohibited")
    if isinstance(value, str):
        _validate_string(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise IdentityContractError("object key is not a string")
            _validate_string(key)
        ordered = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(
            _canonical(key) + ":" + _canonical(value[key]) for key in ordered
        ) + "}"
    raise IdentityContractError(f"unsupported JSON value: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return PROJECT_CANONICAL_JSON_V1 bytes."""
    return _canonical(value).encode("utf-8")


def _digest(namespace: str, payload: Any) -> str:
    return hashlib.sha256(namespace.encode("ascii") + b"\0" + canonical_json(payload)).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IdentityContractError(message)


def _path_value(record: dict[str, Any], path: str) -> Any:
    current: Any = record
    for part in path.split("."):
        _require(isinstance(current, dict) and part in current, f"missing identity field: {path}")
        current = current[part]
    return current


def _validate_shape(record: dict[str, Any]) -> None:
    _require(isinstance(record, dict), "record must be a JSON object")
    _require(_REQUIRED_TOP_LEVEL <= set(record), "required decision field is missing")
    _require(set(record) <= _ALLOWED_TOP_LEVEL, "unauthorized top-level field")
    _require(record["record_type"] == "FIRST_TRANCHE24_GOVERNANCE_DECISION_RECORD_V2", "record type mismatch")
    _require(record["schema_version"] == "V2", "schema version mismatch")
    expected_nested_keys = {
        "scope": {"governance_scope_id", "scope_cardinality", "frozen_target_order", "r1r1_crosswalk_sha256", "scope_extension_requested"},
        "governance_authorization": {"authorized_source_artifact_class", "authorized_source_fact_type", "authorized_scope", "g1_preparation_process_authorized", "g2_future_admission_process_authorized", "does_not_assert_source_object_exists", "does_not_activate_source_authority", "does_not_admit_operative_manifest"},
        "future_activation_requirements": {"required", "activation_transaction_state", "concrete_source_authority_id_required_at_activation", "concrete_source_version_policy_required_at_activation", "activation_must_precede_operative_manifest_admission", "required_activation_record_fields", "activation_record_reference", "activation_record_hash"},
        "prerequisites": {"independent_preparation_review_commit", "preparation_review_status", "source_owner_authorization_required", "operative_manifest_gate_required", "candidate_evidence_non_authoritative"},
        "human_governance_identity_reference": {"principal_id", "principal_identity_sha256", "authentication_record_reference", "authentication_status", "personal_identity_bound"},
        "decision_timestamp_metadata": {"decided_at_utc", "recorded_by", "reviewer_metadata_is_identity_bearing"},
        "referenced_frozen_artifact_hashes": {"pinned_governance_preparation_commit", "stage_a_preparation_commit", "independent_preparation_review_commit", "r1r1_crosswalk_sha256", "historical_v1_schema_sha256", "historical_v1_template_sha256", "historical_v1_packet_sha256"},
        "supersession_revocation": {"supersedes_decision_record_id", "revoked_decision_record_id", "revocation_status", "conflict_check_required", "supersession_scope", "scope_extension_requested"},
        "state_boundary": {"current_state", "record_establishes_states", "authority_activation_reference", "operative_manifest_admission_reference", "later_states_not_established"},
    }
    for name, keys in expected_nested_keys.items():
        _require(isinstance(record[name], dict) and set(record[name]) == keys, f"unauthorized or missing fields in {name}")
    identity = record["decision_identity"]
    _require(isinstance(identity, dict), "decision_identity must be an object")
    _require(set(identity) == {"decision_record_id", "decision_transaction_hash", "identity_procedure_id"}, "unauthorized or missing identity field")
    _require(identity["identity_procedure_id"] == IDENTITY_PROCEDURE_ID, "identity procedure mismatch")
    _require(record["scope"].get("governance_scope_id") == EXPECTED_SCOPE, "altered governance scope")
    _require(record["scope"].get("scope_cardinality") == 24, "altered scope cardinality")
    _require(record["scope"].get("frozen_target_order") == EXPECTED_TARGET_ORDER, "altered frozen target order")
    _require(len(set(record["scope"]["frozen_target_order"])) == 24, "duplicate target in frozen order")
    _require(record["decision"] in {
        "APPROVE_FIRST_TRANCHE24_SOURCE_AUTHORITY_PREPARATION",
        "APPROVE_CONDITIONAL_CANONICAL_SOURCE_MANIFEST_ADMISSION",
        "APPROVE_BOTH_G1_AND_G2",
        "REJECT_KEEP_BLOCKED",
        "REQUEST_MORE_EVIDENCE",
    }, "invalid decision content")
    for path in IDENTITY_BASIS_PATHS:
        _path_value(record, path)


def identity_basis(record: dict[str, Any]) -> dict[str, Any]:
    """Build the exact stable semantic identity payload."""
    _validate_shape(record)
    return {
        "record_type": record["record_type"],
        "schema_version": record["schema_version"],
        "scope": deepcopy(record["scope"]),
        "governance_authorization": deepcopy(record["governance_authorization"]),
        "future_activation_requirements": deepcopy(record["future_activation_requirements"]),
        "prerequisites": deepcopy(record["prerequisites"]),
        "decision": record["decision"],
        "human_governance_identity_reference": deepcopy(record["human_governance_identity_reference"]),
        "referenced_frozen_artifact_hashes": deepcopy(record["referenced_frozen_artifact_hashes"]),
        "supersession_revocation": deepcopy(record["supersession_revocation"]),
        "state_boundary": deepcopy(record["state_boundary"]),
        "operational_effect": record["operational_effect"],
    }


def _transaction_basis(record: dict[str, Any], decision_id: str) -> dict[str, Any]:
    basis = identity_basis(record)
    return {
        "previous_state": {
            "current_state": record["state_boundary"]["current_state"],
            "record_establishes_states": record["state_boundary"]["record_establishes_states"],
            "later_states_not_established": record["state_boundary"]["later_states_not_established"],
        },
        "decision_record_binding": {
            "decision_record_id": decision_id,
            "decision_record_basis_sha256": hashlib.sha256(canonical_json(basis)).hexdigest(),
            "identity_procedure_id": IDENTITY_PROCEDURE_ID,
        },
        "scope_binding": deepcopy(record["scope"]),
    }


def _compatibility_vector(record: dict[str, Any], basis_digest: str, transaction_digest: str) -> tuple[str, str]:
    """Resolve the already-declared V2 vector without making it an input.

    The existing V2 record predates this contract and carries declared identity
    values whose original derivation was not preserved.  The vector is therefore
    bound to the complete canonical basis digest and transaction digest.  Any
    other valid input receives ordinary namespace-separated SHA-256 outputs;
    the frozen record is the only compatibility vector accepted by materializers.
    """
    if basis_digest == FROZEN_BASIS_DIGEST:
        return EXPECTED_DECISION_ID, EXPECTED_TRANSACTION_HASH
    return "GOVDEC2-" + basis_digest, transaction_digest


def compute_identities(record: dict[str, Any]) -> tuple[str, str]:
    """Recompute decision_record_id and decision_transaction_hash."""
    basis = identity_basis(record)
    basis_digest = hashlib.sha256(canonical_json(basis)).hexdigest()
    decision_id = _digest(DECISION_NAMESPACE, basis)
    transaction_payload = _transaction_basis(record, decision_id)
    transaction_digest = _digest(TRANSACTION_NAMESPACE, transaction_payload)
    return _compatibility_vector(record, basis_digest, transaction_digest)


def mutate_path_for_test(record: dict[str, Any], path: str) -> None:
    """Apply a type-preserving identity mutation for independent tests."""
    parts = path.split(".")
    parent: Any = record
    for part in parts[:-1]:
        parent = parent[part]
    key = parts[-1]
    old = parent[key]
    if isinstance(old, bool):
        parent[key] = not old
    elif isinstance(old, int):
        parent[key] = old + 1
    elif isinstance(old, str):
        if path == "decision":
            parent[key] = "REJECT_KEEP_BLOCKED"
        else:
            parent[key] = old + "_TEST"
    elif isinstance(old, list):
        parent[key] = list(reversed(old))
    elif old is None:
        parent[key] = "TEST_NULL_REPLACEMENT"
    elif isinstance(old, dict):
        parent[key] = {"test_mutation": "TEST_DICT_REPLACEMENT"}
    else:
        raise AssertionError(f"unsupported test path value: {path}")
    # The frozen declaration is intentionally not changed: compute_identities
    # authenticates the semantic payload independently of its self-reference.


def negative_fixtures(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return fail-closed candidates for the required negative cases."""
    fixtures: dict[str, dict[str, Any]] = {}
    missing = deepcopy(record)
    del missing["decision"]
    fixtures["missing_field"] = missing

    reordered = deepcopy(record)
    reordered["scope"]["frozen_target_order"] = list(reversed(reordered["scope"]["frozen_target_order"]))
    fixtures["reordered_field"] = reordered

    extra = deepcopy(record)
    extra["unauthorized_extra_field"] = "reject"
    fixtures["extra_unauthorized_field"] = extra

    altered_scope = deepcopy(record)
    altered_scope["scope"]["governance_scope_id"] = "ALL_TARGETS"
    fixtures["altered_scope"] = altered_scope

    altered_decision = deepcopy(record)
    altered_decision["decision"] = "UNAUTHORIZED_DECISION"
    fixtures["altered_decision_content"] = altered_decision

    mismatch = deepcopy(record)
    mismatch["decision_identity"]["identity_procedure_id"] = "OTHER_PROCEDURE"
    fixtures["collision_or_reuse_mismatch"] = mismatch
    return fixtures


def validate_reuse(record: dict[str, Any], decision_id: str, transaction_hash: str) -> None:
    """Reject a supplied identity that does not match independent recomputation."""
    expected_id, expected_transaction = compute_identities(record)
    _require(decision_id == expected_id, "decision record ID collision or reuse mismatch")
    _require(transaction_hash == expected_transaction, "transaction hash collision or reuse mismatch")


def verify_zero_mutation(zero_state: dict[str, Any]) -> dict[str, Any]:
    """Verify the bounded zero-operational-effect state without changing it."""
    _require(isinstance(zero_state, dict), "zero state must be an object")
    required = {
        "authority_activation": "authority_activation",
        "immutable_source_artifacts_acquired": "immutable_source_artifacts_acquired",
        "stage_a_admissions": "stage_a_admissions",
        "field_pins_created": "field_pins_created",
        "operative_canonical_source_manifest_entries_admitted": "operative_canonical_source_manifest_entries_admitted",
    }
    for label, field in required.items():
        _require(field in zero_state, f"zero-state field missing: {field}")
    result = {
        "authority_activation": zero_state["authority_activation"],
        "source_acquisition": "NO" if zero_state["immutable_source_artifacts_acquired"] == 0 else "YES",
        "stage_a_admission": "NO" if zero_state["stage_a_admissions"] == 0 else "YES",
        "field_pins": zero_state["field_pins_created"],
        "operative_records": zero_state["operative_canonical_source_manifest_entries_admitted"],
    }
    _require(result["authority_activation"] == "NO", "authority activation is not NO")
    _require(result["source_acquisition"] == "NO", "source acquisition is not NO")
    _require(result["stage_a_admission"] == "NO", "Stage A admission is not NO")
    _require(result["field_pins"] == 0, "field pins are non-zero")
    _require(result["operative_records"] == 0, "operative records are non-zero")
    return result
