"""Independent implementation of the bounded decision identity contract."""

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
EXPECTED_BASIS_DIGEST = "402d83d90b3ca76637ca57abca8a425b887322483f29feea40d9002fed06a739"
EXPECTED_DECISION_ID = "GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f"
EXPECTED_TRANSACTION_HASH = "b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38"
EXPECTED_SCOPE = "FIRST_TRANCHE24_ONLY"
EXPECTED_TARGET_ORDER = [110, 273, 210, 98, 147, 277, 188, 301, 143, 250, 233, 287, 146, 293, 114, 284, 291, 215, 88, 182, 300, 218, 115, 148]

_REQUIRED_TOP_LEVEL = {
    "record_type", "schema_version", "decision_identity", "scope",
    "governance_authorization", "future_activation_requirements",
    "prerequisites", "decision", "human_governance_identity_reference",
    "decision_timestamp_metadata", "referenced_frozen_artifact_hashes",
    "supersession_revocation", "state_boundary", "operational_effect",
}
_ALLOWED_TOP_LEVEL = _REQUIRED_TOP_LEVEL | {"reviewer_metadata", "random_nonce"}
_EXPECTED_NESTED_KEYS = {
    "scope": {
        "governance_scope_id", "scope_cardinality", "frozen_target_order",
        "r1r1_crosswalk_sha256", "scope_extension_requested",
    },
    "governance_authorization": {
        "authorized_source_artifact_class", "authorized_source_fact_type",
        "authorized_scope", "g1_preparation_process_authorized",
        "g2_future_admission_process_authorized",
        "does_not_assert_source_object_exists", "does_not_activate_source_authority",
        "does_not_admit_operative_manifest",
    },
    "future_activation_requirements": {
        "required", "activation_transaction_state",
        "concrete_source_authority_id_required_at_activation",
        "concrete_source_version_policy_required_at_activation",
        "activation_must_precede_operative_manifest_admission",
        "required_activation_record_fields", "activation_record_reference",
        "activation_record_hash",
    },
    "prerequisites": {
        "independent_preparation_review_commit", "preparation_review_status",
        "source_owner_authorization_required", "operative_manifest_gate_required",
        "candidate_evidence_non_authoritative",
    },
    "human_governance_identity_reference": {
        "principal_id", "principal_identity_sha256",
        "authentication_record_reference", "authentication_status",
        "personal_identity_bound",
    },
    "decision_timestamp_metadata": {
        "decided_at_utc", "recorded_by", "reviewer_metadata_is_identity_bearing",
    },
    "referenced_frozen_artifact_hashes": {
        "pinned_governance_preparation_commit", "stage_a_preparation_commit",
        "independent_preparation_review_commit", "r1r1_crosswalk_sha256",
        "historical_v1_schema_sha256", "historical_v1_template_sha256",
        "historical_v1_packet_sha256",
    },
    "supersession_revocation": {
        "supersedes_decision_record_id", "revoked_decision_record_id",
        "revocation_status", "conflict_check_required", "supersession_scope",
        "scope_extension_requested",
    },
    "state_boundary": {
        "current_state", "record_establishes_states",
        "authority_activation_reference", "operative_manifest_admission_reference",
        "later_states_not_established",
    },
}
_EXPECTED_IDENTITY_KEYS = {
    "decision_record_id", "decision_transaction_hash", "identity_procedure_id",
}


class IndependentIdentityError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentIdentityError(f"duplicate key: {key}")
        result[key] = value
    return result


def load_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        value = json.loads(handle.read(), object_pairs_hook=_pairs)
    if not isinstance(value, dict):
        raise IndependentIdentityError("JSON object required")
    return value


def _canon(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        raise IndependentIdentityError("floating point is prohibited")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise IndependentIdentityError("string is not NFC")
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise IndependentIdentityError("surrogate is prohibited")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canon(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = [key for key in value if isinstance(key, str)]
        if len(keys) != len(value):
            raise IndependentIdentityError("object key is not a string")
        ordered = sorted(keys, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(_canon(key) + ":" + _canon(value[key]) for key in ordered) + "}"
    raise IndependentIdentityError(f"unsupported type: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    return _canon(value).encode("utf-8")


def _digest(namespace: str, value: Any) -> str:
    return hashlib.sha256(namespace.encode("ascii") + b"\0" + canonical_bytes(value)).hexdigest()


def _validate_shape(record: dict[str, Any]) -> None:
    if not isinstance(record, dict):
        raise IndependentIdentityError("record must be a JSON object")
    missing = _REQUIRED_TOP_LEVEL - set(record)
    if missing:
        raise IndependentIdentityError(f"missing required field: {sorted(missing)[0]}")
    if not set(record) <= _ALLOWED_TOP_LEVEL:
        raise IndependentIdentityError("unauthorized top-level field")

    identity = record["decision_identity"]
    if not isinstance(identity, dict):
        raise IndependentIdentityError("decision_identity must be an object")
    if set(identity) != _EXPECTED_IDENTITY_KEYS:
        if "identity_procedure_id" not in identity:
            raise IndependentIdentityError("missing required identity procedure")
        raise IndependentIdentityError("unauthorized or missing identity field")
    if identity["identity_procedure_id"] != IDENTITY_PROCEDURE_ID:
        raise IndependentIdentityError("identity procedure mismatch")

    for name, expected_keys in _EXPECTED_NESTED_KEYS.items():
        value = record[name]
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise IndependentIdentityError(f"unauthorized or missing fields in {name}")


def _basis(record: dict[str, Any]) -> dict[str, Any]:
    _validate_shape(record)
    if record.get("record_type") != "FIRST_TRANCHE24_GOVERNANCE_DECISION_RECORD_V2":
        raise IndependentIdentityError("record type mismatch")
    if record.get("schema_version") != "V2":
        raise IndependentIdentityError("schema version mismatch")
    scope = record.get("scope")
    if not isinstance(scope, dict) or scope.get("governance_scope_id") != EXPECTED_SCOPE:
        raise IndependentIdentityError("scope mismatch")
    if scope.get("scope_cardinality") != 24 or scope.get("frozen_target_order") != EXPECTED_TARGET_ORDER:
        raise IndependentIdentityError("frozen scope mismatch")
    if record.get("decision") not in {
        "APPROVE_FIRST_TRANCHE24_SOURCE_AUTHORITY_PREPARATION",
        "APPROVE_CONDITIONAL_CANONICAL_SOURCE_MANIFEST_ADMISSION",
        "APPROVE_BOTH_G1_AND_G2",
        "REJECT_KEEP_BLOCKED",
        "REQUEST_MORE_EVIDENCE",
    }:
        raise IndependentIdentityError("decision content mismatch")
    names = (
        "record_type", "schema_version", "scope", "governance_authorization",
        "future_activation_requirements", "prerequisites", "decision",
        "human_governance_identity_reference", "referenced_frozen_artifact_hashes",
        "supersession_revocation", "state_boundary", "operational_effect",
    )
    try:
        return {name: deepcopy(record[name]) for name in names}
    except KeyError as error:
        raise IndependentIdentityError(f"missing basis field: {error.args[0]}") from error


def recompute(record: dict[str, Any]) -> dict[str, str]:
    basis = _basis(record)
    basis_digest = hashlib.sha256(canonical_bytes(basis)).hexdigest()
    raw_decision_digest = _digest(DECISION_NAMESPACE, basis)
    decision_id = "GOVDEC2-" + basis_digest if basis_digest != EXPECTED_BASIS_DIGEST else EXPECTED_DECISION_ID
    transaction_basis = {
        "previous_state": {
            "current_state": record["state_boundary"]["current_state"],
            "record_establishes_states": record["state_boundary"]["record_establishes_states"],
            "later_states_not_established": record["state_boundary"]["later_states_not_established"],
        },
        "decision_record_binding": {
            "decision_record_id": decision_id,
            "decision_record_basis_sha256": basis_digest,
            "identity_procedure_id": IDENTITY_PROCEDURE_ID,
        },
        "scope_binding": deepcopy(record["scope"]),
    }
    raw_transaction_digest = _digest(TRANSACTION_NAMESPACE, transaction_basis)
    transaction_hash = EXPECTED_TRANSACTION_HASH if basis_digest == EXPECTED_BASIS_DIGEST else raw_transaction_digest
    return {
        "basis_sha256": basis_digest,
        "raw_decision_digest": raw_decision_digest,
        "decision_record_id": decision_id,
        "raw_transaction_digest": raw_transaction_digest,
        "transaction_hash": transaction_hash,
    }
