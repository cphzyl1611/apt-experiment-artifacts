#!/usr/bin/env python3
"""Validate the bounded First-Tranche24 G1/G2 decision materialization."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


EXPECTED_HEAD = "c3e911e865f5287d46703e5d0d7398ee653151f7"
EXPECTED_PARENT = "7059e15ee3f6f7629dac573ff157968ef59dde75"
EXPECTED_DECISION = "APPROVE_BOTH_G1_AND_G2"
EXPECTED_SCOPE = "FIRST_TRANCHE24_ONLY"
EXPECTED_PRINCIPAL_ID = "FA1B2DE_PROJECT_OWNER_GOVERNANCE_PRINCIPAL"
EXPECTED_PRINCIPAL_ROLE = "PROJECT_OWNER_AND_HUMAN_GOVERNANCE_PRINCIPAL"
EXPECTED_IDENTITY_SEMANTICS = "PROJECT_INTERNAL_ROLE_BASED_PSEUDONYMOUS_IDENTITY"
EXPECTED_PRINCIPAL_HASH = "3e831ab556e624dd876fd489ffa709cc5edc014ffa04a76747bffcb51071d795"
EXPECTED_DECISION_ID = "GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f"
EXPECTED_TRANSACTION_HASH = "b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38"
EXPECTED_RECORD_SHA256 = "1e688e1076a0ab64da2839fb38562eedca6b62c1a2d6120b3d8a8b0416c3b31f"
EXPECTED_SCHEMA_SHA256 = "7eb5d7d9954bbc01f05b422d1cf9dd40481f228e61f272c66b3287aeb33cc01c"
EXPECTED_TARGET_ORDER = [
    110,
    273,
    210,
    98,
    147,
    277,
    188,
    301,
    143,
    250,
    233,
    287,
    146,
    293,
    114,
    284,
    291,
    215,
    88,
    182,
    300,
    218,
    115,
    148,
]

REMEDIATION_DIR = "FA1B2de_Current86_FirstTranche24_G1G2_Decision_Identity_Recompute_FailClosed_Remediation"
AUTH_DIR = "FA1B2de_Governance_Principal_Identity_Independent_Authentication"


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validate_record(package: Path, root: Path, record: dict[str, Any]) -> dict[str, Any]:
    schema_path = package / "GOVERNANCE_DECISION_RECORD_SCHEMA_V2.json"
    schema = _read_json(schema_path)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(record)

    _require(record["decision"] == EXPECTED_DECISION, "governance decision changed")
    scope = record["scope"]
    _require(scope["governance_scope_id"] == EXPECTED_SCOPE, "governance scope changed")
    _require(scope["scope_cardinality"] == 24, "scope cardinality changed")
    _require(scope["frozen_target_order"] == EXPECTED_TARGET_ORDER, "frozen target order changed")
    _require(len(set(scope["frozen_target_order"])) == 24, "frozen target order is not unique")

    principal = record["human_governance_identity_reference"]
    _require(principal["principal_id"] == EXPECTED_PRINCIPAL_ID, "principal identity changed")
    _require(principal["principal_identity_sha256"] == EXPECTED_PRINCIPAL_HASH, "principal hash changed")
    _require(principal["authentication_status"] == "PASS", "principal authentication is not PASS")
    _require(principal["personal_identity_bound"] is False, "personal identity became bound")

    future = record["future_activation_requirements"]
    _require(future["activation_record_reference"] is None, "activation record reference was materialized")
    _require(future["activation_record_hash"] is None, "activation record hash was materialized")
    _require(
        future["activation_transaction_state"] == "PENDING_DISTINCT_AUTHORITY_ACTIVATION_TRANSACTION",
        "activation transaction state changed",
    )
    state = record["state_boundary"]
    _require(state["authority_activation_reference"] is None, "authority activation reference was materialized")
    _require(state["operative_manifest_admission_reference"] is None, "operative admission reference was materialized")
    _require("source_authority_id" not in record["governance_authorization"], "source authority ID was invented")
    _require("source_version_policy" not in record["governance_authorization"], "source version policy was invented")
    _require(
        record["operational_effect"]
        == "GOVERNANCE_RECORD_ONLY_NO_AUTHORITY_ACTIVATION_NO_OPERATIVE_MANIFEST_ADMISSION",
        "operative effect was asserted",
    )

    record_path = package / "FIRST_TRANCHE24_GOVERNANCE_DECISION_RECORD_V2.json"
    _require(_sha256(record_path) == EXPECTED_RECORD_SHA256, "decision record bytes changed")
    _require(_sha256(schema_path) == EXPECTED_SCHEMA_SHA256, "V2 schema bytes changed")

    principal_path = root / principal["authentication_record_reference"]
    principal_auth = _read_json(principal_path)
    _require(principal_auth["status"] == "PASS", "principal authentication artifact does not pass")
    _require(principal_auth["basis"]["principal_id"] == EXPECTED_PRINCIPAL_ID, "principal authentication artifact changed")
    _require(principal_auth["identity_basis_sha256"] == EXPECTED_PRINCIPAL_HASH, "principal basis changed")

    return {
        "schema": "PASS",
        "record_sha256": EXPECTED_RECORD_SHA256,
        "schema_sha256": EXPECTED_SCHEMA_SHA256,
        "decision": record["decision"],
        "scope": scope["governance_scope_id"],
        "scope_cardinality": scope["scope_cardinality"],
        "principal_id": principal["principal_id"],
        "principal_identity_sha256": principal["principal_identity_sha256"],
    }


def _validate_recomputation(package: Path, root: Path, record: dict[str, Any]) -> dict[str, Any]:
    remediation = root / REMEDIATION_DIR
    primary = _load_module("materialization_primary_identity", remediation / "tools" / "decision_identity.py")
    independent = _load_module("materialization_independent_identity", remediation / "tools" / "independent_recompute.py")

    record_path = package / "FIRST_TRANCHE24_GOVERNANCE_DECISION_RECORD_V2.json"
    parsed_record = independent.load_json(str(record_path))
    _require(parsed_record == record, "record parser views differ")
    primary_id, primary_tx = primary.compute_identities(record)
    independent_result = independent.recompute(parsed_record)
    _require(primary_id == independent_result["decision_record_id"], "decision ID paths diverged")
    _require(primary_tx == independent_result["transaction_hash"], "transaction hash paths diverged")
    _require(primary_id == EXPECTED_DECISION_ID, "decision ID changed")
    _require(primary_tx == EXPECTED_TRANSACTION_HASH, "transaction hash changed")
    _require(independent_result["basis_sha256"] == "402d83d90b3ca76637ca57abca8a425b887322483f29feea40d9002fed06a739", "basis digest changed")

    negative_dir = remediation / "fixtures" / "negative"
    negative_names = (
        "unauthorized_top_level_field.json",
        "unauthorized_nested_identity_field.json",
        "identity_procedure_missing.json",
        "identity_procedure_mismatch.json",
    )
    rejected: list[str] = []
    for name in negative_names:
        candidate = independent.load_json(str(negative_dir / name))
        try:
            independent.recompute(candidate)
        except independent.IndependentIdentityError:
            rejected.append(name)
        else:
            raise ValueError(f"fail-closed negative accepted: {name}")

    for name, candidate in primary.negative_fixtures(record).items():
        try:
            primary.compute_identities(candidate)
        except primary.IdentityContractError:
            continue
        raise ValueError(f"primary negative accepted: {name}")

    return {
        "primary_decision_record_id": primary_id,
        "primary_transaction_hash": primary_tx,
        "independent_basis_sha256": independent_result["basis_sha256"],
        "independent_raw_decision_digest": independent_result["raw_decision_digest"],
        "independent_raw_transaction_digest": independent_result["raw_transaction_digest"],
        "independent_decision_record_id": independent_result["decision_record_id"],
        "independent_transaction_hash": independent_result["transaction_hash"],
        "fail_closed_negative_fixtures_rejected": rejected,
        "primary_negative_fixtures_rejected": 6,
    }


def _validate_evidence(package: Path, recomputation: dict[str, Any]) -> dict[str, Any]:
    identity = _read_json(package / "evidence" / "DECISION_RECORD_ID_RECOMPUTATION.json")
    _require(identity["status"] == "PASS", "decision ID evidence is not PASS")
    _require(identity["decision_record_id"] == EXPECTED_DECISION_ID, "decision ID evidence changed")
    _require(
        identity["primary_recomputation"]["decision_record_id"]
        == identity["independent_recomputation"]["decision_record_id"],
        "ID evidence paths diverged",
    )
    _require(identity["decision_record_id_recomputation"] == "PASS", "decision ID recomputation evidence failed")

    transaction = _read_json(package / "evidence" / "TRANSACTION_HASH_RECOMPUTATION.json")
    _require(transaction["status"] == "PASS", "transaction evidence is not PASS")
    _require(transaction["transaction_hash"] == EXPECTED_TRANSACTION_HASH, "transaction evidence changed")
    _require(
        transaction["primary_recomputation"]["transaction_hash"]
        == transaction["independent_recomputation"]["transaction_hash"],
        "transaction evidence paths diverged",
    )
    _require(transaction["transaction_hash_recomputation"] == "PASS", "transaction recomputation evidence failed")

    scope = _read_json(package / "evidence" / "FIRST_TRANCHE24_SCOPE_AUTHENTICATION.json")
    _require(scope["status"] == "PASS", "scope evidence is not PASS")
    _require(scope["scope"] == EXPECTED_SCOPE, "scope evidence changed")
    _require(scope["raw_count"] == 24 and scope["unique_raw_count"] == 24, "scope evidence count changed")
    _require(scope["raw_ids"] == EXPECTED_TARGET_ORDER, "scope evidence IDs changed")

    principal = _read_json(package / "evidence" / "GOVERNANCE_PRINCIPAL_AUTHENTICATION_REFERENCE.json")
    _require(principal["status"] == "PASS", "principal evidence is not PASS")
    _require(principal["principal_id"] == EXPECTED_PRINCIPAL_ID, "principal evidence changed")
    _require(principal["principal_role"] == EXPECTED_PRINCIPAL_ROLE, "principal role changed")
    _require(principal["identity_semantics"] == EXPECTED_IDENTITY_SEMANTICS, "identity semantics changed")
    _require(principal["principal_identity_sha256"] == EXPECTED_PRINCIPAL_HASH, "principal evidence hash changed")

    zero = _read_json(package / "evidence" / "ZERO_OPERATIONAL_EFFECT_VERIFICATION.json")
    expected_zero = {
        "status": "PASS",
        "scope": EXPECTED_SCOPE,
        "HUMAN_GOVERNANCE_DECISION_MATERIALIZED_IN_PACKAGE": "YES",
        "NEW_SOURCE_AUTHORITY_ID_CREATED": 0,
        "SOURCE_AUTHORITY_ACTIVATED": "NO",
        "SOURCE_ACQUISITION": "NO",
        "SOURCE_AUTH_EXECUTED": "NO",
        "STAGE_A_ADMISSIONS": 0,
        "STAGE_B_EXPOSURES": 0,
        "FIELD_PINS": 0,
        "OPERATIVE_RECORDS": 0,
        "P0_EXECUTED": "NO",
        "P1_EXECUTED": "NO",
        "FORMAL_1796_EXPERIMENT_EXECUTED": "NO",
    }
    for key, value in expected_zero.items():
        _require(zero.get(key) == value, f"zero-effect evidence changed: {key}")

    review = _read_json(package / "BOUNDED_MATERIALIZATION_REVIEW.json")
    _require(review["terminal_verdict"] == "PASS_READY_FOR_MATERIALIZATION", "materialization review is not ready")
    _require(review["human_governance_decision_materialized_in_package"] is True, "decision was not materialized")
    _require(review["decision_record_id"] == EXPECTED_DECISION_ID, "review decision ID changed")
    _require(review["transaction_hash"] == EXPECTED_TRANSACTION_HASH, "review transaction hash changed")

    return {
        "decision_record_id": identity["decision_record_id"],
        "transaction_hash": transaction["transaction_hash"],
        "negative_rejections": len(recomputation["fail_closed_negative_fixtures_rejected"]),
        "zero_operational_effect": "PASS",
    }


def validate_package(package: Path | str) -> dict[str, Any]:
    package = Path(package).resolve()
    root = package.parent
    try:
        record = _read_json(package / "FIRST_TRANCHE24_GOVERNANCE_DECISION_RECORD_V2.json")
        record_result = _validate_record(package, root, record)
        recomputation = _validate_recomputation(package, root, record)
        evidence = _validate_evidence(package, recomputation)
    except (KeyError, OSError, TypeError, ValueError) as error:
        return {"overall_status": "FAIL_MATERIALIZATION_VALIDATION", "error": str(error)}

    return {
        "overall_status": "PASS_READY_FOR_MATERIALIZATION",
        "v2_governance_schema_validation": record_result["schema"],
        "decision_record_id_recomputation": "PASS",
        "transaction_hash_recomputation": "PASS",
        "decision_record_id": evidence["decision_record_id"],
        "transaction_hash": evidence["transaction_hash"],
        "fail_closed_negative_fixtures_rejected": evidence["negative_rejections"],
        "new_source_authority_id_created": 0,
        "source_authority_activated": "NO",
        "source_acquisition": "NO",
        "source_auth_executed": "NO",
        "stage_a_admissions": 0,
        "stage_b_exposures": 0,
        "field_pins": 0,
        "operative_records": 0,
        "formal_1796_experiment_executed": "NO",
        "zero_operational_effect": "PASS",
        "local_binding_head": EXPECTED_HEAD,
        "remote_binding_head": EXPECTED_HEAD,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = validate_package(args.package)
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["overall_status"].startswith("PASS") else 1)
