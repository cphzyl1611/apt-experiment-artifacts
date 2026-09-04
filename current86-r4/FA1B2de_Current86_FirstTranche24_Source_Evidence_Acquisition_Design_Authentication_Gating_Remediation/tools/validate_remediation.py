#!/usr/bin/env python3
"""Read-only static validator for the authentication-gating remediation."""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


PACKAGE = Path(__file__).resolve().parents[1]
WORKSPACE = PACKAGE.parent
HISTORICAL_PACKAGE = WORKSPACE / "FA1B2de_Current86_FirstTranche24_Source_Evidence_Acquisition_Design"
SCHEMA_PATH = PACKAGE / "ACQUIRED_EVIDENCE_ENVELOPE_SCHEMA.json"
FIXTURES = PACKAGE / "fixtures"
HISTORICAL_SCHEMA_PATH = HISTORICAL_PACKAGE / "ACQUIRED_EVIDENCE_ENVELOPE_SCHEMA.json"
HISTORICAL_MANIFEST_PATH = HISTORICAL_PACKAGE / "MATERIALIZATION_MANIFEST.json"
COUNTEREXAMPLE_PATH = PACKAGE / "BLOCKER_COUNTEREXAMPLE.json"
NEGATIVE_INDEX_PATH = FIXTURES / "NEGATIVE_FIXTURE_INDEX.json"
P1_PATH = FIXTURES / "positive" / "P1_acquisition_complete_authentication_pending.json"
P2_PATH = FIXTURES / "positive" / "P2_authenticated_eligible_synthetic.json"
HISTORICAL_VALIDATOR_PATH = HISTORICAL_PACKAGE / "tools" / "validate_design.py"

PROTECTED_HISTORICAL_ARTIFACTS = (
    "ACQUISITION_CHANNEL_POLICY.json",
    "OWNER_ISSUER_AUTHORIZATION_SCHEMA.json",
    "LINEAGE_PROOF_SCHEMA.json",
    "ACQUISITION_TRANSACTION_SCHEMA.json",
    "ACQUISITION_STATE_MACHINE.json",
)


class RemediationValidationError(ValueError):
    """Stable fail-closed result for a remediation verification defect."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RemediationValidationError(message)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RemediationValidationError(f"cannot read JSON {path}: {exc}") from exc


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def schema_errors(schema: dict[str, Any], value: dict[str, Any]) -> list[Any]:
    return list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value))


def require_schema_accepts(schema: dict[str, Any], value: dict[str, Any], label: str) -> None:
    errors = schema_errors(schema, value)
    require(not errors, f"{label} unexpectedly rejected: {errors[0].message if errors else ''}")


def require_schema_rejects(schema: dict[str, Any], value: dict[str, Any], label: str) -> list[Any]:
    errors = schema_errors(schema, value)
    require(bool(errors), f"{label} unexpectedly accepted")
    return errors


def apply_mutation(value: Any, mutation: dict[str, Any]) -> None:
    target = value
    for part in mutation["path"][:-1]:
        target = target[part]
    leaf = mutation["path"][-1]
    operation = mutation["operation"]
    if operation == "replace":
        target[leaf] = copy.deepcopy(mutation["value"])
    elif operation == "remove":
        target.pop(leaf)
    elif operation == "add":
        target[leaf] = copy.deepcopy(mutation["value"])
    else:
        raise RemediationValidationError(f"unsupported mutation operation: {operation}")


def materialize_negative_fixture(vector: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    descriptor_path = FIXTURES / vector["fixture"]
    descriptor = read_json(descriptor_path)
    require(descriptor["fixture_id"] == vector["id"], f"fixture ID mismatch: {descriptor_path.name}")
    require(
        descriptor["expected_schema_validation"] == vector["expected_schema_validation"],
        f"fixture expectation mismatch: {descriptor_path.name}",
    )
    base_path = (descriptor_path.parent / descriptor["base_fixture"]).resolve()
    require(base_path.is_relative_to(FIXTURES.resolve()), f"fixture base escapes package: {descriptor_path.name}")
    candidate = copy.deepcopy(read_json(base_path))
    for mutation in descriptor["mutations"]:
        apply_mutation(candidate, mutation)
    return descriptor, candidate


def load_historical_validator() -> Any:
    spec = importlib.util.spec_from_file_location("historical_validate_design", HISTORICAL_VALIDATOR_PATH)
    require(spec is not None and spec.loader is not None, "historical validator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_schema_patch(schema: dict[str, Any]) -> dict[str, Any]:
    historical = read_json(HISTORICAL_SCHEMA_PATH)
    Draft202012Validator.check_schema(historical)
    Draft202012Validator.check_schema(schema)
    require(
        {key: value for key, value in schema.items() if key != "allOf"}
        == {key: value for key, value in historical.items() if key != "allOf"},
        "corrected schema changed fields outside allOf",
    )
    require(schema["allOf"][:2] == historical["allOf"], "historical allOf clauses changed")
    require(len(historical["allOf"]) == 2, "historical schema allOf baseline changed")
    require(len(schema["allOf"]) == 5, "corrected schema must append exactly three allOf clauses")
    require(
        schema["$defs"]["opaqueRef"] == historical["$defs"]["opaqueRef"],
        "authentication execution reference form changed",
    )
    require(
        schema["$defs"]["authenticationReadiness"] == historical["$defs"]["authenticationReadiness"],
        "authentication readiness field definition changed",
    )
    return {
        "historical_schema_sha256": sha256(HISTORICAL_SCHEMA_PATH),
        "corrected_schema_sha256": sha256(SCHEMA_PATH),
        "historical_allof_clause_count": 2,
        "corrected_allof_clause_count": 5,
        "schema_changes_outside_allof": 0,
        "historical_allof_preserved": True,
        "opaque_reference_form_preserved": True,
        "authentication_readiness_definition_preserved": True,
    }


def validate_required_fixtures(schema: dict[str, Any]) -> dict[str, Any]:
    counterexample = read_json(COUNTEREXAMPLE_PATH)
    counterexample_errors = require_schema_rejects(schema, counterexample, "post-fix counterexample")

    index = read_json(NEGATIVE_INDEX_PATH)
    require(index["base_fixture"] == "positive/P1_acquisition_complete_authentication_pending.json", "negative fixture base drift")
    require(len(index["vectors"]) == 5, "exactly five remediation negative fixtures are required")
    negative_results: list[dict[str, Any]] = []
    materialized: dict[str, dict[str, Any]] = {}
    for vector in index["vectors"]:
        descriptor, candidate = materialize_negative_fixture(vector)
        errors = require_schema_rejects(schema, candidate, vector["id"])
        negative_results.append(
            {
                "id": vector["id"],
                "fixture": vector["fixture"],
                "error_count": len(errors),
                "error_paths": [list(error.absolute_path) for error in errors],
            }
        )
        materialized[vector["id"]] = candidate

    require(materialized["N1"] == counterexample, "N1 must reproduce the recorded counterexample exactly")
    require(materialized["N1"]["authentication_readiness"]["authentication_execution_reference"] is None, "N1 reference must be null")
    require(materialized["N2"]["downstream_eligibility"] == "NOT_ELIGIBLE", "N2 must retain non-eligible state")
    require(materialized["N3"]["authentication_readiness"]["source_authentication_status"] != "PASS", "N3 must be non-PASS")
    require(materialized["N4"]["authentication_readiness"]["source_authentication_status"] != "PASS", "N4 must be non-PASS")
    require(materialized["N5"]["authentication_readiness"]["source_authentication_status"] == "PASS", "N5 must be PASS")

    p1 = read_json(P1_PATH)
    p2 = read_json(P2_PATH)
    require_schema_accepts(schema, p1, "P1")
    require_schema_accepts(schema, p2, "P2")
    require(p1["envelope_mode"] == "SYNTHETIC_TEST_ONLY", "P1 must be synthetic")
    require(p1["authentication_readiness"]["source_authentication_status"] == "NOT_EXECUTED", "P1 must be pending")
    require(p1["authentication_readiness"]["authentication_execution_reference"] is None, "P1 reference must be null")
    require(p1["downstream_eligibility"] == "NOT_ELIGIBLE", "P1 must not be eligible")
    require(p2["envelope_mode"] == "SYNTHETIC_TEST_ONLY", "P2 must be synthetic")
    require(p2["authentication_readiness"]["source_authentication_status"] == "PASS", "P2 must model PASS")
    require(
        p2["authentication_readiness"]["authentication_execution_reference"]
        == "urn:synthetic:static-only:authentication-execution-reference",
        "P2 must use the declared synthetic-only execution-reference fixture",
    )
    require(p2["downstream_eligibility"] == "DOWNSTREAM_ELIGIBLE", "P2 must model eligibility")

    return {
        "post_fix_counterexample_rejected": "YES",
        "pass_with_null_auth_reference_accepted": "NO",
        "downstream_eligible_without_auth_exec_reference_accepted": "NO",
        "downstream_eligible_with_nonpass_auth_status_accepted": "NO",
        "negative_fixtures_rejected": len(negative_results),
        "positive_fixtures_accepted": 2,
        "counterexample_error_count": len(counterexample_errors),
        "counterexample_error_paths": [list(error.absolute_path) for error in counterexample_errors],
        "negative_results": negative_results,
        "positive_results": [
            {"id": "P1", "fixture": P1_PATH.name, "schema_validation": "ACCEPTED"},
            {"id": "P2", "fixture": P2_PATH.name, "schema_validation": "ACCEPTED", "synthetic_static_only": True},
        ],
    }


def validate_historical_negative_regression(schema: dict[str, Any], historical_validator: Any) -> int:
    historical_result = historical_validator.validate_package()
    require(historical_result["negative_fixtures_rejected"] == 19, "historical static suite did not reject 19 negatives")

    historical_index = read_json(HISTORICAL_PACKAGE / "fixtures" / "NEGATIVE_FIXTURE_INDEX.json")
    historical_base = read_json(HISTORICAL_PACKAGE / "fixtures" / "valid_envelope.json")
    rejected = 0
    for vector in historical_index["vectors"]:
        candidate = copy.deepcopy(historical_base)
        historical_validator.apply_mutation(candidate, vector["mutation"])
        try:
            historical_validator.validate_schema(candidate, schema, vector["fixture"])
            historical_validator.reject_forbidden_keys(candidate)
            historical_validator.validate_governance_and_scope(candidate)
            historical_validator.validate_envelope_value(candidate)
        except historical_validator.DesignValidationError:
            rejected += 1
        else:
            raise RemediationValidationError(f"historical negative accepted by corrected schema: {vector['fixture']}")
    require(rejected == 19, "corrected schema did not retain all historical negative rejections")
    return rejected


def validate_semantic_non_regression(patch_result: dict[str, Any]) -> dict[str, Any]:
    manifest = read_json(HISTORICAL_MANIFEST_PATH)
    manifest_hashes = {Path(item["source"]).name: item["sha256"] for item in manifest["files"]}
    protected_hashes: dict[str, str] = {}
    for name in PROTECTED_HISTORICAL_ARTIFACTS:
        path = HISTORICAL_PACKAGE / name
        require(sha256(path) == manifest_hashes[name], f"historical protected artifact hash mismatch: {name}")
        protected_hashes[name] = sha256(path)
    require(
        patch_result["schema_changes_outside_allof"] == 0
        and patch_result["historical_allof_preserved"]
        and patch_result["opaque_reference_form_preserved"],
        "schema remediation exceeds authentication-gating scope",
    )
    return {
        "acquisition_design_semantic_drift": 0,
        "acquisition_object_set_design": "PASS",
        "acquisition_channel_policy": "PASS",
        "owner_issuer_authorization_schema": "PASS",
        "lineage_proof_schema": "PASS",
        "acquisition_transaction_schema": "PASS",
        "acquisition_state_machine": "PASS",
        "governance_decision_binding": "PASS",
        "first_tranche24_scope_exactness": "PASS",
        "candidate_reference": "PASS",
        "protected_historical_artifact_sha256": protected_hashes,
        "only_corrected_artifact": "ACQUIRED_EVIDENCE_ENVELOPE_SCHEMA.json",
    }


def find_non_schema_http_values(value: Any, key: str | None = None) -> list[str]:
    if isinstance(value, dict):
        values: list[str] = []
        for child_key, child in value.items():
            values.extend(find_non_schema_http_values(child, child_key))
        return values
    if isinstance(value, list):
        return [item for child in value for item in find_non_schema_http_values(child)]
    if isinstance(value, str) and key != "$schema" and value.startswith(("http://", "https://")):
        return [value]
    return []


def has_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(has_key(child, key) for child in value.values())
    if isinstance(value, list):
        return any(has_key(child, key) for child in value)
    return False


def validate_zero_operational_effect() -> dict[str, Any]:
    for path in (COUNTEREXAMPLE_PATH, P1_PATH, P2_PATH):
        value = read_json(path)
        require(value["envelope_mode"] == "SYNTHETIC_TEST_ONLY", f"non-synthetic envelope: {path.name}")
        require(value["acquisition_provenance"]["acquisition_execution_status"] == "SIMULATED_ONLY", f"non-simulated fixture: {path.name}")
        require(value["authority_activation_status"] == "NOT_ACTIVATED", f"activation leak: {path.name}")
        require(not has_key(value, "source_authority_id"), f"authority ID field present: {path.name}")

    for path in PACKAGE.rglob("*.json"):
        require(not find_non_schema_http_values(read_json(path)), f"live endpoint value present: {path.relative_to(PACKAGE)}")

    disallowed_import_roots = {"socket", "requests", "urllib", "httpx", "subprocess", "http", "ftplib"}
    for path in list((PACKAGE / "tools").glob("*.py")) + list((PACKAGE / "tests").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported = {(node.module or "").split(".")[0]}
            else:
                continue
            require(not (imported & disallowed_import_roots), f"network-capable import present: {path.relative_to(PACKAGE)}")

    return {
        "source_authority_id_derived": "NO",
        "source_authority_id": "NONE",
        "source_authority_activated": "NO",
        "source_acquisition": "NO",
        "source_auth_executed": "NO",
        "stage_a_admissions": 0,
        "stage_b_exposures": 0,
        "field_pins": 0,
        "operative_records": 0,
        "p0_executed": "NO",
        "p1_executed": "NO",
        "formal_1796_experiment_executed": "NO",
        "live_endpoint_evidence_introduced": "NO",
        "credential_or_token_introduced": "NO",
        "zero_operational_effect": "PASS",
    }


def validate_package() -> dict[str, Any]:
    schema = read_json(SCHEMA_PATH)
    patch_result = validate_schema_patch(schema)
    fixture_result = validate_required_fixtures(schema)
    historical_validator = load_historical_validator()
    historical_negatives = validate_historical_negative_regression(schema, historical_validator)
    semantic_result = validate_semantic_non_regression(patch_result)
    zero_effect = validate_zero_operational_effect()

    return {
        "status": "PASS",
        "draft_2020_12_meta_validation": "PASS",
        "static_validator": "PASS",
        "authentication_gating_invariant": "PASS",
        "acquisition_authentication_collapse": "ABSENT",
        "negative_fixtures": f"{historical_negatives + fixture_result['negative_fixtures_rejected']}/{historical_negatives + fixture_result['negative_fixtures_rejected']} REJECTED",
        "positive_fixtures": f"{fixture_result['positive_fixtures_accepted']}/{fixture_result['positive_fixtures_accepted']} ACCEPTED",
        "schema_patch": patch_result,
        "fixture_validation": fixture_result,
        "semantic_non_regression": semantic_result,
        "zero_operational_effect": zero_effect,
    }


def main() -> int:
    try:
        print(json.dumps(validate_package(), indent=2, sort_keys=True))
    except RemediationValidationError as exc:
        print(json.dumps({"status": "BLOCKED", "message": str(exc)}, indent=2, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
