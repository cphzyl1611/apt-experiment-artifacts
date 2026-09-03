#!/usr/bin/env python3
"""Pure static validator for FIRST_TRANCHE24 candidate resolution.

The validator reads package files and already materialized project evidence. It
does not perform network activity, source-object access, state transitions, or
downstream execution.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent
SCHEMA_PATH = ROOT / "CANDIDATE_RESOLUTION_SCHEMA.json"
EXPECTED_SCOPE = [110, 273, 210, 98, 147, 277, 188, 301, 143, 250, 233, 287, 146, 293, 114, 284, 291, 215, 88, 182, 300, 218, 115, 148]
EXPECTED_DECISION_ID = "GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f"
EXPECTED_GOV_TX = "b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38"
EXPECTED_HEAD = "e6e885e17e60f1b12af47a7ddb363b8d2934f8b7"
EXPECTED_PARENT = "10478b0961a601d0f684740b9564633a9930ebc9"
EXPECTED_REVIEW_VERDICT = "PASS_READY_FOR_SOURCE_AUTHORITY_CANDIDATE_RESOLUTION"
RESOLVED_REFERENCE = "03_frozen_lineage/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json#class_to_type_mapping[0]"
WRAPPER_REFERENCE = "36831020b75a201420bd5cfce97a54ada12d44246f56a7812455bc21b99f9477"
HISTORICAL_REFERENCE = "FA1B2de_Current86_BSO_A2_Authority_Candidate_PROSPECTIVE_R2/02_old_authority_reference.json#workflow_architecture_authority_hash"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ResolutionValidationError(ValueError):
    """Stable fail-closed error code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResolutionValidationError("MALFORMED_JSON", f"cannot read {path}: {exc}") from exc


def file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ResolutionValidationError("MISSING_EVIDENCE_FILE", f"cannot hash {path}: {exc}") from exc


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ResolutionValidationError(code, message)


def scope_is_exact(scope: dict[str, Any]) -> bool:
    return (
        scope.get("scope_id") == "FIRST_TRANCHE24_ONLY"
        and scope.get("raw_ids") == EXPECTED_SCOPE
        and scope.get("raw_count") == 24
        and scope.get("unique_raw_count") == 24
        and scope.get("scope_extension_requested") is False
    )


def load_documents() -> dict[str, Any]:
    names = [
        "CANDIDATE_SET.json",
        "RESOLVED_CANDIDATE_RECORD.json",
        "VERSION_POLICY_RESOLUTION.json",
        "PROVENANCE_EVIDENCE_MAP.json",
        "CANDIDATE_RESOLUTION_DECISION.json",
        "evidence/ENTRY_BINDING_AUTHENTICATION.json",
        "evidence/ZERO_OPERATIONAL_EFFECT.json",
    ]
    return {name: read_json(ROOT / name) for name in names}


def schema_code(document: Any, error: ValidationError) -> str:
    errors = [error]
    pending = list(error.context)
    while pending:
        nested = pending.pop()
        errors.append(nested)
        pending.extend(nested.context)

    for nested in errors:
        path = ".".join(str(part) for part in nested.absolute_path)
        message = nested.message.lower()
        if "candidate_type" in path:
            return "UNSUPPORTED_CANDIDATE_TYPE"
        if "scope" in path or "raw_ids" in path:
            return "SCOPE_WIDENING"
        if "decision_record_id" in path:
            return "WRONG_GOVERNANCE_DECISION_ID"
        if "governance_transaction_hash" in path:
            return "WRONG_GOVERNANCE_TRANSACTION_HASH"
        if "selected_policy_form" in path or "version_policy" in path:
            return "VERSION_POLICY_INCOMPATIBILITY"
        if (
            "activation_boundary" in path
            or "zero_operational_effect" in path
            or (
                document.get("record_type")
                == "FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_RESOLUTION_ZERO_OPERATIONAL_EFFECT"
                and path.split(".")[-1]
                in {
                    "SOURCE_AUTHORITY_ACTIVATED",
                    "SOURCE_ACQUISITION",
                    "SOURCE_AUTH_EXECUTED",
                    "STAGE_A_ADMISSIONS",
                    "STAGE_B_EXPOSURES",
                    "FIELD_PINS",
                    "OPERATIVE_RECORDS",
                    "P0_EXECUTED",
                    "P1_EXECUTED",
                    "FORMAL_1796_EXPERIMENT_EXECUTED",
                }
            )
        ):
            return "FAKE_ACTIVATED_STATE"
        if "artifact_sha256" in path or "candidate_reference" in path:
            return "PROVENANCE_REFERENCE_MISMATCH"

    for nested in errors:
        if "additional properties" in nested.message.lower():
            return "UNAUTHORIZED_FIELD"
    if document.get("record_type", "").endswith("CANDIDATE_SET"):
        return "CANDIDATE_SET_INCONSISTENCY"
    return "SCHEMA_REJECTION"


def validate_document_schema(document: Any, schema: dict[str, Any]) -> None:
    try:
        Draft202012Validator(schema).validate(document)
    except ValidationError as exc:
        raise ResolutionValidationError(schema_code(document, exc), exc.message) from exc


def validate_entry_binding(entry: dict[str, Any]) -> None:
    require(entry["status"] == "PASS", "ENTRY_BINDING_AUTHENTICATION", "entry authentication is not PASS")
    require(entry["local_binding_head_observed"] == EXPECTED_HEAD, "ENTRY_BINDING_AUTHENTICATION", "local Binding head mismatch")
    require(entry["remote_tracking_binding_head_observed"] == EXPECTED_HEAD, "ENTRY_BINDING_AUTHENTICATION", "remote-tracking Binding head mismatch")
    require(entry["live_remote_head_from_authenticated_project_evidence"] == EXPECTED_HEAD, "ENTRY_BINDING_AUTHENTICATION", "authenticated live Binding head mismatch")
    require(entry["head_equality"] is True, "ENTRY_BINDING_AUTHENTICATION", "Binding heads are not equal")
    require(entry["design_materialization_commit"] == EXPECTED_HEAD, "ENTRY_BINDING_AUTHENTICATION", "design commit mismatch")
    require(entry["design_materialization_parent"] == EXPECTED_PARENT, "ENTRY_BINDING_AUTHENTICATION", "design parent mismatch")
    require(entry["design_independent_review_commit"] == EXPECTED_HEAD, "ENTRY_BINDING_AUTHENTICATION", "review commit mismatch")
    require(entry["unexplained_lineage_drift"] is False, "ENTRY_BINDING_AUTHENTICATION", "lineage drift is unexplained")
    require(entry["source_material_acquired"] is False and entry["source_objects_authenticated"] is False, "ENTRY_BINDING_AUTHENTICATION", "source operations occurred")


def validate_governance_binding(resolved: dict[str, Any], decision: dict[str, Any]) -> None:
    for document, key in ((resolved, "governance_binding"), (decision, "governance_binding")):
        binding = document[key]
        require(binding["decision_record_id"] == EXPECTED_DECISION_ID, "WRONG_GOVERNANCE_DECISION_ID", "decision ID mismatch")
        require(binding["governance_transaction_hash"] == EXPECTED_GOV_TX, "WRONG_GOVERNANCE_TRANSACTION_HASH", "governance transaction hash mismatch")
        require(binding["governance_scope"] == "FIRST_TRANCHE24_ONLY", "SCOPE_WIDENING", "governance scope mismatch")
        require(binding["human_governance_decision"] == "APPROVE_BOTH_G1_AND_G2", "GOVERNANCE_BINDING", "governance decision mismatch")

    design = resolved["design_contract_binding"]
    require(design["design_materialization_commit"] == EXPECTED_HEAD, "DESIGN_CONTRACT_BINDING", "design head mismatch")
    require(design["design_materialization_parent"] == EXPECTED_PARENT, "DESIGN_CONTRACT_BINDING", "design parent mismatch")
    require(design["design_independent_review_verdict"] == EXPECTED_REVIEW_VERDICT, "DESIGN_CONTRACT_BINDING", "design review verdict mismatch")


def validate_candidate_set(candidate_set: dict[str, Any]) -> dict[str, Any]:
    require(scope_is_exact(candidate_set["scope_reference"]), "SCOPE_WIDENING", "candidate-set scope is not the exact frozen tranche")
    search = candidate_set["search_space"]
    require(search["admissible_authority_type"] == "AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE", "CANDIDATE_SET_INCONSISTENCY", "authority type search space mismatch")
    require(search["admissible_source_class"] == "AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE", "CANDIDATE_SET_INCONSISTENCY", "source class search space mismatch")
    require(search["admissible_source_fact_type"] == "PINNED_CANONICAL_INTRINSIC_FIELD", "CANDIDATE_SET_INCONSISTENCY", "fact type search space mismatch")

    candidates = candidate_set["candidates"]
    statuses = [candidate.get("resolution_status") for candidate in candidates]
    resolved = [candidate for candidate in candidates if candidate.get("resolution_status") == "RESOLVED_CLASS_ONLY_VERSION_PENDING"]
    require(len(resolved) <= 1, "MULTIPLE_CANDIDATES_RESOLVED", "more than one candidate is marked resolved")
    require(len(resolved) == 1, "ZERO_RESOLVED_CANDIDATES", "no candidate is marked resolved while the package claims a unique result")
    selected = resolved[0]
    require(selected["candidate_id_or_local_reference"] == RESOLVED_REFERENCE, "UNSUPPORTED_CANDIDATE_TYPE", "resolved candidate is not the governed class reference")
    require(selected["candidate_type"] == "SOURCE_AUTHORITY_CANDIDATE_CLASS", "UNSUPPORTED_CANDIDATE_TYPE", "resolved candidate type is unsupported")
    require(selected["authority_type"] == "AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE", "CANDIDATE_SET_INCONSISTENCY", "resolved authority type mismatch")
    require(selected["source_class"] == "AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE", "CANDIDATE_SET_INCONSISTENCY", "resolved source class mismatch")
    require(selected["source_fact_type"] == "PINNED_CANONICAL_INTRINSIC_FIELD", "CANDIDATE_SET_INCONSISTENCY", "resolved fact type mismatch")
    require(scope_is_exact(selected["scope"]), "SCOPE_WIDENING", "resolved candidate scope mismatch")
    require(selected["identity_basis"]["authority_id_derivation_status"] == "NOT_DERIVED", "FAKE_AUTHORITY_ID", "candidate class derived an authority ID")

    rejected = [candidate for candidate in candidates if candidate.get("resolution_status") == "REJECTED"]
    require(len(rejected) == 2, "CANDIDATE_SET_INCONSISTENCY", "expected exactly two rejected alternatives")
    require({candidate["candidate_id_or_local_reference"] for candidate in rejected} == {WRAPPER_REFERENCE, HISTORICAL_REFERENCE}, "CANDIDATE_SET_INCONSISTENCY", "rejected alternatives changed")
    require(all(candidate.get("rejection_reason_if_rejected") for candidate in rejected), "CANDIDATE_SET_INCONSISTENCY", "rejected candidate lacks a reason")
    summary = candidate_set["inventory_summary"]
    require(summary["total_candidate_entries"] == len(candidates), "CANDIDATE_SET_INCONSISTENCY", "candidate count mismatch")
    require(summary["resolved_class_entries"] == 1 and summary["resolved_concrete_object_entries"] == 0, "CANDIDATE_SET_INCONSISTENCY", "resolved count summary mismatch")
    require(summary["rejected_entries"] == 2 and summary["plausible_unrejected_entries"] == 0, "CANDIDATE_SET_INCONSISTENCY", "rejection count summary mismatch")
    require(summary["ambiguous_candidate_set"] is False, "MULTIPLE_CANDIDATES_RESOLVED", "candidate set claims ambiguity or multiple resolution")
    return selected


def validate_resolved_record(resolved: dict[str, Any], candidate_set: dict[str, Any]) -> None:
    validate_governance_binding(resolved, read_json(ROOT / "CANDIDATE_RESOLUTION_DECISION.json"))
    require(scope_is_exact(resolved["scope_reference"]), "SCOPE_WIDENING", "resolved record scope mismatch")
    selected = resolved["resolved_candidate"]
    require(selected["candidate_id_or_local_reference"] == RESOLVED_REFERENCE, "UNSUPPORTED_CANDIDATE_TYPE", "resolved record points to another candidate")
    require(selected["candidate_status"] == "RESOLVED_CLASS_ONLY", "CANDIDATE_SET_INCONSISTENCY", "resolved candidate status mismatch")
    require(selected["authority_type"] == "AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE", "CANDIDATE_SET_INCONSISTENCY", "resolved record authority type mismatch")
    require(selected["source_class"] == "AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE", "CANDIDATE_SET_INCONSISTENCY", "resolved record source class mismatch")
    require(selected["source_fact_type"] == "PINNED_CANONICAL_INTRINSIC_FIELD", "CANDIDATE_SET_INCONSISTENCY", "resolved record fact type mismatch")
    require(selected["identity_basis"]["concrete_source_locator_status"] == "UNRESOLVED_PENDING_SOURCE_EVIDENCE", "CANDIDATE_SET_INCONSISTENCY", "concrete locator was invented")
    require(selected["identity_basis"]["content_digest_status"] == "UNRESOLVED_PENDING_SOURCE_EVIDENCE", "CANDIDATE_SET_INCONSISTENCY", "content digest was invented")
    expected_set_hash = file_sha256(ROOT / "CANDIDATE_SET.json")
    require(selected["competing_candidate_disposition"]["candidate_set_sha256"] == expected_set_hash, "CANDIDATE_SET_INCONSISTENCY", "candidate-set hash mismatch")
    require(resolved["source_authority_id_derivation"]["source_authority_id_derived"] is False, "FAKE_AUTHORITY_ID", "authority ID derivation was performed")
    require(resolved["source_authority_id_derivation"]["source_authority_id"] == "NONE", "FAKE_AUTHORITY_ID", "authority ID is not NONE")
    require(resolved["source_authority_id_derivation"]["source_authority_id_state"] == "NONE", "FAKE_AUTHORITY_ID", "authority ID state is not NONE")
    boundary = resolved["activation_boundary"]
    require(boundary["candidate_resolution_only"] is True, "FAKE_ACTIVATED_STATE", "record is not resolution-only")
    require(boundary["source_authority_activated"] == "NO", "FAKE_ACTIVATED_STATE", "authority is activated")
    require(boundary["source_acquisition"] == "NO" and boundary["source_auth_executed"] == "NO", "FAKE_ACTIVATED_STATE", "source operation occurred")
    require(boundary["stage_a_admissions"] == 0 and boundary["stage_b_exposures"] == 0 and boundary["field_pins"] == 0, "FAKE_ACTIVATED_STATE", "downstream state changed")
    require(boundary["operative_records"] == 0 and boundary["p0_executed"] == "NO" and boundary["p1_executed"] == "NO", "FAKE_ACTIVATED_STATE", "execution state changed")
    require(boundary["formal_1796_experiment_executed"] == "NO", "FAKE_ACTIVATED_STATE", "formal experiment state changed")


def validate_version_policy(version: dict[str, Any]) -> None:
    require(version["version_policy_resolution"] == "BLOCKED_PENDING_SOURCE_EVIDENCE", "VERSION_POLICY_INCOMPATIBILITY", "version policy is not explicitly pending")
    require(version["selected_policy_form"] == "UNRESOLVED_PENDING_SOURCE_EVIDENCE", "VERSION_POLICY_INCOMPATIBILITY", "version policy form was fabricated")
    for key in ("policy_id_status", "immutable_identifier_status", "content_sha256_status", "lineage_evidence_status", "owner_issuer_authorization_status"):
        require(version[key] == "UNRESOLVED_PENDING_SOURCE_EVIDENCE", "VERSION_POLICY_INCOMPATIBILITY", f"version evidence field {key} was fabricated")
    contract = version["required_policy_contract"]
    require(contract["floating_reference_allowed"] is False, "VERSION_POLICY_INCOMPATIBILITY", "floating references are enabled")
    require(contract["update_policy"] == "NEW_ACTIVATION_REQUIRED", "VERSION_POLICY_INCOMPATIBILITY", "update policy changed")


def validate_reference_hash(reference: str, reported_hash: str) -> None:
    path_text = reference.split("#", 1)[0]
    path = PROJECT_ROOT / path_text
    require(path.is_file(), "PROVENANCE_REFERENCE_MISMATCH", f"evidence file is missing: {reference}")
    require(file_sha256(path) == reported_hash, "PROVENANCE_REFERENCE_MISMATCH", f"evidence hash mismatch: {reference}")


def validate_provenance(provenance: dict[str, Any]) -> None:
    require(provenance["map_status"] == "PASS_CLASS_ONLY", "PROVENANCE_REFERENCE_MISMATCH", "provenance map is not class-only PASS")
    require(provenance["resolved_candidate_reference"] == RESOLVED_REFERENCE, "MIXED_CANDIDATE_EVIDENCE", "provenance map resolved reference mismatch")
    claims = provenance["claims"]
    require(len({claim["claim_id"] for claim in claims}) == len(claims), "PROVENANCE_REFERENCE_MISMATCH", "claim IDs are not unique")
    supporting = [claim for claim in claims if claim["supports_resolved_candidate"] is True]
    require(supporting, "PROVENANCE_REFERENCE_MISMATCH", "no claims support the resolved candidate")
    supporting_candidates = {claim["candidate_reference"] for claim in supporting}
    require(supporting_candidates == {RESOLVED_REFERENCE}, "MIXED_CANDIDATE_EVIDENCE", "supporting claims mix candidate identities")
    for claim in claims:
        validate_reference_hash(claim["artifact_reference"], claim["artifact_sha256"])
        require(claim["commit"] == EXPECTED_HEAD, "PROVENANCE_REFERENCE_MISMATCH", f"claim commit mismatch: {claim['claim_id']}")
        if claim["supports_resolved_candidate"]:
            require(claim["limits_claim_to_class_only"] is True, "MIXED_CANDIDATE_EVIDENCE", f"claim exceeds class-only boundary: {claim['claim_id']}")
        else:
            require(claim["candidate_reference"] in {WRAPPER_REFERENCE, HISTORICAL_REFERENCE}, "MIXED_CANDIDATE_EVIDENCE", f"unknown rejected candidate in {claim['claim_id']}")
            require(claim["limits_claim_to_class_only"] is False, "MIXED_CANDIDATE_EVIDENCE", f"elimination claim is marked as class evidence: {claim['claim_id']}")


def validate_decision(decision: dict[str, Any]) -> None:
    validate_governance_binding(read_json(ROOT / "RESOLVED_CANDIDATE_RECORD.json"), decision)
    require(decision["decision"] == "CANDIDATE_RESOLVED_VERSION_EVIDENCE_PENDING", "CANDIDATE_SET_INCONSISTENCY", "decision state mismatch")
    require(decision["resolved_candidate_reference"] == RESOLVED_REFERENCE, "UNSUPPORTED_CANDIDATE_TYPE", "decision resolved candidate mismatch")
    require(decision["resolved_candidate_type"] == "SOURCE_AUTHORITY_CANDIDATE_CLASS", "UNSUPPORTED_CANDIDATE_TYPE", "decision candidate type mismatch")
    require(decision["version_policy_resolution"] == "BLOCKED_PENDING_SOURCE_EVIDENCE", "VERSION_POLICY_INCOMPATIBILITY", "decision version state mismatch")
    require(decision["source_authority_id_derived"] == "NO" and decision["source_authority_id"] == "NONE", "FAKE_AUTHORITY_ID", "decision contains an authority ID")
    require(decision["activation_status"] == "NOT_ACTIVATED", "FAKE_ACTIVATED_STATE", "decision claims activation")


def validate_zero_effect(zero: dict[str, Any]) -> None:
    require(zero["NEW_SOURCE_AUTHORITY_ID_CREATED"] == 0, "FAKE_ACTIVATED_STATE", "new authority ID was created")
    require(zero["SOURCE_AUTHORITY_ACTIVATED"] == "NO", "FAKE_ACTIVATED_STATE", "authority is activated")
    require(zero["SOURCE_ACQUISITION"] == "NO" and zero["SOURCE_AUTH_EXECUTED"] == "NO", "FAKE_ACTIVATED_STATE", "source operations occurred")
    require(zero["STAGE_A_ADMISSIONS"] == 0 and zero["STAGE_B_EXPOSURES"] == 0 and zero["FIELD_PINS"] == 0, "FAKE_ACTIVATED_STATE", "downstream records changed")
    require(zero["OPERATIVE_RECORDS"] == 0 and zero["P0_EXECUTED"] == "NO" and zero["P1_EXECUTED"] == "NO", "FAKE_ACTIVATED_STATE", "execution state changed")
    require(zero["FORMAL_1796_EXPERIMENT_EXECUTED"] == "NO", "FAKE_ACTIVATED_STATE", "formal experiment executed")
    require(zero["candidate_resolution_only"] is True and zero["source_authority_id_derived"] == "NO", "FAKE_ACTIVATED_STATE", "zero-effect boundary changed")


def apply_mutation(value: Any, mutation: dict[str, Any]) -> Any:
    target = value
    for component in mutation["path"][:-1]:
        target = target[component]
    leaf = mutation["path"][-1]
    operation = mutation["operation"]
    if operation == "replace":
        target[leaf] = copy.deepcopy(mutation["value"])
    elif operation == "remove":
        target.pop(leaf)
    elif operation == "add":
        target[leaf] = copy.deepcopy(mutation["value"])
    else:
        raise ResolutionValidationError("MALFORMED_FIXTURE", f"unsupported fixture operation: {operation}")
    return value


def validate_fixture(descriptor: dict[str, Any], schema: dict[str, Any], documents: dict[str, Any]) -> str:
    target_name = descriptor["base_fixture"]
    require(target_name in documents, "MALFORMED_FIXTURE", f"fixture targets an unknown base document: {target_name}")
    candidate = copy.deepcopy(documents[target_name])
    for mutation in descriptor["mutations"]:
        apply_mutation(candidate, mutation)
    if candidate.get("record_type") == "FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_SET":
        resolved_status = "RESOLVED_CLASS_ONLY_VERSION_PENDING"
        resolved_count = sum(
            item.get("resolution_status") == resolved_status
            for item in candidate.get("candidates", [])
        )
        if resolved_count > 1:
            raise ResolutionValidationError(
                "MULTIPLE_CANDIDATES_RESOLVED",
                "more than one candidate is marked resolved",
            )
    validate_document_schema(candidate, schema)
    record_type = candidate.get("record_type", "")
    if record_type == "FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_SET":
        validate_candidate_set(candidate)
    elif record_type == "FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_RESOLUTION":
        validate_resolved_record(candidate, documents["CANDIDATE_SET.json"])
    elif record_type == "FIRST_TRANCHE24_SOURCE_AUTHORITY_VERSION_POLICY_RESOLUTION":
        validate_version_policy(candidate)
    elif record_type == "FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_PROVENANCE_EVIDENCE_MAP":
        validate_provenance(candidate)
    elif record_type == "FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_RESOLUTION_DECISION":
        validate_decision(candidate)
    elif record_type == "FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_RESOLUTION_ZERO_OPERATIONAL_EFFECT":
        validate_zero_effect(candidate)
    else:
        raise ResolutionValidationError("SCHEMA_REJECTION", f"unknown fixture record type: {record_type}")
    raise ResolutionValidationError("NEGATIVE_FIXTURE_ACCEPTED", f"fixture was accepted: {descriptor['fixture']}")


def validate_negative_fixtures(schema: dict[str, Any], documents: dict[str, Any]) -> list[dict[str, str]]:
    index = read_json(ROOT / "fixtures" / "NEGATIVE_FIXTURE_INDEX.json")
    results: list[dict[str, str]] = []
    for entry in index["fixtures"]:
        descriptor = read_json(ROOT / "fixtures" / "negative" / entry["fixture"])
        require(
            descriptor.get("base_fixture") == entry["target"],
            "MALFORMED_FIXTURE",
            f"{entry['fixture']}: descriptor base fixture does not match the fixture index",
        )
        try:
            validate_fixture(descriptor, schema, documents)
        except ResolutionValidationError as exc:
            require(exc.code == entry["expected_rejection"], "NEGATIVE_FIXTURE_MISMATCH", f"{entry['fixture']}: expected {entry['expected_rejection']}, got {exc.code}")
            results.append({"fixture": entry["fixture"], "rejection": exc.code})
    return results


def validate_package() -> dict[str, Any]:
    schema = read_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    documents = load_documents()
    for document in documents.values():
        validate_document_schema(document, schema)

    validate_entry_binding(documents["evidence/ENTRY_BINDING_AUTHENTICATION.json"])
    selected = validate_candidate_set(documents["CANDIDATE_SET.json"])
    validate_resolved_record(documents["RESOLVED_CANDIDATE_RECORD.json"], documents["CANDIDATE_SET.json"])
    validate_version_policy(documents["VERSION_POLICY_RESOLUTION.json"])
    validate_provenance(documents["PROVENANCE_EVIDENCE_MAP.json"])
    validate_decision(documents["CANDIDATE_RESOLUTION_DECISION.json"])
    validate_zero_effect(documents["evidence/ZERO_OPERATIONAL_EFFECT.json"])
    require(selected["candidate_id_or_local_reference"] == RESOLVED_REFERENCE, "CANDIDATE_SET_INCONSISTENCY", "selected class differs across package")
    require(documents["VERSION_POLICY_RESOLUTION.json"]["candidate_reference"] == RESOLVED_REFERENCE, "VERSION_POLICY_INCOMPATIBILITY", "version policy candidate differs")
    require(documents["PROVENANCE_EVIDENCE_MAP.json"]["resolved_candidate_reference"] == RESOLVED_REFERENCE, "PROVENANCE_REFERENCE_MISMATCH", "provenance candidate differs")
    negative = validate_negative_fixtures(schema, documents)
    return {
        "schema_validation": "PASS",
        "entry_binding_authentication": "PASS",
        "governance_binding": "PASS",
        "first_tranche24_scope_exactness": "PASS",
        "candidate_set_consistency": "PASS",
        "provenance_map_consistency": "PASS",
        "version_policy_compatibility": "PASS_PENDING",
        "negative_fixtures_rejected": len(negative),
        "negative_fixture_codes": [item["rejection"] for item in negative],
        "zero_operational_effect": "PASS",
        "candidate_resolution_state": "CANDIDATE_RESOLVED_VERSION_EVIDENCE_PENDING",
    }


if __name__ == "__main__":
    try:
        print(json.dumps(validate_package(), indent=2, sort_keys=True))
    except ResolutionValidationError as exc:
        print(json.dumps({"status": "FAIL", "code": exc.code, "message": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)
