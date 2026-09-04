#!/usr/bin/env python3
"""Fail-closed static validator for source-version evidence resolution.

This module reads local package files and authenticated project artifacts only.
It has no network, source-acquisition, activation, or downstream capability.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent
EXPECTED_HEAD = "6171a460ef527b99f2176eb047d51ca7082d067a"
EXPECTED_PREVIOUS_HEAD = "62c822589ac783c04a4a02af13ca0c4548892aac"
EXPECTED_DECISION_ID = "GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f"
EXPECTED_GOVERNANCE_HASH = "b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38"
EXPECTED_CANDIDATE = "03_frozen_lineage/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json#class_to_type_mapping[0]"
EXPECTED_SCOPE = [110, 273, 210, 98, 147, 277, 188, 301, 143, 250, 233, 287, 146, 293, 114, 284, 291, 215, 88, 182, 300, 218, 115, 148]
SUPPORTED_FORMS = ["CONTENT_DIGEST", "GIT_COMMIT", "RELEASE_TAG_WITH_DIGEST"]
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ResolutionValidationError(ValueError):
    """Stable fail-closed rejection with a machine-readable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ResolutionValidationError(code, message)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResolutionValidationError("MALFORMED_OR_MISSING_JSON", f"cannot read {path}: {exc}") from exc


def file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ResolutionValidationError("MISSING_AUTHENTICATED_EVIDENCE", f"cannot hash {path}: {exc}") from exc


def closed_keys(document: dict[str, Any], expected: set[str]) -> None:
    extras = set(document) - expected
    require(not extras, "UNAUTHORIZED_FIELD", f"unauthorized fields: {sorted(extras)}")
    missing = expected - set(document)
    require(not missing, "MISSING_REQUIRED_FIELD", f"missing fields: {sorted(missing)}")


def load_documents() -> dict[str, Any]:
    names = [
        "CANONICAL_ARTIFACT_IDENTITY_RESOLUTION.json",
        "IMMUTABLE_VERSION_POLICY_RESOLUTION.json",
        "CONTENT_DIGEST_RESOLUTION.json",
        "AUTHORITY_DESCRIPTOR_ARTIFACT_LINEAGE.json",
        "OWNER_ISSUER_AUTHORIZATION_RESOLUTION.json",
        "VERSION_EVIDENCE_INVENTORY.json",
        "VERSION_EVIDENCE_RESOLUTION_RECORD.json",
        "evidence/ENTRY_BINDING_AUTHENTICATION.json",
        "evidence/AUTHENTICATED_EVIDENCE_SOURCE_INDEX.json",
        "evidence/ZERO_OPERATIONAL_EFFECT.json",
    ]
    return {name: read_json(ROOT / name) for name in names}


def validate_entry_binding(document: dict[str, Any]) -> None:
    expected = {
        "record_type", "status", "binding_repository", "binding_worktree", "binding_branch",
        "local_binding_head", "remote_binding_head", "live_remote_binding_head", "previous_remote_head",
        "transition_commit", "transition_parent", "transition_commit_message", "transition_payload_scope",
        "head_equality", "direct_parent_transition", "unexplained_lineage_drift", "authenticated_at_date",
        "source_acquisition_performed", "external_source_objects_fetched",
    }
    closed_keys(document, expected)
    require(document["status"] == "PASS", "ENTRY_BINDING_AUTHENTICATION", "entry authentication is not PASS")
    for key in ("local_binding_head", "remote_binding_head", "live_remote_binding_head", "transition_commit"):
        require(document[key] == EXPECTED_HEAD, "ENTRY_BINDING_AUTHENTICATION", f"{key} mismatch")
    require(document["previous_remote_head"] == EXPECTED_PREVIOUS_HEAD, "ENTRY_BINDING_AUTHENTICATION", "previous remote head mismatch")
    require(document["transition_parent"] == EXPECTED_PREVIOUS_HEAD, "ENTRY_BINDING_AUTHENTICATION", "transition parent mismatch")
    require(document["transition_commit_message"] == "materialize binding: FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_RESOLUTION_INDEPENDENT_REVIEW_R3", "ENTRY_BINDING_AUTHENTICATION", "transition message mismatch")
    require(document["transition_payload_scope"] == "CANDIDATE_RESOLUTION_INDEPENDENT_REVIEW_R3_ONLY", "ENTRY_BINDING_AUTHENTICATION", "transition scope mismatch")
    require(document["head_equality"] is True and document["direct_parent_transition"] is True, "ENTRY_BINDING_AUTHENTICATION", "head or direct-parent authentication failed")
    require(document["unexplained_lineage_drift"] is False, "ENTRY_BINDING_AUTHENTICATION", "unexplained lineage drift")
    require(document["source_acquisition_performed"] is False and document["external_source_objects_fetched"] is False, "SOURCE_ACQUISITION_PROHIBITED", "source acquisition occurred")


def validate_source_index(document: dict[str, Any]) -> None:
    closed_keys(document, {"record_type", "binding_head", "sources", "external_sources_queried", "source_objects_acquired"})
    require(document["binding_head"] == EXPECTED_HEAD, "ENTRY_BINDING_AUTHENTICATION", "source index Binding head mismatch")
    require(document["external_sources_queried"] is False and document["source_objects_acquired"] is False, "SOURCE_ACQUISITION_PROHIBITED", "source index records source acquisition")
    require(len(document["sources"]) == 12, "EVIDENCE_INVENTORY_INCONSISTENCY", "unexpected authenticated source count")
    seen: set[str] = set()
    for item in document["sources"]:
        closed_keys(item, {"reference", "sha256", "commit_or_lineage_reference", "claim_supported", "authentication_status"})
        require(item["reference"] not in seen, "EVIDENCE_INVENTORY_INCONSISTENCY", "duplicate evidence reference")
        seen.add(item["reference"])
        require(SHA256_RE.fullmatch(item["sha256"]) is not None, "EVIDENCE_INVENTORY_INCONSISTENCY", f"invalid hash for {item['reference']}")
        path = PROJECT_ROOT / item["reference"].split("#", 1)[0]
        require(path.is_file(), "MISSING_AUTHENTICATED_EVIDENCE", f"missing evidence {item['reference']}")
        require(file_sha256(path) == item["sha256"], "AUTHENTICATED_EVIDENCE_HASH_MISMATCH", f"hash mismatch for {item['reference']}")
        require(item["authentication_status"].startswith("PASS"), "EVIDENCE_INVENTORY_INCONSISTENCY", f"evidence is not authenticated: {item['reference']}")


def validate_identity(document: dict[str, Any]) -> None:
    expected = {
        "record_type", "candidate_reference", "required_source_artifact_class", "required_source_fact_type",
        "CANONICAL_ARTIFACT_IDENTITY_STATUS", "CANONICAL_ARTIFACT_IDENTITY", "identity_bearing_elements",
        "eligible_artifact_instances_found", "excluded_artifact_instances", "ambiguity_status",
        "resolution_basis_references",
    }
    closed_keys(document, expected)
    require(document["candidate_reference"] == EXPECTED_CANDIDATE, "ARTIFACT_IDENTITY_MISMATCH", "candidate reference mismatch")
    status = document["CANONICAL_ARTIFACT_IDENTITY_STATUS"]
    if status == "AMBIGUOUS":
        raise ResolutionValidationError("AMBIGUOUS_ARTIFACT_IDENTITY", "more than one artifact remains plausible")
    require(status == "MISSING", "ARTIFACT_IDENTITY_MISMATCH", "artifact identity status is not MISSING")
    require(document["CANONICAL_ARTIFACT_IDENTITY"] == "NONE", "ARTIFACT_IDENTITY_MISMATCH", "artifact identity was invented")
    require(document["eligible_artifact_instances_found"] == 0, "ARTIFACT_IDENTITY_MISMATCH", "eligible artifact count is not zero")
    require(document["ambiguity_status"] == "NOT_AMBIGUOUS_NO_ELIGIBLE_INSTANCE", "AMBIGUOUS_ARTIFACT_IDENTITY", "ambiguity classification mismatch")
    elements = document["identity_bearing_elements"]
    require(set(elements.values()) == {"NONE"}, "ARTIFACT_IDENTITY_MISMATCH", "identity-bearing value was invented")
    excluded = document["excluded_artifact_instances"]
    require(len(excluded) == 3, "ARTIFACT_IDENTITY_MISMATCH", "excluded artifact inventory changed")
    require(all(SHA256_RE.fullmatch(item["content_sha256"]) for item in excluded), "ARTIFACT_IDENTITY_MISMATCH", "excluded artifact hash malformed")


def validate_version_policy(document: dict[str, Any]) -> None:
    expected = {
        "record_type", "candidate_reference", "policy_contract_reference", "policy_version",
        "design_supported_forms", "IMMUTABLE_VERSION_FORM", "IMMUTABLE_VERSION_IDENTIFIER",
        "VERSION_FORM_SUPPORTED_BY_DESIGN", "VERSION_FORM_AUTHENTICATED_BY_EVIDENCE", "FLOATING_REFERENCE",
        "VERSION_POLICY_RESOLUTION", "elimination_logic", "required_acquisition",
    }
    closed_keys(document, expected)
    require(document["candidate_reference"] == EXPECTED_CANDIDATE, "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "candidate reference mismatch")
    require(document["design_supported_forms"] == SUPPORTED_FORMS, "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "supported form list changed")
    if document["FLOATING_REFERENCE"] == "YES":
        raise ResolutionValidationError("FLOATING_VERSION_REFERENCE", "floating version reference")
    require(document["FLOATING_REFERENCE"] == "NO", "FLOATING_VERSION_REFERENCE", "floating-reference state malformed")
    form = document["IMMUTABLE_VERSION_FORM"]
    if form not in ["NONE", *SUPPORTED_FORMS]:
        raise ResolutionValidationError("UNSUPPORTED_IMMUTABLE_VERSION_FORM", f"unsupported form {form}")
    require(form == "NONE", "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "version form selected without source evidence")
    require(document["IMMUTABLE_VERSION_IDENTIFIER"] == "NONE", "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "immutable identifier invented")
    require(document["VERSION_FORM_SUPPORTED_BY_DESIGN"] == "NO", "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "NONE cannot be marked supported")
    require(document["VERSION_FORM_AUTHENTICATED_BY_EVIDENCE"] == "NO", "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "version form falsely authenticated")
    require(document["VERSION_POLICY_RESOLUTION"] == "BLOCKED_PENDING_SOURCE_ACQUISITION", "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "version policy terminal state mismatch")


def validate_digest(document: dict[str, Any]) -> None:
    expected = {
        "record_type", "candidate_reference", "canonical_artifact_identity", "CONTENT_SHA256_RESOLVED",
        "CONTENT_SHA256", "digest_algorithm_required", "digest_binding_status", "evidence_version_consistency",
        "excluded_digests", "provenance_reference", "required_acquisition",
    }
    closed_keys(document, expected)
    if document["evidence_version_consistency"] != "PASS_SINGLE_PENDING_VERSION_STATE":
        raise ResolutionValidationError("MIXED_ARTIFACT_VERSIONS", "evidence mixes artifact versions")
    if document["digest_binding_status"] == "WRONG_ARTIFACT":
        raise ResolutionValidationError("DIGEST_FROM_WRONG_ARTIFACT", "digest belongs to another artifact")
    if document["CONTENT_SHA256_RESOLVED"] == "YES" or document["CONTENT_SHA256"] != "NONE" or document["digest_binding_status"] != "BLOCKED_NO_CANONICAL_ARTIFACT":
        raise ResolutionValidationError("CONTENT_SHA_MISMATCH", "content digest is unsupported or mismatched")
    require(document["canonical_artifact_identity"] == "NONE", "CONTENT_SHA_MISMATCH", "digest bound to invented artifact")
    require(document["digest_algorithm_required"] == "SHA-256", "CONTENT_SHA_MISMATCH", "digest algorithm changed")
    require(len(document["excluded_digests"]) == 3, "DIGEST_FROM_WRONG_ARTIFACT", "excluded digest inventory changed")


def validate_lineage(document: dict[str, Any]) -> None:
    expected = {
        "record_type", "candidate_reference", "authority_descriptor", "lineage_edges",
        "AUTHORITY_TO_ARTIFACT_LINEAGE", "lineage_proof_complete", "lineage_not_inferred_from_naming",
    }
    closed_keys(document, expected)
    require(document["candidate_reference"] == EXPECTED_CANDIDATE, "BROKEN_AUTHORITY_TO_ARTIFACT_LINEAGE", "lineage candidate mismatch")
    require(len(document["lineage_edges"]) == 3, "BROKEN_AUTHORITY_TO_ARTIFACT_LINEAGE", "lineage edge count mismatch")
    if any(edge["status"] not in {"BLOCKED"} for edge in document["lineage_edges"]):
        raise ResolutionValidationError("BROKEN_AUTHORITY_TO_ARTIFACT_LINEAGE", "lineage contains a broken or unsupported edge")
    require(document["AUTHORITY_TO_ARTIFACT_LINEAGE"] == "BLOCKED", "BROKEN_AUTHORITY_TO_ARTIFACT_LINEAGE", "lineage falsely passes")
    require(document["lineage_proof_complete"] is False and document["lineage_not_inferred_from_naming"] is True, "BROKEN_AUTHORITY_TO_ARTIFACT_LINEAGE", "lineage boundary mismatch")


def validate_owner_authorization(document: dict[str, Any]) -> None:
    expected = {
        "record_type", "candidate_reference", "OWNER_ISSUER_AUTHORIZATION", "authorization_subject",
        "authorization_object_or_artifact", "authorization_scope", "authorization_evidence_reference",
        "authentication_status", "required_authorization_elements", "negative_evidence_reference", "reason",
    }
    closed_keys(document, expected)
    require(document["candidate_reference"] == EXPECTED_CANDIDATE, "MISSING_OWNER_ISSUER_AUTHORIZATION", "owner candidate mismatch")
    require(document["OWNER_ISSUER_AUTHORIZATION"] == "MISSING", "MISSING_OWNER_ISSUER_AUTHORIZATION", "unsupported owner authorization state")
    require(document["authorization_subject"] == "NONE" and document["authorization_object_or_artifact"] == "NONE" and document["authorization_scope"] == "NONE", "MISSING_OWNER_ISSUER_AUTHORIZATION", "owner authorization inferred without evidence")
    require(document["authentication_status"] == "MISSING", "MISSING_OWNER_ISSUER_AUTHORIZATION", "owner authorization falsely authenticated")
    require(len(document["required_authorization_elements"]) == 8, "MISSING_OWNER_ISSUER_AUTHORIZATION", "authorization requirements incomplete")


def validate_inventory(document: dict[str, Any]) -> None:
    closed_keys(document, {"record_type", "schema_version", "task_id", "candidate_reference", "scope", "evidence_classes", "VERSION_EVIDENCE_INVENTORY_CONSISTENCY"})
    expected_classes = {
        "canonical_artifact_identity", "immutable_version_form", "content_digest",
        "authority_descriptor_artifact_lineage", "owner_issuer_authorization",
    }
    require(set(document["evidence_classes"]) == expected_classes, "EVIDENCE_INVENTORY_INCONSISTENCY", "five evidence classes are not represented exactly")
    for name, evidence_class in document["evidence_classes"].items():
        closed_keys(evidence_class, {"status", "items"})
        require(evidence_class["status"] == "MISSING", "EVIDENCE_INVENTORY_INCONSISTENCY", f"{name} status is not MISSING")
        require(evidence_class["items"], "EVIDENCE_INVENTORY_INCONSISTENCY", f"{name} has no evidence items")
        for item in evidence_class["items"]:
            closed_keys(item, {"evidence_id_or_reference", "evidence_type", "artifact_path_or_reference", "commit_or_lineage_reference", "sha256_if_applicable", "claim_supported", "authentication_status"})
            reported = item["sha256_if_applicable"]
            if SHA256_RE.fullmatch(reported):
                path = PROJECT_ROOT / item["artifact_path_or_reference"].split("#", 1)[0]
                require(path.is_file(), "MISSING_AUTHENTICATED_EVIDENCE", f"missing inventory evidence {path}")
                require(file_sha256(path) == reported, "AUTHENTICATED_EVIDENCE_HASH_MISMATCH", f"inventory hash mismatch for {path}")
            else:
                require(reported == "COMPUTED_AT_MATERIALIZATION", "EVIDENCE_INVENTORY_INCONSISTENCY", f"invalid inventory hash marker for {name}")
            require(item["authentication_status"].startswith("PASS"), "EVIDENCE_INVENTORY_INCONSISTENCY", f"inventory evidence is not authenticated for {name}")
    require(document["VERSION_EVIDENCE_INVENTORY_CONSISTENCY"] == "PASS", "EVIDENCE_INVENTORY_INCONSISTENCY", "inventory does not claim PASS")


def validate_resolution_record(document: dict[str, Any], owner: dict[str, Any]) -> None:
    expected = {
        "record_type", "schema_version", "task_id", "resolution_state", "candidate_resolution_state",
        "candidate_reference", "resolved_candidate_type", "authority_type", "source_fact_type",
        "governance_binding", "evidence_requirements", "source_authority_id_derived", "source_authority_id",
        "source_authority_id_state", "activation_boundary", "missing_evidence", "required_acquisition_objects",
        "required_authentication_checks", "SOURCE_AUTHORITY_ACTIVATED", "SOURCE_ACQUISITION",
        "SOURCE_AUTH_EXECUTED", "STAGE_A_ADMISSIONS", "STAGE_B_EXPOSURES", "FIELD_PINS",
        "OPERATIVE_RECORDS", "P0_EXECUTED", "P1_EXECUTED", "FORMAL_1796_EXPERIMENT_EXECUTED",
        "ZERO_OPERATIONAL_EFFECT",
    }
    closed_keys(document, expected)
    governance = document["governance_binding"]
    require(governance["decision_record_id"] == EXPECTED_DECISION_ID, "WRONG_GOVERNANCE_DECISION_BINDING", "governance decision ID mismatch")
    require(governance["governance_transaction_hash"] == EXPECTED_GOVERNANCE_HASH, "WRONG_GOVERNANCE_DECISION_BINDING", "governance transaction hash mismatch")
    require(governance["governance_scope"] == "FIRST_TRANCHE24_ONLY" and governance["human_governance_decision"] == "APPROVE_BOTH_G1_AND_G2", "WRONG_GOVERNANCE_DECISION_BINDING", "governance binding mismatch")
    require(governance["raw_ids"] == EXPECTED_SCOPE and governance["scope_extension_permitted"] is False, "SCOPE_WIDENING", "scope differs from exact first tranche")
    require(document["candidate_reference"] == EXPECTED_CANDIDATE, "ARTIFACT_IDENTITY_MISMATCH", "resolution candidate mismatch")
    if document["resolution_state"] == "VERSION_EVIDENCE_RESOLVED" and owner["OWNER_ISSUER_AUTHORIZATION"] != "PASS":
        raise ResolutionValidationError("MISSING_OWNER_ISSUER_AUTHORIZATION", "resolved state lacks owner/issuer authorization")
    require(document["resolution_state"] == "VERSION_EVIDENCE_REQUIRES_SOURCE_ACQUISITION", "TERMINAL_STATE_INCONSISTENCY", "resolution state changed")
    require(set(document["evidence_requirements"].values()) == {"MISSING"}, "TERMINAL_STATE_INCONSISTENCY", "evidence requirement status changed")
    require(len(document["missing_evidence"]) == 5 and len(document["required_acquisition_objects"]) == 5, "TERMINAL_STATE_INCONSISTENCY", "bounded blocker list changed")
    require(document["source_authority_id_derived"] == "NO" and document["source_authority_id"] == "NONE" and document["source_authority_id_state"] == "NONE", "PREMATURE_SOURCE_AUTHORITY_ID", "source authority ID was derived")
    zero_values = {
        "SOURCE_AUTHORITY_ACTIVATED": "NO", "SOURCE_ACQUISITION": "NO", "SOURCE_AUTH_EXECUTED": "NO",
        "STAGE_A_ADMISSIONS": 0, "STAGE_B_EXPOSURES": 0, "FIELD_PINS": 0, "OPERATIVE_RECORDS": 0,
        "P0_EXECUTED": "NO", "P1_EXECUTED": "NO", "FORMAL_1796_EXPERIMENT_EXECUTED": "NO",
    }
    for key, value in zero_values.items():
        require(document[key] == value and document["activation_boundary"][key] == value, "ZERO_OPERATIONAL_EFFECT_FAILURE", f"{key} changed")
    require(document["ZERO_OPERATIONAL_EFFECT"] == "PASS", "ZERO_OPERATIONAL_EFFECT_FAILURE", "zero-effect status changed")


def validate_zero_effect(document: dict[str, Any]) -> None:
    expected = {
        "record_type", "SOURCE_AUTHORITY_ACTIVATED", "SOURCE_ACQUISITION", "SOURCE_AUTH_EXECUTED",
        "STAGE_A_ADMISSIONS", "STAGE_B_EXPOSURES", "FIELD_PINS", "OPERATIVE_RECORDS", "P0_EXECUTED",
        "P1_EXECUTED", "FORMAL_1796_EXPERIMENT_EXECUTED", "SOURCE_AUTHORITY_ID_DERIVED",
        "SOURCE_AUTHORITY_ID", "ZERO_OPERATIONAL_EFFECT",
    }
    closed_keys(document, expected)
    require(document["SOURCE_AUTHORITY_ACTIVATED"] == "NO" and document["SOURCE_ACQUISITION"] == "NO" and document["SOURCE_AUTH_EXECUTED"] == "NO", "ZERO_OPERATIONAL_EFFECT_FAILURE", "source operational state changed")
    require(document["STAGE_A_ADMISSIONS"] == 0 and document["STAGE_B_EXPOSURES"] == 0 and document["FIELD_PINS"] == 0 and document["OPERATIVE_RECORDS"] == 0, "ZERO_OPERATIONAL_EFFECT_FAILURE", "downstream state changed")
    require(document["P0_EXECUTED"] == "NO" and document["P1_EXECUTED"] == "NO" and document["FORMAL_1796_EXPERIMENT_EXECUTED"] == "NO", "ZERO_OPERATIONAL_EFFECT_FAILURE", "execution occurred")
    require(document["SOURCE_AUTHORITY_ID_DERIVED"] == "NO" and document["SOURCE_AUTHORITY_ID"] == "NONE", "PREMATURE_SOURCE_AUTHORITY_ID", "source authority ID was derived")
    require(document["ZERO_OPERATIONAL_EFFECT"] == "PASS", "ZERO_OPERATIONAL_EFFECT_FAILURE", "zero-effect status mismatch")


def apply_mutation(value: Any, mutation: dict[str, Any]) -> Any:
    target = value
    for component in mutation["path"][:-1]:
        target = target[component]
    leaf = mutation["path"][-1]
    operation = mutation["operation"]
    if operation == "replace":
        target[leaf] = copy.deepcopy(mutation["value"])
    elif operation == "add":
        if isinstance(target, list) and isinstance(leaf, int) and leaf == len(target):
            target.append(copy.deepcopy(mutation["value"]))
        else:
            target[leaf] = copy.deepcopy(mutation["value"])
    else:
        raise ResolutionValidationError("MALFORMED_FIXTURE", f"unsupported mutation {operation}")
    return value


def validate_mutated_document(name: str, document: dict[str, Any], documents: dict[str, Any]) -> None:
    if name == "CANONICAL_ARTIFACT_IDENTITY_RESOLUTION.json":
        validate_identity(document)
    elif name == "IMMUTABLE_VERSION_POLICY_RESOLUTION.json":
        validate_version_policy(document)
    elif name == "CONTENT_DIGEST_RESOLUTION.json":
        validate_digest(document)
    elif name == "AUTHORITY_DESCRIPTOR_ARTIFACT_LINEAGE.json":
        validate_lineage(document)
    elif name == "VERSION_EVIDENCE_RESOLUTION_RECORD.json":
        validate_resolution_record(document, documents["OWNER_ISSUER_AUTHORIZATION_RESOLUTION.json"])
    else:
        raise ResolutionValidationError("MALFORMED_FIXTURE", f"unknown fixture target {name}")
    raise ResolutionValidationError("NEGATIVE_FIXTURE_ACCEPTED", f"negative fixture accepted for {name}")


def validate_negative_fixtures(documents: dict[str, Any] | None = None) -> list[dict[str, str]]:
    if documents is None:
        documents = load_documents()
    index = read_json(ROOT / "fixtures" / "NEGATIVE_FIXTURE_INDEX.json")
    results: list[dict[str, str]] = []
    for item in index["fixtures"]:
        descriptor = read_json(ROOT / "fixtures" / "negative" / item["fixture"])
        require(descriptor["base_fixture"] == item["target"], "MALFORMED_FIXTURE", f"fixture target mismatch: {item['fixture']}")
        candidate = copy.deepcopy(documents[item["target"]])
        for mutation in descriptor["mutations"]:
            apply_mutation(candidate, mutation)
        try:
            validate_mutated_document(item["target"], candidate, documents)
        except ResolutionValidationError as exc:
            require(exc.code == item["expected_rejection"], "NEGATIVE_FIXTURE_MISMATCH", f"{item['fixture']}: expected {item['expected_rejection']}, got {exc.code}")
            results.append({"fixture": item["fixture"], "rejection": exc.code})
    return results


def validate_package() -> dict[str, Any]:
    documents = load_documents()
    validate_entry_binding(documents["evidence/ENTRY_BINDING_AUTHENTICATION.json"])
    validate_source_index(documents["evidence/AUTHENTICATED_EVIDENCE_SOURCE_INDEX.json"])
    validate_identity(documents["CANONICAL_ARTIFACT_IDENTITY_RESOLUTION.json"])
    validate_version_policy(documents["IMMUTABLE_VERSION_POLICY_RESOLUTION.json"])
    validate_digest(documents["CONTENT_DIGEST_RESOLUTION.json"])
    validate_lineage(documents["AUTHORITY_DESCRIPTOR_ARTIFACT_LINEAGE.json"])
    validate_owner_authorization(documents["OWNER_ISSUER_AUTHORIZATION_RESOLUTION.json"])
    validate_inventory(documents["VERSION_EVIDENCE_INVENTORY.json"])
    validate_resolution_record(documents["VERSION_EVIDENCE_RESOLUTION_RECORD.json"], documents["OWNER_ISSUER_AUTHORIZATION_RESOLUTION.json"])
    validate_zero_effect(documents["evidence/ZERO_OPERATIONAL_EFFECT.json"])
    require(documents["CANONICAL_ARTIFACT_IDENTITY_RESOLUTION.json"]["CANONICAL_ARTIFACT_IDENTITY_STATUS"] == documents["VERSION_EVIDENCE_RESOLUTION_RECORD.json"]["evidence_requirements"]["canonical_artifact_identity"], "EVIDENCE_INVENTORY_INCONSISTENCY", "artifact status differs across records")
    require(documents["OWNER_ISSUER_AUTHORIZATION_RESOLUTION.json"]["OWNER_ISSUER_AUTHORIZATION"] == documents["VERSION_EVIDENCE_RESOLUTION_RECORD.json"]["evidence_requirements"]["owner_issuer_authorization"], "EVIDENCE_INVENTORY_INCONSISTENCY", "owner status differs across records")
    negative = validate_negative_fixtures(documents)
    return {
        "status": "PASS",
        "entry_binding_authentication": "PASS",
        "governance_decision_binding": "PASS",
        "first_tranche24_scope_exactness": "PASS",
        "candidate_reference_authentication": "PASS",
        "version_evidence_resolution_state": "VERSION_EVIDENCE_REQUIRES_SOURCE_ACQUISITION",
        "version_evidence_inventory_consistency": "PASS",
        "static_validator": "PASS",
        "negative_fixtures": f"{len(negative)}/{len(negative)} REJECTED",
        "negative_fixture_codes": [item["rejection"] for item in negative],
        "zero_operational_effect": "PASS",
    }


if __name__ == "__main__":
    try:
        print(json.dumps(validate_package(), indent=2, sort_keys=True))
    except ResolutionValidationError as exc:
        print(json.dumps({"status": "FAIL", "code": exc.code, "message": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)
