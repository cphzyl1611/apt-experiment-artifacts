#!/usr/bin/env python3
"""Pure local validator for the FIRST_TRANCHE24 acquisition design.

Only package-local JSON, Markdown, and the frozen governance records are read.
The validator performs schema and semantic checks and never changes state.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError


ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent
EXPECTED_SCOPE = [110,273,210,98,147,277,188,301,143,250,233,287,146,293,114,284,291,215,88,182,300,218,115,148]
EXPECTED_DECISION_ID = "GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f"
EXPECTED_GOVERNANCE_HASH = "b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38"
EXPECTED_RESOLUTION_COMMIT = "81c843c48619fd8e25983f68a7248d0273dc2192"
EXPECTED_RESOLUTION_PARENT = "6171a460ef527b99f2176eb047d51ca7082d067a"
EXPECTED_REVIEW_COMMIT = "a67377396ae6d20e87c1870bddeed8700a6c871b"
EXPECTED_REVIEW_PARENT = "81c843c48619fd8e25983f68a7248d0273dc2192"
EXPECTED_REVIEW_MESSAGE = "materialize binding: FIRST_TRANCHE24_SOURCE_VERSION_EVIDENCE_RESOLUTION_INDEPENDENT_REVIEW"
EXPECTED_CANDIDATE_REFERENCE = "03_frozen_lineage/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json#class_to_type_mapping[0]"
EXPECTED_AUTHORITY_TYPE = "AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE"
EXPECTED_FACT_TYPE = "PINNED_CANONICAL_INTRINSIC_FIELD"
EXPECTED_ARTIFACT_CLASS = "CANONICAL_SOURCE_ARTIFACT"
SUPPORTED_FORMS = {"CONTENT_DIGEST", "GIT_COMMIT", "RELEASE_TAG_WITH_DIGEST"}
ALLOWED_CHANNELS = {
    "CONTENT_ADDRESSED_OBJECT_HANDOFF",
    "GIT_COMMIT_TREE_SNAPSHOT_HANDOFF",
    "RELEASE_ARTIFACT_WITH_DIGEST_HANDOFF",
    "SIGNED_DESCRIPTOR_AUTHORIZATION_BUNDLE_HANDOFF",
}
ID_KEY = "source_" + "authority_" + "id"
LIVE_SECRET_VALUE = re.compile(r"(?i)\b(?:bearer\s+[A-Za-z0-9._-]{12,}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})\b")


class DesignValidationError(ValueError):
    """Stable rejection code for a design or fixture defect."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DesignValidationError("MALFORMED_JSON", f"cannot read {path}: {exc}") from exc


def canonical_bytes(value: Any) -> bytes:
    def normalize(item: Any) -> Any:
        if isinstance(item, str):
            return unicodedata.normalize("NFC", item)
        if isinstance(item, list):
            return [normalize(child) for child in item]
        if isinstance(item, dict):
            return {key: normalize(child) for key, child in item.items()}
        return item

    return json.dumps(normalize(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise DesignValidationError(code, message)


def schema_error_code(error: ValidationError) -> str:
    path = ".".join(str(part) for part in error.absolute_path)
    message = error.message.lower()
    if "credential" in message or "secret" in message:
        return "LIVE_CREDENTIAL_EMBEDDED"
    if "additional properties" in message:
        return "UNAUTHORIZED_FIELD"
    if "governance_binding" in path or "governance_binding" in message:
        return "MISSING_GOVERNANCE_BINDING"
    if "scope_binding" in path or "scope_binding" in message:
        return "SCOPE_WIDENING"
    if "eligible_artifact_count" in path or "uniqueness_status" in path:
        return "MULTIPLE_ELIGIBLE_ARTIFACTS"
    if "floating_reference_allowed" in path:
        return "FLOATING_VERSION"
    if "policy_form" in path:
        return "UNSUPPORTED_IMMUTABLE_VERSION_FORM"
    if "content_digest_evidence" in path or "content_digest_evidence" in message:
        return "DIGEST_ABSENT"
    if "lineage_proof" in path or "lineage_proof" in message:
        return "LINEAGE_EDGE_MISSING"
    if "authorization_scope" in path:
        return "AUTHORIZATION_SCOPE_MISMATCH"
    if "owner_issuer_authorization" in path or "owner_issuer_authorization" in message:
        return "MISSING_OWNER_ISSUER_AUTHORIZATION"
    if "source_authentication_status" in path or "downstream_eligibility" in path:
        return "ACQUISITION_MARKED_AUTHENTICATED_WITHOUT_AUTHENTICATION"
    if "authority_activation_status" in path:
        return "ACQUISITION_MARKED_AUTHORITY_ACTIVATED"
    return "SCHEMA_REJECTION"


def validate_schema(value: dict[str, Any], schema: dict[str, Any], label: str) -> None:
    try:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    except ValidationError as exc:
        code = schema_error_code(exc)
        raise DesignValidationError(code, f"{label}: schema rejection at {list(exc.absolute_path)}: {exc.message}") from exc


def reject_forbidden_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            require(key.lower() != ID_KEY, "PREMATURE_AUTHORITY_ID", "final authority identity key is forbidden")
            reject_forbidden_keys(child)
    elif isinstance(value, list):
        for child in value:
            reject_forbidden_keys(child)


def validate_entry_binding() -> None:
    evidence = read_json(ROOT / "evidence" / "ENTRY_BINDING_AUTHENTICATION.json")
    require(evidence.get("status") == "PASS", "ENTRY_BINDING_FAILED", "entry binding is not PASS")
    require(evidence.get("local_binding_head") == EXPECTED_REVIEW_COMMIT, "ENTRY_BINDING_FAILED", "local Binding head mismatch")
    require(evidence.get("origin_binding_head") == EXPECTED_REVIEW_COMMIT, "ENTRY_BINDING_FAILED", "tracking Binding head mismatch")
    require(evidence.get("live_remote_binding_head") == EXPECTED_REVIEW_COMMIT, "ENTRY_BINDING_FAILED", "live Binding head mismatch")
    require(evidence.get("local_remote_live_equality") is True, "ENTRY_BINDING_FAILED", "Binding refs are not equal")
    require(evidence.get("review_materialization_parent") == EXPECTED_REVIEW_PARENT, "ENTRY_BINDING_FAILED", "review parent mismatch")
    require(evidence.get("review_materialization_message") == EXPECTED_REVIEW_MESSAGE, "ENTRY_BINDING_FAILED", "review message mismatch")
    require(evidence.get("review_materialization_descends_from_resolution") is True, "ENTRY_BINDING_FAILED", "review does not descend from resolution")
    require(evidence.get("review_verdict") == "PASS_READY_FOR_SOURCE_EVIDENCE_ACQUISITION_DESIGN", "ENTRY_BINDING_FAILED", "review verdict mismatch")
    require(evidence.get("review_package_materialized") is True and evidence.get("review_package_committed") is True and evidence.get("review_package_pushed") is True, "ENTRY_BINDING_FAILED", "review package is not persisted")
    require(evidence.get("resolution_commit") == EXPECTED_RESOLUTION_COMMIT and evidence.get("resolution_parent") == EXPECTED_RESOLUTION_PARENT, "ENTRY_BINDING_FAILED", "resolution lineage mismatch")


def validate_governance_and_scope(value: dict[str, Any]) -> None:
    governance = value["governance_binding"]
    require(governance["decision_record_id"] == EXPECTED_DECISION_ID, "GOVERNANCE_BINDING_MISMATCH", "decision ID mismatch")
    require(governance["governance_transaction_hash"] == EXPECTED_GOVERNANCE_HASH, "GOVERNANCE_BINDING_MISMATCH", "governance transaction hash mismatch")
    require(governance["human_governance_decision"] == "APPROVE_BOTH_G1_AND_G2", "GOVERNANCE_BINDING_MISMATCH", "governance decision mismatch")
    require(governance["governance_scope"] == "FIRST_TRANCHE24_ONLY", "GOVERNANCE_BINDING_MISMATCH", "governance scope mismatch")
    require(governance["version_evidence_resolution_commit"] == EXPECTED_RESOLUTION_COMMIT, "GOVERNANCE_BINDING_MISMATCH", "resolution commit mismatch")
    require(governance["version_evidence_resolution_parent"] == EXPECTED_RESOLUTION_PARENT, "GOVERNANCE_BINDING_MISMATCH", "resolution parent mismatch")
    require(governance["review_materialization_commit"] == EXPECTED_REVIEW_COMMIT, "GOVERNANCE_BINDING_MISMATCH", "review commit mismatch")
    require(governance["review_materialization_parent"] == EXPECTED_REVIEW_PARENT, "GOVERNANCE_BINDING_MISMATCH", "review parent mismatch")
    require(governance["review_materialization_message"] == EXPECTED_REVIEW_MESSAGE, "GOVERNANCE_BINDING_MISMATCH", "review message mismatch")

    scope = value["scope_binding"]
    require(scope["scope_id"] == "FIRST_TRANCHE24_ONLY", "SCOPE_WIDENING", "scope ID mismatch")
    require(scope["raw_ids"] == EXPECTED_SCOPE, "SCOPE_WIDENING", "scope array mismatch")
    require(scope["raw_count"] == 24 and scope["unique_raw_count"] == 24, "SCOPE_WIDENING", "scope cardinality mismatch")
    require(scope["scope_binding_mode"] == "LITERAL_ORDERED_SET", "SCOPE_WIDENING", "scope binding mode changed")
    if "scope_extension_permitted" in scope:
        require(scope["scope_extension_permitted"] is False, "SCOPE_WIDENING", "scope is extensible")
    else:
        require(scope.get("scope_extension_requested") is False, "SCOPE_WIDENING", "scope extension was requested")

    candidate = value["candidate_reference"]
    require(candidate["reference"] == EXPECTED_CANDIDATE_REFERENCE, "CANDIDATE_BINDING_MISMATCH", "candidate reference mismatch")
    require(candidate["resolution_state"] == "CANDIDATE_RESOLVED_VERSION_EVIDENCE_PENDING", "CANDIDATE_BINDING_MISMATCH", "candidate state mismatch")
    require(candidate["candidate_type"] == "SOURCE_AUTHORITY_CANDIDATE_CLASS", "CANDIDATE_BINDING_MISMATCH", "candidate type mismatch")
    require(candidate["authority_type"] == EXPECTED_AUTHORITY_TYPE and candidate["source_fact_type"] == EXPECTED_FACT_TYPE, "CANDIDATE_BINDING_MISMATCH", "candidate class mismatch")


def validate_transaction() -> None:
    schema = read_json(ROOT / "ACQUISITION_TRANSACTION_SCHEMA.json")
    record = read_json(ROOT / "fixtures" / "valid_transaction.json")
    validate_schema(record, schema, "valid_transaction")
    reject_forbidden_keys(record)
    validate_governance_and_scope(record)
    require(record["record_mode"] == "DESIGN_ONLY_TEMPLATE", "NON_DESIGN_TRANSACTION", "design fixture is executable")
    require(record["acquisition_status"] == "DESIGN_ONLY", "NON_DESIGN_TRANSACTION", "design fixture has an execution state")
    for field in ("acquisition_channel", "acquisition_provenance", "retrieved_artifact_reference", "immutable_version_representation", "content_digest", "descriptor_to_artifact_lineage_evidence", "owner_issuer_authorization_evidence", "failure_reason"):
        require(record[field] is None, "NON_DESIGN_TRANSACTION", f"design fixture contains {field}")
    require(record["downstream_eligibility"] == "NOT_ELIGIBLE", "DOWNSTREAM_EFFECT_REQUESTED", "design fixture is downstream eligible")
    boundary = record["operational_boundary"]
    expected = {
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
    }
    require(boundary == expected, "ZERO_OPERATIONAL_EFFECT_FAILED", "transaction boundary is not zero effect")


def validate_envelope() -> None:
    schema = read_json(ROOT / "ACQUIRED_EVIDENCE_ENVELOPE_SCHEMA.json")
    envelope = read_json(ROOT / "fixtures" / "valid_envelope.json")
    validate_schema(envelope, schema, "valid_envelope")
    reject_forbidden_keys(envelope)
    validate_governance_and_scope(envelope)

    artifact = envelope["artifact_identity"]
    require(artifact["artifact_class"] == EXPECTED_ARTIFACT_CLASS, "ARTIFACT_IDENTITY_MISMATCH", "artifact class mismatch")
    require(artifact["eligible_artifact_count"] == 1 and artifact["uniqueness_status"] == "UNIQUE_ELIGIBLE_ARTIFACT", "MULTIPLE_ELIGIBLE_ARTIFACTS", "artifact is not uniquely resolved")

    version = envelope["immutable_version_representation"]
    require(version["policy_form"] in SUPPORTED_FORMS, "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "unsupported version form")
    require(version["floating_reference_allowed"] is False, "FLOATING_VERSION", "floating version is allowed")
    require(version["artifact_id"] == artifact["artifact_id"], "MIXED_ARTIFACT_VERSION_EVIDENCE", "version names another artifact")
    require(version["reference"]["reference_kind"] == {"CONTENT_DIGEST": "CONTENT_URI", "GIT_COMMIT": "GIT_COMMIT_TREE", "RELEASE_TAG_WITH_DIGEST": "RELEASE_TAG_DIGEST"}[version["policy_form"]], "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "version reference kind does not match form")
    require(version["policy_form"] != "CONTENT_DIGEST" or version["immutable_identifier"] == "sha256:" + version["content_sha256"], "FLOATING_VERSION", "content-digest identifier is not immutable")

    content = envelope["content_digest_evidence"]
    require(content["artifact_id"] == artifact["artifact_id"] and content["policy_id"] == version["policy_id"], "MIXED_ARTIFACT_VERSION_EVIDENCE", "digest evidence names another artifact or policy")
    require(content["content_sha256"] == version["content_sha256"], "DIGEST_MISMATCH", "version and digest differ")
    require(content["recomputed_content_sha256"] == content["content_sha256"], "DIGEST_MISMATCH", "recomputed digest differs")
    require(content["digest_binding_status"] == "PASS_SAME_ARTIFACT_AND_VERSION", "DIGEST_FROM_DIFFERENT_ARTIFACT_OR_VERSION", "digest binding failed")

    lineage = envelope["lineage_proof"]
    require(lineage["candidate_reference"] == EXPECTED_CANDIDATE_REFERENCE, "BROKEN_LINEAGE", "lineage candidate differs")
    require(lineage["artifact_id"] == artifact["artifact_id"] and lineage["policy_id"] == version["policy_id"] and lineage["content_sha256"] == content["content_sha256"], "BROKEN_LINEAGE", "lineage node differs")
    require(lineage["proof_status"] in {"PASS", "SYNTHETIC_PASS"} and lineage["mixed_lineage_allowed"] is False, "BROKEN_LINEAGE", "lineage is not authenticated")
    edges = lineage["edges"]
    require(len(edges) == 3 and {edge["edge_id"] for edge in edges} == {"DESCRIPTOR_TO_ARTIFACT", "ARTIFACT_TO_IMMUTABLE_VERSION", "IMMUTABLE_VERSION_TO_CONTENT_DIGEST"}, "LINEAGE_EDGE_MISSING", "lineage does not contain exactly three edges")
    by_id = {edge["edge_id"]: edge for edge in edges}
    require(by_id["DESCRIPTOR_TO_ARTIFACT"]["to_reference"] == artifact["artifact_id"], "BROKEN_LINEAGE", "descriptor points to another artifact")
    require(by_id["ARTIFACT_TO_IMMUTABLE_VERSION"]["from_reference"] == artifact["artifact_id"], "BROKEN_LINEAGE", "artifact edge starts elsewhere")
    require(by_id["ARTIFACT_TO_IMMUTABLE_VERSION"]["to_reference"] == version["reference"]["locator"], "BROKEN_LINEAGE", "artifact points to another version")
    require(by_id["IMMUTABLE_VERSION_TO_CONTENT_DIGEST"]["from_reference"] == version["reference"]["locator"], "BROKEN_LINEAGE", "version edge starts elsewhere")
    require(by_id["IMMUTABLE_VERSION_TO_CONTENT_DIGEST"]["to_reference"] == "sha256:" + content["content_sha256"], "BROKEN_LINEAGE", "version points to another digest")
    require(all(edge["edge_authentication_status"] in {"PASS", "SYNTHETIC_PASS"} for edge in edges), "BROKEN_LINEAGE", "one lineage edge is unauthenticated")

    authorization = envelope["owner_issuer_authorization"]
    require(authorization["authorization_status"] == "ACTIVE", "STALE_REVOKED_OR_SUPERSEDED_AUTHORIZATION", "authorization is not active")
    require(authorization["artifact_identity"]["artifact_id"] == artifact["artifact_id"] and authorization["immutable_version_binding"]["policy_id"] == version["policy_id"], "OWNER_ISSUER_MISMATCH", "authorization names another artifact or policy")
    require(authorization["immutable_version_binding"]["immutable_identifier"] == version["immutable_identifier"] and authorization["immutable_version_binding"]["content_sha256"] == content["content_sha256"], "OWNER_ISSUER_MISMATCH", "authorization version or digest differs")
    scope = authorization["authorization_scope"]
    require(scope["scope_id"] == "FIRST_TRANCHE24_ONLY" and scope["raw_ids"] == EXPECTED_SCOPE and scope["raw_count"] == 24 and scope["unique_raw_count"] == 24, "AUTHORIZATION_SCOPE_MISMATCH", "authorization scope differs")
    require(scope["scope_binding_mode"] == "LITERAL_ORDERED_SET" and scope["permitted_use"] == "SOURCE_AUTHENTICATION_INPUT_ONLY" and scope["scope_extension_permitted"] is False, "AUTHORIZATION_SCOPE_MISMATCH", "authorization scope is widened")
    require(authorization["public_accessibility_not_authorization"] is True, "MISSING_OWNER_ISSUER_AUTHORIZATION", "publication is used as authorization")
    owner = authorization["owner_or_issuer_identity"]
    require(owner["canonical_name"] and owner["identity_reference"], "MISSING_OWNER_ISSUER_AUTHORIZATION", "owner or issuer identity is absent")

    provenance = envelope["acquisition_provenance"]
    require(provenance["channel_class"] in ALLOWED_CHANNELS, "AMBIGUOUS_ACQUISITION_PROVENANCE", "channel class is not allowed")
    require(provenance["requested_candidate_reference"] == EXPECTED_CANDIDATE_REFERENCE and provenance["requested_scope_id"] == "FIRST_TRANCHE24_ONLY", "AMBIGUOUS_ACQUISITION_PROVENANCE", "provenance request binding differs")
    require(provenance["returned_object_count"] == 1 and provenance["selected_object_count"] == 1, "AMBIGUOUS_ACQUISITION_PROVENANCE", "selection is not unique")
    require(provenance["selected_object_reference"] == artifact["artifact_id"], "AMBIGUOUS_ACQUISITION_PROVENANCE", "selected object is not the envelope artifact")
    require(provenance["selection_rule"] == "EXACTLY_ONE_ELIGIBLE_ARTIFACT_AND_ONE_CONSISTENT_EVIDENCE_SET", "AMBIGUOUS_ACQUISITION_PROVENANCE", "selection rule differs")
    require(provenance["credential_material_recorded"] is False, "LIVE_CREDENTIAL_EMBEDDED", "credential material was recorded")
    require(provenance["provenance_status"] in {"DETERMINISTIC_SYNTHETIC_PASS", "CAPTURED_PASS"}, "AMBIGUOUS_ACQUISITION_PROVENANCE", "provenance is not deterministic")

    auth_readiness = envelope["authentication_readiness"]
    require(auth_readiness["source_authentication_status"] == "NOT_EXECUTED", "ACQUISITION_MARKED_AUTHENTICATED_WITHOUT_AUTHENTICATION", "source authentication is already marked PASS")
    require(auth_readiness["authentication_required"] is True, "AUTHENTICATION_GATE_MISSING", "authentication gate is not required")
    require(envelope["downstream_eligibility"] == "NOT_ELIGIBLE", "DOWNSTREAM_EFFECT_REQUESTED", "envelope is downstream eligible")
    require(envelope["authority_activation_status"] == "NOT_ACTIVATED", "ACQUISITION_MARKED_AUTHORITY_ACTIVATED", "acquisition envelope activates authority")


def apply_mutation(value: Any, mutation: dict[str, Any]) -> Any:
    target = value
    path = mutation["path"]
    for component in path[:-1]:
        target = target[component]
    leaf = path[-1]
    operation = mutation["operation"]
    if operation == "remove":
        target.pop(leaf)
    elif operation == "replace":
        target[leaf] = copy.deepcopy(mutation["value"])
    elif operation == "add":
        target[leaf] = copy.deepcopy(mutation["value"])
    else:
        raise DesignValidationError("MALFORMED_FIXTURE", f"unknown fixture operation: {operation}")
    return value


def validate_negative_vectors() -> list[dict[str, str]]:
    schema = read_json(ROOT / "ACQUIRED_EVIDENCE_ENVELOPE_SCHEMA.json")
    index = read_json(ROOT / "fixtures" / "NEGATIVE_FIXTURE_INDEX.json")
    results: list[dict[str, str]] = []
    for vector in index["vectors"]:
        descriptor = read_json(ROOT / "fixtures" / "negative" / vector["fixture"])
        require(descriptor["base_fixture"] == "valid_envelope.json", "MALFORMED_FIXTURE", f"unexpected base fixture: {vector['fixture']}")
        candidate = copy.deepcopy(read_json(ROOT / "fixtures" / descriptor["base_fixture"]))
        apply_mutation(candidate, vector["mutation"])
        try:
            validate_schema(candidate, schema, vector["fixture"])
            reject_forbidden_keys(candidate)
            validate_governance_and_scope(candidate)
            validate_envelope_value(candidate)
        except DesignValidationError as exc:
            expected = vector["expected_rejection"]
            require(exc.code == expected, "NEGATIVE_FIXTURE_MISMATCH", f"{vector['fixture']}: expected {expected}, got {exc.code}")
            results.append({"fixture": vector["fixture"], "rejection": exc.code})
        else:
            raise DesignValidationError("NEGATIVE_FIXTURE_ACCEPTED", f"negative fixture accepted: {vector['fixture']}")
    return results


def validate_envelope_value(envelope: dict[str, Any]) -> None:
    """Semantic envelope checks shared by the positive and negative vectors."""
    artifact = envelope["artifact_identity"]
    version = envelope["immutable_version_representation"]
    content = envelope["content_digest_evidence"]
    lineage = envelope["lineage_proof"]
    authorization = envelope["owner_issuer_authorization"]
    provenance = envelope["acquisition_provenance"]
    auth_readiness = envelope["authentication_readiness"]
    require(artifact["eligible_artifact_count"] == 1 and artifact["uniqueness_status"] == "UNIQUE_ELIGIBLE_ARTIFACT", "MULTIPLE_ELIGIBLE_ARTIFACTS", "artifact is not unique")
    require(version["policy_form"] in SUPPORTED_FORMS, "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "unsupported form")
    require(version["floating_reference_allowed"] is False, "FLOATING_VERSION", "floating version")
    identifier = version["immutable_identifier"].lower()
    require(not any(token in identifier for token in ("latest", "branch", "head", "range", "date-only")), "FLOATING_VERSION", "version identifier is floating")
    require(version["artifact_id"] == artifact["artifact_id"], "MIXED_ARTIFACT_VERSION_EVIDENCE", "version artifact mismatch")
    require(version["reference"]["reference_kind"] == {"CONTENT_DIGEST": "CONTENT_URI", "GIT_COMMIT": "GIT_COMMIT_TREE", "RELEASE_TAG_WITH_DIGEST": "RELEASE_TAG_DIGEST"}[version["policy_form"]], "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "version reference kind mismatch")
    require(version["policy_form"] != "CONTENT_DIGEST" or version["immutable_identifier"] == "sha256:" + version["content_sha256"], "FLOATING_VERSION", "content-digest identifier is not immutable")
    if version["policy_form"] == "GIT_COMMIT":
        require(version["reference"]["commit"] is not None and version["reference"]["tree"] is not None, "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "Git form lacks full commit/tree")
    if version["policy_form"] == "RELEASE_TAG_WITH_DIGEST":
        require(version["reference"]["release"] is not None and version["reference"]["tag"] is not None, "UNSUPPORTED_IMMUTABLE_VERSION_FORM", "release form lacks release/tag")
    require(content["artifact_id"] == artifact["artifact_id"] and content["policy_id"] == version["policy_id"], "MIXED_ARTIFACT_VERSION_EVIDENCE", "digest artifact mismatch")
    require(content["content_sha256"] == version["content_sha256"] and content["recomputed_content_sha256"] == content["content_sha256"], "DIGEST_MISMATCH", "digest mismatch")
    require(len(lineage["edges"]) == 3, "LINEAGE_EDGE_MISSING", "lineage edge missing")
    require(lineage["artifact_id"] == artifact["artifact_id"] and lineage["policy_id"] == version["policy_id"] and lineage["content_sha256"] == content["content_sha256"], "BROKEN_LINEAGE", "lineage node mismatch")
    edges = {edge["edge_id"]: edge for edge in lineage["edges"]}
    require(set(edges) == {"DESCRIPTOR_TO_ARTIFACT", "ARTIFACT_TO_IMMUTABLE_VERSION", "IMMUTABLE_VERSION_TO_CONTENT_DIGEST"}, "LINEAGE_EDGE_MISSING", "lineage edge set is incomplete")
    require(edges["DESCRIPTOR_TO_ARTIFACT"]["to_reference"] == artifact["artifact_id"], "BROKEN_LINEAGE", "descriptor edge points elsewhere")
    require(edges["ARTIFACT_TO_IMMUTABLE_VERSION"]["from_reference"] == artifact["artifact_id"] and edges["ARTIFACT_TO_IMMUTABLE_VERSION"]["to_reference"] == version["reference"]["locator"], "BROKEN_LINEAGE", "artifact-version edge is broken")
    require(edges["IMMUTABLE_VERSION_TO_CONTENT_DIGEST"]["from_reference"] == version["reference"]["locator"] and edges["IMMUTABLE_VERSION_TO_CONTENT_DIGEST"]["to_reference"] == "sha256:" + content["content_sha256"], "BROKEN_LINEAGE", "version-digest edge is broken")
    require(authorization["authorization_status"] == "ACTIVE", "STALE_REVOKED_OR_SUPERSEDED_AUTHORIZATION", "stale authorization")
    require(authorization["artifact_identity"]["artifact_id"] == artifact["artifact_id"], "OWNER_ISSUER_MISMATCH", "authorization artifact mismatch")
    require(authorization["immutable_version_binding"]["policy_id"] == version["policy_id"] and authorization["immutable_version_binding"]["immutable_identifier"] == version["immutable_identifier"], "OWNER_ISSUER_MISMATCH", "authorization version mismatch")
    require(authorization["authorization_scope"]["scope_id"] == "FIRST_TRANCHE24_ONLY" and authorization["authorization_scope"]["raw_ids"] == EXPECTED_SCOPE, "AUTHORIZATION_SCOPE_MISMATCH", "authorization scope mismatch")
    owner = authorization["owner_or_issuer_identity"]
    expected_relationship = {"SOURCE_OWNER": "OWNS", "SOURCE_ISSUER": "ISSUED", "AUTHORIZED_DELEGATE": "DELEGATED_BY_OWNER_OR_ISSUER"}[owner["identity_type"]]
    require(owner["relationship_to_artifact"] == expected_relationship, "OWNER_ISSUER_MISMATCH", "owner or issuer relationship mismatch")
    require(authorization["evidence_reference"]["attestation_status"] in {"PASS", "SYNTHETIC_PASS"}, "MISSING_OWNER_ISSUER_AUTHORIZATION", "authorization proof is not attested")
    require(provenance["returned_object_count"] == 1 and provenance["selected_object_count"] == 1, "AMBIGUOUS_ACQUISITION_PROVENANCE", "ambiguous provenance")
    require(provenance["credential_material_recorded"] is False, "LIVE_CREDENTIAL_EMBEDDED", "credential material recorded")
    require(auth_readiness["source_authentication_status"] == "NOT_EXECUTED", "ACQUISITION_MARKED_AUTHENTICATED_WITHOUT_AUTHENTICATION", "authentication already passed")
    require(envelope["authority_activation_status"] == "NOT_ACTIVATED", "ACQUISITION_MARKED_AUTHORITY_ACTIVATED", "authority activated")


def validate_channel_policy() -> None:
    policy = read_json(ROOT / "ACQUISITION_CHANNEL_POLICY.json")
    require(policy["scope_id"] == "FIRST_TRANCHE24_ONLY", "POLICY_SCOPE_MISMATCH", "channel policy scope mismatch")
    require(policy["allowed_object_classes"] == ["CANONICAL_SOURCE_ARTIFACT", "IMMUTABLE_VERSION_EVIDENCE", "ARTIFACT_CONTENT_DIGEST_EVIDENCE", "DESCRIPTOR_ARTIFACT_LINEAGE_PROOF", "OWNER_ISSUER_AUTHORIZATION_PROOF"], "ACQUISITION_OBJECT_SET_MISMATCH", "object set is not exact")
    require(policy["prohibited_channel_classes"] and policy["selection_rules"]["artifact_count_must_equal"] == 1, "ACQUISITION_CHANNEL_POLICY_INCOMPLETE", "policy is permissive")
    require(all(channel["deterministic_provenance_required"] is True and channel["live_endpoint_value_embedded"] is False for channel in policy["allowed_channel_classes"]), "ACQUISITION_CHANNEL_POLICY_INCOMPLETE", "channel provenance is not deterministic")
    require(policy["credential_handling"]["credential_material_may_be_embedded"] is False and policy["credential_handling"]["credential_material_may_be_retained"] is False, "ACQUISITION_CHANNEL_POLICY_INCOMPLETE", "credential handling is permissive")


def validate_state_machine() -> None:
    machine = read_json(ROOT / "ACQUISITION_STATE_MACHINE.json")
    states = set(machine["states"])
    required_states = {"DESIGN_ONLY", "REQUEST_PREPARED", "ACQUISITION_ATTEMPTED", "ARTIFACT_ACQUIRED", "EVIDENCE_ENVELOPE_ASSEMBLED", "PENDING_AUTHENTICATION", "REJECTED"}
    require(states == required_states, "STATE_MACHINE_INCOMPLETE", "state set is not exact")
    require(machine["initial_state"] == "DESIGN_ONLY", "STATE_MACHINE_INCOMPLETE", "wrong initial state")
    require(all(transition["to"] != "AUTHORITY_ACTIVATED" and transition["from"] != "AUTHORITY_ACTIVATED" for transition in machine["transitions"]), "STATE_MACHINE_ACTIVATION_LEAK", "activation state appears in acquisition machine")
    require(set(machine["invariants"]) >= {"ACQUISITION_IS_NOT_AUTHENTICATION", "AUTHENTICATION_IS_NOT_AUTHORITY_ACTIVATION", "AUTHORITY_ACTIVATION_IS_NOT_STAGE_A_ADMISSION", "NO_STATE_HAS_AUTHORITY_ACTIVATED_TRANSITION", "NO_STATE_MAKES_EVIDENCE_DOWNSTREAM_ELIGIBLE"}, "STATE_MACHINE_INCOMPLETE", "separation invariant missing")


def validate_owner_and_lineage_schemas() -> None:
    for name in ("OWNER_ISSUER_AUTHORIZATION_SCHEMA.json", "LINEAGE_PROOF_SCHEMA.json"):
        Draft202012Validator.check_schema(read_json(ROOT / name))
    owner = read_json(ROOT / "OWNER_ISSUER_AUTHORIZATION_SCHEMA.json")
    lineage = read_json(ROOT / "LINEAGE_PROOF_SCHEMA.json")
    require(owner["properties"]["authorization_scope"]["properties"]["scope_id"]["const"] == "FIRST_TRANCHE24_ONLY", "AUTHORIZATION_SCHEMA_INCOMPLETE", "authorization scope is not exact")
    require(owner["properties"]["public_accessibility_not_authorization"]["const"] is True, "AUTHORIZATION_SCHEMA_INCOMPLETE", "publication substitute was allowed")
    require(lineage["properties"]["mixed_lineage_allowed"]["const"] is False, "LINEAGE_SCHEMA_INCOMPLETE", "mixed lineage was allowed")


def scan_design_sources() -> None:
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in {".json", ".md", ".py"}:
            continue
        text = path.read_text(encoding="utf-8")
        require(LIVE_SECRET_VALUE.search(text) is None, "LIVE_CREDENTIAL_EMBEDDED", f"secret-like value in {path.relative_to(ROOT)}")


def validate_zero_effect() -> None:
    zero = read_json(ROOT / "evidence" / "ZERO_OPERATIONAL_EFFECT.json")
    expected = {
        "design_phase_only": True,
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
        "zero_operational_effect": "PASS",
    }
    for key, value in expected.items():
        require(zero.get(key) == value, "ZERO_OPERATIONAL_EFFECT_FAILED", f"zero-effect field changed: {key}")


def validate_package() -> dict[str, Any]:
    schema_names = ["ACQUISITION_TRANSACTION_SCHEMA.json", "ACQUIRED_EVIDENCE_ENVELOPE_SCHEMA.json", "OWNER_ISSUER_AUTHORIZATION_SCHEMA.json", "LINEAGE_PROOF_SCHEMA.json"]
    for name in schema_names:
        Draft202012Validator.check_schema(read_json(ROOT / name))
    validate_entry_binding()
    validate_channel_policy()
    validate_state_machine()
    validate_owner_and_lineage_schemas()
    validate_transaction()
    validate_envelope()
    scan_design_sources()
    validate_zero_effect()
    negatives = validate_negative_vectors()
    require(len(negatives) == 19, "NEGATIVE_FIXTURE_MISMATCH", "negative fixture count is not 19")
    return {
        "schema_meta_validation": "PASS",
        "static_validator": "PASS",
        "governance_decision_binding": "PASS",
        "first_tranche24_scope_exactness": "PASS",
        "negative_fixtures_rejected": len(negatives),
        "zero_operational_effect": "PASS",
        "source_authority_id_derived": "NO",
        "source_authority_id": "NONE",
    }


def main() -> int:
    try:
        print(json.dumps(validate_package(), sort_keys=True, indent=2))
    except DesignValidationError as exc:
        print(json.dumps({"status": "BLOCKED", "code": exc.code, "message": str(exc)}, sort_keys=True, indent=2))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
