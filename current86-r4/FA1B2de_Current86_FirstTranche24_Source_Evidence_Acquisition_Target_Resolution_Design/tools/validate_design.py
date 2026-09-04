#!/usr/bin/env python3
"""Pure local validator for the FIRST_TRANCHE24 target-resolution design."""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SCOPE = [110, 273, 210, 98, 147, 277, 188, 301, 143, 250, 233, 287, 146, 293, 114, 284, 291, 215, 88, 182, 300, 218, 115, 148]
EXPECTED_DECISION = "APPROVE_BOTH_G1_AND_G2"
EXPECTED_SCOPE_ID = "FIRST_TRANCHE24_ONLY"
EXPECTED_DECISION_ID = "GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f"
EXPECTED_TRANSACTION_HASH = "b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38"
EXPECTED_CANDIDATE_REFERENCE = "03_frozen_lineage/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json#class_to_type_mapping[0]"
EXPECTED_AUTHORITY_TYPE = "AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE"
EXPECTED_FACT_TYPE = "PINNED_CANONICAL_INTRINSIC_FIELD"
AUTOMATION_MODEL = "AUTOMATIC_WHEN_UNIQUE_BY_FROZEN_RULES"
SUPPORTED_CHANNELS = {
    "CONTENT_ADDRESSED_OBJECT_HANDOFF",
    "GIT_COMMIT_TREE_SNAPSHOT_HANDOFF",
    "RELEASE_ARTIFACT_WITH_DIGEST_HANDOFF",
    "SIGNED_DESCRIPTOR_AUTHORIZATION_BUNDLE_HANDOFF",
}
VERSION_TO_CHANNEL = {
    "CONTENT_DIGEST": "CONTENT_ADDRESSED_OBJECT_HANDOFF",
    "GIT_COMMIT": "GIT_COMMIT_TREE_SNAPSHOT_HANDOFF",
    "RELEASE_TAG_WITH_DIGEST": "RELEASE_ARTIFACT_WITH_DIGEST_HANDOFF",
}
ALLOWED_DISCOVERY_CLASSES = {
    "AUTHENTICATED_PROJECT_INDEX",
    "GOVERNED_MANIFEST_INDEX",
    "SIGNED_DESCRIPTOR_INDEX",
    "VERSIONED_PROJECT_METADATA",
}
FLOATING_TOKENS = re.compile(r"(?i)(?:^|[^a-z])(latest|head|branch|floating|date-only)(?:$|[^a-z])")
SCHEMA_FILES = (
    "TARGET_CANDIDATE_SCHEMA.json",
    "TARGET_CANDIDATE_SET_SCHEMA.json",
    "TARGET_ELIGIBILITY_POLICY.json",
    "TARGET_DEDUPLICATION_AND_ALIAS_POLICY.json",
    "TARGET_PRECEDENCE_POLICY.json",
    "TARGET_RESOLUTION_TRANSACTION_SCHEMA.json",
    "TARGET_RESOLUTION_STATE_MACHINE.json",
    "ACQUISITION_TARGET_HANDOFF_SCHEMA.json",
    "GOVERNANCE_ADJUDICATION_HANDOFF_SCHEMA.json",
)


class DesignValidationError(ValueError):
    """Fail-closed validation error with a stable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise DesignValidationError(code, message)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DesignValidationError("MALFORMED_JSON", f"cannot read {path}: {exc}") from exc


def schema_error_code(error: ValidationError) -> str:
    path = ".".join(str(part) for part in error.absolute_path)
    message = error.message.lower()
    if "governance_binding" in message:
        return "MISSING_GOVERNANCE_BINDING"
    if "candidate_set_reference" in message:
        return "MISSING_CANDIDATE_SET_REFERENCE"
    if "artifact_bytes" in message or "retrieved_artifact" in message:
        return "ACQUIRED_ARTIFACT_BYTES"
    if "additional properties" in message:
        return "UNAUTHORIZED_FIELD"
    if "governance_binding" in path or "governance_binding" in message:
        return "MISSING_GOVERNANCE_BINDING"
    if "candidate_set_reference" in path:
        return "MISSING_CANDIDATE_SET_REFERENCE"
    if "scope_binding" in path or "scope" in path or "scope_id" in message:
        return "SCOPE_WIDENING"
    if "authority_type" in path:
        return "CLASS_MISMATCH"
    if "source_fact_type" in path:
        return "FACT_TYPE_MISMATCH"
    if "source_authentication_status" in path:
        return "SOURCE_AUTHENTICATION_CLAIM"
    if "source_authority_activated" in path:
        return "AUTHORITY_ACTIVATION_CLAIM"
    if "selected_candidate_id" in path and "type" in message:
        return "MULTIPLE_SELECTED_CANDIDATES"
    if "selected_acquisition_channel_class" in path or "channel_class" in path:
        return "UNAUTHORIZED_ACQUISITION_CHANNEL"
    if "floating_reference" in path:
        return "FLOATING_VERSION_CLAIM"
    return "SCHEMA_REJECTION"


def validate_schema(value: Any, schema: dict[str, Any], label: str) -> None:
    try:
        Draft202012Validator(schema).validate(value)
    except ValidationError as exc:
        raise DesignValidationError(schema_error_code(exc), f"{label}: {exc.message}") from exc


def load_schema(name: str) -> dict[str, Any]:
    return read_json(ROOT / name)


def validate_governance(binding: dict[str, Any]) -> None:
    require(binding.get("human_governance_decision") == EXPECTED_DECISION, "GOVERNANCE_BINDING_MISMATCH", "governance decision differs")
    require(binding.get("governance_scope") == EXPECTED_SCOPE_ID, "SCOPE_WIDENING", "governance scope differs")
    require(binding.get("governance_decision_id") == EXPECTED_DECISION_ID, "GOVERNANCE_BINDING_MISMATCH", "governance decision ID differs")
    require(binding.get("governance_transaction_hash") == EXPECTED_TRANSACTION_HASH, "GOVERNANCE_BINDING_MISMATCH", "governance transaction hash differs")


def validate_scope(binding: dict[str, Any]) -> None:
    require(binding.get("scope_id") == EXPECTED_SCOPE_ID, "SCOPE_WIDENING", "scope ID differs")
    require(binding.get("ordered_target_ids") == EXPECTED_SCOPE, "SCOPE_WIDENING", "ordered target scope differs")
    require(binding.get("raw_count") == 24 and binding.get("unique_raw_count") == 24, "SCOPE_WIDENING", "scope cardinality differs")
    require(binding.get("scope_extension_permitted") is False and binding.get("scope_widening") is False, "SCOPE_WIDENING", "scope extension is permitted")


def validate_boundary(boundary: dict[str, Any]) -> None:
    expected = {
        "target_discovery_executed": "NO",
        "target_candidates_discovered": 0,
        "target_selected": "NO",
        "source_acquisition": "NO",
        "artifact_acquisition_attempted": "NO",
        "source_auth_executed": "NO",
        "source_authority_id": "NONE",
        "source_authority_activated": "NO",
        "stage_a_admissions": 0,
        "stage_b_exposures": 0,
        "field_pins": 0,
        "operative_records": 0,
        "p0_executed": "NO",
        "p1_executed": "NO",
        "formal_1796_experiment_executed": "NO",
        "zero_operational_effect": "PASS",
    }
    require(boundary == expected, "ZERO_OPERATIONAL_EFFECT_FAILED", "operational boundary is not zero effect")


def validate_candidate(candidate: dict[str, Any], schema: dict[str, Any]) -> None:
    validate_schema(candidate, schema, candidate.get("candidate_id", "candidate"))
    require(candidate["authority_type"] == EXPECTED_AUTHORITY_TYPE, "CLASS_MISMATCH", "candidate authority class differs")
    require(candidate["source_fact_type"] == EXPECTED_FACT_TYPE, "FACT_TYPE_MISMATCH", "candidate fact type differs")

    identity = candidate["artifact_identity_claim"]
    require(identity["concrete"] is True and identity["claimed_artifact_id"] != "NONE", "MISSING_ARTIFACT_IDENTITY", "artifact identity is not concrete")
    require(FLOATING_TOKENS.search(identity["claimed_artifact_id"]) is None, "FLOATING_VERSION_CLAIM", "artifact identity is floating")
    locator = candidate["artifact_locator_claim"]
    require(locator["floating_locator"] is False, "FLOATING_VERSION_CLAIM", "artifact locator is floating")

    provenance = candidate["discovery_provenance"]
    if candidate["discovery_channel"] in {"GENERIC_SEARCH_RESULT", "OFFICIAL_LOOKING_DOMAIN", "USER_SUPPLIED_REFERENCE"}:
        raise DesignValidationError("GENERIC_SEARCH_RESULT_PROMOTED", "lead-only discovery was promoted to an eligible candidate")
    if provenance["source_class"] not in ALLOWED_DISCOVERY_CLASSES or provenance["provenance_strength"] != "ADMISSIBLE" or provenance["sole_basis_for_selection"]:
        raise DesignValidationError("INADMISSIBLE_DISCOVERY_PROVENANCE", "candidate provenance is not admissible")
    owner = candidate["issuer_or_owner_claim"]
    if owner["authority_basis"] in {"OFFICIAL_LOOKING_DOMAIN_ONLY", "PUBLIC_AVAILABILITY_ONLY"}:
        raise DesignValidationError("PUBLIC_OR_OFFICIAL_LOOKING_IS_NOT_AUTHORITY", "presentation or availability is not authority")
    require(owner["later_authorization_evidence_path"] is True and owner["authentication_status"] == "NOT_EXECUTED", "OWNER_AUTHORIZATION_BOUNDARY", "owner claim crosses the authentication boundary")

    version = candidate["version_form_claim"]
    require(version["floating_reference"] is False, "FLOATING_VERSION_CLAIM", "version reference is floating")
    if version["immutable_identifier_claim"] is not None:
        require(FLOATING_TOKENS.search(version["immutable_identifier_claim"]) is None, "FLOATING_VERSION_CLAIM", "version identifier is floating")
    require(version["later_version_evidence_path"] is True, "MISSING_LATER_EVIDENCE_PATH", "version evidence path is absent")

    lineage = candidate["lineage_claims"]
    require(all(item["later_lineage_evidence_path"] is True and item["authentication_status"] == "NOT_EXECUTED" for item in lineage), "LINEAGE_AUTHENTICATION_BOUNDARY", "lineage claim crosses the authentication boundary")
    require(candidate["authorization_claims"]["scope_id"] == EXPECTED_SCOPE_ID, "SCOPE_WIDENING", "authorization claim scope differs")
    require(candidate["authorization_claims"]["later_authorization_evidence_path"] is True and candidate["authorization_claims"]["authentication_status"] == "NOT_EXECUTED", "OWNER_AUTHORIZATION_BOUNDARY", "authorization claim crosses the authentication boundary")

    relationship = candidate["identity_relationship_claim"]
    if relationship["relation_type"] == "MIRROR" and relationship["relationship_status"] != "EXPLICIT":
        raise DesignValidationError("MIRROR_RELATIONSHIP_UNPROVEN", "mirror relationship lacks explicit evidence")
    if relationship["relation_type"] in {"ALIAS", "FORK_OR_COPY", "DERIVATIVE"} and relationship["relationship_status"] == "UNPROVEN":
        raise DesignValidationError("UNPROVEN_CANONICAL_RELATIONSHIP", "canonical relationship is unproven")


def validate_candidate_set(document: dict[str, Any], schemas: dict[str, dict[str, Any]]) -> dict[str, Any]:
    validate_schema(document, schemas["TARGET_CANDIDATE_SET_SCHEMA.json"], "candidate set")
    validate_governance(document["governance_binding"])
    validate_scope(document["scope_binding"])
    target = document["target_binding"]
    require(target["candidate_reference"] == EXPECTED_CANDIDATE_REFERENCE, "CANDIDATE_BINDING_MISMATCH", "candidate reference differs")
    require(target["candidate_type"] == "SOURCE_AUTHORITY_CANDIDATE_CLASS", "CANDIDATE_BINDING_MISMATCH", "candidate type differs")
    require(target["authority_type"] == EXPECTED_AUTHORITY_TYPE and target["source_fact_type"] == EXPECTED_FACT_TYPE, "CANDIDATE_BINDING_MISMATCH", "target binding differs")
    validate_boundary(document["operational_boundary"])

    candidates = document["candidates"]
    ids = [candidate["candidate_id"] for candidate in candidates]
    require(len(ids) == len(set(ids)), "DUPLICATE_CANDIDATE_ID", "candidate IDs are not unique")
    require(document["enumerated_candidate_ids"] == ids, "CANDIDATE_ENUMERATION_MISMATCH", "enumerated candidate list differs")
    require(document["dispositioned_candidate_ids"] == ids, "SILENT_CANDIDATE_DROPPED", "not every candidate has a disposition")
    inventory = document["candidate_inventory"]
    require(inventory["candidate_count_in_record"] == len(ids), "CANDIDATE_ENUMERATION_MISMATCH", "candidate count differs")
    require(inventory["enumerated_count"] == len(ids) and inventory["dispositioned_count"] == len(ids), "SILENT_CANDIDATE_DROPPED", "candidate disposition count differs")
    require(inventory["no_silent_candidate_drop"] is True and inventory["all_candidates_have_disposition"] is True, "SILENT_CANDIDATE_DROPPED", "silent candidate deletion is allowed")
    require(document["candidate_population"]["candidate_records_in_fixture"] == len(ids), "CANDIDATE_ENUMERATION_MISMATCH", "fixture candidate count differs")

    for candidate in candidates:
        validate_candidate(candidate, schemas["TARGET_CANDIDATE_SCHEMA.json"])

    groups = document["deduplication_result"]["groups"]
    members = [member for group in groups for member in group["member_candidate_ids"]]
    require(sorted(members) == sorted(ids) and len(members) == len(set(members)), "CANDIDATE_DEDUPLICATION_INCOMPLETE", "deduplication does not disposition every candidate exactly once")
    eligibility = document["eligibility_result"]
    evaluated = eligibility["evaluated_candidate_ids"]
    eligible = eligibility["eligible_candidate_ids"]
    rejected = [item["candidate_id"] for item in eligibility["rejected_candidates"]]
    require(sorted(evaluated) == sorted(ids), "ELIGIBILITY_EVALUATION_INCOMPLETE", "not every candidate was evaluated")
    require(set(eligible).isdisjoint(rejected) and set(eligible) | set(rejected) == set(ids), "ELIGIBILITY_RESULT_INCONSISTENT", "eligible and rejected sets are not conservative")
    require(eligibility["final_authentication_required"] is False and eligibility["eligibility_is_claim_only"] is True, "ELIGIBILITY_AUTHENTICATION_BOUNDARY", "eligibility crosses the authentication boundary")

    resolution = document["resolution_result"]
    state = resolution["resolution_state"]
    selected = resolution["selected_candidate_id"]
    channel = resolution["selected_acquisition_channel_class"]
    proof = resolution["uniqueness_proof"]
    require(resolution["precedence_policy"] == "NO_AUTOMATIC_PRECEDENCE" and resolution["automation_model"] == AUTOMATION_MODEL, "PRECEDENCE_POLICY_MISMATCH", "resolution precedence model differs")
    require(proof["eligible_candidate_count"] == len(eligible), "UNIQUENESS_PROOF_INCONSISTENT", "eligible count differs")
    if len(candidates) == 0:
        require(state == "NO_CANDIDATES" and selected is None and channel is None and not resolution["governance_adjudication_required"], "NO_CANDIDATES_STATE_INCONSISTENT", "empty candidate set is not closed")
    elif len(eligible) == 1:
        require(state == "UNIQUE_TARGET_RESOLVED", "UNIQUE_TARGET_REQUIRED", "one eligible candidate did not resolve uniquely")
        require(selected == eligible[0] and channel in SUPPORTED_CHANNELS, "UNIQUE_TARGET_REQUIRES_SELECTION", "unique result lacks selected candidate or channel")
        candidate = next(item for item in candidates if item["candidate_id"] == selected)
        form = candidate["version_form_claim"]["claimed_form"]
        require(form in VERSION_TO_CHANNEL and channel == VERSION_TO_CHANNEL[form], "ACQUISITION_CHANNEL_BINDING_MISMATCH", "channel does not match version form")
        require(proof["eligible_candidate_count"] == 1 and proof["distinct_canonical_representative_count"] == 1 and proof["proof_status"] == "UNIQUE_BY_CARDINALITY", "UNIQUENESS_PROOF_INCONSISTENT", "unique proof is incomplete")
    elif len(eligible) >= 2:
        if state == "UNIQUE_TARGET_RESOLVED":
            raise DesignValidationError("ARBITRARY_TIE_BREAK", "multiple equally eligible candidates have an arbitrary winner")
        require(state == "REQUIRES_GOVERNANCE_ADJUDICATION", "AMBIGUITY_NOT_ESCALATED", "multi-candidate result is not governance-required")
        require(selected is None and channel is None and resolution["governance_adjudication_required"] is True, "GOVERNANCE_REQUIRED_STATE_INCONSISTENT", "ambiguous result selected a target")
        require(document["ambiguity_result"]["ambiguity_state"] == "MULTIPLE_EQUALLY_ELIGIBLE" and sorted(document["ambiguity_result"]["ambiguous_candidate_ids"]) == sorted(eligible), "AMBIGUITY_RESULT_INCONSISTENT", "ambiguous candidate list differs")
    else:
        require(state == "REJECTED" and selected is None and channel is None, "REJECTED_STATE_INCONSISTENT", "no eligible result is not rejected")
    return {"ids": ids, "eligible": eligible, "rejected": rejected, "state": state, "selected": selected, "channel": channel}


def validate_transaction(document: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    if isinstance(document.get("selected_candidate_id"), list):
        raise DesignValidationError("MULTIPLE_SELECTED_CANDIDATES", "selected candidate field contains multiple candidates")
    validate_schema(document, schema, "resolution transaction")
    validate_governance(document["governance_binding"])
    validate_scope(document["scope_binding"])
    require(document["candidate_reference"] == EXPECTED_CANDIDATE_REFERENCE, "CANDIDATE_BINDING_MISMATCH", "transaction candidate reference differs")
    require(document["authority_type"] == EXPECTED_AUTHORITY_TYPE, "CLASS_MISMATCH", "transaction authority type differs")
    require(document["source_fact_type"] == EXPECTED_FACT_TYPE, "FACT_TYPE_MISMATCH", "transaction fact type differs")
    validate_boundary(document["operational_boundary"])

    eligible = document["eligible_candidate_ids"]
    state = document["resolution_state"]
    selected = document["selected_candidate_id"]
    channel = document["selected_acquisition_channel_class"]
    escalation = document["governance_escalation_requirement"]
    if state == "UNIQUE_TARGET_RESOLVED":
        require(len(eligible) == 1 and selected == eligible[0], "UNIQUE_TARGET_REQUIRES_SELECTION", "unique state lacks one selected candidate")
        require(channel in SUPPORTED_CHANNELS, "UNAUTHORIZED_ACQUISITION_CHANNEL", "unique state lacks an authorized channel")
        require(document["downstream_acquisition_eligibility"] is True and escalation["required"] is False, "UNIQUE_TRANSACTION_INCONSISTENT", "unique transaction is not eligible for later acquisition")
        require(not document["ambiguous_candidate_ids"], "UNIQUE_TRANSACTION_INCONSISTENT", "unique transaction retains ambiguity")
    elif state == "REQUIRES_GOVERNANCE_ADJUDICATION":
        require(len(eligible) >= 2 and selected is None and channel is None, "AMBIGUITY_NOT_ESCALATED", "governance-required transaction is not ambiguous")
        require(document["downstream_acquisition_eligibility"] is False and escalation["required"] is True, "GOVERNANCE_REQUIRED_NOT_ELIGIBLE", "governance-required transaction is downstream eligible")
        require(escalation["handoff_reference"] is not None and escalation["question"] is not None, "GOVERNANCE_HANDOFF_MISSING", "governance handoff is incomplete")
    elif state == "NO_CANDIDATES":
        require(not eligible and selected is None and channel is None and document["downstream_acquisition_eligibility"] is False, "NO_CANDIDATES_STATE_INCONSISTENT", "empty transaction is not closed")
    return {"state": state, "eligible": eligible, "selected": selected, "channel": channel}


def validate_handoff(document: dict[str, Any], schema: dict[str, Any]) -> None:
    validate_schema(document, schema, "acquisition target handoff")
    validate_governance(document["governance_binding"])
    validate_scope(document["scope_binding"])
    target = document["resolved_target_claim"]
    require(target["authority_type"] == EXPECTED_AUTHORITY_TYPE and target["source_fact_type"] == EXPECTED_FACT_TYPE, "CANDIDATE_BINDING_MISMATCH", "handoff target class differs")
    require(document["downstream_acquisition_eligibility"] is True, "HANDOFF_NOT_ELIGIBLE", "handoff is not uniquely resolved")
    require(document["selected_acquisition_channel"]["channel_class"] in SUPPORTED_CHANNELS, "UNAUTHORIZED_ACQUISITION_CHANNEL", "handoff channel is not authorized")
    boundary = document["downstream_boundary"]
    require(boundary["source_authentication_status"] == "NOT_EXECUTED", "SOURCE_AUTHENTICATION_CLAIM", "handoff claims source authentication")
    require(boundary["source_authority_activated"] == "NO" and boundary["source_authority_id"] == "NONE", "AUTHORITY_ACTIVATION_CLAIM", "handoff claims source authority")


def validate_governance_handoff(document: dict[str, Any], schema: dict[str, Any]) -> None:
    validate_schema(document, schema, "governance adjudication handoff")
    validate_governance(document["governance_binding"])
    validate_scope(document["scope_binding"])
    require(len(document["ambiguous_candidate_ids"]) >= 2, "AMBIGUITY_HANDOFF_INCOMPLETE", "fewer than two candidates are escalated")
    require(document["decision_created"] is False and document["decision_record_reference"] is None, "GOVERNANCE_DECISION_CREATED", "human decision was created in the design package")
    require(document["downstream_acquisition_eligibility"] is False, "GOVERNANCE_REQUIRED_NOT_ELIGIBLE", "governance packet is downstream eligible")


def apply_mutation(value: Any, mutation: dict[str, Any]) -> Any:
    target = value
    path = mutation["path"]
    for component in path[:-1]:
        target = target[component]
    leaf = path[-1]
    operation = mutation["operation"]
    if operation == "replace":
        target[leaf] = copy.deepcopy(mutation["value"])
    elif operation == "remove":
        if isinstance(target, list):
            target.pop(leaf)
        else:
            target.pop(leaf)
    elif operation == "add":
        target[leaf] = copy.deepcopy(mutation["value"])
    else:
        raise DesignValidationError("MALFORMED_FIXTURE", f"unsupported mutation {operation}")
    return value


def validate_document(document: dict[str, Any], schemas: dict[str, dict[str, Any]]) -> None:
    record_type = document.get("record_type")
    if record_type == "FIRST_TRANCHE24_TARGET_CANDIDATE_SET":
        validate_candidate_set(document, schemas)
    elif record_type == "FIRST_TRANCHE24_TARGET_RESOLUTION_TRANSACTION":
        validate_transaction(document, schemas["TARGET_RESOLUTION_TRANSACTION_SCHEMA.json"])
    elif record_type == "FIRST_TRANCHE24_ACQUISITION_TARGET_HANDOFF":
        validate_handoff(document, schemas["ACQUISITION_TARGET_HANDOFF_SCHEMA.json"])
    elif record_type == "FIRST_TRANCHE24_GOVERNANCE_ADJUDICATION_HANDOFF":
        validate_governance_handoff(document, schemas["GOVERNANCE_ADJUDICATION_HANDOFF_SCHEMA.json"])
    else:
        raise DesignValidationError("UNKNOWN_RECORD_TYPE", f"unsupported fixture record type: {record_type}")


def load_fixture(name: str) -> dict[str, Any]:
    return read_json(ROOT / "fixtures" / "positive" / name)


def validate_positive_fixtures(schemas: dict[str, dict[str, Any]]) -> list[str]:
    index = read_json(ROOT / "fixtures" / "POSITIVE_FIXTURE_INDEX.json")
    accepted: list[str] = []
    for item in index["fixtures"]:
        for filename in item["documents"]:
            validate_document(load_fixture(filename), schemas)
        accepted.append(item["fixture_id"])
    return accepted


def validate_negative_fixtures(schemas: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    index = read_json(ROOT / "fixtures" / "NEGATIVE_FIXTURE_INDEX.json")
    results: list[dict[str, str]] = []
    for item in index["fixtures"]:
        descriptor = read_json(ROOT / "fixtures" / "negative" / item["fixture"])
        require(descriptor["base_fixture"] == item["base_fixture"], "MALFORMED_FIXTURE", f"base fixture mismatch: {item['fixture']}")
        document = load_fixture(descriptor["base_fixture"])
        for mutation in descriptor["mutations"]:
            apply_mutation(document, mutation)
        try:
            validate_document(document, schemas)
        except DesignValidationError as exc:
            require(exc.code == item["expected_rejection"], "NEGATIVE_FIXTURE_MISMATCH", f"{item['fixture']}: expected {item['expected_rejection']}, got {exc.code}")
            results.append({"fixture": item["fixture"], "rejection": exc.code})
        else:
            raise DesignValidationError("NEGATIVE_FIXTURE_ACCEPTED", f"negative fixture accepted: {item['fixture']}")
    return results


def validate_state_machine(schemas: dict[str, dict[str, Any]]) -> None:
    document = schemas["TARGET_RESOLUTION_STATE_MACHINE.json"]
    require(document["properties"]["machine_id"]["const"] == "TARGET_RESOLUTION_STATE_MACHINE_FIRST_TRANCHE24_V1", "STATE_MACHINE_MISMATCH", "state machine ID differs")
    require(document["properties"]["scope"]["const"] == EXPECTED_SCOPE_ID, "SCOPE_WIDENING", "state machine scope differs")
    transitions = document["properties"]["transitions"]["const"]
    require(isinstance(transitions, list) and transitions, "STATE_MACHINE_MISMATCH", "state machine transitions are absent")
    expected = ["DESIGN_ONLY", "DISCOVERY_REQUEST_PREPARED", "CANDIDATE_SET_ASSEMBLED", "ELIGIBILITY_EVALUATED", "UNIQUENESS_EVALUATED", "AMBIGUOUS", "UNIQUE_TARGET_RESOLVED", "REQUIRES_GOVERNANCE_ADJUDICATION", "REJECTED"]
    require(document["properties"]["states"]["const"] == expected, "STATE_MACHINE_MISMATCH", "state machine state set differs")
    require(document["properties"]["initial_state"]["const"] == "DESIGN_ONLY", "STATE_MACHINE_MISMATCH", "state machine starts outside design-only")
    require(set(document["properties"]["terminal_states"]["const"]) == {"UNIQUE_TARGET_RESOLVED", "REQUIRES_GOVERNANCE_ADJUDICATION", "REJECTED"}, "STATE_MACHINE_MISMATCH", "terminal states differ")


def validate_package() -> dict[str, Any]:
    schemas = {name: load_schema(name) for name in SCHEMA_FILES}
    for name, schema in schemas.items():
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            raise DesignValidationError("SCHEMA_META_VALIDATION_FAILED", f"{name}: {exc}") from exc
    validate_state_machine(schemas)
    positives = validate_positive_fixtures(schemas)
    negatives = validate_negative_fixtures(schemas)
    require(len(positives) == 3, "POSITIVE_FIXTURE_COUNT", "positive fixture count differs")
    require(len(negatives) == 20, "NEGATIVE_FIXTURE_COUNT", "negative fixture count differs")
    return {
        "schema_meta_validation": "PASS",
        "static_validator": "PASS",
        "automation_model": AUTOMATION_MODEL,
        "governance_decision_binding": "PASS",
        "first_tranche24_scope_exactness": "PASS",
        "negative_fixtures_rejected": len(negatives),
        "positive_fixtures_accepted": len(positives),
        "zero_operational_effect": "PASS",
    }


if __name__ == "__main__":
    try:
        print(json.dumps(validate_package(), indent=2, sort_keys=True))
    except DesignValidationError as exc:
        print(json.dumps({"status": "FAIL", "code": exc.code, "message": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)
