#!/usr/bin/env python3
"""Pure, fail-closed validator for the FIRST_TRANCHE24 activation design.

This module reads only package-local JSON and Markdown-adjacent evidence.  It
does not launch processes, use networking, call source adapters, access
activation stores, or invoke runtime evaluators, and it never writes state. It
validates the future record contract using a clearly marked synthetic fixture.
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
SCHEMA_PATH = ROOT / "SOURCE_AUTHORITY_ACTIVATION_RECORD_SCHEMA.json"
VALID_FIXTURE = ROOT / "fixtures" / "valid_record.json"
INDEX_PATH = ROOT / "fixtures" / "NEGATIVE_FIXTURE_INDEX.json"
EXPECTED_SCOPE = [110,273,210,98,147,277,188,301,143,250,233,287,146,293,114,284,291,215,88,182,300,218,115,148]
EXPECTED_DECISION_ID = "GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f"
EXPECTED_GOV_TX = "b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38"
EXPECTED_MATERIALIZATION_COMMIT = "3c5c014238b569377963c1cb20f3d7df2600f135"
EXPECTED_MATERIALIZATION_PARENT = "c3e911e865f5287d46703e5d0d7398ee653151f7"
EXPECTED_REVIEW_COMMIT = "10478b0961a601d0f684740b9564633a9930ebc9"
EXPECTED_AUTHORITY_NAMESPACE = "fa1b2de.source-authority/current86/first-tranche24"
EXPECTED_AUTHORITY_PROCEDURE = "FIRST_TRANCHE24_SOURCE_AUTHORITY_IDENTITY_V1"
EXPECTED_ACTIVATION_PROCEDURE = "FIRST_TRANCHE24_SOURCE_AUTHORITY_ACTIVATION_IDENTITY_V1"
RESERVED_TOKENS = re.compile(r"(?i)^(unknown|tbd|temp|dummy|placeholder)$")


class DesignValidationError(ValueError):
    """A semantic or fail-closed design error with a stable rejection code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DesignValidationError("MALFORMED_JSON", f"cannot read JSON {path}: {exc}") from exc


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


def reject_reserved(value: Any) -> None:
    if isinstance(value, str):
        require(not RESERVED_TOKENS.fullmatch(value), "PLACEHOLDER_VALUE", f"reserved placeholder value: {value}")
    elif isinstance(value, dict):
        for child in value.values():
            reject_reserved(child)
    elif isinstance(value, list):
        for child in value:
            reject_reserved(child)


def identity_preimage(record: dict[str, Any]) -> dict[str, Any]:
    authority = record["source_authority_identity"]
    basis = authority["identity_basis"]
    return {
        "identity_procedure_id": authority["identity_procedure_id"],
        "identity_namespace": authority["identity_namespace"],
        "identity_version": authority["identity_version"],
        "authority_type": basis["authority_type"],
        "source_class": basis["source_class"],
        "source_locator": basis["source_locator"],
        "source_locator_type": basis["source_locator_type"],
        "source_version_policy_id": basis["source_version_policy_id"],
        "content_digest": basis["content_digest"],
        "scope_id": record["scope_reference"]["scope_id"],
        "raw_ids": record["scope_reference"]["raw_ids"],
    }


def transaction_preimage(record: dict[str, Any]) -> dict[str, Any]:
    """Return the documented hash input without transaction identity fields."""
    value = copy.deepcopy(record)
    tx = value["activation_transaction"]
    for field in ("transaction_id", "record_id", "transaction_hash", "canonical_preimage_sha256"):
        tx.pop(field, None)
    return value


def replay_preimage(record: dict[str, Any]) -> dict[str, Any]:
    governance = record["governance_authorization_reference"]
    scope = record["scope_reference"]
    authority = record["source_authority_identity"]
    policy = record["source_version_policy"]
    return {
        "transaction_type": record["activation_transaction"]["transaction_type"],
        "decision_record_id": governance["decision_record_id"],
        "governance_transaction_hash": governance["governance_transaction_hash"],
        "scope_id": scope["scope_id"],
        "raw_ids": scope["raw_ids"],
        "authority_id": authority["authority_id"],
        "source_version_policy_id": policy["policy_id"],
        "content_sha256": policy["content_sha256"],
    }


def validate_schema(record: dict[str, Any], schema: dict[str, Any]) -> None:
    try:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(record)
    except ValidationError as exc:
        path = ".".join(str(x) for x in exc.absolute_path)
        text = exc.message
        lower_text = text.lower()
        if "additional properties" in lower_text:
            code = "UNAUTHORIZED_FIELD"
        elif path.startswith("governance_authorization_reference") or "governance_authorization_reference" in text:
            code = "WRONG_GOVERNANCE_DECISION_ID" if "decision_record_id" in path else "MISSING_GOVERNANCE_DECISION_REFERENCE"
        elif path.startswith("scope_reference") or "scope_reference" in text:
            code = "SCOPE_WIDENING"
        elif path.startswith("source_version_policy") or "source_version_policy" in text:
            code = "FLOATING_OR_UNPINNED_VERSION" if "floating_reference_allowed" in path else "MISSING_VERSION_POLICY"
        elif path.startswith("source_authority_identity") or "source_authority_identity" in text:
            code = "UNSUPPORTED_IDENTITY_PROCEDURE" if "identity_procedure_id" in path else "MISSING_SOURCE_AUTHORITY_IDENTITY"
        else:
            code = "SCHEMA_REJECTION"
        raise DesignValidationError(code, f"schema rejection at {path}: {text}") from exc


def validate_entry_and_governance(record: dict[str, Any]) -> None:
    entry = read_json(ROOT / "evidence" / "ENTRY_BINDING_AUTHENTICATION.json")
    require(entry.get("status") == "PASS", "BLOCKED_ENTRY_AUTHENTICATION", "entry evidence is not PASS")
    require(entry.get("local_binding_head") == entry.get("remote_binding_head"), "BLOCKED_ENTRY_AUTHENTICATION", "Binding heads differ")
    require(entry.get("local_binding_head") == EXPECTED_REVIEW_COMMIT, "BLOCKED_ENTRY_AUTHENTICATION", "unexpected live Binding head")
    require(entry.get("decision_materialization_commit") == EXPECTED_MATERIALIZATION_COMMIT, "BLOCKED_ENTRY_AUTHENTICATION", "decision commit mismatch")
    require(entry.get("decision_materialization_parent") == EXPECTED_MATERIALIZATION_PARENT, "BLOCKED_ENTRY_AUTHENTICATION", "decision parent mismatch")
    require(entry.get("independent_review_commit") == EXPECTED_REVIEW_COMMIT, "BLOCKED_ENTRY_AUTHENTICATION", "review commit mismatch")
    require(entry.get("review_package_traceable_to_live_binding_history") is True, "BLOCKED_ENTRY_AUTHENTICATION", "review is not traceable")
    require(entry.get("parent_exact") is True and entry.get("changed_scope") == "INDEPENDENT_REVIEW_PACKAGE_ONLY", "BLOCKED_ENTRY_AUTHENTICATION", "review commit scope is unexplained")

    gov = record["governance_authorization_reference"]
    require(gov["decision_record_id"] == EXPECTED_DECISION_ID, "WRONG_GOVERNANCE_DECISION_ID", "decision ID mismatch")
    require(gov["governance_transaction_hash"] == EXPECTED_GOV_TX, "WRONG_GOVERNANCE_TRANSACTION_HASH", "governance transaction hash mismatch")
    require(gov["governance_scope"] == "FIRST_TRANCHE24_ONLY", "WRONG_GOVERNANCE_SCOPE", "governance scope mismatch")
    require(gov["decision_materialization_commit"] == EXPECTED_MATERIALIZATION_COMMIT, "WRONG_GOVERNANCE_DECISION_REFERENCE", "materialization commit mismatch")
    require(gov["decision_materialization_parent"] == EXPECTED_MATERIALIZATION_PARENT, "WRONG_GOVERNANCE_DECISION_REFERENCE", "materialization parent mismatch")
    require(gov["independent_review_commit"] == EXPECTED_REVIEW_COMMIT, "WRONG_GOVERNANCE_DECISION_REFERENCE", "independent review commit mismatch")

    decision_path = PROJECT_ROOT / "FA1B2de_Current86_FirstTranche24_G1G2_Decision_Materialization" / "FIRST_TRANCHE24_GOVERNANCE_DECISION_RECORD_V2.json"
    decision = read_json(decision_path)
    require(decision.get("decision_identity", {}).get("decision_record_id") == EXPECTED_DECISION_ID, "WRONG_GOVERNANCE_DECISION_ID", "materialized record ID mismatch")
    require(decision.get("decision_identity", {}).get("decision_transaction_hash") == EXPECTED_GOV_TX, "WRONG_GOVERNANCE_TRANSACTION_HASH", "materialized transaction hash mismatch")
    require(decision.get("scope", {}).get("governance_scope_id") == "FIRST_TRANCHE24_ONLY", "WRONG_GOVERNANCE_SCOPE", "materialized scope mismatch")
    authorization = decision.get("governance_authorization", {})
    require(authorization.get("does_not_assert_source_object_exists") is True, "CIRCULAR_GOVERNANCE_DEPENDENCY", "governance asserts a source object")
    require("source_authority_id" not in authorization and "source_version_policy" not in authorization, "CIRCULAR_GOVERNANCE_DEPENDENCY", "source authority leaked into governance")


def validate_binding_artifact() -> None:
    binding = read_json(ROOT / "GOVERNANCE_TO_AUTHORITY_BINDING.json")
    governance = binding["governance_decision"]
    require(governance["decision_record_id"] == EXPECTED_DECISION_ID, "WRONG_GOVERNANCE_DECISION_ID", "binding artifact decision ID mismatch")
    require(governance["governance_transaction_hash"] == EXPECTED_GOV_TX, "WRONG_GOVERNANCE_TRANSACTION_HASH", "binding artifact transaction hash mismatch")
    require(governance["governance_scope"] == "FIRST_TRANCHE24_ONLY", "WRONG_GOVERNANCE_SCOPE", "binding artifact scope mismatch")
    require(governance["decision_materialization_commit"] == EXPECTED_MATERIALIZATION_COMMIT, "WRONG_GOVERNANCE_DECISION_REFERENCE", "binding artifact materialization mismatch")
    require(governance["decision_materialization_parent"] == EXPECTED_MATERIALIZATION_PARENT, "WRONG_GOVERNANCE_DECISION_REFERENCE", "binding artifact parent mismatch")
    require(governance["independent_review_commit"] == EXPECTED_REVIEW_COMMIT, "WRONG_GOVERNANCE_DECISION_REFERENCE", "binding artifact review mismatch")
    constraint = binding["scope_constraint"]
    require(constraint["scope_id"] == "FIRST_TRANCHE24_ONLY" and constraint["raw_ids"] == EXPECTED_SCOPE, "SCOPE_WIDENING", "binding artifact raw-ID set changed")
    require(constraint["raw_count"] == 24 and constraint["unique_raw_count"] == 24 and constraint["scope_extension_permitted"] is False, "SCOPE_WIDENING", "binding artifact scope extension is permitted")
    activation = binding["activation_constraint"]
    require(activation["source_authority_id_at_design_time"] is None and activation["source_version_policy_at_design_time"] is None, "AMBIGUOUS_SOURCE_AUTHORITY_IDENTITY", "design selected a concrete authority")
    guard = binding["circularity_guard"]
    require(guard["governance_materialization_requires_source_authority"] is False and guard["source_authority_activation_requires_materialized_governance"] is True and guard["v1_circular_dependency_reintroduced"] is False, "CIRCULAR_GOVERNANCE_DEPENDENCY", "circularity guard changed")


def validate_policy_rules() -> None:
    policy = read_json(ROOT / "FAIL_CLOSED_RULES.json")
    required = {
        "MISSING_GOVERNANCE_DECISION_REFERENCE", "WRONG_GOVERNANCE_DECISION_ID", "WRONG_GOVERNANCE_TRANSACTION_HASH",
        "WRONG_GOVERNANCE_SCOPE", "SCOPE_WIDENING", "MISSING_SOURCE_AUTHORITY_IDENTITY", "AMBIGUOUS_SOURCE_AUTHORITY_IDENTITY",
        "MISSING_VERSION_POLICY", "FLOATING_OR_UNPINNED_VERSION", "PROVENANCE_MISMATCH", "UNSUPPORTED_IDENTITY_PROCEDURE",
        "UNAUTHORIZED_FIELD", "DUPLICATE_REUSE_MISMATCH", "STALE_OR_SUPERSEDED_CANDIDATE", "MIXED_CANDIDATE_EVIDENCE",
    }
    actual = {rule["rule_id"] for rule in policy["rules"]}
    require(required <= actual, "FAIL_CLOSED_POLICY_INCOMPLETE", "required fail-closed rule is missing")
    require(policy["default_decision"] == "FAIL_CLOSED_NO_ACTIVATION", "FAIL_CLOSED_POLICY_INCOMPLETE", "default decision is permissive")


def validate_zero_effect_evidence() -> None:
    zero = read_json(ROOT / "evidence" / "ZERO_OPERATIONAL_EFFECT.json")
    expected = {
        "status": "PASS", "design_phase_only": True, "human_governance_decision_materialized": "YES",
        "human_governance_decision": "APPROVE_BOTH_G1_AND_G2", "governance_scope": "FIRST_TRANCHE24_ONLY",
        "governance_decision_changed": False, "NEW_SOURCE_AUTHORITY_ID_CREATED": 0,
        "SOURCE_AUTHORITY_ACTIVATED": "NO", "SOURCE_ACQUISITION": "NO", "SOURCE_AUTH_EXECUTED": "NO",
        "STAGE_A_ADMISSIONS": 0, "STAGE_B_EXPOSURES": 0, "FIELD_PINS": 0, "OPERATIVE_RECORDS": 0,
        "P0_EXECUTED": "NO", "P1_EXECUTED": "NO", "FORMAL_1796_EXPERIMENT_EXECUTED": "NO",
        "zero_operational_effect_except_prior_governance_decision": "PASS",
    }
    for key, value in expected.items():
        require(zero.get(key) == value, "ZERO_OPERATIONAL_EFFECT_FAILED", f"zero-effect evidence changed: {key}")


def validate_semantics(record: dict[str, Any]) -> dict[str, Any]:
    reject_reserved(record)
    scope = record["scope_reference"]
    require(scope["scope_id"] == "FIRST_TRANCHE24_ONLY", "SCOPE_WIDENING", "scope ID is not FIRST_TRANCHE24_ONLY")
    require(scope["raw_ids"] == EXPECTED_SCOPE, "SCOPE_WIDENING", "raw-ID array is not the frozen ordered set")
    require(len(scope["raw_ids"]) == 24 and len(set(scope["raw_ids"])) == 24, "SCOPE_WIDENING", "scope cardinality/uniqueness failed")

    tx = record["activation_transaction"]
    require(tx["identity_procedure_id"] == EXPECTED_ACTIVATION_PROCEDURE, "UNSUPPORTED_IDENTITY_PROCEDURE", "activation identity procedure mismatch")
    require(tx["transaction_hash"] == digest(transaction_preimage(record)), "AMBIGUOUS_SOURCE_AUTHORITY_IDENTITY", "transaction hash does not match canonical record preimage")
    require(tx["transaction_hash"] == tx["canonical_preimage_sha256"], "AMBIGUOUS_SOURCE_AUTHORITY_IDENTITY", "transaction hash and preimage digest differ")
    suffix = tx["transaction_hash"]
    require(tx["transaction_id"].endswith(suffix) and tx["record_id"].endswith(suffix), "AMBIGUOUS_SOURCE_AUTHORITY_IDENTITY", "transaction IDs are not hash-bound")
    replay = tx["replay_and_reuse"]
    require(replay["replay_key"] == digest(replay_preimage(record)), "DUPLICATE_REUSE_MISMATCH", "replay key does not bind the activation identity tuple")
    prior, disposition = replay["prior_record_state"], replay["replay_disposition"]
    if prior == "NONE":
        require(disposition == "NEW_TRANSACTION" and replay["existing_record_id"] is None and replay["existing_record_hash"] is None, "DUPLICATE_REUSE_MISMATCH", "new replay state is inconsistent")
    elif prior == "EXACT_REPLAY_SAME_HASH":
        require(disposition == "IDEMPOTENT_REPLAY" and replay["existing_record_id"] is not None and replay["existing_record_hash"] == tx["transaction_hash"], "DUPLICATE_REUSE_MISMATCH", "exact replay does not match committed bytes")
    else:
        require(disposition == "REJECT_CONFLICT", "DUPLICATE_REUSE_MISMATCH", "conflicting replay was not rejected")

    authority = record["source_authority_identity"]
    require(authority["identity_procedure_id"] == EXPECTED_AUTHORITY_PROCEDURE and authority["identity_namespace"] == EXPECTED_AUTHORITY_NAMESPACE, "UNSUPPORTED_IDENTITY_PROCEDURE", "authority identity procedure/namespace mismatch")
    computed_identity = digest(identity_preimage(record))
    require(authority["identity_digest"] == computed_identity and authority["authority_id"] == "sha256:" + computed_identity, "AMBIGUOUS_SOURCE_AUTHORITY_IDENTITY", "authority ID does not match canonical preimage")
    require(authority["scope_binding"]["scope_id"] == scope["scope_id"] and authority["scope_binding"]["raw_ids"] == EXPECTED_SCOPE, "SCOPE_WIDENING", "identity scope binding differs")
    require(authority["candidate_status"] not in {"STALE", "SUPERSEDED"}, "STALE_OR_SUPERSEDED_CANDIDATE", "candidate is stale or superseded")

    policy = record["source_version_policy"]
    require(policy["policy_id"] == authority["identity_basis"]["source_version_policy_id"], "PROVENANCE_MISMATCH", "policy ID differs from identity basis")
    require(policy["content_sha256"] == authority["identity_basis"]["content_digest"], "PROVENANCE_MISMATCH", "policy digest differs from identity basis")
    require(policy["floating_reference_allowed"] is False, "FLOATING_OR_UNPINNED_VERSION", "floating version is prohibited")
    require(policy["immutable_identifier"].startswith("sha256:") or policy["policy_form"] != "CONTENT_DIGEST", "FLOATING_OR_UNPINNED_VERSION", "content-digest policy lacks immutable digest identifier")
    require(not any(token in policy["immutable_identifier"].lower() for token in ("latest", "branch", "range")), "FLOATING_OR_UNPINNED_VERSION", "floating token in immutable identifier")
    ref_kind = policy["reference"]["kind"]
    expected_kind = {"CONTENT_DIGEST":"CONTENT_URI", "GIT_COMMIT":"GIT_COMMIT_TREE", "RELEASE_TAG_WITH_DIGEST":"RELEASE_TAG_DIGEST"}[policy["policy_form"]]
    if record["record_mode"] == "SYNTHETIC_TEST_ONLY":
        expected_kind = "SYNTHETIC_URI"
    require(ref_kind == expected_kind, "MISSING_VERSION_POLICY", "version reference kind does not match policy form")

    provenance = record["source_provenance_evidence"]
    require(provenance["evidence_set_id"] == authority["provenance_binding"]["provenance_set_id"], "PROVENANCE_MISMATCH", "evidence set ID mismatch")
    require(provenance["all_same_candidate"] is True, "MIXED_CANDIDATE_EVIDENCE", "evidence set does not assert one candidate")
    refs = provenance["evidence_refs"]
    candidate_ids = {item["candidate_authority_id"] for item in refs}
    if len(candidate_ids) > 1:
        raise DesignValidationError("MIXED_CANDIDATE_EVIDENCE", "evidence names multiple authority candidates")
    require(refs and all(item["candidate_authority_id"] == authority["authority_id"] for item in refs), "PROVENANCE_MISMATCH", "evidence candidate does not match authority")
    require(all(item["source_version_policy_id"] == policy["policy_id"] and item["content_sha256"] == policy["content_sha256"] for item in refs), "PROVENANCE_MISMATCH", "evidence policy/digest mismatch")
    require(provenance["evidence_set_sha256"] == digest(refs), "PROVENANCE_MISMATCH", "evidence-set digest mismatch")
    require(authority["provenance_binding"]["evidence_digest"] == provenance["evidence_set_sha256"], "PROVENANCE_MISMATCH", "identity provenance digest mismatch")

    profile = record["canonicalization_profile"]
    require(profile["profile_id"] == "RFC8785_LIKE_UTF8_SORTED_JSON" and profile["profile_version"] == "V1", "UNSUPPORTED_IDENTITY_PROCEDURE", "canonicalization profile mismatch")
    require(canonical_bytes({"b":1,"a":[2,3]}) == canonical_bytes({"a":[2,3],"b":1}), "UNSUPPORTED_IDENTITY_PROCEDURE", "canonicalization is not deterministic")

    zero = record["zero_downstream_effect_assertions"]
    require(zero["assertion_scope"] == "FIRST_TRANCHE24_ONLY" and zero["governance_decision_unchanged"] is True, "DOWNSTREAM_EFFECT_REQUESTED", "zero-effect assertion scope changed")
    for key in ("stage_a_admissions","stage_b_exposures","field_pins","operative_records"):
        require(zero[key] == 0, "DOWNSTREAM_EFFECT_REQUESTED", f"{key} is nonzero")
    for key in ("source_acquisition","source_auth_executed","p0_executed","p1_executed","formal_1796_experiment_executed"):
        require(zero[key] == "NO", "DOWNSTREAM_EFFECT_REQUESTED", f"{key} is enabled")
    if record["record_mode"] == "SYNTHETIC_TEST_ONLY":
        require(record["activation_status"] == "DESIGN_ONLY_NOT_EXECUTED" and tx["design_only"] is True, "DOWNSTREAM_EFFECT_REQUESTED", "synthetic fixture is executable")
        require(authority["candidate_status"] == "SYNTHETIC_ONLY" and provenance["provenance_status"] == "SYNTHETIC_PASS", "PROVENANCE_MISMATCH", "synthetic evidence status changed")
        require(zero["source_authority_activated"] == "NO", "DOWNSTREAM_EFFECT_REQUESTED", "synthetic fixture activates authority")
    else:
        require(tx["design_only"] is False and authority["candidate_status"] == "AUTHENTICATED_CANDIDATE", "MISSING_SOURCE_AUTHORITY_IDENTITY", "future activation is not authenticated")
        require(record["source_authority_type_class"]["selection_decision"] == "ADJUDICATED_SINGLE_CANDIDATE", "MISSING_SOURCE_AUTHORITY_IDENTITY", "future activation lacks single-candidate adjudication")
        require(provenance["provenance_status"] == "PASS" and all(item["attestation_status"] == "PASS" for item in refs), "PROVENANCE_MISMATCH", "future provenance is not authenticated")
        require(provenance["authentication_method"] != "SYNTHETIC_DETERMINISTIC", "PROVENANCE_MISMATCH", "future activation uses synthetic evidence")
    return {"authority_identity_sha256": computed_identity, "evidence_set_sha256": provenance["evidence_set_sha256"], "transaction_hash": tx["transaction_hash"]}


def apply_mutation(value: Any, mutation: dict[str, Any]) -> Any:
    target = value
    path = mutation["path"]
    for component in path[:-1]:
        target = target[component]
    leaf = path[-1]
    operation = mutation["operation"]
    if operation == "remove":
        if isinstance(target, list):
            target.pop(leaf)
        else:
            target.pop(leaf)
    elif operation == "replace":
        target[leaf] = copy.deepcopy(mutation["value"])
    elif operation == "add":
        if isinstance(target, list):
            target.insert(leaf, copy.deepcopy(mutation["value"]))
        else:
            target[leaf] = copy.deepcopy(mutation["value"])
    else:
        raise DesignValidationError("MALFORMED_FIXTURE", f"unsupported mutation {operation}")
    return value


def refresh_transaction_identity(record: dict[str, Any]) -> None:
    """Keep a mutated vector internally hash-consistent for its target check."""
    tx_hash = digest(transaction_preimage(record))
    tx = record["activation_transaction"]
    tx["transaction_hash"] = tx_hash
    tx["canonical_preimage_sha256"] = tx_hash
    tx["transaction_id"] = "SATX-FIRST_TRANCHE24_SOURCE_AUTHORITY_ACTIVATION_V1-" + tx_hash
    tx["record_id"] = "SATREC-FIRST_TRANCHE24_SOURCE_AUTHORITY_ACTIVATION_V1-" + tx_hash


def validate_negative_vectors(schema: dict[str, Any]) -> list[dict[str, str]]:
    index = read_json(INDEX_PATH)
    results: list[dict[str, str]] = []
    for vector in index["vectors"]:
        path = ROOT / vector["file"]
        descriptor = read_json(path)
        base_path = path.parent / descriptor["base_fixture"]
        candidate = copy.deepcopy(read_json(base_path))
        apply_mutation(candidate, descriptor["mutation"])
        if "secondary_mutation" in descriptor:
            apply_mutation(candidate, descriptor["secondary_mutation"])
        refresh_transaction_identity(candidate)
        expected = vector["expected_rejection"]
        try:
            validate_schema(candidate, schema)
            validate_semantics(candidate)
        except DesignValidationError as exc:
            require(exc.code == expected, "NEGATIVE_FIXTURE_MISMATCH", f"{path.name}: expected {expected}, got {exc.code}")
            results.append({"fixture": path.name, "rejection": exc.code})
        else:
            raise DesignValidationError("NEGATIVE_FIXTURE_ACCEPTED", f"negative fixture accepted: {path.name}")
    return results


def validate_package() -> dict[str, Any]:
    schema = read_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    record = read_json(VALID_FIXTURE)
    require(isinstance(record, dict), "SCHEMA_REJECTION", "valid fixture must be an object")
    validate_schema(record, schema)
    validate_binding_artifact()
    validate_policy_rules()
    validate_zero_effect_evidence()
    validate_entry_and_governance(record)
    semantics = validate_semantics(record)
    negatives = validate_negative_vectors(schema)
    require(len(negatives) == 10, "NEGATIVE_FIXTURE_MISMATCH", "negative fixture count changed")
    return {
        "schema_meta_validation": "PASS",
        "valid_synthetic_fixture": "PASS",
        "negative_fixtures_rejected": len(negatives),
        "negative_fixture_results": negatives,
        "governance_decision_binding": "PASS",
        "first_tranche24_scope_exactness": "PASS",
        "v1_circular_dependency_reintroduced": "NO",
        "static_validator_fail_closed": "PASS",
        "identity_digest": semantics["authority_identity_sha256"],
        "evidence_set_digest": semantics["evidence_set_sha256"],
        "transaction_hash": semantics["transaction_hash"],
    }


def main() -> int:
    try:
        result = validate_package()
    except DesignValidationError as exc:
        print(json.dumps({"status":"BLOCKED","error_code":exc.code,"error":str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"status":"PASS", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
