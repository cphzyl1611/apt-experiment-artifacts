#!/usr/bin/env python3
"""Fail-closed verification for the bounded candidate-reference remediation."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any


PROJECT = Path(__file__).resolve().parents[2]
PACKAGE = PROJECT / "FA1B2de_Current86_FirstTranche24_Source_Authority_Candidate_Resolution_Evidence_Reference_Remediation"
HISTORICAL = PROJECT / "FA1B2de_Current86_FirstTranche24_Source_Authority_Candidate_Resolution"
RESOLVED_PATH = PROJECT / "FA1B2de_Current86_FirstTranche24_Source_Authority_Activation_Design_Independent_Review/evidence/GOVERNANCE_BINDING.json"
BAD_PATH = "FA1B2de_Current86_FirstTranche24_G1G2_Decision_Materialization_Independent_Review/evidence/GOVERNANCE_BINDING.json"
RESOLVED_REFERENCE = "FA1B2de_Current86_FirstTranche24_Source_Authority_Activation_Design_Independent_Review/evidence/GOVERNANCE_BINDING.json"
BAD_SHA = "081e68e5a042cb7ec2c53da49424fa0ae46a1abc9a9839b2f429db433853e705"
DECISION_ID = "GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f"
TRANSACTION_HASH = "b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38"
COMMIT = "e6e885e17e60f1b12af47a7ddb363b8d2934f8b7"
PARENT = "10478b0961a601d0f684740b9564633a9930ebc9"
SCOPE = [110, 273, 210, 98, 147, 277, 188, 301, 143, 250, 233, 287, 146, 293, 114, 284, 291, 215, 88, 182, 300, 218, 115, 148]


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> None:
    raise AssertionError(message)


def load_static_validator() -> Any:
    path = HISTORICAL / "tools/validate_candidate_resolution.py"
    spec = importlib.util.spec_from_file_location("candidate_resolution_validator", path)
    if spec is None or spec.loader is None:
        fail("cannot load historical static validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> dict[str, Any]:
    before = read(HISTORICAL / "CANDIDATE_SET.json")
    after = read(PACKAGE / "CANDIDATE_SET.json")
    supporting_before = before["candidates"][0]["supporting_artifact_references"][1]
    supporting_after = after["candidates"][0]["supporting_artifact_references"][1]
    assert supporting_before["reference"] == BAD_PATH
    assert supporting_before["sha256"] == BAD_SHA
    assert not (PROJECT / BAD_PATH).is_file()

    matching = sorted(
        path.relative_to(PROJECT).as_posix()
        for path in PROJECT.rglob("*")
        if path.is_file() and digest(path) == BAD_SHA
    )
    assert matching == [RESOLVED_REFERENCE], matching
    assert RESOLVED_PATH.is_file()
    assert digest(RESOLVED_PATH) == BAD_SHA
    assert supporting_after["reference"] == RESOLVED_REFERENCE
    assert supporting_after["sha256"] == BAD_SHA

    expected_after = copy.deepcopy(before)
    expected_after["candidates"][0]["supporting_artifact_references"][1]["reference"] = RESOLVED_REFERENCE
    assert after == expected_after, "semantic or non-reference drift detected"

    # The resolved object is an existing authenticated review payload, not a
    # newly created substitute. Its manifest and review bind it to Binding.
    review_dir = PROJECT / "FA1B2de_Current86_FirstTranche24_Source_Authority_Activation_Design_Independent_Review"
    review = read(review_dir / "INDEPENDENT_REVIEW.json")
    lineage = read(review_dir / "evidence/LINEAGE_AUTHENTICATION.json")
    manifest = read(review_dir / "MATERIALIZATION_MANIFEST.json")
    manifest_entry = next(item for item in manifest["files"] if item["destination"].endswith(RESOLVED_REFERENCE))
    assert review["verdict"] == "PASS_READY_FOR_SOURCE_AUTHORITY_CANDIDATE_RESOLUTION"
    assert review["design_materialization_commit"] == COMMIT
    assert review["design_materialization_parent"] == PARENT
    assert lineage["head_equality"] is True
    assert lineage["local_binding_head"] == COMMIT
    assert lineage["remote_binding_head"] == COMMIT
    assert lineage["design_materialization_commit"] == COMMIT
    assert lineage["design_materialization_parent"] == PARENT
    assert manifest_entry["sha256"] == BAD_SHA
    assert digest(RESOLVED_PATH) == manifest_entry["sha256"]

    evidence = read(RESOLVED_PATH)
    assert evidence["decision_record_id"] == DECISION_ID
    assert evidence["governance_transaction_hash"] == TRANSACTION_HASH
    assert evidence["governance_scope"] == "FIRST_TRANCHE24_ONLY"
    assert evidence["human_governance_decision"] == "APPROVE_BOTH_G1_AND_G2"
    assert evidence["materialized_record_does_not_assert_source_object"] is True
    assert evidence["materialized_record_does_not_activate_authority"] is True

    candidate = after["candidates"][0]
    assert len(after["candidates"]) == 3
    assert candidate["candidate_type"] == "SOURCE_AUTHORITY_CANDIDATE_CLASS"
    assert candidate["candidate_id_or_local_reference"] == "03_frozen_lineage/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json#class_to_type_mapping[0]"
    assert candidate["authority_type"] == "AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE"
    assert candidate["source_fact_type"] == "PINNED_CANONICAL_INTRINSIC_FIELD"
    assert candidate["resolution_status"] == "RESOLVED_CLASS_ONLY_VERSION_PENDING"
    assert candidate["identity_basis"]["authority_id_derivation_status"] == "NOT_DERIVED"
    assert after["scope_reference"]["scope_id"] == "FIRST_TRANCHE24_ONLY"
    assert after["scope_reference"]["raw_ids"] == SCOPE
    assert after["inventory_summary"]["total_candidate_entries"] == 3

    validator = load_static_validator()
    static = validator.validate_package()
    assert static["entry_binding_authentication"] == "PASS"
    assert static["governance_binding"] == "PASS"
    assert static["first_tranche24_scope_exactness"] == "PASS"
    assert static["candidate_set_consistency"] == "PASS"
    assert static["provenance_map_consistency"] == "PASS"
    assert static["negative_fixtures_rejected"] == 10
    assert static["zero_operational_effect"] == "PASS"

    stale_count = sum(
        1
        for item in after["candidates"][0]["supporting_artifact_references"]
        if item.get("reference") == BAD_PATH
    )
    assert stale_count == 0
    assert (PROJECT / RESOLVED_REFERENCE).is_file()
    assert digest(PROJECT / RESOLVED_REFERENCE) == supporting_after["sha256"]

    return {
        "BAD_REFERENCE_REPRODUCED": "YES",
        "BAD_REFERENCE_PATH": BAD_PATH,
        "BAD_REFERENCE_SHA256": BAD_SHA,
        "MATCHING_EXISTING_PATH": RESOLVED_REFERENCE,
        "MATCHING_EXISTING_PATH_SHA256": digest(RESOLVED_PATH),
        "RESOLVED_EVIDENCE_PATH": RESOLVED_REFERENCE,
        "RESOLVED_EVIDENCE_SHA256": digest(RESOLVED_PATH),
        "RESOLVED_EVIDENCE_AUTHENTICATION": "PASS",
        "RESOLVED_EVIDENCE_SEMANTIC_SUPPORT": "PASS",
        "CORRECTED_REFERENCE_PATH_EXISTS": "YES",
        "CORRECTED_REFERENCE_SHA256_MATCH": "YES",
        "CORRECTED_REFERENCE_AUTHENTICATED_LINEAGE": "PASS",
        "CORRECTED_REFERENCE_SEMANTIC_SUPPORT": "PASS",
        "RESOLVED_EVIDENCE_COMMIT_OR_AUTHENTICATED_LINEAGE_REFERENCE": f"{review_dir.relative_to(PROJECT).as_posix()}/MATERIALIZATION_MANIFEST.json; Binding commit {COMMIT} (parent {PARENT})",
        "CANDIDATE_SEMANTIC_DRIFT": 0,
        "STALE_BAD_REFERENCE_COUNT": stale_count,
        "STATIC_VALIDATOR": "PASS",
        "NEGATIVE_FIXTURES": "10/10 REJECTED",
        "VALID_RESOLUTION_FIXTURE": "NOT_PRESENT",
        "GOVERNANCE_DECISION_BINDING": "PASS",
        "FIRST_TRANCHE24_SCOPE_EXACTNESS": "PASS",
        "CANDIDATE_SET_CONSISTENCY": "PASS",
        "PROVENANCE_EVIDENCE_MAP": "PASS",
        "SOURCE_AUTHORITY_ID_DERIVED": "NO",
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
        "ZERO_OPERATIONAL_EFFECT": "PASS",
    }


if __name__ == "__main__":
    print(json.dumps(main(), indent=2, sort_keys=True))
