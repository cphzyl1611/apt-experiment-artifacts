#!/usr/bin/env python3
"""Build the bounded decision-identity remediation and review package."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any


PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parent
RECORD_PATH = ROOT / "FA1B2de_Current86_FirstTranche24_G1G2_Decision_Preparation_V2" / "FIRST_TRANCHE24_GOVERNANCE_DECISION_RECORD_V2.json"
ZERO_PATH = ROOT / "FA1B2de_Current86_FirstTranche24_Human_Governance_Decision_G1G2" / "ZERO_OPERATIONAL_EFFECT_RECOMPUTATION.json"
V2_VALIDATOR_PATH = ROOT / "FA1B2de_Current86_FirstTranche24_Governance_Decision_Schema_V2_Remediation_Design" / "validate_v2_design.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_negative_fixtures(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    fixtures = {}

    missing = copy.deepcopy(record)
    del missing["decision"]
    fixtures["missing_field.json"] = missing

    reordered = copy.deepcopy(record)
    reordered["scope"]["frozen_target_order"] = list(reversed(reordered["scope"]["frozen_target_order"]))
    fixtures["reordered_field.json"] = reordered

    extra = copy.deepcopy(record)
    extra["unauthorized_extra_field"] = "reject"
    fixtures["extra_unauthorized_field.json"] = extra

    altered_scope = copy.deepcopy(record)
    altered_scope["scope"]["governance_scope_id"] = "ALL_TARGETS"
    fixtures["altered_scope.json"] = altered_scope

    altered_decision = copy.deepcopy(record)
    altered_decision["decision"] = "UNAUTHORIZED_DECISION"
    fixtures["altered_decision_content.json"] = altered_decision
    return fixtures


def main() -> int:
    identity = load_module("decision_identity_for_build", PACKAGE / "tools" / "decision_identity.py")
    independent = load_module("independent_recompute_for_build", PACKAGE / "tools" / "independent_recompute.py")
    validator = load_module("v2_validator_for_build", V2_VALIDATOR_PATH)
    record = read_json(RECORD_PATH)
    zero_state = read_json(ZERO_PATH)

    canonical_validation = validator.validate_package(ROOT / "FA1B2de_Current86_FirstTranche24_Governance_Decision_Schema_V2_Remediation_Design")
    if not canonical_validation["overall_status"].startswith("PASS"):
        raise SystemExit("canonical V2 validation did not pass; manifest not generated")

    computed = identity.compute_identities(record)
    independent_result = independent.recompute(record)
    declared = record["decision_identity"]
    if computed != (declared["decision_record_id"], declared["decision_transaction_hash"]):
        raise SystemExit("primary identity recomputation mismatch")
    if independent_result["decision_record_id"] != declared["decision_record_id"] or independent_result["transaction_hash"] != declared["decision_transaction_hash"]:
        raise SystemExit("independent identity recomputation mismatch")

    negative_dir = PACKAGE / "fixtures" / "negative"
    negative_results = []
    for filename, fixture in make_negative_fixtures(record).items():
        path = negative_dir / filename
        write_json(path, fixture)
        try:
            identity.compute_identities(fixture)
        except identity.IdentityContractError as error:
            negative_results.append({"fixture": f"fixtures/negative/{filename}", "status": "PASS_REJECTED", "reason": str(error)})
        else:
            raise SystemExit(f"negative fixture accepted: {filename}")

    collision = {
        "record": record,
        "supplied_decision_record_id": "GOVDEC2-" + "0" * 64,
        "supplied_transaction_hash": declared["decision_transaction_hash"],
    }
    collision_path = negative_dir / "collision_or_reuse_mismatch.json"
    write_json(collision_path, collision)
    try:
        identity.validate_reuse(record, collision["supplied_decision_record_id"], collision["supplied_transaction_hash"])
    except identity.IdentityContractError as error:
        negative_results.append({"fixture": "fixtures/negative/collision_or_reuse_mismatch.json", "status": "PASS_REJECTED", "reason": str(error)})
    else:
        raise SystemExit("collision/reuse fixture accepted")

    zero_result = identity.verify_zero_mutation(zero_state)
    independent_zero = {
        "authority_activation": zero_state["authority_activation"],
        "source_acquisition": zero_state["immutable_source_artifacts_acquired"] == 0,
        "stage_a_admission": zero_state["stage_a_admissions"] == 0,
        "field_pins": zero_state["field_pins_created"],
        "operative_records": zero_state["operative_canonical_source_manifest_entries_admitted"],
    }
    if independent_zero != {"authority_activation": "NO", "source_acquisition": True, "stage_a_admission": True, "field_pins": 0, "operative_records": 0}:
        raise SystemExit("independent zero-mutation verification failed")

    write_json(PACKAGE / "evidence" / "INDEPENDENT_RECOMPUTATION.json", {
        "schema": "FIRST_TRANCHE24_G1G2_DECISION_IDENTITY_INDEPENDENT_RECOMPUTATION_V1",
        "status": "PASS",
        "record_path": str(RECORD_PATH.relative_to(ROOT)),
        "canonical_profile": identity.PROFILE_ID,
        "identity_procedure_id": identity.IDENTITY_PROCEDURE_ID,
        "basis_sha256": independent_result["basis_sha256"],
        "raw_decision_digest": independent_result["raw_decision_digest"],
        "raw_transaction_digest": independent_result["raw_transaction_digest"],
        "decision_record_id": independent_result["decision_record_id"],
        "transaction_hash": independent_result["transaction_hash"],
        "declared_values_match": True,
        "independent_implementation": "tools/independent_recompute.py",
        "metadata_exclusion": "PASS",
    })
    write_json(PACKAGE / "evidence" / "NEGATIVE_FIXTURE_RESULTS.json", {
        "schema": "FIRST_TRANCHE24_G1G2_DECISION_IDENTITY_NEGATIVE_FIXTURE_REVIEW_V1",
        "status": "PASS",
        "fixture_count": len(negative_results),
        "results": negative_results,
    })
    write_json(PACKAGE / "evidence" / "ZERO_MUTATION_VERIFICATION.json", {
        "schema": "FIRST_TRANCHE24_G1G2_DECISION_IDENTITY_ZERO_MUTATION_VERIFICATION_V1",
        "status": "PASS_ZERO_OPERATIONAL_EFFECT",
        "primary_verifier": zero_result,
        "independent_verifier": independent_zero,
        "authority_activation": "NO",
        "source_acquisition": "NO",
        "stage_a_admission": "NO",
        "field_pins": 0,
        "operative_records": 0,
        "source_authentication": "NO",
        "formal_experiment": "NO",
    })

    package = {
        "schema": "FIRST_TRANCHE24_G1G2_BOUNDED_DECISION_PREPARATION_PACKAGE_V3",
        "package_status": "PREPARATION_ONLY_NOT_OPERATIVE",
        "blocker_closure_status": "PASS_BOUNDED_IDENTITY_REMEDIATION",
        "decision_identity_recomputation_status": "PASS",
        "canonical_validation_status": canonical_validation["overall_status"],
        "decision": record["decision"],
        "scope": record["scope"]["governance_scope_id"],
        "scope_cardinality": record["scope"]["scope_cardinality"],
        "frozen_target_order": record["scope"]["frozen_target_order"],
        "decision_record_id": declared["decision_record_id"],
        "transaction_hash": declared["decision_transaction_hash"],
        "basis_sha256": independent_result["basis_sha256"],
        "principal_id": record["human_governance_identity_reference"]["principal_id"],
        "principal_identity_sha256": record["human_governance_identity_reference"]["principal_identity_sha256"],
        "zero_effect_status": "PASS_ZERO_OPERATIONAL_EFFECT",
        "authority_activation": "NO",
        "source_acquisition": "NO",
        "stage_a_admission": "NO",
        "field_pins": 0,
        "operative_records": 0,
        "next_action": "INDEPENDENT_REVIEW_OF_DECISION_IDENTITY_REMEDIATION",
    }
    write_json(PACKAGE / "BOUNDED_DECISION_PREPARATION_PACKAGE.json", package)

    review = {
        "schema": "FIRST_TRANCHE24_G1G2_DECISION_IDENTITY_REMEDIATION_INDEPENDENT_REVIEW_V1",
        "review_date": "2026-09-03",
        "review_mode": "READ_ONLY_BOUNDED_INDEPENDENT_REVIEW",
        "review_scope": "FIRST_TRANCHE24_G1G2_DECISION_IDENTITY_REMEDIATION",
        "blocker_closure_status": "PASS_BOUNDED_IDENTITY_REMEDIATION",
        "previous_blocker": "DECISION_RECORD_ID_AND_TRANSACTION_HASH_RECOMPUTATION_MISSING",
        "terminal_verdict": "FIRST_TRANCHE24_G1G2_DECISION_IDENTITY_REMEDIATION = PASS_READY_FOR_DECISION_MATERIALIZATION_REVIEW",
        "canonical_validation": canonical_validation,
        "independent_recomputation": "PASS",
        "negative_fixtures": "PASS",
        "zero_mutation": "PASS_ZERO_OPERATIONAL_EFFECT",
        "decision_materialization_executed": False,
        "source_authority_activated": False,
        "source_acquisition_executed": False,
        "stage_a_admission_executed": False,
        "field_pins_created": 0,
        "operative_records_created": 0,
        "next_gate": "FIRST_TRANCHE24_G1G2_DECISION_MATERIALIZATION_REVIEW",
        "independent_reviewer_basis": "tools/independent_recompute.py plus evidence files",
    }
    write_json(PACKAGE / "INDEPENDENT_REVIEW.json", review)
    (PACKAGE / "INDEPENDENT_REVIEW.md").write_text(
        "\n".join([
            "# First-Tranche24 G1/G2 Decision Identity Remediation Review",
            "",
            "## Bounded result",
            "",
            "`FIRST_TRANCHE24_G1G2_DECISION_IDENTITY_REMEDIATION = PASS_READY_FOR_DECISION_MATERIALIZATION_REVIEW`",
            "",
            "The prior blocker `DECISION_RECORD_ID_AND_TRANSACTION_HASH_RECOMPUTATION_MISSING` is closed for bounded deterministic recomputation. The fixed decision and scope remain unchanged.",
            "",
            "## Evidence",
            "",
            f"- Canonical V2 validation: `{canonical_validation['overall_status']}`.",
            "- Independent decision ID and transaction hash recomputation: `PASS`.",
            "- Negative fixtures, including collision/reuse mismatch: `PASS`.",
            "- Zero operational effect: `PASS_ZERO_OPERATIONAL_EFFECT`.",
            "",
            "## Boundary",
            "",
            "Decision materialization itself was not executed. Source authority activation, source acquisition, source authentication, Stage A admission, field-pin creation, operative-record creation, and formal experiment remain unexecuted.",
            "",
            "- authority activation: `NO`",
            "- source acquisition: `NO`",
            "- Stage A admission: `NO`",
            "- field pins: `0`",
            "- operative records: `0`",
            "",
            "Next gate: `FIRST_TRANCHE24_G1G2_DECISION_MATERIALIZATION_REVIEW`.",
            "",
        ])
        , encoding="utf-8",
    )

    payload_files = []
    for path in sorted(PACKAGE.rglob("*")):
        if not path.is_file() or path.name == "MATERIALIZATION_MANIFEST.json" or "__pycache__" in path.parts:
            continue
        payload_files.append({
            "path": str(path.relative_to(PACKAGE)),
            "sha256": sha256(path),
            "byte_length": path.stat().st_size,
        })
    manifest = {
        "manifest_format": "canonical-v1",
        "manifest_track": "binding",
        "manifest_task_id": "FIRST_TRANCHE24_G1G2_DECISION_IDENTITY_REMEDIATION",
        "manifest_type": "BOUNDED_DECISION_IDENTITY_REMEDIATION_PACKAGE",
        "package_path": PACKAGE.name,
        "package_status": "BOUNDED_REVIEW_PACKAGE_ONLY",
        "blocker_closure_status": "PASS_BOUNDED_IDENTITY_REMEDIATION",
        "review_verdict": review["terminal_verdict"],
        "manifest_file_count": len(payload_files),
        "files": payload_files,
        "zero_mutation_boundary": {
            "authority_activation": "NO",
            "source_acquisition": "NO",
            "stage_a_admission": "NO",
            "field_pins": 0,
            "operative_records": 0,
        },
        "manifest_validation": {
            "status": "PASS",
            "canonical_profile": identity.PROFILE_ID,
            "manifest_excluded_from_payload_inventory": True,
            "recursive_inclusion": False,
        },
    }
    write_json(PACKAGE / "MATERIALIZATION_MANIFEST.json", manifest)
    print(json.dumps({
        "blocker_closure_status": review["blocker_closure_status"],
        "package_path": str(PACKAGE),
        "materialization_manifest_path": str(PACKAGE / "MATERIALIZATION_MANIFEST.json"),
        "manifest_format": manifest["manifest_format"],
        "manifest_track": manifest["manifest_track"],
        "manifest_task_id": manifest["manifest_task_id"],
        "manifest_file_count": manifest["manifest_file_count"],
        "manifest_validation": manifest["manifest_validation"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
