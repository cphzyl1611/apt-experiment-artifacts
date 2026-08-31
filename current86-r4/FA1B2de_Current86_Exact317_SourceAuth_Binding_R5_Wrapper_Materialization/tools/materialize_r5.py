#!/usr/bin/env python3
"""Materialize the approved R5 wrapper package without activating authority."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parent
R4 = ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Prospective_Canonical_Wrapper_Governance_R4"
TARGET_MANIFEST = ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4/00_lineage/EXACT317_TARGET_MANIFEST.json"
RAW_REGISTRY = Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/project_snapshots/raw_action_registry.jsonl")
PLAYBOOK_ROOT = Path("/home/cph/experiment")
C0_SOURCE = Path("/home/cph/experiment-artifacts/tier-de1c0-handoff-20260823-083725/tier_de1c0_typed_operation_semantics.jsonl")
C0_SUBSET = Path("/home/cph/experiment-artifacts/fa1b2de-current86-canonical-source-authentication-r1/CURRENT86_C0_Typed_Operation_Semantics_60_Recovered.jsonl")
SCORING_SOURCE = Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/c2/c2_scoring_snapshot_post_c1.jsonl")

sys.path.insert(0, str(PACKAGE))
from r5_wrapper import (  # noqa: E402
    authenticate_human_approval,
    extract_c0,
    extract_raw,
    extract_scoring,
    validate_exact317_conservation,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    return sha256(path.read_bytes())


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def write_json(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    path.write_bytes(data)
    return sha256(data)


def write_jsonl(path: Path, rows: list[dict]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = b"".join(canonical_bytes(row) for row in rows)
    path.write_bytes(data)
    return sha256(data)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def route_targets(manifest: dict, commitments: dict, rule_id: str) -> list[dict]:
    route = next(r for r in commitments["routes"] if r["rule_id"] == rule_id)
    by_id = {t["source_binding_target_id"]: t for t in manifest["targets"]}
    return [by_id[target_id] for target_id in route["target_ids"]]


def main() -> int:
    rules_package = load_json(R4 / "PROSPECTIVE_EXTRACTION_AUTHORITY_RULES.json")
    wrapper_rules_package = load_json(R4 / "PROSPECTIVE_CANONICAL_SOURCE_WRAPPER_RULES.json")
    manifest = load_json(TARGET_MANIFEST)
    commitments = load_json(R4 / "PROSPECTIVE_TARGET_EXPANSION_COMMITMENTS.json")
    rules = {r["rule_id"]: r for r in rules_package["rules"]}
    wrapper_rules = {r["rule_id"]: r for r in wrapper_rules_package["routes"]}
    r4_package_sha = file_sha(R4 / "SHA256SUMS.txt")
    approval = {
        "HUMAN_ORIGIN": "USER_EXPLICIT_APPROVAL",
        "decisions": {rule_id: "APPROVE_EXACT_CANONICAL_WRAPPER_RULE" for rule_id in rules},
    }
    approval_auth = authenticate_human_approval(approval, rules_package, r4_package_sha)
    write_json(PACKAGE / "01_approval/HUMAN_APPROVAL_AUTHENTICATION.json", {
        "schema": "FA1B2DE_CURRENT86_BINDING_R5_HUMAN_APPROVAL_AUTHENTICATION_V1",
        "human_origin": "USER_EXPLICIT_APPROVAL",
        "approval_decisions": approval["decisions"],
        "approved_r4_rule_ids": approval_auth["approved_rule_ids"],
        "authenticated": True,
        "frozen_r4_package": {
            "path": str(R4),
            "sha256sums_sha256": r4_package_sha,
            "rule_package_sha256": file_sha(R4 / "PROSPECTIVE_EXTRACTION_AUTHORITY_RULES.json"),
        },
        "source_auth_executed": False,
        "active_canonical_source_authority_created": False,
        "field_pins_created": 0,
    })
    write_json(PACKAGE / "00_lineage/R5_LINEAGE_PIN.json", {
        "schema": "FA1B2DE_CURRENT86_BINDING_R5_LINEAGE_PIN_V1",
        "stage": "BINDING_R5_WRAPPER_MATERIALIZATION",
        "human_origin": "USER_EXPLICIT_APPROVAL",
        "approval_artifact": "01_approval/HUMAN_APPROVAL_AUTHENTICATION.json",
        "frozen_r4_package": str(R4),
        "frozen_r4_sha256sums_sha256": r4_package_sha,
        "exact317_manifest": str(TARGET_MANIFEST),
        "exact317_manifest_sha256": file_sha(TARGET_MANIFEST),
        "target_total": 317,
        "raw_target_total": 86,
        "candidate_target_total": 231,
        "active_canonical_source_authority_created": False,
        "source_auth_executed": False,
        "field_pins_created": 0,
        "binding_publication": False,
    })
    write_json(PACKAGE / "02_specs/APPROVED_R4_WRAPPER_SPECS.json", {
        "schema": "FA1B2DE_CURRENT86_BINDING_R5_APPROVED_R4_WRAPPER_SPECS_V1",
        "source_package": str(R4 / "PROSPECTIVE_EXTRACTION_AUTHORITY_RULES.json"),
        "source_package_sha256": file_sha(R4 / "PROSPECTIVE_EXTRACTION_AUTHORITY_RULES.json"),
        "rules": rules_package["rules"],
        "materialization_status": "MATERIALIZED_SPEC_REFERENCE_ONLY",
        "authority_activation": "NONE",
    })
    write_json(PACKAGE / "02_specs/APPROVED_R4_TARGET_COMMITMENTS.json", {
        "schema": "FA1B2DE_CURRENT86_BINDING_R5_APPROVED_R4_TARGET_COMMITMENTS_V1",
        "source_package": str(R4 / "PROSPECTIVE_TARGET_EXPANSION_COMMITMENTS.json"),
        "source_package_sha256": file_sha(R4 / "PROSPECTIVE_TARGET_EXPANSION_COMMITMENTS.json"),
        "commitments": commitments,
        "materialization_status": "MATERIALIZED_COMMITMENT_REFERENCE_ONLY",
        "authority_activation": "NONE",
    })

    raw_rows = [json.loads(line) for line in RAW_REGISTRY.read_text(encoding="utf-8").splitlines()]
    raw_targets = route_targets(manifest, commitments, "R4_WRAPPER_RAW_LEGACY_26")
    c0_targets = route_targets(manifest, commitments, "R4_WRAPPER_C0_60")
    scoring_targets = route_targets(manifest, commitments, "R4_WRAPPER_SCORING_231")
    raw_records = extract_raw(
        raw_targets,
        raw_rows,
        PLAYBOOK_ROOT,
        expected_git_commit=wrapper_rules["R4_WRAPPER_RAW_LEGACY_26"]["corpus"]["commit"],
    )
    c0_records = extract_c0(c0_targets, C0_SOURCE, file_sha(C0_SOURCE))
    scoring_records = extract_scoring(scoring_targets, SCORING_SOURCE, file_sha(SCORING_SOURCE))
    conservation = validate_exact317_conservation(
        manifest["targets"],
        {
            "R4_WRAPPER_RAW_LEGACY_26": raw_records,
            "R4_WRAPPER_C0_60": c0_records,
            "R4_WRAPPER_SCORING_231": scoring_records,
        },
    )

    module_path = PACKAGE / "r5_wrapper.py"
    implementation_sha = file_sha(module_path)
    extractor_dir = PACKAGE / "04_extractors"
    extractor_dir.mkdir(parents=True, exist_ok=True)
    extractor_sources = {
        "R4_WRAPPER_RAW_LEGACY_26": (
            "raw_positional_extractor.py",
            "R4_RAW_PLAYBOOK_POSITIONAL_EXTRACTOR_V1",
            "extract_raw",
        ),
        "R4_WRAPPER_C0_60": (
            "c0_exact_row_extractor.py",
            "R4_C0_IMMUTABLE_JSONL_WRAPPER_EXTRACTOR_V1",
            "extract_c0",
        ),
        "R4_WRAPPER_SCORING_231": (
            "scoring_exact_id_row_extractor.py",
            "R4_SCORING_ID_JSONL_WRAPPER_EXTRACTOR_V1",
            "extract_scoring",
        ),
    }
    extractor_hashes = {}
    for rule_id, (name, spec_id, function) in extractor_sources.items():
        content = (
            '"""Materialized R5 route entrypoint; extraction remains non-authoritative."""\n'
            "from r5_wrapper import " + function + "\n\n"
            f'EXTRACTOR_SPEC_ID = "{spec_id}"\n'
            f'RULE_ID = "{rule_id}"\n'
            f'EXTRACTOR = {function}\n'
        ).encode("utf-8")
        path = extractor_dir / name
        path.write_bytes(content)
        extractor_hashes[rule_id] = {"path": str(path.relative_to(PACKAGE)), "sha256": sha256(content), "spec_id": spec_id}

    source_hashes = {
        "raw_registry": {"path": str(RAW_REGISTRY), "sha256": file_sha(RAW_REGISTRY), "byte_length": RAW_REGISTRY.stat().st_size},
        "c0_source": {"path": str(C0_SOURCE), "sha256": file_sha(C0_SOURCE), "byte_length": C0_SOURCE.stat().st_size},
        "c0_exact_subset": {"path": str(C0_SUBSET), "sha256": file_sha(C0_SUBSET), "byte_length": C0_SUBSET.stat().st_size},
        "scoring_snapshot": {"path": str(SCORING_SOURCE), "sha256": file_sha(SCORING_SOURCE), "byte_length": SCORING_SOURCE.stat().st_size},
        "r4_exact317_manifest": {"path": str(TARGET_MANIFEST), "sha256": file_sha(TARGET_MANIFEST), "byte_length": TARGET_MANIFEST.stat().st_size},
    }
    route_input_hashes = {
        "R4_WRAPPER_RAW_LEGACY_26": {
            "r4_exact317_manifest": source_hashes["r4_exact317_manifest"],
            "raw_registry": source_hashes["raw_registry"],
        },
        "R4_WRAPPER_C0_60": {
            "r4_exact317_manifest": source_hashes["r4_exact317_manifest"],
            "c0_source": source_hashes["c0_source"],
            "c0_exact_subset": source_hashes["c0_exact_subset"],
        },
        "R4_WRAPPER_SCORING_231": {
            "r4_exact317_manifest": source_hashes["r4_exact317_manifest"],
            "scoring_snapshot": source_hashes["scoring_snapshot"],
        },
    }

    records_by_rule = {
        "R4_WRAPPER_RAW_LEGACY_26": raw_records,
        "R4_WRAPPER_C0_60": c0_records,
        "R4_WRAPPER_SCORING_231": scoring_records,
    }
    input_paths = {}
    for rule_id, records in records_by_rule.items():
        rule = rules[rule_id]
        ids = [t["source_binding_target_id"] for t in route_targets(manifest, commitments, rule_id)]
        input_manifest = {
            "schema": "FA1B2DE_CURRENT86_BINDING_R5_WRAPPER_INPUT_MANIFEST_V1",
            "materialization_status": "MATERIALIZED_PROSPECTIVE_INPUT_MANIFEST",
            "authority_status": "NON_AUTHORITATIVE_CANDIDATE_INPUT",
            "rule_id": rule_id,
            "approved_spec_id": rule["extractor_spec"]["spec_version"],
            "approved_spec_sha256": rule["deterministic_extractor_sha256"],
            "approved_r4_input_manifest_sha256": rule["exact_input_manifest_sha256"],
            "approved_r4_checkpoint_sha256": rule["exact_checkpoint_sha256"],
            "exact317_manifest_sha256": file_sha(TARGET_MANIFEST),
            "target_count": len(records),
            "target_indices": [r["target_index"] for r in records],
            "target_ids": ids,
            "expansion_set_commitment_sha256": rule["expansion_set_commitment_sha256"],
            "source_auth_executed": False,
            "field_pins_created": 0,
            "route_inputs": route_input_hashes[rule_id],
            "authenticated_r4_corpus_lineage": wrapper_rules[rule_id]["corpus"],
            "row_commitments": [
                {
                    "target_index": r["target_index"],
                    "source_binding_target_id": r["source_binding_target_id"],
                    "source_key": r["source_key"],
                    "source_locator": r["source_locator"],
                    "row_bytes_sha256": r.get("row_bytes_sha256"),
                    "source_file_sha256": r.get("source_file_sha256"),
                }
                for r in records
            ],
        }
        path = PACKAGE / "03_inputs" / f"{rule_id}_INPUT_MANIFEST.json"
        actual_sha = write_json(path, input_manifest)
        input_paths[rule_id] = {"path": str(path.relative_to(PACKAGE)), "sha256": actual_sha}
        checkpoint = {
            "schema": "FA1B2DE_CURRENT86_BINDING_R5_WRAPPER_CHECKPOINT_V1",
            "status": "MATERIALIZED_PROSPECTIVE_CHECKPOINT_NON_AUTHORITATIVE",
            "rule_id": rule_id,
            "approved_r4_checkpoint_sha256": rule["exact_checkpoint_sha256"],
            "input_manifest_sha256": actual_sha,
            "extractor_spec_id": rule["extractor_spec"]["spec_version"],
            "extractor_spec_sha256": rule["deterministic_extractor_sha256"],
            "extractor_implementation_sha256": implementation_sha,
            "route_entrypoint": extractor_hashes[rule_id],
            "target_count": len(records),
            "source_auth_executed": False,
            "active_canonical_source_authority_created": False,
            "field_pins_created": 0,
            "dry_run_only": True,
        }
        write_json(PACKAGE / "03_inputs" / f"{rule_id}_CHECKPOINT.json", checkpoint)

    dry_dir = PACKAGE / "05_dry_run"
    write_jsonl(dry_dir / "RAW_26_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl", raw_records)
    write_jsonl(dry_dir / "C0_60_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl", c0_records)
    write_jsonl(dry_dir / "SCORING_231_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl", scoring_records)
    all_records = sorted(raw_records + c0_records + scoring_records, key=lambda r: r["target_index"])
    exact_sha = write_jsonl(dry_dir / "EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl", all_records)
    write_json(dry_dir / "DRY_RUN_CONSERVATION.json", {
        "schema": "FA1B2DE_CURRENT86_BINDING_R5_DRY_RUN_CONSERVATION_V1",
        "status": "NON_AUTHORITATIVE_DRY_RUN_ONLY",
        "candidate_wrapper_objects_only": True,
        "exact317_dry_run_sha256": exact_sha,
        **conservation,
        "source_auth_executed": False,
        "active_canonical_source_authority_created": False,
        "field_pins_created": 0,
    })

    candidate_common = {
        "authority_status": "NON_ACTIVE_CANDIDATE",
        "activation_status": "NOT_ACTIVE",
        "scope": "EXACT317_ONLY",
        "target_count": 317,
        "target_manifest_sha256": file_sha(TARGET_MANIFEST),
        "wrapper_rule_ids": sorted(records_by_rule),
        "source_auth_executed": False,
        "active_canonical_source_authority_created": False,
        "field_pins_created": 0,
        "binding_publication": False,
        "scoring_authority_mutated": False,
        "git_ref_mutation": False,
    }
    write_json(PACKAGE / "06_non_active_candidates/SOURCE_ADMISSION_REGISTRY_ROOT_CANDIDATE.json", {
        "schema": "FA1B2DE_CURRENT86_SOURCE_ADMISSION_AUTHORITY_ROOTS_R5_CANDIDATE",
        "authority_role": "SOURCE_ADMISSION_REGISTRY_ROOT",
        **candidate_common,
        "exact_route_target_sets": {rule_id: [r["target_index"] for r in records] for rule_id, records in records_by_rule.items()},
        "candidate_object_ids": [record["candidate_object_id"] for record in all_records],
        "candidate_tuples_materialized": True,
        "human_field_pin_decisions": "NOT_CREATED",
        "field_pin_authority_status": "BLOCKED_NOT_CREATED",
    })
    write_json(PACKAGE / "06_non_active_candidates/SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT_CANDIDATE.json", {
        "schema": "FA1B2DE_CURRENT86_SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT_R5_CANDIDATE",
        "authority_role": "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT",
        **candidate_common,
        "expansion_policy": "EXACT_COMMITTED_TARGET_SET_ONLY",
        "fail_closed": True,
        "corpus_schema_rules": {rule_id: rules[rule_id]["row_locator_contract"] for rule_id in records_by_rule},
    })
    write_json(PACKAGE / "06_non_active_candidates/COMMON_INPUT_FREEZE_ADDITIONS_CANDIDATE.json", {
        "schema": "FA1B2DE_CURRENT86_EXACT317_SOURCE_AUTH_COMMON_INPUT_FREEZE_ADDITIONS_R5_CANDIDATE",
        "authority_role": "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST",
        **candidate_common,
        "input_manifests": input_paths,
        "checkpoints": {rule_id: {"path": f"03_inputs/{rule_id}_CHECKPOINT.json"} for rule_id in records_by_rule},
        "extractor_implementation_sha256": implementation_sha,
    })
    write_json(PACKAGE / "06_non_active_candidates/EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION_PATCH_CANDIDATE.json", {
        "schema": "FA1B2DE_CURRENT86_EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION_PATCH_R5_CANDIDATE",
        "authority_role": "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION",
        **candidate_common,
        "exec_r4_mutated": False,
        "registered_in_exec_r4": False,
        "dispatch_entries": [
            {"rule_id": rule_id, "entrypoint": extractor_hashes[rule_id], "status": "PROSPECTIVE_NOT_REGISTERED"}
            for rule_id in sorted(records_by_rule)
        ],
    })

    write_json(PACKAGE / "07_verification/R5_TERMINAL_STATE.json", {
        "BINDING_R5_WRAPPER_MATERIALIZATION": "PASS_READY_FOR_FRESH_REVIEW",
        "HUMAN_APPROVAL_AUTHENTICATED": "YES",
        "TARGETS_TOTAL": 317,
        "DRY_RUN_EXACT317_CONSERVATION": "PASS",
        "ACTIVE_SOURCE_AUTHORITY_CREATED": "NO",
        "SOURCE_AUTH_EXECUTED": "NO",
        "FIELD_PINS_CREATED": 0,
        "P0_EXECUTED": "NO",
        "P1_EXECUTED": "NO",
        "BINDING_PUBLICATION": "NO",
        "NEXT_ACTION": "FRESH_INDEPENDENT_REVIEW_OF_BINDING_R5_WRAPPER_MATERIALIZATION",
        "STOP": True,
    })
    report = """# Binding R5 Wrapper Materialization\n\nThis package materializes the three explicitly approved R4 deterministic wrapper specifications and performs only a non-authoritative dry run. The RAW legacy route preserves the absence of historical producer identity; the C0 route preserves its historical evidence identity; and the scoring route does not mutate scoring authority.\n\n- Exact317: 317 targets = 86 RAW + 231 CANDIDATE\n- Dry-run route counts: RAW legacy 26/26, C0 60/60, scoring 231/231\n- Union: Exact317; duplicates: 0; cross-route substitution: 0\n- Output class: `CANDIDATE_WRAPPER_OBJECTS_ONLY`\n- Active canonical source authority: no\n- Source-auth execution: no\n- Field pins: 0\n- P0/P1: not executed\n- Binding publication: no\n- EXEC-R4/GOV-R4 mutation: no\n\nThe four files under `06_non_active_candidates/` are candidates only and are not registered or active.\n\n## Required Terminal\n\n```text\nBINDING_R5_WRAPPER_MATERIALIZATION = PASS_READY_FOR_FRESH_REVIEW\nHUMAN_APPROVAL_AUTHENTICATED = YES\nTARGETS_TOTAL = 317\nDRY_RUN_EXACT317_CONSERVATION = PASS\nACTIVE_SOURCE_AUTHORITY_CREATED = NO\nSOURCE_AUTH_EXECUTED = NO\nFIELD_PINS_CREATED = 0\nP0_EXECUTED = NO\nP1_EXECUTED = NO\nBINDING_PUBLICATION = NO\nNEXT_ACTION = FRESH_INDEPENDENT_REVIEW_OF_BINDING_R5_WRAPPER_MATERIALIZATION\nSTOP = true\n```\n"""
    (PACKAGE / "07_verification/R5_WRAPPER_MATERIALIZATION_REPORT.md").write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
