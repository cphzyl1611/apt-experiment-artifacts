#!/usr/bin/env python3
"""Targeted, read-only fresh review of the E0C-R8R1 remediation.

This reviewer intentionally does not rebuild the 203-member Exact12 analysis.
It reuses the preserved independent recomputation from the historical review,
after authenticating that all R6/R7/R3 inputs and member commitments are still
the same.  It then checks only the corrected UNKNOWN-sensitive output fields.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable, Mapping


REPOSITORY_URL = "https://github.com/cphzyl1611/apt-experiment-artifacts.git"
HISTORICAL_MAIN = "2ff2b21cd313c5b91567adfe05691d3e25aabb87"
FRESH_REVIEW_MATERIALIZATION = "822079ec58e90f2d1a00fa967a8bd7f77ff9614d"
UNKNOWN = "UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE"
MANUAL_STATUS = "MANUAL_DESIGN_REQUIRED"
EXPECTED_TEMPLATE_COUNT = 12
EXPECTED_RAW_COVERAGE = 203
EXPECTED_BLOCKED_OVERLAP = 0
ALLOWED_DECISIONS = [
    "APPROVE_TEMPLATE_FOR_MEMBER_SET",
    "REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL",
    "REQUEST_SPLIT_OR_MORE_EVIDENCE",
]
EXPECTED_TEMPLATE_IDS = [
    "r4-template-120-process_command_execution",
    "r4-template-136-process_command_execution",
    "r4-template-107-process_command_execution",
    "r4-template-159-process_command_execution",
    "r4-template-130-process_command_execution",
    "r4-template-152-process_command_execution",
    "r4-template-069-persistence_configuration",
    "r4-template-009-credential_store_access",
    "r4-template-006-credential_store_access",
    "r4-template-048-network_c2_beacon",
    "r4-template-035-file_resource_operation",
    "r4-template-071-persistence_configuration",
]
STRUCTURED_FIELDS = (
    "source_action_type",
    "os_platform",
    "explicit_protocol_service",
    "explicit_required_protocol",
    "explicit_required_service_class",
    "service_prerequisites",
    "telemetry_surface_flags",
    "host_process_file_socket_network_requirements",
    "destructive_state_flag",
    "reset_safety_complexity",
    "environment_blocker",
    "source_detail_completeness",
    "controlled_environment_feasibility",
)
AUTHENTICATED_INPUT_FILES = (
    "E0C_R6_FIRST_HUMAN_REVIEW_TRANCHE.json",
    "E0C_R6_EXACT89_ENRICHED_TEMPLATE_PACKETS.jsonl",
    "E0C_R6_INPUT_AUTHENTICATION.json",
    "E0C_R6_BLOCKED31_SOURCE_RECOVERY_RESULTS.json",
    "E0C_R7_FIRST_TRANCHE_INPUT_AUTHENTICATION.json",
    "E0C_R7_FIRST_TRANCHE_DECISION_PACKET.json",
    "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl",
)
R8_OUTPUT_FILES = (
    "E0C_R8_INPUT_AUTHENTICATION.json",
    "E0C_R8_EXACT12_STRUCTURED_HETEROGENEITY.json",
    "E0C_R8_EXACT12_CANDIDATE_SPLIT_EVIDENCE.jsonl",
    "E0C_R8_EXACT12_REVIEW_COMPLEXITY.json",
    "E0C_R8_HUMAN_DECISION_SUPPORT_SHEETS.md",
    "E0C_R8_HUMAN_DECISION_PACKET.json",
    "E0C_R8_STRUCTURED_COHESION_REVIEW_REPORT.md",
)
PACKAGE_FILES = (
    "E0C_R8R1_DEFECT_REPRODUCTION.json",
    "E0C_R8R1_UNKNOWN_NORMALIZATION_CONTRACT.json",
    "E0C_R8R1_CORRECTED_HETEROGENEITY_VERIFICATION.json",
    "E0C_R8R1_NONREGRESSION.json",
    "E0C_R8R1_TEST_RERUN.json",
    "E0C_R8R1_REMEDIATION_REPORT.md",
)
HISTORICAL_REVIEW_SHA256 = {
    "E0C_R8_FRESH_INDEPENDENT_REVIEW.json": "6af27263d54a411f1890628d941b2aa2f5f8566dc7d9f62336343c6055f86254",
    "E0C_R8_FRESH_INDEPENDENT_REVIEW.md": "2b6db413fc938497dd40e1c52b9fa250ce5e375caa162a2cf6835c9b13dbc225",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path.name}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object at {path.name}:{number}")
        rows.append(value)
    return rows


def _resolve_remote_head() -> str:
    result = subprocess.run(
        ["git", "ls-remote", REPOSITORY_URL, "refs/heads/main"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    parts = result.stdout.strip().split()
    return parts[0] if parts and re.fullmatch(r"[0-9a-f]{40}", parts[0]) else ""


def _package_audit(root: Path) -> dict[str, Any]:
    package = root / "E0C_R8R1_UNKNOWN_NORMALIZATION_REMEDIATION"
    missing = [name for name in PACKAGE_FILES if not (package / name).is_file()]
    if missing:
        return {"status": "BLOCKED", "missing_files": missing}
    hashes = {name: _sha256(package / name) for name in PACKAGE_FILES}
    defect = _load_json(package / "E0C_R8R1_DEFECT_REPRODUCTION.json")
    contract = _load_json(package / "E0C_R8R1_UNKNOWN_NORMALIZATION_CONTRACT.json")
    corrected = _load_json(package / "E0C_R8R1_CORRECTED_HETEROGENEITY_VERIFICATION.json")
    nonreg = _load_json(package / "E0C_R8R1_NONREGRESSION.json")
    tests = _load_json(package / "E0C_R8R1_TEST_RERUN.json")
    report = (package / "E0C_R8R1_REMEDIATION_REPORT.md").read_text(encoding="utf-8")
    internal_pass = all(
        value.get("status") == "PASS"
        for value in (defect, contract, corrected, nonreg, tests)
    ) and "E0C_R8R1_UNKNOWN_NORMALIZATION_REMEDIATION = PASS_READY_FOR_TARGETED_FRESH_REVIEW" in report
    return {
        "status": "PASS" if internal_pass else "BLOCKED",
        "package_path": str(package),
        "package_sha256": hashes,
        "package_files": list(PACKAGE_FILES),
        "remediation_terminal": report.splitlines()[2] if len(report.splitlines()) > 2 else "",
        "defect_status": defect.get("status"),
        "contract_status": contract.get("status"),
        "corrected_verification_status": corrected.get("status"),
        "nonregression_status": nonreg.get("status"),
        "test_rerun_status": tests.get("status"),
        "corrected_verification": corrected,
        "nonregression": nonreg,
        "contract": contract,
        "tests": tests,
    }


def _historical_review_audit(root: Path, package: Mapping[str, Any]) -> dict[str, Any]:
    paths = {name: root / name for name in HISTORICAL_REVIEW_SHA256}
    hashes = {name: _sha256(path) for name, path in paths.items() if path.is_file()}
    review = _load_json(root / "E0C_R8_FRESH_INDEPENDENT_REVIEW.json")
    defect = package["nonregression"]["historical_fresh_review_defect_evidence"]
    expected_hashes = defect.get("artifact_sha256", HISTORICAL_REVIEW_SHA256)
    hashes_ok = hashes == expected_hashes == HISTORICAL_REVIEW_SHA256
    blob_audit = defect.get("materialization_blob_authentication", {})
    reproduced = (
        review.get("terminal", {}).get("status") == "BLOCKED"
        and review.get("terminal", {}).get("next_action") == "REMEDIATE_E0C_R8"
        and review.get("r8_published_output_audit", {}).get("structured_heterogeneity_mismatch_count") == 80
    )
    return {
        "status": "PASS" if hashes_ok and reproduced and blob_audit.get("status") == "PASS" else "BLOCKED",
        "historical_report_unchanged": hashes_ok,
        "historical_artifact_sha256": hashes,
        "expected_artifact_sha256": HISTORICAL_REVIEW_SHA256,
        "materialization_commit": FRESH_REVIEW_MATERIALIZATION,
        "materialization_blob_authentication": blob_audit,
        "prior_defect_reproduced": reproduced,
        "prior_terminal": review.get("terminal", {}),
        "prior_templates": review.get("templates", []),
        "prior_authentication": review.get("authentication", {}),
    }


def _input_identity_audit(root: Path, package: Mapping[str, Any], historical: Mapping[str, Any]) -> dict[str, Any]:
    current_auth = _load_json(root / "E0C_R8_INPUT_AUTHENTICATION.json")
    current_packet = _load_json(root / "E0C_R8_HUMAN_DECISION_PACKET.json")
    prior_auth = historical["prior_authentication"]
    nonreg = package["nonregression"]
    expected_files = nonreg["historical_input_authentication"]["files"]
    file_checks = {}
    source_mismatches: list[str] = []
    for name in AUTHENTICATED_INPUT_FILES:
        path = root / name
        expected = expected_files.get(name, {})
        local_blob = _git_blob_sha1(path.read_bytes()) if path.is_file() else None
        match = local_blob == expected.get("local_git_blob_sha1") == expected.get("historical_remote_git_blob_sha1")
        file_checks[name] = {
            "local_git_blob_sha1": local_blob,
            "expected_historical_git_blob_sha1": expected.get("historical_remote_git_blob_sha1"),
            "match": match,
        }
        if not match:
            source_mismatches.append(name)
    prior_ids = prior_auth.get("exact12_template_ids", prior_auth.get("template_ids", []))
    current_ids = current_auth.get("template_ids", [])
    prior_hashes = prior_auth.get("template_member_sha256", {})
    current_hashes = {
        str(item.get("template_id")): item.get("member_set_sha256")
        for item in current_auth.get("template_member_authentication", [])
        if isinstance(item, Mapping)
    }
    packet_hashes = {
        str(item.get("template_id")): item.get("member_set_sha256")
        for item in current_packet.get("templates", [])
        if isinstance(item, Mapping)
    }
    identity_checks = {
        "template_ids_match_prior": current_ids == prior_ids == EXPECTED_TEMPLATE_IDS,
        "template_count_match": current_auth.get("template_count") == EXPECTED_TEMPLATE_COUNT,
        "raw_coverage_match": current_auth.get("raw_coverage") == EXPECTED_RAW_COVERAGE,
        "member_hashes_match_prior": current_hashes == prior_hashes,
        "packet_hashes_match_auth": packet_hashes == current_hashes,
        "member_overlap": current_auth.get("template_member_overlap") == 0,
        "member_set_drift": current_auth.get("member_set_drift") == 0,
        "blocked31_overlap": current_auth.get("blocked_member_overlap") == EXPECTED_BLOCKED_OVERLAP,
        "all_members_manual_design_required": current_auth.get("all_members_manual_design_required") == "PASS",
    }
    r8_auth_before = package["corrected_verification"]["before_output_sha256"].get("E0C_R8_INPUT_AUTHENTICATION.json")
    identity_checks["r8_authentication_output_unchanged"] = _sha256(root / "E0C_R8_INPUT_AUTHENTICATION.json") == r8_auth_before
    substantive_drift = bool(source_mismatches) or not all(identity_checks.values())
    return {
        "status": "PASS" if not substantive_drift else "BLOCKED",
        "source_file_checks": file_checks,
        "source_mismatches": source_mismatches,
        "identity_checks": identity_checks,
        "substantive_non_unknown_drift": substantive_drift,
        "targeted_review_reuse": "YES" if not substantive_drift else "NO",
        "full_fresh_review_required": "YES" if substantive_drift else "NO",
        "current_template_member_hashes": current_hashes,
    }


def _canonical(value: Any) -> str:
    if value is None or value == "" or value == [] or value == {}:
        return UNKNOWN
    if isinstance(value, str):
        return value or UNKNOWN
    if isinstance(value, (list, tuple, set)):
        values = sorted(set(_canonical(item) for item in value))
        if not values or all(_is_unknown(item) for item in values):
            return UNKNOWN
        return json.dumps(values, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, Mapping):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def _is_unknown(value: Any) -> bool:
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    if value == UNKNOWN or value == "UNKNOWN" or value.startswith("UNKNOWN"):
        return True
    if value.startswith("[") and value.endswith("]"):
        try:
            members = json.loads(value)
        except json.JSONDecodeError:
            return False
        return isinstance(members, list) and (not members or any(_is_unknown(item) for item in members))
    return False


def _unknown_normalization_audit(package: Mapping[str, Any]) -> dict[str, Any]:
    cases = {
        "scalar_unknown": {"canonical": _canonical(UNKNOWN), "is_unknown": _is_unknown(_canonical(UNKNOWN))},
        "empty_collection": {"canonical": _canonical([]), "is_unknown": _is_unknown(_canonical([]))},
        "all_unknown_collection": {"canonical": _canonical(["UNKNOWN"]), "is_unknown": _is_unknown(_canonical(["UNKNOWN"]))},
        "all_unknown_sentinel_collection": {"canonical": _canonical([UNKNOWN]), "is_unknown": _is_unknown(_canonical([UNKNOWN]))},
        "mixed_collection": {"canonical": _canonical(["UNKNOWN", "HTTP"]), "is_unknown": _is_unknown(_canonical(["UNKNOWN", "HTTP"]))},
    }
    contract = package["contract"]
    expected = (
        cases["scalar_unknown"] == {"canonical": UNKNOWN, "is_unknown": True}
        and cases["empty_collection"] == {"canonical": UNKNOWN, "is_unknown": True}
        and cases["all_unknown_collection"] == {"canonical": UNKNOWN, "is_unknown": True}
        and cases["all_unknown_sentinel_collection"] == {"canonical": UNKNOWN, "is_unknown": True}
        and cases["mixed_collection"]["canonical"] == '["HTTP","UNKNOWN"]'
        and cases["mixed_collection"]["is_unknown"] is True
        and contract.get("status") == "PASS"
        and contract.get("authenticated_exact12_mixed_collection_cells") == 0
    )
    return {
        "status": "PASS" if expected else "BLOCKED",
        "independent_cases": cases,
        "mixed_collection_rule": "retain canonical JSON and count the entire field cell as UNKNOWN-bearing; never use UNKNOWN as an authenticated split boundary",
        "authenticated_exact12_mixed_collection_cells": contract.get("authenticated_exact12_mixed_collection_cells"),
        "no_unauthenticated_semantics_invented": True,
    }


def _compare(expected: Any, observed: Any, path: str, mismatches: list[dict[str, Any]]) -> None:
    if expected != observed:
        mismatches.append({"path": path, "expected": expected, "observed": observed})


def _expected_complexity(analysis: Mapping[str, Any]) -> dict[str, Any]:
    fraction = float(analysis["unknown_burden"]["unknown_fraction"])
    hetero = int(analysis["heterogeneous_field_count"])
    level = "HIGH" if fraction >= 0.5 or hetero >= 5 else "MEDIUM" if fraction > 0 or hetero > 1 else "LOW"
    return {
        "template_id": analysis["template_id"],
        "member_count": analysis["member_count"],
        "heterogeneous_field_count": hetero,
        "unknown_cell_count": analysis["unknown_burden"]["unknown_cell_count"],
        "unknown_fraction": fraction,
        "candidate_split_count": analysis["candidate_split_count"],
        "deterministic_review_complexity_level": level,
        "interpretation": "REVIEW_AID_ONLY_NOT_AN_APPROVE_REJECT_OR_SPLIT_RECOMMENDATION",
    }


def _output_comparison(root: Path, package: Mapping[str, Any], historical: Mapping[str, Any]) -> dict[str, Any]:
    hetero = _load_json(root / "E0C_R8_EXACT12_STRUCTURED_HETEROGENEITY.json")
    complexity = _load_json(root / "E0C_R8_EXACT12_REVIEW_COMPLEXITY.json")
    splits = _load_jsonl(root / "E0C_R8_EXACT12_CANDIDATE_SPLIT_EVIDENCE.jsonl")
    prior_templates = {str(item["template_id"]): item for item in historical["prior_templates"]}
    current_templates = {str(item["template_id"]): item for item in hetero.get("templates", [])}
    mismatches: list[dict[str, Any]] = []
    for template_id in EXPECTED_TEMPLATE_IDS:
        expected = prior_templates.get(template_id)
        observed = current_templates.get(template_id)
        if expected is None or observed is None:
            mismatches.append({"template_id": template_id, "reason": "missing template"})
            continue
        _compare(expected.get("member_count"), observed.get("member_count"), f"{template_id}.member_count", mismatches)
        _compare(expected.get("member_set_sha256"), observed.get("member_set_sha256"), f"{template_id}.member_set_sha256", mismatches)
        for field in STRUCTURED_FIELDS:
            e_dist = expected.get("structured_fields", {}).get(field, {})
            o_dist = observed.get("structured_fields", {}).get(field, {})
            for key in ("unknown_member_count", "known_member_count", "unknown_fraction", "coverage", "distinct_values", "members_per_value"):
                _compare(e_dist.get(key), o_dist.get(key), f"{template_id}.{field}.{key}", mismatches)
        _compare(expected.get("unknown_burden"), observed.get("unknown_burden"), f"{template_id}.unknown_burden", mismatches)
    current_complexity = {str(item.get("template_id")): item for item in complexity.get("templates", []) if isinstance(item, Mapping)}
    complexity_mismatches: list[dict[str, Any]] = []
    for template_id, analysis in prior_templates.items():
        _compare(_expected_complexity(analysis), current_complexity.get(template_id), f"review_complexity.{template_id}", complexity_mismatches)
    split_ok = len(splits) == EXPECTED_TEMPLATE_COUNT and all(
        item.get("template_id") in EXPECTED_TEMPLATE_IDS
        and item.get("candidate_split_status") == "NO_STRUCTURED_SPLIT_EVIDENCE"
        and item.get("candidate_split_count") == 0
        and item.get("candidate_splits") == []
        for item in splits
    )
    aid_only = complexity.get("review_aid_only") is True and all(
        item.get("interpretation") == "REVIEW_AID_ONLY_NOT_AN_APPROVE_REJECT_OR_SPLIT_RECOMMENDATION"
        and not any(key in item for key in ("recommendation", "approval", "rejection", "split_recommendation"))
        for item in complexity.get("templates", [])
    )
    fractions = {f"{item['unknown_burden']['unknown_fraction']:.3f}" for item in prior_templates.values()}
    sheets = (root / "E0C_R8_HUMAN_DECISION_SUPPORT_SHEETS.md").read_text(encoding="utf-8")
    sheet_ok = all(f"`{fraction}` of structured cells)" in sheets for fraction in fractions)
    output_hashes = package["corrected_verification"]["after_output_sha256"]
    output_hash_match = all(_sha256(root / name) == expected for name, expected in output_hashes.items())
    return {
        "status": "PASS" if not mismatches and not complexity_mismatches and split_ok and aid_only and sheet_ok and output_hash_match else "BLOCKED",
        "structured_heterogeneity_match": not mismatches,
        "structured_distribution_mismatch_count": len(mismatches),
        "structured_distribution_mismatches": mismatches[:40],
        "unknown_member_counts_match": not any("unknown_member_count" in item["path"] for item in mismatches),
        "unknown_fractions_match": not any("unknown_fraction" in item["path"] or "unknown_burden" in item["path"] for item in mismatches),
        "review_complexity_match": not complexity_mismatches,
        "review_complexity_mismatch_count": len(complexity_mismatches),
        "review_complexity_mismatches": complexity_mismatches,
        "review_complexity_aid_only": aid_only,
        "candidate_split_evidence_valid": split_ok,
        "templates_with_structured_split_evidence": 0 if split_ok else None,
        "templates_with_no_structured_split_evidence": EXPECTED_TEMPLATE_COUNT if split_ok else None,
        "decision_sheet_unknown_fractions_match": sheet_ok,
        "remediation_output_hashes_match": output_hash_match,
        "previously_mismatched_fields_rechecked": ["unknown_member_count", "known_member_count", "unknown_fraction", "coverage", "distinct_values", "members_per_value", "unknown_burden", "review_complexity"],
    }


def _boundary_audit(root: Path, package: Mapping[str, Any], historical: Mapping[str, Any], identity: Mapping[str, Any], comparison: Mapping[str, Any]) -> dict[str, Any]:
    packet = _load_json(root / "E0C_R8_HUMAN_DECISION_PACKET.json")
    templates = packet.get("templates", [])
    null_decisions = len(templates) == EXPECTED_TEMPLATE_COUNT and all(
        item.get("decision") is None
        and item.get("human_decision") is None
        and item.get("decision_options") == ALLOWED_DECISIONS
        and item.get("human_decision_options", ALLOWED_DECISIONS) == ALLOWED_DECISIONS
        and item.get("r3_global_planning_status") == MANUAL_STATUS
        and item.get("status_mutations") == 0
        and item.get("formal_execution_authorized") is False
        for item in templates
    )
    report = (root / "E0C_R8_STRUCTURED_COHESION_REVIEW_REPORT.md").read_text(encoding="utf-8")
    authority = (
        packet.get("allowed_decisions") == ALLOWED_DECISIONS
        and packet.get("human_decision_options") == ALLOWED_DECISIONS
        and packet.get("human_decisions_created") == 0
        and packet.get("applied_splits") == 0
        and packet.get("status_mutations") == 0
        and packet.get("formal_experiment_executed") == "NO"
        and packet.get("denominator_change") == "NO"
        and packet.get("authority_mutation") == "NO"
    )
    packet_hash = _sha256(root / "E0C_R8_HUMAN_DECISION_PACKET.json")
    expected_packet_hash = package["corrected_verification"]["after_output_sha256"]["E0C_R8_HUMAN_DECISION_PACKET.json"]
    forbidden = ("embedding", "nearest_neighbor", "nearest-neighbor", "semantic_inference", "attack_guess")
    forbidden_hits = [key for key in forbidden if f'"{key}' in report.lower()]
    return {
        "status": "PASS" if null_decisions and authority and packet_hash == expected_packet_hash and not forbidden_hits and comparison["candidate_split_evidence_valid"] else "BLOCKED",
        "human_decision_packet_unchanged_sha256": packet_hash == expected_packet_hash,
        "human_decisions_created": packet.get("human_decisions_created"),
        "applied_splits": packet.get("applied_splits"),
        "status_mutations": packet.get("status_mutations"),
        "formal_experiment_executed": packet.get("formal_experiment_executed"),
        "denominator_change": packet.get("denominator_change"),
        "authority_mutation": packet.get("authority_mutation"),
        "all_decisions_null": null_decisions,
        "allowed_decisions_only": authority,
        "forbidden_inference_keys_found": forbidden_hits,
        "review_complexity_is_aid_only": comparison["review_complexity_aid_only"],
    }


def _run(command: list[str], root: Path) -> dict[str, Any]:
    result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=600)
    output = result.stdout + result.stderr
    match = re.search(r"Ran (\d+) tests?", output)
    return {
        "command": " ".join(command),
        "return_code": result.returncode,
        "status": "PASS" if result.returncode == 0 else "BLOCKED",
        "test_count": int(match.group(1)) if match else None,
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "output": output,
    }


def build_targeted_review(root: Path = Path("."), run_tests: bool = False) -> dict[str, Any]:
    package = _package_audit(root)
    historical = _historical_review_audit(root, package)
    identity = _input_identity_audit(root, package, historical)
    normalization = _unknown_normalization_audit(package)
    comparison = _output_comparison(root, package, historical)
    boundary = _boundary_audit(root, package, historical, identity, comparison)
    try:
        current_head = _resolve_remote_head()
    except (OSError, subprocess.SubprocessError):
        current_head = ""
    tests = {"targeted": {"status": "NOT_RUN"}, "full": {"status": "NOT_RUN"}}
    if run_tests:
        tests["targeted"] = _run([sys.executable, "-m", "unittest", "-v", "test_exp_e0c_r8r1_unknown_normalization.py"], root)
        tests["full"] = _run([sys.executable, "-m", "unittest", "discover", "-v", "-p", "test_*.py"], root)
    tests_ok = not run_tests or (tests["targeted"]["status"] == "PASS" and tests["full"]["status"] == "PASS")
    all_checks = (
        bool(current_head)
        and package.get("status") == "PASS"
        and historical.get("status") == "PASS"
        and identity.get("status") == "PASS"
        and normalization.get("status") == "PASS"
        and comparison.get("status") == "PASS"
        and boundary.get("status") == "PASS"
        and tests_ok
    )
    full_required = identity.get("full_fresh_review_required") == "YES"
    terminal_status = "PASS_READY_FOR_EXPLICIT_HUMAN_TEMPLATE_DECISIONS" if all_checks else "BLOCKED"
    terminal = {
        "status": terminal_status,
        "current_head": current_head,
        "historical_remediation_basis": HISTORICAL_MAIN,
        "exact12_authentication": "PASS" if identity.get("status") == "PASS" else "BLOCKED",
        "template_count": EXPECTED_TEMPLATE_COUNT if identity.get("identity_checks", {}).get("template_count_match") else None,
        "raw_coverage": EXPECTED_RAW_COVERAGE if identity.get("identity_checks", {}).get("raw_coverage_match") else None,
        "member_overlap": 0 if identity.get("identity_checks", {}).get("member_overlap") else None,
        "member_set_drift": 0 if identity.get("identity_checks", {}).get("member_set_drift") else None,
        "blocked31_overlap": EXPECTED_BLOCKED_OVERLAP if identity.get("identity_checks", {}).get("blocked31_overlap") else None,
        "unknown_normalization_review": "PASS" if normalization.get("status") == "PASS" else "BLOCKED",
        "structured_heterogeneity_match": "PASS" if comparison.get("structured_heterogeneity_match") else "BLOCKED",
        "review_complexity_match": "PASS" if comparison.get("review_complexity_match") else "BLOCKED",
        "templates_with_structured_split_evidence": comparison.get("templates_with_structured_split_evidence"),
        "templates_with_no_structured_split_evidence": comparison.get("templates_with_no_structured_split_evidence"),
        "targeted_review_reuse_of_prior_exact12_audit": identity.get("targeted_review_reuse"),
        "full_e0c_r8_fresh_review_required": "YES" if full_required else "NO",
        "human_decisions_created": 0,
        "applied_splits": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "next_action": "EXPLICIT_HUMAN_TEMPLATE_DECISIONS" if all_checks else "FULL_E0C_R8_FRESH_REVIEW" if full_required else "REMEDIATE_E0C_R8R1",
        "stop": True,
    }
    return {
        "schema_version": "e0c-r8r1-targeted-fresh-review-v1",
        "review_scope": "E0C_R8R1_TARGETED_FRESH_REVIEW",
        "terminal": terminal,
        "repository_head_authentication": {"status": "PASS" if current_head else "BLOCKED", "current_remote_main": current_head, "historical_basis": HISTORICAL_MAIN, "local_git_worktree": False},
        "remediation_package_authentication": package,
        "historical_fresh_review_audit": historical,
        "targeted_input_authentication": identity,
        "unknown_normalization_review": normalization,
        "corrected_output_comparison": comparison,
        "boundary_audit": boundary,
        "tests": tests,
    }


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")


def _markdown(review: Mapping[str, Any]) -> str:
    t = review["terminal"]
    comparison = review["corrected_output_comparison"]
    tests = review["tests"]
    lines = [
        "# E0C-R8R1 Targeted Fresh Review",
        "",
        f"E0C_R8R1_TARGETED_FRESH_REVIEW = {t['status']}",
        f"CURRENT_HEAD = {t['current_head']}",
        "",
        f"EXACT12_AUTHENTICATION = {t['exact12_authentication']}",
        f"TEMPLATE_COUNT = {t['template_count']}",
        f"RAW_COVERAGE = {t['raw_coverage']}",
        f"MEMBER_OVERLAP = {t['member_overlap']}",
        f"MEMBER_SET_DRIFT = {t['member_set_drift']}",
        f"BLOCKED31_OVERLAP = {t['blocked31_overlap']}",
        "",
        f"UNKNOWN_NORMALIZATION_REVIEW = {t['unknown_normalization_review']}",
        f"STRUCTURED_HETEROGENEITY_MATCH = {t['structured_heterogeneity_match']}",
        f"REVIEW_COMPLEXITY_MATCH = {t['review_complexity_match']}",
        f"TEMPLATES_WITH_STRUCTURED_SPLIT_EVIDENCE = {t['templates_with_structured_split_evidence']}",
        f"TEMPLATES_WITH_NO_STRUCTURED_SPLIT_EVIDENCE = {t['templates_with_no_structured_split_evidence']}",
        "",
        f"TARGETED_REVIEW_REUSE_OF_PRIOR_EXACT12_AUDIT = {t['targeted_review_reuse_of_prior_exact12_audit']}",
        f"FULL_E0C_R8_FRESH_REVIEW_REQUIRED = {t['full_e0c_r8_fresh_review_required']}",
        "",
        "HUMAN_DECISIONS_CREATED = 0",
        "APPLIED_SPLITS = 0",
        "STATUS_MUTATIONS = 0",
        "FORMAL_EXPERIMENT_EXECUTED = NO",
        "DENOMINATOR_CHANGE = NO",
        f"TARGETED_TEST = {tests['targeted'].get('test_count', 'NOT_RUN')}/{tests['targeted'].get('test_count', 'NOT_RUN') if tests['targeted'].get('status') == 'PASS' else '?'}",
        f"FULL_E0C_TEST_SUITE = {tests['full'].get('test_count', 'NOT_RUN')}/{tests['full'].get('test_count', 'NOT_RUN') if tests['full'].get('status') == 'PASS' else '?'}",
        "",
        "The historical `E0C_R8_FRESH_INDEPENDENT_REVIEW.*` BLOCKED artifacts were authenticated and not rewritten. The targeted review reused their prior Exact12 audit because all frozen source and member commitments remained unchanged.",
        "",
        f"Corrected output comparison: `{comparison['structured_distribution_mismatch_count']}` structured distribution mismatches and `{comparison['review_complexity_mismatch_count']}` complexity mismatches. UNKNOWN normalization was independently checked for scalar, empty, all-UNKNOWN, and mixed collections.",
        "",
        "No human decision was made, and no split, status mutation, execution, denominator, binding, or scoring action occurred.",
        "",
        f"NEXT_ACTION = {t['next_action']}",
        "STOP = true",
    ]
    return "\n".join(lines) + "\n"


def write_review(root: Path, review: Mapping[str, Any]) -> Path:
    output = root / "E0C_R8R1_TARGETED_FRESH_REVIEW"
    output.mkdir(parents=True, exist_ok=True)
    _write_json(output / "E0C_R8R1_TARGETED_INPUT_AUTHENTICATION.json", {
        "schema_version": "e0c-r8r1-targeted-input-authentication-v1",
        "status": review["targeted_input_authentication"]["status"],
        "repository_head_authentication": review["repository_head_authentication"],
        "remediation_package_authentication": {
            key: value for key, value in review["remediation_package_authentication"].items() if key not in ("corrected_verification", "nonregression", "contract", "tests")
        },
        "targeted_input_authentication": review["targeted_input_authentication"],
        "historical_fresh_review_audit": review["historical_fresh_review_audit"],
    })
    _write_json(output / "E0C_R8R1_TARGETED_UNKNOWN_AUDIT.json", review["unknown_normalization_review"])
    _write_json(output / "E0C_R8R1_TARGETED_OUTPUT_COMPARISON.json", review["corrected_output_comparison"])
    _write_json(output / "E0C_R8R1_TARGETED_BOUNDARY_AUDIT.json", review["boundary_audit"])
    _write_json(output / "E0C_R8R1_TARGETED_TEST_RERUN.json", review["tests"])
    (output / "E0C_R8R1_TARGETED_FRESH_REVIEW.md").write_text(_markdown(review), encoding="utf-8", newline="\n")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        review = build_targeted_review(args.root, run_tests=True)
        output = write_review(args.root, review)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print("E0C_R8R1_TARGETED_FRESH_REVIEW = BLOCKED")
        print(f"ERROR = {error}")
        print("STOP = true")
        return 1
    print(_markdown(review))
    print(f"ARTIFACT_DIRECTORY = {output}")
    return 0 if review["terminal"]["status"] != "BLOCKED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
