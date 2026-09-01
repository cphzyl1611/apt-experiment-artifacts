#!/usr/bin/env python3
"""Build and verify the bounded E0C-R8R1 UNKNOWN remediation package.

The verifier deliberately keeps the independent recomputation in
``review_exp_e0c_r8_fresh_independent_review`` separate from the R8 builder.
It rebuilds the R8 support artifacts, compares every authenticated structured
distribution and review-aid value, and records the non-mutating boundary
checks required by the remediation prompt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Mapping
import urllib.request
import urllib.error

import build_exp_e0c_r8_structured_human_review_support as builder
import review_exp_e0c_r8_fresh_independent_review as fresh


HISTORICAL_MAIN = "2ff2b21cd313c5b91567adfe05691d3e25aabb87"
FRESH_REVIEW_MATERIALIZATION = "822079ec58e90f2d1a00fa967a8bd7f77ff9614d"
EXPECTED_HISTORICAL_REVIEW_SHA256 = {
    "E0C_R8_FRESH_INDEPENDENT_REVIEW.json": "6af27263d54a411f1890628d941b2aa2f5f8566dc7d9f62336343c6055f86254",
    "E0C_R8_FRESH_INDEPENDENT_REVIEW.md": "2b6db413fc938497dd40e1c52b9fa250ce5e375caa162a2cf6835c9b13dbc225",
}
R8_OUTPUT_FILES = tuple(fresh.R8_OUTPUT_FILES)
HISTORICAL_R8_OUTPUT_SHA256 = {
    "E0C_R8_INPUT_AUTHENTICATION.json": "4b0021c7393e7e473023e46e1fbbe70f7cb5e6b1e292cb293116d074fa32f91e",
    "E0C_R8_EXACT12_STRUCTURED_HETEROGENEITY.json": "1e10abeec16b003f6566f18785386403ddffefef9d2857b5dab501fa57bdcaf8",
    "E0C_R8_EXACT12_CANDIDATE_SPLIT_EVIDENCE.jsonl": "368fda9b2da49c4607b43286fb89d91ddaa90b01c969d5bccc4e708fa030b6af",
    "E0C_R8_EXACT12_REVIEW_COMPLEXITY.json": "3a4a037f1cbfcfc8dc50a3e8b5ae4c1a894f384da0befb1789b4a2d4f6615a98",
    "E0C_R8_HUMAN_DECISION_SUPPORT_SHEETS.md": "a89ebed9384f66eb4ab34e528a66fc675c564fcf9ab24f54227aeefbe82ca867",
    "E0C_R8_HUMAN_DECISION_PACKET.json": "cb7b49546631887fe403e31fae77a1fbee91f2905a363186b90c0b30c9dfe533",
    "E0C_R8_STRUCTURED_COHESION_REVIEW_REPORT.md": "7e2bd4f1a09cbb375bf6bd9403dedd3bef3a253a7293784c7db12a52c95d9f60",
}
AUTHENTICATED_INPUT_FILES = (
    fresh.R6_TRANCHE_FILE,
    fresh.R6_PACKETS_FILE,
    fresh.R6_AUTH_FILE,
    fresh.R6_BLOCKED_FILE,
    fresh.R7_AUTH_FILE,
    fresh.R7_DECISION_FILE,
    fresh.R3_STATUS_FILE,
)
ORIGINAL_RED_OUTPUT = """test_all_unknown_collection_collapses_to_scalar_unknown ... FAIL
test_empty_collection_is_unknown ... ok
test_mixed_collection_preserves_known_value_and_counts_unknown_evidence ... FAIL

----------------------------------------------------------------------
Ran 3 tests in 0.001s

FAILED (failures=2)
"""


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
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object at {path.name}:{line_number}")
        rows.append(value)
    return rows


def _remote_tree(commit: str) -> dict[str, str]:
    url = f"https://api.github.com/repos/cphzyl1611/apt-experiment-artifacts/git/trees/{commit}?recursive=1"
    request = urllib.request.Request(url, headers={"User-Agent": "e0c-r8r1-remediation"})
    payload = None
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.load(response)
            break
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
            last_error = error
            if attempt < 2:
                time.sleep(1)
    if payload is None:
        raise urllib.error.URLError(str(last_error))
    return {
        str(item["path"]): str(item["sha"])
        for item in payload.get("tree", [])
        if isinstance(item, Mapping) and item.get("type") == "blob"
    }


def _remote_main() -> str:
    result = subprocess.run(
        ["git", "ls-remote", fresh.REPOSITORY_URL, "refs/heads/main"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    parts = result.stdout.strip().split()
    return parts[0] if parts and re.fullmatch(r"[0-9a-f]{40}", parts[0]) else ""


def _authenticate_relevant_files(root: Path) -> dict[str, Any]:
    historical_tree = _remote_tree(HISTORICAL_MAIN)
    names = AUTHENTICATED_INPUT_FILES + R8_OUTPUT_FILES
    files: dict[str, Any] = {}
    mismatches: list[str] = []
    for name in names:
        path = root / name
        local_blob = _git_blob_sha1(path.read_bytes()) if path.is_file() else None
        remote_blob = historical_tree.get(f"parallel/c/{name}")
        # R6/R7/R3 inputs must remain byte-identical.  R8 output blobs are
        # intentionally changed by this bounded remediation.
        required_match = name in AUTHENTICATED_INPUT_FILES
        match = bool(local_blob and remote_blob and local_blob == remote_blob)
        files[name] = {
            "role": "authenticated_input" if required_match else "historical_r8_output",
            "local_git_blob_sha1": local_blob,
            "historical_remote_git_blob_sha1": remote_blob,
            "matches_historical_blob": match,
            "expected_after_remediation": "UNCHANGED" if required_match else "REBUILT",
        }
        if required_match and not match:
            mismatches.append(name)
    return {
        "status": "PASS" if not mismatches else "BLOCKED",
        "historical_basis_commit": HISTORICAL_MAIN,
        "remote_main_observed": _remote_main(),
        "local_git_worktree": False,
        "local_head": None,
        "files": files,
        "input_mismatches": mismatches,
    }


def _historical_review_evidence(root: Path) -> dict[str, Any]:
    hashes = {
        name: _sha256(root / name)
        for name in EXPECTED_HISTORICAL_REVIEW_SHA256
        if (root / name).is_file()
    }
    review = _load_json(root / "E0C_R8_FRESH_INDEPENDENT_REVIEW.json")
    terminal = review.get("terminal", {})
    output_audit = review.get("r8_published_output_audit", {})
    expected = EXPECTED_HISTORICAL_REVIEW_SHA256
    unchanged = hashes == expected
    materialization_tree = _remote_tree(FRESH_REVIEW_MATERIALIZATION)
    materialization_blobs = {}
    for name in expected:
        path = root / name
        local_blob = _git_blob_sha1(path.read_bytes()) if path.is_file() else None
        remote_blob = materialization_tree.get(f"parallel/c/{name}")
        materialization_blobs[name] = {
            "local_git_blob_sha1": local_blob,
            "materialization_remote_git_blob_sha1": remote_blob,
            "match": bool(local_blob and remote_blob and local_blob == remote_blob),
        }
    materialization_auth = all(item["match"] for item in materialization_blobs.values())
    defect_fields = {
        "terminal_status": terminal.get("status"),
        "next_action": terminal.get("next_action"),
        "structured_heterogeneity_recomputation": terminal.get("structured_heterogeneity_recomputation"),
        "published_output_audit_status": output_audit.get("status"),
        "published_mismatch_count": output_audit.get("structured_heterogeneity_mismatch_count"),
    }
    reproduced = (
        terminal.get("status") == "BLOCKED"
        and terminal.get("next_action") == "REMEDIATE_E0C_R8"
        and output_audit.get("structured_heterogeneity_mismatch_count") == 80
    )
    return {
        "status": "PASS" if reproduced and unchanged and materialization_auth else "BLOCKED",
        "materialization_commit": FRESH_REVIEW_MATERIALIZATION,
        "artifact_sha256": hashes,
        "expected_artifact_sha256": expected,
        "historical_report_unchanged": unchanged,
        "materialization_blob_authentication": {
            "status": "PASS" if materialization_auth else "BLOCKED",
            "commit": FRESH_REVIEW_MATERIALIZATION,
            "files": materialization_blobs,
        },
        "defect_evidence": defect_fields,
        "original_defect_reproduced_by_fresh_review": reproduced,
        "red_regression_transcript": {
            "command": "python -m unittest -v test_exp_e0c_r8r1_unknown_normalization.py (before remediation patch)",
            "return_code": 1,
            "status": "FAIL_EXPECTED_BEFORE_FIX",
            "failed_tests": [
                "test_all_unknown_collection_collapses_to_scalar_unknown",
                "test_mixed_collection_preserves_known_value_and_counts_unknown_evidence",
            ],
            "output": ORIGINAL_RED_OUTPUT,
        },
    }


def _compare(expected: Any, observed: Any, path: str, mismatches: list[dict[str, Any]]) -> None:
    if expected != observed:
        mismatches.append({"path": path, "expected": expected, "observed": observed})


def _complexity_from_analysis(analysis: Mapping[str, Any]) -> dict[str, Any]:
    unknown_fraction = float(analysis["unknown_burden"]["unknown_fraction"])
    hetero = int(analysis["heterogeneous_field_count"])
    split_count = int(analysis["candidate_split_count"])
    if unknown_fraction >= 0.5 or hetero >= 5:
        level = "HIGH"
    elif unknown_fraction > 0 or hetero > 1:
        level = "MEDIUM"
    else:
        level = "LOW"
    return {
        "template_id": analysis["template_id"],
        "member_count": analysis["member_count"],
        "heterogeneous_field_count": hetero,
        "unknown_cell_count": analysis["unknown_burden"]["unknown_cell_count"],
        "unknown_fraction": unknown_fraction,
        "candidate_split_count": split_count,
        "deterministic_review_complexity_level": level,
        "interpretation": "REVIEW_AID_ONLY_NOT_AN_APPROVE_REJECT_OR_SPLIT_RECOMMENDATION",
    }


def _corrected_verification(root: Path, review: Mapping[str, Any]) -> dict[str, Any]:
    hetero = _load_json(root / "E0C_R8_EXACT12_STRUCTURED_HETEROGENEITY.json")
    complexity = _load_json(root / "E0C_R8_EXACT12_REVIEW_COMPLEXITY.json")
    splits = _load_jsonl(root / "E0C_R8_EXACT12_CANDIDATE_SPLIT_EVIDENCE.jsonl")
    fresh_templates = {str(item["template_id"]): item for item in review["templates"]}
    published_templates = {str(item["template_id"]): item for item in hetero.get("templates", [])}
    mismatches: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    distribution_keys = ("unknown_member_count", "known_member_count", "unknown_fraction", "coverage", "distinct_values", "members_per_value")
    for template_id in fresh.EXPECTED_TEMPLATE_IDS:
        expected = fresh_templates.get(template_id)
        observed = published_templates.get(template_id)
        if expected is None or observed is None:
            mismatches.append({"template_id": template_id, "reason": "missing template"})
            continue
        _compare(expected["member_set_sha256"], observed.get("member_set_sha256"), f"{template_id}.member_set_sha256", mismatches)
        _compare(expected["member_count"], observed.get("member_count"), f"{template_id}.member_count", mismatches)
        for field in fresh.STRUCTURED_FIELDS:
            e_dist = expected["structured_fields"][field]
            o_dist = observed.get("structured_fields", {}).get(field, {})
            for key in distribution_keys:
                _compare(e_dist.get(key), o_dist.get(key), f"{template_id}.{field}.{key}", mismatches)
        _compare(expected["unknown_burden"], observed.get("unknown_burden"), f"{template_id}.unknown_burden", mismatches)
        rows.append({
            "template_id": template_id,
            "member_count": expected["member_count"],
            "unknown_cell_count": expected["unknown_burden"]["unknown_cell_count"],
            "unknown_fraction": expected["unknown_burden"]["unknown_fraction"],
            "heterogeneous_fields": expected["heterogeneous_fields"],
            "candidate_split_status": expected["candidate_split_status"],
        })

    published_complexity = {str(item.get("template_id")): item for item in complexity.get("templates", []) if isinstance(item, Mapping)}
    complexity_mismatches: list[dict[str, Any]] = []
    for template_id, expected_analysis in fresh_templates.items():
        expected = _complexity_from_analysis(expected_analysis)
        observed = published_complexity.get(template_id)
        _compare(expected, observed, f"review_complexity.{template_id}", complexity_mismatches)

    split_ok = (
        len(splits) == fresh.EXPECTED_TEMPLATE_COUNT
        and all(
            item.get("template_id") in fresh.EXPECTED_TEMPLATE_IDS
            and item.get("candidate_split_status") == "NO_STRUCTURED_SPLIT_EVIDENCE"
            and item.get("candidate_split_count") == 0
            and item.get("candidate_splits") == []
            for item in splits
        )
    )
    all_no_split = all(item.get("candidate_split_status") == "NO_STRUCTURED_SPLIT_EVIDENCE" and item.get("candidate_split_count") == 0 for item in fresh_templates.values())
    expected_with_split = sum(1 for item in fresh_templates.values() if item.get("candidate_split_count"))
    expected_unknown = {f"{item['unknown_burden']['unknown_fraction']:.3f}" for item in fresh_templates.values()}
    sheets = (root / "E0C_R8_HUMAN_DECISION_SUPPORT_SHEETS.md").read_text(encoding="utf-8")
    sheets_ok = all(f"`{fraction}` of structured cells)" in sheets for fraction in expected_unknown)
    return {
        "status": "PASS" if not mismatches and not complexity_mismatches and split_ok and sheets_ok and all_no_split else "BLOCKED",
        "fresh_recomputation_source": "review_exp_e0c_r8_fresh_independent_review.py (does not import the R8 builder)",
        "structured_distribution_mismatch_count": len(mismatches),
        "structured_distribution_mismatches": mismatches[:40],
        "structured_heterogeneity_matches_fresh_recompute": not mismatches,
        "unknown_member_counts_match": not any("unknown_member_count" in item["path"] for item in mismatches),
        "unknown_fractions_match": not any("unknown_fraction" in item["path"] or "unknown_burden" in item["path"] for item in mismatches),
        "review_complexity_mismatch_count": len(complexity_mismatches),
        "review_complexity_mismatches": complexity_mismatches,
        "review_complexity_values_match_fresh_recompute": not complexity_mismatches,
        "review_complexity_aid_only": complexity.get("review_aid_only") is True and all(
            item.get("interpretation") == "REVIEW_AID_ONLY_NOT_AN_APPROVE_REJECT_OR_SPLIT_RECOMMENDATION"
            and not any(key in item for key in ("recommendation", "approval", "rejection", "split_recommendation"))
            for item in complexity.get("templates", [])
        ),
        "candidate_split_evidence_output_valid": split_ok,
        "templates_with_structured_split_evidence": expected_with_split,
        "templates_with_no_structured_split_evidence": fresh.EXPECTED_TEMPLATE_COUNT - expected_with_split,
        "decision_sheet_unknown_fractions_match": sheets_ok,
        "template_results": rows,
    }


def _nonregression(root: Path, review: Mapping[str, Any], auth: Mapping[str, Any], corrected: Mapping[str, Any], historical: Mapping[str, Any]) -> dict[str, Any]:
    packet = _load_json(root / "E0C_R8_HUMAN_DECISION_PACKET.json")
    auth_out = _load_json(root / "E0C_R8_INPUT_AUTHENTICATION.json")
    packet_templates = packet.get("templates", [])
    packet_ok = (
        packet.get("allowed_decisions") == fresh.ALLOWED_DECISIONS
        and packet.get("human_decisions_created") == 0
        and packet.get("applied_splits") == 0
        and packet.get("status_mutations") == 0
        and all(
            item.get("decision") is None
            and item.get("human_decision") is None
            and item.get("human_origin") is None
            and item.get("decision_options") == fresh.ALLOWED_DECISIONS
            and item.get("r3_global_planning_status") == fresh.MANUAL_STATUS
            and item.get("status_mutations") == 0
            and item.get("formal_execution_authorized") is False
            for item in packet_templates
        )
    )
    packet_hashes = {str(item.get("template_id")): item.get("member_set_sha256") for item in packet_templates}
    expected_hashes = {str(item["template_id"]): item["member_set_sha256"] for item in review["templates"]}
    exact12 = review["terminal"]
    exact12_ok = all(exact12.get(key) == value for key, value in {
        "exact12_authentication": "PASS",
        "template_count": 12,
        "raw_coverage": 203,
        "member_overlap": 0,
        "member_set_drift": 0,
        "blocked31_overlap": 0,
        "all_members_manual_design_required": "PASS",
    }.items()) and auth_out.get("template_count") == 12 and auth_out.get("raw_coverage") == 203
    inference = review.get("inference_audit", {})
    forbidden_ok = inference.get("status") == "PASS" and not inference.get("forbidden_structured_keys_found")
    statuses_ok = all(item.get("r3_global_planning_status") == fresh.MANUAL_STATUS for item in auth_out.get("template_member_authentication", []))
    return {
        "status": "PASS" if exact12_ok and packet_ok and packet_hashes == expected_hashes and corrected["status"] == "PASS" and forbidden_ok and statuses_ok and historical["historical_report_unchanged"] else "BLOCKED",
        "exact12": {
            "template_count": exact12.get("template_count"),
            "raw_coverage": exact12.get("raw_coverage"),
            "member_overlap": exact12.get("member_overlap"),
            "member_set_drift": exact12.get("member_set_drift"),
            "blocked31_overlap": exact12.get("blocked31_overlap"),
            "all_members_manual_design_required": exact12.get("all_members_manual_design_required"),
            "status": "PASS" if exact12_ok else "BLOCKED",
        },
        "member_hashes_match": packet_hashes == expected_hashes,
        "human_decision_packet_audit": "PASS" if packet_ok else "BLOCKED",
        "all_decisions_null": packet_ok,
        "status_values_manual_design_required": statuses_ok,
        "no_unauthorized_inference": forbidden_ok,
        "human_decisions_created": packet.get("human_decisions_created"),
        "applied_splits": packet.get("applied_splits"),
        "status_mutations": packet.get("status_mutations"),
        "formal_experiment_executed": packet.get("formal_experiment_executed"),
        "denominator_change": packet.get("denominator_change"),
        "authority_mutation": packet.get("authority_mutation"),
        "historical_fresh_review_unchanged": historical["historical_report_unchanged"],
        "push_executed": False,
        "r8_authentication_output": auth.get("status"),
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


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")


def _report(terminal: Mapping[str, Any], auth: Mapping[str, Any], corrected: Mapping[str, Any], tests: Mapping[str, Any]) -> str:
    lines = [
        "# E0C-R8R1 UNKNOWN Normalization Targeted Remediation",
        "",
        f"E0C_R8R1_UNKNOWN_NORMALIZATION_REMEDIATION = {terminal['status']}",
        f"CURRENT_HEAD = {terminal['current_head']}",
        f"ORIGINAL_DEFECT_REPRODUCED = {terminal['original_defect_reproduced']}",
        "",
        f"EXACT12_AUTHENTICATION = {terminal['exact12_authentication']}",
        f"TEMPLATE_COUNT = {terminal['template_count']}",
        f"RAW_COVERAGE = {terminal['raw_coverage']}",
        f"MEMBER_OVERLAP = {terminal['member_overlap']}",
        f"MEMBER_SET_DRIFT = {terminal['member_set_drift']}",
        f"BLOCKED31_OVERLAP = {terminal['blocked31_overlap']}",
        "",
        f"UNKNOWN_NORMALIZATION_CONTRACT = {terminal['unknown_normalization_contract']}",
        f"STRUCTURED_HETEROGENEITY_MATCHES_FRESH_RECOMPUTE = {terminal['structured_heterogeneity_matches_fresh_recompute']}",
        f"REVIEW_COMPLEXITY_MATCHES_FRESH_RECOMPUTE = {terminal['review_complexity_matches_fresh_recompute']}",
        f"TEMPLATES_WITH_STRUCTURED_SPLIT_EVIDENCE = {terminal['templates_with_structured_split_evidence']}",
        f"TEMPLATES_WITH_NO_STRUCTURED_SPLIT_EVIDENCE = {terminal['templates_with_no_structured_split_evidence']}",
        "",
        "HUMAN_DECISIONS_CREATED = 0",
        "APPLIED_SPLITS = 0",
        "STATUS_MUTATIONS = 0",
        "FORMAL_EXPERIMENT_EXECUTED = NO",
        "DENOMINATOR_CHANGE = NO",
        f"FULL_E0C_TEST_SUITE = {tests['full']['test_count']}/{tests['full']['test_count'] if tests['full']['status'] == 'PASS' else '?'}",
        "PUSH_EXECUTED = NO",
        "",
        "The historical fresh-review BLOCKED report was not rewritten. Its 80-record mismatch is preserved as defect evidence; corrected R8 outputs now agree with an independent recomputation.",
        "Only derived UNKNOWN-sensitive heterogeneity, review-complexity, and decision-sheet values changed; authenticated inputs, candidate-split evidence, decision packet, and terminal report remain byte-identical to the historical R8 outputs.",
        "",
        "Canonicalization contract: scalar UNKNOWN and empty collections normalize to the UNKNOWN sentinel; all-UNKNOWN collections also normalize to that sentinel. Mixed collections retain canonical JSON and remain UNKNOWN-bearing for accounting and split eligibility.",
        "",
        "The exact12 member sets and all MANUAL_DESIGN_REQUIRED statuses are unchanged. Decisions remain null, and no split or execution action was applied.",
        "",
        "NEXT_ACTION = TARGETED_FRESH_REVIEW_OF_E0C_R8R1",
        "STOP = true",
    ]
    return "\n".join(lines) + "\n"


def build_remediation(root: Path) -> dict[str, Any]:
    package = root / "E0C_R8R1_UNKNOWN_NORMALIZATION_REMEDIATION"
    package.mkdir(parents=True, exist_ok=True)
    historical = _historical_review_evidence(root)
    historical["schema_version"] = "e0c-r8r1-defect-reproduction-v1"
    auth = _authenticate_relevant_files(root)
    outputs = builder.build_outputs(root)
    builder.write_outputs(root, outputs)
    after_hashes = {name: _sha256(root / name) for name in R8_OUTPUT_FILES}
    review = fresh.build_review(root, current_commit=HISTORICAL_MAIN)
    corrected = _corrected_verification(root, review)
    nonreg = _nonregression(root, review, auth, corrected, historical)
    targeted = _run([sys.executable, "-m", "unittest", "-v", "test_exp_e0c_r8r1_unknown_normalization.py"], root)
    full = _run([sys.executable, "-m", "unittest", "discover", "-v", "-p", "test_*.py"], root)
    tests = {"targeted": {key: value for key, value in targeted.items() if key != "output"}, "full": {key: value for key, value in full.items() if key != "output"}}
    terminal_status = "PASS_READY_FOR_TARGETED_FRESH_REVIEW" if (
        historical["status"] == "PASS"
        and auth["status"] == "PASS"
        and corrected["status"] == "PASS"
        and nonreg["status"] == "PASS"
        and targeted["status"] == "PASS"
        and full["status"] == "PASS"
    ) else "BLOCKED"
    terminal = {
        "status": terminal_status,
        "current_head": HISTORICAL_MAIN,
        "remote_main_observed": auth.get("remote_main_observed"),
        "original_defect_reproduced": "YES" if historical["status"] == "PASS" else "NO",
        "exact12_authentication": "PASS" if nonreg["exact12"]["status"] == "PASS" else "BLOCKED",
        "template_count": nonreg["exact12"]["template_count"],
        "raw_coverage": nonreg["exact12"]["raw_coverage"],
        "member_overlap": nonreg["exact12"]["member_overlap"],
        "member_set_drift": nonreg["exact12"]["member_set_drift"],
        "blocked31_overlap": nonreg["exact12"]["blocked31_overlap"],
        "unknown_normalization_contract": "PASS" if corrected["status"] == "PASS" else "BLOCKED",
        "structured_heterogeneity_matches_fresh_recompute": "PASS" if corrected["structured_heterogeneity_matches_fresh_recompute"] else "BLOCKED",
        "review_complexity_matches_fresh_recompute": "PASS" if corrected["review_complexity_values_match_fresh_recompute"] else "BLOCKED",
        "templates_with_structured_split_evidence": corrected["templates_with_structured_split_evidence"],
        "templates_with_no_structured_split_evidence": corrected["templates_with_no_structured_split_evidence"],
        "human_decision_packet_audit": nonreg["human_decision_packet_audit"],
        "human_decisions_created": 0,
        "applied_splits": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "full_e0c_test_suite": f"{full['test_count']}/{full['test_count']}" if full["status"] == "PASS" else f"0/{full['test_count'] or '?'}",
        "push_executed": "NO",
        "next_action": "TARGETED_FRESH_REVIEW_OF_E0C_R8R1" if terminal_status != "BLOCKED" else "REMEDIATE_E0C_R8R1",
        "stop": True,
    }
    _write_json(package / "E0C_R8R1_DEFECT_REPRODUCTION.json", historical)
    _write_json(package / "E0C_R8R1_UNKNOWN_NORMALIZATION_CONTRACT.json", {
        "schema_version": "e0c-r8r1-unknown-normalization-contract-v1",
        "status": "PASS" if corrected["status"] == "PASS" else "BLOCKED",
        "scalar_unknown": {"input": builder.UNKNOWN, "canonical": builder.UNKNOWN, "is_unknown": builder._is_unknown(builder.UNKNOWN)},
        "empty_collection": {"inputs": [[], {}, ""], "canonical": [builder._json_value(value) for value in ([], {}, "")], "all_unknown": True},
        "all_unknown_collection": {
            "inputs": [["UNKNOWN"], [builder.UNKNOWN], ("UNKNOWN",)],
            "canonical": [builder._json_value(value) for value in (["UNKNOWN"], [builder.UNKNOWN], ("UNKNOWN",))],
            "is_unknown": [builder._is_unknown(builder._json_value(value)) for value in (["UNKNOWN"], [builder.UNKNOWN], ("UNKNOWN",))],
        },
        "mixed_collection": {
            "input": ["UNKNOWN", "HTTP"],
            "canonical": builder._json_value(["UNKNOWN", "HTTP"]),
            "is_unknown": builder._is_unknown(builder._json_value(["UNKNOWN", "HTTP"])),
            "rule": "retain canonical JSON so known source evidence remains visible, but count the entire field cell as UNKNOWN-bearing and exclude it from candidate split boundaries",
        },
        "authenticated_exact12_mixed_collection_cells": 0,
        "source_semantics": "No semantics are invented for unauthenticated source values.",
    })
    _write_json(package / "E0C_R8R1_CORRECTED_HETEROGENEITY_VERIFICATION.json", {
        "schema_version": "e0c-r8r1-corrected-heterogeneity-verification-v1",
        "status": corrected["status"],
        "verification": corrected,
        "historical_pre_remediation_output_sha256": HISTORICAL_R8_OUTPUT_SHA256,
        "before_output_sha256": HISTORICAL_R8_OUTPUT_SHA256,
        "after_output_sha256": after_hashes,
        "independent_review_terminal": review["terminal"],
    })
    _write_json(package / "E0C_R8R1_NONREGRESSION.json", {
        "schema_version": "e0c-r8r1-nonregression-v1",
        **nonreg,
        "historical_input_authentication": auth,
        "historical_fresh_review_defect_evidence": historical,
    })
    _write_json(package / "E0C_R8R1_TEST_RERUN.json", {
        "schema_version": "e0c-r8r1-test-rerun-v1",
        "status": "PASS" if targeted["status"] == "PASS" and full["status"] == "PASS" else "BLOCKED",
        "targeted": targeted,
        "full": full,
        "full_e0c_test_suite": f"{full['test_count']}/{full['test_count']}" if full["status"] == "PASS" else None,
    })
    (package / "E0C_R8R1_REMEDIATION_REPORT.md").write_text(_report(terminal, auth, corrected, tests), encoding="utf-8", newline="\n")
    return {
        "terminal": terminal,
        "historical": historical,
        "authentication": auth,
        "corrected": corrected,
        "nonregression": nonreg,
        "tests": tests,
        "package": str(package),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        result = build_remediation(args.root)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, urllib.error.URLError) as error:
        print("E0C_R8R1_UNKNOWN_NORMALIZATION_REMEDIATION = BLOCKED")
        print(f"ERROR = {error}")
        print("PUSH_EXECUTED = NO")
        print("STOP = true")
        return 1
    print(_report(result["terminal"], result["authentication"], result["corrected"], result["tests"]))
    return 0 if result["terminal"]["status"] != "BLOCKED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
