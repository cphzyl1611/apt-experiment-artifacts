#!/usr/bin/env python3
"""Build the R2R2 materialization manifest after evidence gates pass.

This utility only hashes the R2R2 package. It does not apply a split, mutate
authority, create a decision, execute an experiment, commit, or push.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


PACKAGE_DIR = Path(__file__).resolve().parent
MANIFEST_NAME = "MATERIALIZATION_MANIFEST.json"
EVIDENCE_NAME = "E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2_VALIDATION_EVIDENCE.json"
UNION_SHA256 = "ffeb2704a1c971b89129e1959ae721bbc9ef159153a5f0a20f8abda13edb441a"


class MaterializationGateError(ValueError):
    """Raised when the persisted R2R2 evidence does not permit manifesting."""


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise MaterializationGateError(f"{label}: expected {expected!r}, got {actual!r}")


def _require_pass(terminal: Mapping[str, Any], key: str) -> None:
    _require_equal(terminal.get(key), "PASS", f"terminal.{key}")


def _validate_materialization_gate(package_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    evidence_path = package_dir / EVIDENCE_NAME
    boundary_path = package_dir / "ZERO_MUTATION_BOUNDARY.json"
    fixture_manifest_path = package_dir / "fixtures" / "FIXTURE_MANIFEST.json"
    for path in (evidence_path, boundary_path, fixture_manifest_path):
        if not path.is_file():
            raise MaterializationGateError(f"required artifact is missing: {path.name}")

    evidence = _load_json(evidence_path)
    boundary = _load_json(boundary_path)
    fixture_manifest = _load_json(fixture_manifest_path)
    terminal = evidence.get("terminal")
    boundary_terminal = boundary.get("terminal")
    if not isinstance(terminal, Mapping) or not isinstance(boundary_terminal, Mapping):
        raise MaterializationGateError("validation or boundary terminal is not an object")

    _require_equal(
        terminal.get("E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2"),
        "PASS_READY_FOR_INDEPENDENT_REVIEW",
        "terminal.E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2",
    )
    for key in (
        "SCHEMA_META_VALIDATION",
        "STRICT_SEMANTIC_VALIDATION",
        "GOVERNANCE_REFERENCE_SYNTAX_ALIGNMENT",
        "NEGATIVE_FIXTURE_REASONS",
        "EXACT12_MEMBER_CONSERVATION",
    ):
        _require_pass(terminal, key)

    fixture_results = evidence.get("fixture_results")
    if not isinstance(fixture_results, Mapping):
        raise MaterializationGateError("fixture_results is not an object")
    _require_equal(
        fixture_results.get("valid_fixture", {}).get("status"),
        "ACCEPTED",
        "fixture_results.valid_fixture.status",
    )
    _require_equal(
        fixture_results.get("all_negative_rejected"),
        True,
        "fixture_results.all_negative_rejected",
    )
    _require_equal(
        fixture_results.get("all_expected_failure_reasons_satisfied"),
        True,
        "fixture_results.all_expected_failure_reasons_satisfied",
    )
    expected_fixtures = fixture_manifest.get("fixtures")
    negative_results = fixture_results.get("negative_fixtures")
    if not isinstance(expected_fixtures, list) or not isinstance(negative_results, list):
        raise MaterializationGateError("fixture manifest or negative fixture results is not an array")
    _require_equal(len(expected_fixtures), 13, "fixture manifest negative fixture count")
    _require_equal(len(negative_results), 13, "validation evidence negative fixture count")
    expected_names = {item.get("filename") for item in expected_fixtures}
    result_names = {item.get("filename") for item in negative_results}
    _require_equal(result_names, expected_names, "negative fixture result filenames")
    for result in negative_results:
        _require_equal(result.get("status"), "REJECTED", f"negative fixture {result.get('filename')} status")
        _require_equal(
            result.get("expected_failure_reasons_satisfied"),
            True,
            f"negative fixture {result.get('filename')} expected reasons",
        )

    baseline = evidence.get("baseline")
    frozen_scope = boundary.get("frozen_scope")
    if not isinstance(baseline, Mapping) or not isinstance(frozen_scope, Mapping):
        raise MaterializationGateError("baseline or frozen scope is not an object")
    expected_scope = {
        "template_count": 12,
        "raw_coverage": 203,
        "union_member_key_sha256": UNION_SHA256,
    }
    for key, expected in expected_scope.items():
        baseline_key = "raw_count_sum" if key == "raw_coverage" else key
        _require_equal(baseline.get(baseline_key), expected, f"baseline.{baseline_key}")
        _require_equal(frozen_scope.get(key), expected, f"frozen_scope.{key}")
    _require_equal(baseline.get("unique_member_count"), 203, "baseline.unique_member_count")
    _require_equal(baseline.get("cross_template_overlap_count"), 0, "baseline.cross_template_overlap_count")

    expected_boundary = {
        "APPLIED_SPLITS": 0,
        "STATUS_MUTATIONS": 0,
        "EXECUTION_AUTHORIZATIONS": 0,
        "DENOMINATOR_CHANGE": "NO",
    }
    for key, expected in expected_boundary.items():
        _require_equal(terminal.get(key), expected, f"terminal.{key}")
        _require_equal(boundary_terminal.get(key), expected, f"boundary.terminal.{key}")
    _require_equal(evidence.get("authority_mutation"), "NO", "authority_mutation")
    return evidence, boundary


def _category(relative_path: Path) -> str:
    if relative_path.parts[0] == "fixtures":
        if relative_path.name == "FIXTURE_MANIFEST.json":
            return "fixture_manifest"
        if relative_path.name == "GOVERNANCE_REFERENCE_SYNTAX_WITNESSES.json":
            return "syntax_witness_fixture"
        return "negative_fixture" if relative_path.name.startswith("NEGATIVE_") else "positive_fixture"
    if relative_path.name == EVIDENCE_NAME:
        return "validation_evidence"
    if relative_path.name == "EXACT12_RESOLUTION_CROSSWALK.jsonl":
        return "frozen_crosswalk"
    if relative_path.name == "ZERO_MUTATION_BOUNDARY.json":
        return "zero_mutation_boundary"
    if relative_path.name == "TEMPLATE_LEVEL_RESOLUTION_SCHEMA.json":
        return "schema"
    if relative_path.name.startswith("test_"):
        return "test"
    if relative_path.name.startswith("validate_"):
        return "validator"
    if relative_path.name.startswith("materialize_"):
        return "materialization_gate"
    return "design" if relative_path.suffix == ".md" else "contract"


def _payload_files(package_dir: Path) -> list[dict[str, str]]:
    payload: list[dict[str, str]] = []
    for path in sorted(package_dir.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.name == MANIFEST_NAME:
            continue
        relative_path = path.relative_to(package_dir)
        payload.append(
            {
                "category": _category(relative_path),
                "relative_path": relative_path.as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return payload


def build_materialization_manifest(package_dir: Path = PACKAGE_DIR) -> dict[str, Any]:
    """Return a canonical manifest, or fail if persisted evidence is not PASS."""
    package_dir = package_dir.resolve()
    evidence, boundary = _validate_materialization_gate(package_dir)
    terminal = evidence["terminal"]
    frozen_scope = boundary["frozen_scope"]
    return {
        "manifest_type": "E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2_MATERIALIZATION_MANIFEST",
        "manifest_version": "r1",
        "hash_algorithm": "SHA-256",
        "materialization_scope": "R2R2 design package and local validation evidence only",
        "payload_policy": {
            "manifest_included_in_payload": False,
            "generated_bytecode_included": False,
            "commit_executed": False,
            "push_executed": False,
        },
        "provenance_note": (
            "R2R2 is an isolated, non-authoritative remediation of governance-reference "
            "syntax alignment. It does not modify R2R1, apply splits, or mutate authority."
        ),
        "frozen_scope": {
            "template_count": frozen_scope["template_count"],
            "raw_coverage": frozen_scope["raw_coverage"],
            "union_member_key_sha256": frozen_scope["union_member_key_sha256"],
            "member_overlap": frozen_scope["member_overlap"],
            "member_set_drift": frozen_scope["member_set_drift"],
            "blocked31_overlap": frozen_scope["blocked31_overlap"],
        },
        "validation_terminal": {
            "E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2": terminal[
                "E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2"
            ],
            "SCHEMA_META_VALIDATION": terminal["SCHEMA_META_VALIDATION"],
            "STRICT_SEMANTIC_VALIDATION": terminal["STRICT_SEMANTIC_VALIDATION"],
            "GOVERNANCE_REFERENCE_SYNTAX_ALIGNMENT": terminal[
                "GOVERNANCE_REFERENCE_SYNTAX_ALIGNMENT"
            ],
            "NEGATIVE_FIXTURE_REASONS": terminal["NEGATIVE_FIXTURE_REASONS"],
            "EXACT12_MEMBER_CONSERVATION": terminal["EXACT12_MEMBER_CONSERVATION"],
            "NEXT_ACTION": terminal["NEXT_ACTION"],
            "STOP": terminal["STOP"],
        },
        "zero_mutation_boundary": {
            "APPLIED_SPLITS": terminal["APPLIED_SPLITS"],
            "STATUS_MUTATIONS": terminal["STATUS_MUTATIONS"],
            "EXECUTION_AUTHORIZATIONS": terminal["EXECUTION_AUTHORIZATIONS"],
            "DENOMINATOR_CHANGE": terminal["DENOMINATOR_CHANGE"],
            "FORMAL_EXPERIMENT_EXECUTED": terminal["FORMAL_EXPERIMENT_EXECUTED"],
            "HUMAN_DECISIONS_CREATED": terminal["HUMAN_DECISIONS_CREATED"],
        },
        "validation_evidence": {
            "relative_path": EVIDENCE_NAME,
            "sha256": hashlib.sha256((package_dir / EVIDENCE_NAME).read_bytes()).hexdigest(),
        },
        "payload_files": _payload_files(package_dir),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    manifest = build_materialization_manifest(PACKAGE_DIR)
    (PACKAGE_DIR / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    print(f"materialization_manifest={MANIFEST_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
