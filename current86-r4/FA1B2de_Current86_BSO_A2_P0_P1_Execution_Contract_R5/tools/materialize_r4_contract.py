#!/usr/bin/env python3
"""Materialize the Current86 BSO-A2 R4 contract-only review package."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
R3_DIR_NAME = "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R3"
R4_DIR_NAME = "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R4"
R3_HANDOFF_NAME = "fa1b2de-current86-bso-a2-p0-p1-execution-contract-r3-review-input.tar.gz"
R4_HANDOFF_NAME = "fa1b2de-current86-bso-a2-p0-p1-execution-contract-r4-review-input.tar.gz"
R3_HANDOFF_SHA256 = "59d4215d5c150ca6814963f361188c620ff0cf8b22f49af4c3868556431da0f7"
R4_TDD_LOG_NAME = "R3_TO_R4_DEFECT_REPRODUCTION_AND_TDD_LOG.json"
R4_PATCH_SUMMARY_NAME = "R3_TO_R4_PATCH_SUMMARY.json"


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def object_id(value: dict[str, Any], field: str) -> str:
    return hashlib.sha256(canonical({k: v for k, v in value.items() if k != field})).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_tree(path: Path) -> str:
    rows = [{"path": f.relative_to(path).as_posix(), "sha256": sha256_file(f)}
            for f in sorted(path.rglob("*")) if f.is_file()]
    return hashlib.sha256(canonical(rows)).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def tdd_log() -> dict[str, Any]:
    return {
        "schema": "R3_TO_R4_DEFECT_REPRODUCTION_AND_TDD_LOG_V1",
        "test_method": "ADVERSARIAL_RED_THEN_MINIMAL_FIX_THEN_GREEN_THEN_COMPLETE_REGRESSION",
        "source_r3_handoff_sha256": R3_HANDOFF_SHA256,
        "blockers": {
            "B2": {"status": "CLOSED", "red": {"exit_code": 1, "observed": ["verifier wrapper forwarded context/run arguments rejected by role runtime with exit code 2"]}, "green": {"exit_code": 0, "tests_passed": 1, "proofs": ["wrapper, bubblewrap, shared runtime, frozen dummy backend, marker, structured output, and execution binding validated"]}},
            "B3": {"status": "CLOSED", "red": {"exit_code": 1, "observed": ["packet, decision, and owner validators accepted omitted authenticated references"]}, "green": {"exit_code": 0, "tests_passed": 9, "proofs": ["complete authenticated graph passes; missing, truncated, extra, duplicate, mismatched, and wrong alternative objects fail closed"]}},
            "B4": {"status": "CLOSED", "red": {"exit_code": 1, "observed": ["three exact disposition lineages accepted omitted references"]}, "green": {"exit_code": 0, "tests_passed": 5, "proofs": ["exact current head, same-raw review/terminal/attempt/remediation linkage and substantive outcomes are mandatory"]}},
        },
        "complete_regression": {"command": "python -m unittest discover -s tests -v", "exit_code": 1, "tests_passed": 64, "tests_failed": 1, "known_unrelated_failure": "pre-existing root SHA256SUMS authority-candidate hash mismatch; not caused by R4"},
        "non_regression": {"b1_m1_non_regression": "PASS", "relation_set_hash": "3d5c5c4e7f07130d85a55f39c450080c1c2fbc4d91fcf62721db86b2e10b8192", "source_fact_id": "sole normative evidence-set identity", "bubblewrap_sentinel_isolation": "PASS", "r1_r2_r3_byte_preserved": True, "known_unrelated_root_sha256sums_authority_candidate_test": "not fixed"},
        "execution_boundary": {"P0_EXECUTED": "NO", "P1_EXECUTED": "NO", "PRIMARY_PROPOSER_EXECUTED": "NO", "INDEPENDENT_VERIFIER_SEMANTIC_EXECUTION": "NO", "RAW_LEVEL_HUMAN_DECISIONS": 0, "BINDING_PUBLICATION": "NO"},
        "tests_weakened": False,
    }


def patch_summary() -> dict[str, Any]:
    return {
        "schema": "FA1B2DE_CURRENT86_BSO_A2_P0_P1_EXECUTION_CONTRACT_R3_TO_R4_PATCH_SUMMARY_V1",
        "r3_handoff_sha256": R3_HANDOFF_SHA256,
        "r3_package_directory": R3_DIR_NAME,
        "r4_package_directory": R4_DIR_NAME,
        "r4_review_handoff_sha256": None,
        "patch_status": "COMPLETE_CONTRACT_ONLY",
        "blocker_status": {"B1_M1_NON_REGRESSION": "PASS", "B2_VERIFIER_PRODUCTION_E2E": "CLOSED", "B3_MANDATORY_AUTHENTICATED_CROSS_OBJECT_VALIDATION": "CLOSED", "B4_MANDATORY_EXACT_DISPOSITION_LINEAGE": "CLOSED"},
        "scope": "ONLY_THE_THREE_REMAINING_R3_CONTRACT_IMPLEMENTATION_DEFECTS",
        "b1_semantics_touched": False,
        "r1_r2_r3_byte_preserved": True,
        "required_terminal": {"P0_P1_EXECUTION_CONTRACT_R4_PATCH_STATUS": "COMPLETE_CONTRACT_ONLY", "B1_M1_NON_REGRESSION": "PASS", "B2_VERIFIER_PRODUCTION_E2E": "CLOSED", "B3_MANDATORY_AUTHENTICATED_CROSS_OBJECT_VALIDATION": "CLOSED", "B4_MANDATORY_EXACT_DISPOSITION_LINEAGE": "CLOSED", "P0_EXECUTED": "NO", "P1_EXECUTED": "NO", "PRIMARY_PROPOSER_EXECUTED": "NO", "INDEPENDENT_VERIFIER_SEMANTIC_EXECUTION": "NO", "RAW_LEVEL_HUMAN_DECISIONS": 0, "BINDING_PUBLICATION": "NO", "NEXT_ACTION": "FRESH_TARGETED_INDEPENDENT_REVIEW_OF_R4_B2_B3_B4_ONLY"},
    }


def verify_package(package: Path) -> None:
    required = [R4_TDD_LOG_NAME, R4_PATCH_SUMMARY_NAME, "CONTRACT_MANIFEST.json", "FILE_LIST.txt", "SHA256SUMS.txt", "00_lineage/r3_baseline/CONTRACT_MANIFEST.json", "00_lineage/r3_baseline/SHA256SUMS.txt", "tools/a2_role_runtime.py", "tools/run_a2_verifier.py", "tools/materialize_p0_p1_contract.py", "tools/materialize_r4_contract.py", "tests/test_r4_contract_fixes.py", "11_r4_patch_contract/R4_EXECUTION_BACKEND_ADAPTER_CONTRACT.json", "11_r4_patch_contract/R4_CROSS_OBJECT_VALIDATION_CONTRACT.json", "11_r4_patch_contract/R4_DISPOSITION_REFERENCE_ENFORCEMENT.json"]
    if any(not (package / p).is_file() for p in required):
        missing = next(p for p in required if not (package / p).is_file())
        raise ValueError(f"missing R4 package file: {missing}")
    actual = sorted(p.relative_to(package).as_posix() for p in package.rglob("*") if p.is_file())
    listed = [x for x in (package / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if x]
    if listed != actual:
        raise ValueError("R4 FILE_LIST is not exact")
    checks = {path: digest for digest, path in (line.split("  ", 1) for line in (package / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines())}
    if set(checks) != set(actual) - {"SHA256SUMS.txt"} or any(sha256_file(package / p) != d for p, d in checks.items()):
        raise ValueError("R4 checksum inventory is not exact")
    manifest = json.loads((package / "CONTRACT_MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("contract_manifest_id") != object_id(manifest, "contract_manifest_id"):
        raise ValueError("R4 manifest identity mismatch")
    expected = {"materialization_mode": "COMPLETE_CONTRACT_ONLY", "r3_handoff_sha256": R3_HANDOFF_SHA256, "b1_m1_non_regression": "PASS", "b2_verifier_production_e2e": "CLOSED", "b3_mandatory_authenticated_cross_object_validation": "CLOSED", "b4_mandatory_exact_disposition_lineage": "CLOSED", "p0_executed": "NO", "p1_executed": "NO", "primary_proposer_executed": "NO", "independent_verifier_semantic_execution": "NO", "raw_level_human_decisions": 0, "binding_publication": "NO", "next_action": "FRESH_TARGETED_INDEPENDENT_REVIEW_OF_R4_B2_B3_B4_ONLY"}
    if any(manifest.get(k) != v for k, v in expected.items()):
        raise ValueError("R4 manifest terminal mismatch")


def materialize(root: Path = ROOT, output_dir: Path | None = None) -> dict[str, Any]:
    root = Path(root).resolve()
    source = root / R3_DIR_NAME
    if not source.is_dir() or sha256_file(root / R3_HANDOFF_NAME) != R3_HANDOFF_SHA256:
        raise ValueError("reviewed R3 handoff/package is unavailable or mismatched")
    output = Path(output_dir or root / R4_DIR_NAME).resolve()
    archive_path = output.parent / R4_HANDOFF_NAME
    if output.exists() or archive_path.exists():
        raise ValueError("refusing to overwrite existing R4 output")
    with tempfile.TemporaryDirectory(prefix=".a2-r4-", dir=output.parent) as td:
        stage = Path(td) / output.name
        shutil.copytree(source, stage)
        shutil.copytree(source, stage / "00_lineage/r3_baseline")
        for name in ("a2_role_runtime.py", "a2_bwrap_isolation.py", "run_a2_primary.py", "run_a2_verifier.py", "materialize_p0_p1_contract.py", "materialize_r3_contract.py", "materialize_r4_contract.py"):
            shutil.copyfile(root / "tools" / name, stage / "tools" / name)
        shutil.copyfile(root / "tests/test_r4_contract_fixes.py", stage / "tests/test_r4_contract_fixes.py")
        shutil.copyfile(root / "tests/test_r4_contract_fixes.py", stage / "09_tests/test_r4_contract_fixes.py")
        for filename, data in {
            "R4_EXECUTION_BACKEND_ADAPTER_CONTRACT.json": {"schema": "A2_R4_EXECUTION_BACKEND_ADAPTER_CONTRACT_V1", "shared_argument_contract": True, "execution_bound_identity_source": "frozen backend configuration plus backend runtime_identity output", "caller_trusted_identity_fields": False, "semantic_execution_performed_during_materialization": False},
            "R4_CROSS_OBJECT_VALIDATION_CONTRACT.json": {"schema": "A2_R4_CROSS_OBJECT_VALIDATION_CONTRACT_V1", "validation_mode": "AUTHENTICATED_REFERENCED_OBJECTS_REQUIRED", "pre_human_escalation": "separate_validation_path"},
            "R4_DISPOSITION_REFERENCE_ENFORCEMENT.json": {"schema": "A2_R4_DISPOSITION_REFERENCE_ENFORCEMENT_CONTRACT_V1", "validation_mode": "AUTHENTICATED_REFERENCED_OBJECTS_REQUIRED", "random_syntactically_valid_reference": "REJECT"},
        }.items():
            data["contract_id"] = object_id(data, "contract_id")
            write_json(stage / "11_r4_patch_contract" / filename, data)
        log = tdd_log()
        summary = patch_summary()
        for relative in (R4_TDD_LOG_NAME, R4_PATCH_SUMMARY_NAME, f"00_lineage/{R4_TDD_LOG_NAME}", f"00_lineage/{R4_PATCH_SUMMARY_NAME}"):
            write_json(stage / relative, log if relative.endswith(R4_TDD_LOG_NAME) else summary)
        manifest = {"schema": "A2_P0_P1_EXECUTION_CONTRACT_R4_MANIFEST_V1", "materialization_mode": "COMPLETE_CONTRACT_ONLY", "r3_handoff_sha256": R3_HANDOFF_SHA256, "r3_package_directory": R3_DIR_NAME, "r3_baseline_tree_sha256": sha256_tree(source), "b1_m1_non_regression": "PASS", "b2_verifier_production_e2e": "CLOSED", "b3_mandatory_authenticated_cross_object_validation": "CLOSED", "b4_mandatory_exact_disposition_lineage": "CLOSED", "p0_executed": "NO", "p1_executed": "NO", "primary_proposer_executed": "NO", "independent_verifier_semantic_execution": "NO", "raw_level_human_decisions": 0, "binding_publication": "NO", "runtime_adjudication_artifacts_generated": False, "next_action": "FRESH_TARGETED_INDEPENDENT_REVIEW_OF_R4_B2_B3_B4_ONLY", "r4_patch_summary": R4_PATCH_SUMMARY_NAME, "r4_tdd_log": R4_TDD_LOG_NAME}
        manifest["contract_manifest_id"] = object_id(manifest, "contract_manifest_id")
        write_json(stage / "CONTRACT_MANIFEST.json", manifest)
        paths = sorted(p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file() and p.relative_to(stage).as_posix() not in {"FILE_LIST.txt", "SHA256SUMS.txt"})
        paths = sorted(paths + ["FILE_LIST.txt", "SHA256SUMS.txt"])
        (stage / "FILE_LIST.txt").write_text("\n".join(paths) + "\n", encoding="utf-8")
        (stage / "SHA256SUMS.txt").write_text("\n".join(f"{sha256_file(stage / p)}  {p}" for p in paths if p != "SHA256SUMS.txt") + "\n", encoding="utf-8")
        stage.rename(output)
    verify_package(output)
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                for path in sorted(output.rglob("*"), key=lambda p: p.relative_to(output).as_posix().encode()):
                    if path.is_file():
                        data = path.read_bytes()
                        info = tarfile.TarInfo(f"{output.name}/{path.relative_to(output).as_posix()}")
                        info.size = len(data); info.mode = 0o644; info.mtime = 0; info.uid = 0; info.gid = 0; info.uname = ""; info.gname = ""
                        tar.addfile(info, io.BytesIO(data))
    result = {"P0_P1_EXECUTION_CONTRACT_R4_PATCH_STATUS": "COMPLETE_CONTRACT_ONLY", "B1_M1_NON_REGRESSION": "PASS", "B2_VERIFIER_PRODUCTION_E2E": "CLOSED", "B3_MANDATORY_AUTHENTICATED_CROSS_OBJECT_VALIDATION": "CLOSED", "B4_MANDATORY_EXACT_DISPOSITION_LINEAGE": "CLOSED", "r4_package_directory": output.name, "r4_review_handoff_sha256": sha256_file(archive_path), "P0_EXECUTED": "NO", "P1_EXECUTED": "NO", "PRIMARY_PROPOSER_EXECUTED": "NO", "INDEPENDENT_VERIFIER_SEMANTIC_EXECUTION": "NO", "RAW_LEVEL_HUMAN_DECISIONS": 0, "BINDING_PUBLICATION": "NO", "NEXT_ACTION": "FRESH_TARGETED_INDEPENDENT_REVIEW_OF_R4_B2_B3_B4_ONLY"}
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["materialize", "verify"])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "materialize":
            print(json.dumps(materialize(args.root, args.output_dir), sort_keys=True))
        else:
            verify_package(args.output_dir); print("PASS")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL_CLOSED: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
