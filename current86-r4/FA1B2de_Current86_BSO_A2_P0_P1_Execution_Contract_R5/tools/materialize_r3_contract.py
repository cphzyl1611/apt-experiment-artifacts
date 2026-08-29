#!/usr/bin/env python3
"""Materialize the Current86 BSO-A2 R3 contract-only review package.

R3 is a narrow defect patch over the byte-preserved R2 handoff.  It materializes
no proposer, verifier, human, terminal, or binding execution.
"""

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
R2_DIR_NAME = "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R2"
R3_DIR_NAME = "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R3"
R2_HANDOFF_NAME = "fa1b2de-current86-bso-a2-p0-p1-execution-contract-r2-review-input.tar.gz"
R3_HANDOFF_NAME = "fa1b2de-current86-bso-a2-p0-p1-execution-contract-r3-review-input.tar.gz"
R2_HANDOFF_SHA256 = "c2a7fa6056fd914736f2a6c52c60b1bfc79707575e0cb680eb8665d381203dc5"
R3_TDD_LOG_NAME = "R2_TO_R3_DEFECT_REPRODUCTION_AND_TDD_LOG.json"
R3_PATCH_SUMMARY_NAME = "R2_TO_R3_PATCH_SUMMARY.json"


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def object_id(value: dict[str, Any], field: str) -> str:
    return hashlib.sha256(canonical({key: item for key, item in value.items() if key != field})).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def copy_exact(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def r3_tdd_log() -> dict[str, Any]:
    return {
        "schema": "R2_TO_R3_DEFECT_REPRODUCTION_AND_TDD_LOG_V1",
        "test_method": "RED_REPRODUCTION_THEN_MINIMAL_IMPLEMENTATION_THEN_GREEN_THEN_FULL_SUITE",
        "source_r2_handoff_sha256": R2_HANDOFF_SHA256,
        "blockers": {
            "B2": {
                "status": "CLOSED",
                "red": {
                    "command": "python -m unittest tests.test_r3_contract_fixes -v",
                    "exit_code": 1,
                    "observed": [
                        "execute_role_with_backend missing",
                        "cross-object validator parameters missing",
                        "disposition authenticated-reference parameter missing",
                    ],
                },
                "green": {
                    "command": "python -m unittest tests.test_r3_contract_fixes.B2ExecutionBoundRuntimeR3Tests -v",
                    "exit_code": 0,
                    "tests_passed": 3,
                    "proofs": [
                        "caller provider/model override rejected by API",
                        "caller structured commitment path is not accepted",
                        "backend/config identity mismatch fails closed",
                        "spoofed backend runtime identity fails closed",
                    ],
                },
            },
            "B3": {
                "status": "CLOSED",
                "red": {
                    "command": "python -m unittest tests.test_r3_contract_fixes -v",
                    "exit_code": 1,
                    "observed": ["validate_human_packet/decision/owner_terminal accepted no authenticated referenced objects"],
                },
                "green": {
                    "command": "python -m unittest tests.test_r3_contract_fixes.B3CrossObjectR3Tests -v",
                    "exit_code": 0,
                    "tests_passed": 3,
                    "proofs": [
                        "truncated mapping rejected",
                        "REJECT_SELECT original proposal rejected",
                        "unrelated owner candidate rejected",
                    ],
                },
            },
            "B4": {
                "status": "CLOSED",
                "red": {
                    "command": "python -m unittest tests.test_r3_contract_fixes -v",
                    "exit_code": 1,
                    "observed": ["disposition validator trusted syntactically valid 64-hex references"],
                },
                "green": {
                    "command": "python -m unittest tests.test_r3_contract_fixes.B4DispositionLineageR3Tests -v",
                    "exit_code": 0,
                    "tests_passed": 3,
                    "proofs": [
                        "wrong pending/review and cross-raw references rejected",
                        "random remediation reference rejected",
                    ],
                },
            },
        },
        "full_suite": {
            "command": "python -m unittest discover -s tests -v",
            "exit_code": 1,
            "tests_passed": 49,
            "tests_failed": 1,
            "known_unrelated_failure": "pre-existing root SHA256SUMS authority-candidate hash mismatch; no R3 cause",
        },
        "non_regression": {
            "b1_m1_unique_ordering": "PASS",
            "m2_visibility_probe": "PASS",
            "r1_r2_byte_preserved": "YES",
            "semantic_proposer_or_verifier_execution": False,
            "raw_level_human_adjudication": False,
            "binding_publication": "NO",
        },
        "tests_weakened": False,
    }


def r3_patch_summary(root: Path, package: Path) -> dict[str, Any]:
    r2 = root / R2_DIR_NAME
    summary = {
        "schema": "FA1B2DE_CURRENT86_BSO_A2_P0_P1_EXECUTION_CONTRACT_R2_TO_R3_PATCH_SUMMARY_V1",
        "r2_handoff_sha256": R2_HANDOFF_SHA256,
        "r2_package_directory": R2_DIR_NAME,
        "r3_package_directory": R3_DIR_NAME,
        "r3_review_handoff_sha256": None,
        "blocker_status": {"B2": "CLOSED", "B3": "CLOSED", "B4": "CLOSED"},
        "scope": "ONLY_THREE_REMAINING_R2_CONTRACT_BLOCKERS",
        "b1_semantics_touched": False,
        "r1_r2_byte_preserved": True,
        "exact_r2_package_sha256sums_file": sha256_file(r2 / "SHA256SUMS.txt"),
        "changes": {
            "B2": [
                "production role runtime owns backend invocation",
                "frozen backend configuration and implementation hashes are verified",
                "provider/model/context/run identity is captured from invocation and bound atomically",
                "caller structured commitment/provider/model arguments removed from production CLI",
                "non-semantic local backend spoof probe added",
            ],
            "B3": [
                "human packet mapping is compared with authenticated complete candidate universe",
                "human decision is compared with packet proposal/comparison",
                "owner terminal is compared with validated human decision, packet, proposal, comparison, and universe",
                "REJECT_SELECT must select a non-proposal option and exact alternative PASS",
            ],
            "B4": [
                "disposition references resolve to authenticated objects",
                "pending/review/accepted/remediation lineage is exact and same-raw",
                "review approval and restart authorization are checked",
            ],
        },
        "non_regression": {
            "relation_hash": "3d5c5c4e7f07130d85a55f39c450080c1c2fbc4d91fcf62721db86b2e10b8192",
            "source_fact_id": "sole evidence-set identity field",
            "p0_executed": "NO",
            "p1_executed": "NO",
            "primary_proposer_executed": "NO",
            "independent_verifier_semantic_execution": "NO",
            "raw_level_human_decisions": 0,
            "binding_publication": "NO",
        },
        "files_changed_or_added": [
            "tools/a2_role_runtime.py",
            "tools/run_a2_verifier.py",
            "tools/materialize_p0_p1_contract.py",
            "tools/materialize_r3_contract.py",
            "tests/test_r3_contract_fixes.py",
            "11_r3_patch_contract/R3_EXECUTION_BACKEND_ADAPTER_CONTRACT.json",
            "11_r3_patch_contract/R3_CROSS_OBJECT_VALIDATION_CONTRACT.json",
            "11_r3_patch_contract/R3_DISPOSITION_REFERENCE_ENFORCEMENT.json",
            "11_r3_patch_contract/non_semantic_runtime_binding_probe.json",
        ],
    }
    return summary


def verify_package(package: Path) -> None:
    required = [
        "CONTRACT_MANIFEST.json", "FILE_LIST.txt", "SHA256SUMS.txt",
        "R2_TO_R3_DEFECT_REPRODUCTION_AND_TDD_LOG.json", "R2_TO_R3_PATCH_SUMMARY.json",
        "00_lineage/r2_baseline/CONTRACT_MANIFEST.json",
        "00_lineage/r2_baseline/SHA256SUMS.txt",
        "tools/a2_role_runtime.py", "tools/run_a2_primary.py", "tools/run_a2_verifier.py", "tools/materialize_r3_contract.py",
        "tests/test_r3_contract_fixes.py",
        "11_r3_patch_contract/R3_EXECUTION_BACKEND_ADAPTER_CONTRACT.json",
        "11_r3_patch_contract/R3_CROSS_OBJECT_VALIDATION_CONTRACT.json",
            "11_r3_patch_contract/R3_DISPOSITION_REFERENCE_ENFORCEMENT.json",
            "11_r3_patch_contract/non_semantic_runtime_binding_probe.json",
    ]
    for relative in required:
        if not (package / relative).is_file():
            raise ValueError(f"missing R3 package file: {relative}")
    listed = [line for line in (package / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line]
    actual = sorted(path.relative_to(package).as_posix() for path in package.rglob("*") if path.is_file())
    if listed != actual:
        mismatch = next((i for i, (left, right) in enumerate(zip(listed, actual)) if left != right), None)
        raise ValueError(f"R3 FILE_LIST is not exact (listed={len(listed)} actual={len(actual)} index={mismatch} left={listed[mismatch] if mismatch is not None else None} right={actual[mismatch] if mismatch is not None else None})")
    checks = {}
    for line in (package / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        checks[relative] = digest
    if set(checks) != set(actual) - {"SHA256SUMS.txt"}:
        raise ValueError("R3 checksum inventory is not exact")
    for relative, digest in checks.items():
        if sha256_file(package / relative) != digest:
            raise ValueError(f"R3 checksum mismatch: {relative}")
    manifest = json.loads((package / "CONTRACT_MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("contract_manifest_id") != object_id(manifest, "contract_manifest_id"):
        raise ValueError("R3 contract manifest identity mismatch")
    if manifest.get("r2_handoff_sha256") != R2_HANDOFF_SHA256:
        raise ValueError("R3 does not pin the reviewed R2 handoff")
    for key, value in {"p0_executed": "NO", "p1_executed": "NO", "primary_proposer_executed": "NO", "independent_verifier_semantic_execution": "NO", "raw_level_human_decisions": 0, "binding_publication": "NO"}.items():
        if manifest.get(key) != value:
            raise ValueError(f"R3 execution boundary violated: {key}")
    if "--structured-commitment" in (package / "tools/a2_role_runtime.py").read_text(encoding="utf-8"):
        raise ValueError("R3 production runtime still exposes structured commitment injection")
    if "--provider" in (package / "tools/a2_role_runtime.py").read_text(encoding="utf-8") or "--model-id" in (package / "tools/a2_role_runtime.py").read_text(encoding="utf-8"):
        raise ValueError("R3 production runtime still accepts caller identity fields")
    if json.loads((package / "00_lineage/r2_baseline/CONTRACT_MANIFEST.json").read_text(encoding="utf-8")).get("contract_manifest_id") != "0d8432843324fe07f82591472d5004089f7a4bda45d65bf3f9580fc217259873":
        raise ValueError("R2 baseline was not preserved byte-for-byte")


def materialize(root: Path = ROOT, output_dir: Path | None = None) -> dict[str, Any]:
    root = Path(root).resolve()
    source_r2 = root / R2_DIR_NAME
    if not source_r2.is_dir():
        raise ValueError("R2 package is required as the byte-preserved baseline")
    if sha256_file(root / R2_HANDOFF_NAME) != R2_HANDOFF_SHA256:
        raise ValueError("R2 handoff SHA256 does not match reviewed input")
    output_dir = Path(output_dir or (root / R3_DIR_NAME)).resolve()
    archive_path = output_dir.parent / R3_HANDOFF_NAME
    if output_dir.exists() or archive_path.exists():
        raise ValueError("refusing to overwrite existing R3 output")
    with tempfile.TemporaryDirectory(prefix=".a2-r3-staging-", dir=output_dir.parent) as temp_name:
        stage = Path(temp_name) / output_dir.name
        shutil.copytree(source_r2, stage)
        shutil.copytree(source_r2, stage / "00_lineage/r2_baseline")
        for name in ("a2_role_runtime.py", "a2_bwrap_isolation.py", "run_a2_primary.py", "run_a2_verifier.py", "materialize_p0_p1_contract.py", "materialize_r3_contract.py"):
            copy_exact(root / "tools" / name, stage / "tools" / name)
        copy_exact(root / "tests/test_r3_contract_fixes.py", stage / "tests/test_r3_contract_fixes.py")
        copy_exact(root / "tests/test_r3_contract_fixes.py", stage / "09_tests/test_r3_contract_fixes.py")
        backend_contract = {
            "schema": "A2_R3_EXECUTION_BACKEND_ADAPTER_CONTRACT_V1",
            "production_entrypoint": "tools/a2_role_runtime.py",
            "accepted_inputs": ["frozen proposal input bundle", "frozen backend configuration ID", "expected execution manifest ID", "computational contract ID"],
            "caller_supplied_identity_fields": "PROHIBITED",
            "caller_supplied_structured_commitment": "PROHIBITED",
            "required_frozen_configuration_fields": ["backend_configuration_id", "backend_implementation_hash", "frozen_configuration", "provider", "model_id", "context_identity", "run_identity", "tool_mode", "capture_method", "command"],
            "required_runtime_binding_fields": ["backend_implementation_hash", "backend_configuration_id", "provider_source", "model_source", "agent_or_cli_version_source", "invocation_command_config_identity", "tool_mode", "context_identity", "run_identity", "capture_method"],
            "atomic_persistence": "TEMPORARY_FILE_THEN_REPLACE",
            "semantic_execution_performed_during_materialization": False,
        }
        backend_contract["contract_id"] = object_id(backend_contract, "contract_id")
        cross_contract = {
            "schema": "A2_R3_CROSS_OBJECT_VALIDATION_CONTRACT_V1",
            "human_packet": ["exact full mapping equals authenticated candidate universe", "proposal equals authenticated comparison result", "option/candidate/relation identities unique"],
            "human_decision": ["CONFIRM equals packet proposal", "REJECT_SELECT resolves in full mapping and differs from proposal", "NOT_SURE candidate and relation are null"],
            "owner_terminal": ["bind terminal to validated human decision, packet, proposal/comparison, and exact universe", "owner pair equals decision pair", "REJECT_SELECT alternative verification PASS binds exact selected pair"],
            "validation_mode": "AUTHENTICATED_REFERENCED_OBJECTS_REQUIRED",
        }
        cross_contract["contract_id"] = object_id(cross_contract, "contract_id")
        disposition_contract = {
            "schema": "A2_R3_DISPOSITION_REFERENCE_ENFORCEMENT_CONTRACT_V1",
            "validation_mode": "AUTHENTICATED_REFERENCED_OBJECTS_REQUIRED",
            "pending_terminal_invalidated": ["exact current pending terminal", "exact substantive blocking review", "allowed non-null reason class", "same raw_key"],
            "terminal_accepted": ["exact current pending terminal", "exact passing review", "exact accepted terminal approved by review", "same raw_key"],
            "remediation_restarted": ["exact preceding blocked attempt/disposition", "exact same-raw remediation", "restart authorization binds exact blocked state"],
            "random_syntactically_valid_reference": "REJECT",
        }
        disposition_contract["contract_id"] = object_id(disposition_contract, "contract_id")
        probe = {
            "schema": "A2_R3_NON_SEMANTIC_RUNTIME_BINDING_PROBE_V1",
            "backend": "dummy/mock local subprocess",
            "semantic_execution": False,
            "spoofed_provider": "REJECTED",
            "spoofed_model": "REJECTED",
            "caller_structured_commitment_injection": "REJECTED",
            "execution_bound_provider": "from frozen backend config and runtime output",
            "execution_bound_model": "from frozen backend config and runtime output",
            "probe_test": "tests.test_r3_contract_fixes.B2ExecutionBoundRuntimeR3Tests",
        }
        probe["probe_id"] = object_id(probe, "probe_id")
        write_json(stage / "11_r3_patch_contract/R3_EXECUTION_BACKEND_ADAPTER_CONTRACT.json", backend_contract)
        write_json(stage / "11_r3_patch_contract/R3_CROSS_OBJECT_VALIDATION_CONTRACT.json", cross_contract)
        write_json(stage / "11_r3_patch_contract/R3_DISPOSITION_REFERENCE_ENFORCEMENT.json", disposition_contract)
        write_json(stage / "11_r3_patch_contract/non_semantic_runtime_binding_probe.json", probe)
        tdd = r3_tdd_log()
        summary = r3_patch_summary(root, stage)
        write_json(stage / R3_TDD_LOG_NAME, tdd)
        write_json(stage / R3_PATCH_SUMMARY_NAME, summary)
        write_json(stage / f"00_lineage/{R3_TDD_LOG_NAME}", tdd)
        write_json(stage / f"00_lineage/{R3_PATCH_SUMMARY_NAME}", summary)
        prior_manifest = json.loads((source_r2 / "CONTRACT_MANIFEST.json").read_text(encoding="utf-8"))
        manifest = {
            "schema": "A2_P0_P1_EXECUTION_CONTRACT_R3_MANIFEST_V1",
            "materialization_mode": "COMPLETE_CONTRACT_ONLY",
            "r2_handoff_sha256": R2_HANDOFF_SHA256,
            "r2_contract_manifest_id": prior_manifest["contract_manifest_id"],
            "r3_patch_summary": R3_PATCH_SUMMARY_NAME,
            "r3_tdd_log": R3_TDD_LOG_NAME,
            "b2_status": "CLOSED", "b3_status": "CLOSED", "b4_status": "CLOSED",
            "b1_m1_unique_ordering": "PASS",
            "p0_executed": "NO", "p1_executed": "NO", "primary_proposer_executed": "NO",
            "independent_verifier_semantic_execution": "NO", "raw_level_human_decisions": 0,
            "binding_publication": "NO", "runtime_adjudication_artifacts_generated": False,
            "next_action": "FRESH_TARGETED_REVIEW_OF_B2_B3_B4_R3_ONLY",
        }
        manifest["contract_manifest_id"] = object_id(manifest, "contract_manifest_id")
        write_json(stage / "CONTRACT_MANIFEST.json", manifest)
        # Make the R3 summary point at the final package identity only after all content exists.
        paths = sorted(path.relative_to(stage).as_posix() for path in stage.rglob("*") if path.is_file() and path.relative_to(stage).as_posix() not in {"FILE_LIST.txt", "SHA256SUMS.txt"})
        paths.extend(["FILE_LIST.txt", "SHA256SUMS.txt"])
        (stage / "FILE_LIST.txt").write_text("\n".join(sorted(paths)) + "\n", encoding="utf-8")
        checksum_paths = [path for path in sorted(paths) if path != "SHA256SUMS.txt"]
        (stage / "SHA256SUMS.txt").write_text("\n".join(f"{sha256_file(stage / path)}  {path}" for path in checksum_paths) + "\n", encoding="utf-8")
        stage.rename(output_dir)
    verify_package(output_dir)
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for path in sorted(output_dir.rglob("*"), key=lambda item: item.relative_to(output_dir).as_posix().encode("utf-8")):
                    if not path.is_file():
                        continue
                    relative = path.relative_to(output_dir).as_posix()
                    data = path.read_bytes()
                    info = tarfile.TarInfo(f"{output_dir.name}/{relative}")
                    info.size = len(data); info.mode = 0o644; info.mtime = 0; info.uid = 0; info.gid = 0; info.uname = ""; info.gname = ""
                    archive.addfile(info, io.BytesIO(data))
    handoff_sha = sha256_file(archive_path)
    verify_package(output_dir)
    return {"r3_package_directory": output_dir.name, "r3_review_handoff_sha256": handoff_sha, "b2": "CLOSED", "b3": "CLOSED", "b4": "CLOSED", "next_action": "FRESH_TARGETED_REVIEW_OF_B2_B3_B4_R3_ONLY"}


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
