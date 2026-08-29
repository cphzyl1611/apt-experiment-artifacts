#!/usr/bin/env python3
"""Materialize the Current86 BSO-A2 R5 B3/B4 contract-only package."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
R4_DIR_NAME = "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R4"
R5_DIR_NAME = "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R5"
R4_HANDOFF_NAME = "fa1b2de-current86-bso-a2-p0-p1-execution-contract-r4-review-input.tar.gz"
R5_HANDOFF_NAME = "fa1b2de-current86-bso-a2-p0-p1-execution-contract-r5-review-input.tar.gz"
R4_HANDOFF_SHA256 = "96680896198c8929dc33a8a4c1f45d4f4535b4197515816b7ed2f2eef52f7cec"
R4_REPOSITORY_REFERENCE_COMMIT = "11b801b8ae04ae32cdd9f4940d4d8e87829a32c9"
R5_TDD_LOG_NAME = "R4_TO_R5_DEFECT_REPRODUCTION_AND_TDD_LOG.json"
R5_PATCH_SUMMARY_NAME = "R4_TO_R5_PATCH_SUMMARY.json"
NEXT_ACTION = "FRESH_TARGETED_INDEPENDENT_REVIEW_OF_R5_B3_B4_ONLY"


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def object_id(value: dict[str, Any], field: str) -> str:
    return hashlib.sha256(
        canonical({key: item for key, item in value.items() if key != field})
    ).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(path: Path) -> str:
    rows = [
        {
            "path": item.relative_to(path).as_posix(),
            "sha256": sha256_file(item),
        }
        for item in sorted(
            path.rglob("*"),
            key=lambda value: value.relative_to(path).as_posix().encode("utf-8"),
        )
        if item.is_file()
    ]
    return hashlib.sha256(canonical(rows)).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _archive_inventory(archive: Path) -> dict[str, str]:
    inventory: dict[str, str] = {}
    with tarfile.open(archive, "r:gz") as handle:
        for member in handle.getmembers():
            pure = PurePosixPath(member.name)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or not pure.parts
                or pure.parts[0] != R4_DIR_NAME
                or not member.isfile()
            ):
                raise ValueError(f"unsafe or non-file R4 archive member: {member.name}")
            relative = PurePosixPath(*pure.parts[1:]).as_posix()
            if not relative or relative in inventory:
                raise ValueError("R4 archive path inventory is malformed or duplicated")
            extracted = handle.extractfile(member)
            if extracted is None:
                raise ValueError(f"R4 archive member is unreadable: {member.name}")
            digest = hashlib.sha256()
            for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                digest.update(chunk)
            inventory[relative] = digest.hexdigest()
    return inventory


def authenticate_r4_input(root: Path) -> dict[str, Any]:
    root = Path(root).resolve()
    archive = root / R4_HANDOFF_NAME
    package = root / R4_DIR_NAME
    if not archive.is_file() or sha256_file(archive) != R4_HANDOFF_SHA256:
        raise ValueError("authenticated R4 outer handoff SHA256 mismatch")
    if not package.is_dir():
        raise ValueError("authenticated R4 package directory is unavailable")
    try:
        from tools import materialize_r4_contract as r4
    except ImportError:
        import materialize_r4_contract as r4
    r4.verify_package(package)
    package_inventory = {
        item.relative_to(package).as_posix(): sha256_file(item)
        for item in sorted(
            package.rglob("*"),
            key=lambda value: value.relative_to(package).as_posix().encode("utf-8"),
        )
        if item.is_file()
    }
    if _archive_inventory(archive) != package_inventory:
        raise ValueError("R4 archive/package byte inventory mismatch")
    review_path = root / "FA1B2de_Current86_BSO_A2_R4_Fresh_Targeted_Independent_Review.json"
    if not review_path.is_file():
        raise ValueError("authenticated R4 targeted review record is unavailable")
    review = json.loads(review_path.read_text(encoding="utf-8"))
    if review.get("repository_main_commit_reviewed") != R4_REPOSITORY_REFERENCE_COMMIT:
        raise ValueError("R4 repository reference commit mismatch")
    return {
        "r4_handoff_sha256": R4_HANDOFF_SHA256,
        "r4_package_tree_sha256": sha256_tree(package),
        "r4_repository_reference_commit": R4_REPOSITORY_REFERENCE_COMMIT,
        "archive_package_byte_identity": "PASS",
        "r4_internal_inventory": "PASS",
    }


def tdd_log() -> dict[str, Any]:
    return {
        "schema": "R4_TO_R5_DEFECT_REPRODUCTION_AND_TDD_LOG_V1",
        "test_method": "AUTHENTICATE_R4_THEN_GENUINE_RED_THEN_MINIMAL_GREEN_THEN_SOURCE_AND_PACKAGED_REGRESSION",
        "source_r4_handoff_sha256": R4_HANDOFF_SHA256,
        "source_r4_repository_reference_commit": R4_REPOSITORY_REFERENCE_COMMIT,
        "blockers": {
            "B3": {
                "status": "CLOSED_CANDIDATE",
                "red": {
                    "command": "python -m unittest tests.test_r5_contract_fixes.B3MandatoryCrossObjectR5Tests -v",
                    "exit_code": 1,
                    "tests_run": 9,
                    "observed": [
                        "R4 validate_human_packet rejected the mandatory authenticated proposal-input bundle API argument",
                        "therefore R4 could not mechanically authenticate the bundle or enforce the required five-way universe, four-way relation-set, and three-way bundle identities",
                    ],
                },
                "green": {
                    "command": "python -m unittest tests.test_r5_contract_fixes.B3MandatoryCrossObjectR5Tests -v",
                    "exit_code": 0,
                    "tests_passed": 9,
                    "proofs": [
                        "frozen universe, proposal bundle, primary, verifier, and comparison validate against their shipped schemas",
                        "semantic universe, relation-set, and proposal-bundle identities are exact across authenticated objects",
                        "comparison assertions and direct context/run identity distinction fail closed",
                        "complete packet option mapping remains exact with no pruning or top-k behavior",
                    ],
                },
            },
            "B4": {
                "status": "CLOSED_CANDIDATE",
                "red": {
                    "command": "python -m unittest tests.test_r5_contract_fixes.B4DispositionReferenceGraphR5Tests -v",
                    "exit_code": 1,
                    "tests_run": 5,
                    "observed": [
                        "R4 chain validation could not resolve the raw/ID-keyed authenticated graph for valid exact transitions",
                        "R4 reconstruct_partitions did not accept the authenticated reference graph",
                    ],
                },
                "green": {
                    "command": "python -m unittest tests.test_r5_contract_fixes.B4DispositionReferenceGraphR5Tests -v",
                    "exit_code": 0,
                    "tests_passed": 5,
                    "proofs": [
                        "invalidation, acceptance, and remediation restart resolve exact same-raw objects",
                        "partition reconstruction follows fully validated heads only",
                        "missing, wrong, stale, cross-raw, forked, duplicate, gap, missing-parent, and unauthorized references fail closed",
                    ],
                },
            },
        },
        "source_regression": {
            "command": "python -m unittest discover -s tests -v",
            "expected_exit_code": 1,
            "expected_known_unrelated_failure_count": 1,
            "known_unrelated_failure": "pre-existing root SHA256SUMS authority-candidate hash mismatch; not changed or normalized by R5",
        },
        "packaged_regression": {
            "command": f"python {R5_DIR_NAME}/run_packaged_tests.py",
            "expected_exit_code": 0,
            "runner_reason": "imports shipped R5 tools while exposing the already-authenticated repo-external source fixtures through a temporary read-only symlink view",
        },
        "non_regression": {
            "b1_m1_m2_behavior": "PRESERVED",
            "b2_verifier_production_e2e": "PRESERVED",
            "r1_r2_r3_r4_lineage_byte_preserved": True,
            "tests_weakened": False,
        },
        "execution_boundary": _execution_boundary(),
    }


def _execution_boundary() -> dict[str, Any]:
    return {
        "P0_EXECUTED": "NO",
        "P1_EXECUTED": "NO",
        "PRIMARY_PROPOSER_EXECUTED": "NO",
        "INDEPENDENT_VERIFIER_SEMANTIC_EXECUTION": "NO",
        "RAW_LEVEL_HUMAN_DECISIONS": 0,
        "BSO_V_EXECUTED": "NO",
        "BSO_P_EXECUTED": "NO",
        "BINDING_PUBLICATION": "NO",
        "SCORING_AUTHORITY_MUTATION": "NO",
        "BINDING_AUTHORITY_MUTATION": "NO",
        "DENOMINATOR_CHANGE": "NO",
        "GIT_REF_MUTATION": "NO",
    }


def patch_summary() -> dict[str, Any]:
    return {
        "schema": "FA1B2DE_CURRENT86_BSO_A2_R4_TO_R5_PATCH_SUMMARY_V1",
        "scope": "MINIMAL_R4_TO_R5_REMEDIATION_OF_B3_AND_B4_ONLY",
        "r4_handoff_sha256": R4_HANDOFF_SHA256,
        "r4_repository_reference_commit": R4_REPOSITORY_REFERENCE_COMMIT,
        "r4_package_directory": R4_DIR_NAME,
        "r5_package_directory": R5_DIR_NAME,
        "r5_review_handoff_sha256": None,
        "patch_status": "COMPLETE_CONTRACT_ONLY",
        "blocker_status": {
            "B1_M1_M2_NON_REGRESSION": "PASS",
            "B2_VERIFIER_PRODUCTION_E2E": "PRESERVED",
            "B3_MANDATORY_AUTHENTICATED_CROSS_OBJECT_VALIDATION": "CLOSED_CANDIDATE",
            "B4_MANDATORY_EXACT_DISPOSITION_LINEAGE": "CLOSED_CANDIDATE",
        },
        "implementation_schema_test_package_files_changed_or_added": [
            "tools/materialize_p0_p1_contract.py",
            "tools/materialize_r5_contract.py",
            "tests/test_p0_p1_contract.py",
            "tests/test_r2_contract_fixes.py",
            "tests/test_r4_contract_fixes.py",
            "tests/test_r5_contract_fixes.py",
            "09_tests/test_materialization_contract.py",
            "09_tests/test_r2_contract_fixes.py",
            "09_tests/test_r4_contract_fixes.py",
            "09_tests/test_r5_contract_fixes.py",
            "run_packaged_tests.py",
        ],
        "schemas_changed": [],
        "r1_r2_r3_r4_lineage_byte_preserved": True,
        "required_terminal": {
            "P0_P1_EXECUTION_CONTRACT_R5_PATCH_STATUS": "COMPLETE_CONTRACT_ONLY",
            "B2_VERIFIER_PRODUCTION_E2E": "PRESERVED",
            "B3_MANDATORY_AUTHENTICATED_CROSS_OBJECT_VALIDATION": "CLOSED_CANDIDATE",
            "B4_MANDATORY_EXACT_DISPOSITION_LINEAGE": "CLOSED_CANDIDATE",
            **_execution_boundary(),
            "NEXT_ACTION": NEXT_ACTION,
        },
    }


PACKAGED_TEST_RUNNER = '''#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


PACKAGE_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = PACKAGE_ROOT.parent


def main() -> int:
    sys.dont_write_bytecode = True
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    sys.path.insert(0, str(PACKAGE_ROOT))
    sys.path.insert(1, str(PACKAGE_ROOT / "09_tests"))
    with tempfile.TemporaryDirectory(prefix="a2-r5-packaged-tests-") as td:
        view = Path(td) / "source"
        view.mkdir()
        for source in SOURCE_ROOT.iterdir():
            if source.name in {PACKAGE_ROOT.name, "tools", "tests"}:
                continue
            os.symlink(source, view / source.name, target_is_directory=source.is_dir())
        os.symlink(PACKAGE_ROOT / "tools", view / "tools", target_is_directory=True)
        os.symlink(PACKAGE_ROOT / "tests", view / "tests", target_is_directory=True)
        suite = unittest.TestSuite()
        loader = unittest.defaultTestLoader
        for path in sorted((PACKAGE_ROOT / "09_tests").glob("test_*.py")):
            name = f"r5_packaged_{path.stem}"
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                raise RuntimeError(f"cannot load packaged test: {path.name}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            if hasattr(module, "ROOT"):
                module.ROOT = view
            if hasattr(module, "R4_PACKAGE"):
                module.R4_PACKAGE = view / "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R4"
            suite.addTests(loader.loadTestsFromModule(module))
        for name, module in tuple(sys.modules.items()):
            if name.endswith("test_r5_contract_fixes"):
                if hasattr(module, "ROOT"):
                    module.ROOT = view
                if hasattr(module, "R4_PACKAGE"):
                    module.R4_PACKAGE = view / "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R4"
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _write_package_inventory(stage: Path) -> None:
    relative_paths = sorted(
        item.relative_to(stage).as_posix()
        for item in stage.rglob("*")
        if item.is_file()
        and item.relative_to(stage).as_posix()
        not in {"FILE_LIST.txt", "SHA256SUMS.txt"}
    )
    relative_paths = sorted(relative_paths + ["FILE_LIST.txt", "SHA256SUMS.txt"])
    (stage / "FILE_LIST.txt").write_text(
        "\n".join(relative_paths) + "\n", encoding="utf-8"
    )
    (stage / "SHA256SUMS.txt").write_text(
        "\n".join(
            f"{sha256_file(stage / relative)}  {relative}"
            for relative in relative_paths
            if relative != "SHA256SUMS.txt"
        )
        + "\n",
        encoding="utf-8",
    )


def verify_package(package: Path) -> None:
    package = Path(package).resolve()
    required = (
        R5_TDD_LOG_NAME,
        R5_PATCH_SUMMARY_NAME,
        "CONTRACT_MANIFEST.json",
        "FILE_LIST.txt",
        "SHA256SUMS.txt",
        "00_lineage/r4_baseline/CONTRACT_MANIFEST.json",
        f"00_lineage/r4_review_input/{R4_HANDOFF_NAME}",
        "tools/materialize_p0_p1_contract.py",
        "tools/materialize_r5_contract.py",
        "tests/test_r5_contract_fixes.py",
        "09_tests/test_r5_contract_fixes.py",
        "09_tests/PACKAGED_TEST_EXECUTION.json",
        "run_packaged_tests.py",
        "11_r5_patch_contract/R5_CROSS_OBJECT_VALIDATION_CONTRACT.json",
        "11_r5_patch_contract/R5_DISPOSITION_REFERENCE_GRAPH_CONTRACT.json",
    )
    missing = next((relative for relative in required if not (package / relative).is_file()), None)
    if missing:
        raise ValueError(f"missing R5 package file: {missing}")
    actual = sorted(
        item.relative_to(package).as_posix()
        for item in package.rglob("*")
        if item.is_file()
    )
    listed = [
        line
        for line in (package / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines()
        if line
    ]
    if listed != actual:
        raise ValueError("R5 FILE_LIST is not exact")
    checks: dict[str, str] = {}
    for line in (package / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        if relative in checks:
            raise ValueError("R5 checksum inventory contains a duplicate path")
        checks[relative] = digest
    if set(checks) != set(actual) - {"SHA256SUMS.txt"}:
        raise ValueError("R5 checksum inventory is not exact")
    mismatch = next(
        (relative for relative, digest in checks.items() if sha256_file(package / relative) != digest),
        None,
    )
    if mismatch:
        raise ValueError(f"R5 checksum mismatch: {mismatch}")
    manifest = json.loads((package / "CONTRACT_MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("contract_manifest_id") != object_id(manifest, "contract_manifest_id"):
        raise ValueError("R5 manifest identity mismatch")
    expected = {
        "materialization_mode": "COMPLETE_CONTRACT_ONLY",
        "r4_handoff_sha256": R4_HANDOFF_SHA256,
        "r4_repository_reference_commit": R4_REPOSITORY_REFERENCE_COMMIT,
        "b1_m1_m2_non_regression": "PASS",
        "b2_verifier_production_e2e": "PRESERVED",
        "b3_mandatory_authenticated_cross_object_validation": "CLOSED_CANDIDATE",
        "b4_mandatory_exact_disposition_lineage": "CLOSED_CANDIDATE",
        "next_action": NEXT_ACTION,
        "p0_executed": "NO",
        "p1_executed": "NO",
        "primary_proposer_executed": "NO",
        "independent_verifier_semantic_execution": "NO",
        "raw_level_human_decisions": 0,
        "bso_v_executed": "NO",
        "bso_p_executed": "NO",
        "binding_publication": "NO",
        "scoring_authority_mutation": "NO",
        "binding_authority_mutation": "NO",
        "denominator_change": "NO",
        "git_ref_mutation": "NO",
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise ValueError("R5 manifest terminal or hard boundary mismatch")
    if sha256_file(package / f"00_lineage/r4_review_input/{R4_HANDOFF_NAME}") != R4_HANDOFF_SHA256:
        raise ValueError("R5 does not preserve the exact authenticated R4 handoff")
    baseline = package / "00_lineage/r4_baseline"
    if sha256_tree(baseline) != manifest.get("r4_baseline_tree_sha256"):
        raise ValueError("R5 R4 baseline tree identity mismatch")
    try:
        from tools import materialize_r4_contract as r4
    except ImportError:
        import materialize_r4_contract as r4
    r4.verify_package(baseline)
    for relative in (
        "tools/a2_role_runtime.py",
        "tools/a2_bwrap_isolation.py",
        "tools/run_a2_primary.py",
        "tools/run_a2_verifier.py",
    ):
        if sha256_file(package / relative) != sha256_file(baseline / relative):
            raise ValueError(f"R5 B2 implementation changed: {relative}")


def materialize(root: Path = ROOT, output_dir: Path | None = None) -> dict[str, Any]:
    root = Path(root).resolve()
    authentication = authenticate_r4_input(root)
    source = root / R4_DIR_NAME
    output = Path(output_dir or root / R5_DIR_NAME).resolve()
    archive_path = output.parent / R5_HANDOFF_NAME
    if output.exists() or archive_path.exists():
        raise ValueError("refusing to overwrite existing R5 output or handoff")
    with tempfile.TemporaryDirectory(prefix=".a2-r5-", dir=output.parent) as td:
        stage = Path(td) / output.name
        shutil.copytree(source, stage)
        shutil.copytree(source, stage / "00_lineage/r4_baseline")
        r4_review_dir = stage / "00_lineage/r4_review_input"
        r4_review_dir.mkdir(parents=True)
        shutil.copyfile(root / R4_HANDOFF_NAME, r4_review_dir / R4_HANDOFF_NAME)
        shutil.copyfile(
            root / "tools/materialize_p0_p1_contract.py",
            stage / "tools/materialize_p0_p1_contract.py",
        )
        shutil.copyfile(
            root / "tools/materialize_r5_contract.py",
            stage / "tools/materialize_r5_contract.py",
        )
        source_tests = {
            "test_materialization_contract.py": "test_p0_p1_contract.py",
            "test_r2_contract_fixes.py": "test_r2_contract_fixes.py",
            "test_r3_contract_fixes.py": "test_r3_contract_fixes.py",
            "test_r4_contract_fixes.py": "test_r4_contract_fixes.py",
            "test_r5_contract_fixes.py": "test_r5_contract_fixes.py",
        }
        for packaged_name, source_name in source_tests.items():
            shutil.copyfile(root / "tests" / source_name, stage / "09_tests" / packaged_name)
            shutil.copyfile(root / "tests" / source_name, stage / "tests" / source_name)
        (stage / "run_packaged_tests.py").write_text(
            PACKAGED_TEST_RUNNER, encoding="utf-8"
        )
        os.chmod(stage / "run_packaged_tests.py", 0o755)
        write_json(
            stage / "09_tests/PACKAGED_TEST_EXECUTION.json",
            {
                "schema": "A2_R5_PACKAGED_TEST_EXECUTION_V1",
                "command": f"python {R5_DIR_NAME}/run_packaged_tests.py",
                "discovers": "09_tests/test_*.py",
                "imports_shipped_r5_tools": True,
                "temporary_fixture_view": "repo-external authenticated source inputs exposed read-only by symlink; shipped package tools and tests override source tools and tests",
                "tests_omitted": False,
                "semantic_execution_performed": False,
            },
        )
        write_json(
            stage / "09_tests/STATIC_TEST_CATALOG.json",
            {
                "schema": "A2_R5_IMPLEMENTATION_TEST_CATALOG_V1",
                "implementation_verification_only": True,
                "runtime_adjudication_executed": False,
                "tests": {
                    "B1_M1_M2": "preserved regression tests",
                    "B2": "preserved non-semantic production verifier E2E",
                    "B3": "mandatory authenticated bundle/universe/commitment/comparison schema and invariant validation",
                    "B4": "raw/ID-keyed exact reference graph through chain and partition reconstruction",
                },
            },
        )
        write_json(
            stage / "09_tests/VERIFICATION_SCOPE.json",
            {
                "real_p1_adjudication_run": False,
                "primary_proposer_run": False,
                "independent_verifier_run": False,
                "independent_verifier_semantic_execution": False,
                "human_decision_capture": False,
                "bso_v_execution": False,
                "bso_p_execution": False,
                "binding_publication": False,
                "ledger_append": False,
                "tests_are_static_contract_verification": True,
            },
        )
        for filename, value in {
            "R5_CROSS_OBJECT_VALIDATION_CONTRACT.json": {
                "schema": "A2_R5_CROSS_OBJECT_VALIDATION_CONTRACT_V1",
                "authenticated_proposal_input_bundle_mandatory": True,
                "frozen_schema_validation_mandatory": True,
                "semantic_universe_hash_equality_arity": 5,
                "relation_set_hash_equality_arity": 4,
                "proposal_input_bundle_id_equality_arity": 3,
                "direct_context_and_run_distinction_mandatory": True,
                "candidate_option_set_exact_equality": True,
            },
            "R5_DISPOSITION_REFERENCE_GRAPH_CONTRACT.json": {
                "schema": "A2_R5_DISPOSITION_REFERENCE_GRAPH_CONTRACT_V1",
                "keyed_by": ["raw_key", "exact_object_id"],
                "collections": [
                    "pending_terminals",
                    "independent_reviews",
                    "accepted_terminals",
                    "blocked_attempts",
                    "remediation_records",
                ],
                "chain_validation_resolves_graph": True,
                "partition_reconstruction_requires_same_graph": True,
                "fail_closed": True,
            },
        }.items():
            value["contract_id"] = object_id(value, "contract_id")
            write_json(stage / "11_r5_patch_contract" / filename, value)
        log = tdd_log()
        summary = patch_summary()
        for relative, value in (
            (R5_TDD_LOG_NAME, log),
            (R5_PATCH_SUMMARY_NAME, summary),
            (f"00_lineage/{R5_TDD_LOG_NAME}", log),
            (f"00_lineage/{R5_PATCH_SUMMARY_NAME}", summary),
        ):
            write_json(stage / relative, value)
        manifest = {
            "schema": "A2_P0_P1_EXECUTION_CONTRACT_R5_MANIFEST_V1",
            "materialization_mode": "COMPLETE_CONTRACT_ONLY",
            **authentication,
            "r4_package_directory": R4_DIR_NAME,
            "r4_baseline_tree_sha256": authentication["r4_package_tree_sha256"],
            "b1_m1_m2_non_regression": "PASS",
            "b2_verifier_production_e2e": "PRESERVED",
            "b3_mandatory_authenticated_cross_object_validation": "CLOSED_CANDIDATE",
            "b4_mandatory_exact_disposition_lineage": "CLOSED_CANDIDATE",
            "p0_executed": "NO",
            "p1_executed": "NO",
            "primary_proposer_executed": "NO",
            "independent_verifier_semantic_execution": "NO",
            "raw_level_human_decisions": 0,
            "bso_v_executed": "NO",
            "bso_p_executed": "NO",
            "binding_publication": "NO",
            "scoring_authority_mutation": "NO",
            "binding_authority_mutation": "NO",
            "denominator_change": "NO",
            "git_ref_mutation": "NO",
            "runtime_adjudication_artifacts_generated": False,
            "next_action": NEXT_ACTION,
            "r5_patch_summary": R5_PATCH_SUMMARY_NAME,
            "r5_tdd_log": R5_TDD_LOG_NAME,
        }
        manifest["contract_manifest_id"] = object_id(manifest, "contract_manifest_id")
        write_json(stage / "CONTRACT_MANIFEST.json", manifest)
        write_json(
            stage / "10_summary/SUMMARY.json",
            {
                "schema": "A2_R5_CONTRACT_ONLY_SUMMARY_V1",
                "status": "COMPLETE_CONTRACT_ONLY",
                "b2": "PRESERVED",
                "b3": "CLOSED_CANDIDATE",
                "b4": "CLOSED_CANDIDATE",
                **_execution_boundary(),
                "next_action": NEXT_ACTION,
            },
        )
        _write_package_inventory(stage)
        stage.rename(output)
    verify_package(output)
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(
            filename="", fileobj=raw, mode="wb", mtime=0
        ) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for path in sorted(
                    output.rglob("*"),
                    key=lambda value: value.relative_to(output).as_posix().encode("utf-8"),
                ):
                    if not path.is_file():
                        continue
                    data = path.read_bytes()
                    info = tarfile.TarInfo(
                        f"{output.name}/{path.relative_to(output).as_posix()}"
                    )
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info, io.BytesIO(data))
    return {
        "P0_P1_EXECUTION_CONTRACT_R5_PATCH_STATUS": "COMPLETE_CONTRACT_ONLY",
        "B1_M1_M2_NON_REGRESSION": "PASS",
        "B2_VERIFIER_PRODUCTION_E2E": "PRESERVED",
        "B3_MANDATORY_AUTHENTICATED_CROSS_OBJECT_VALIDATION": "CLOSED_CANDIDATE",
        "B4_MANDATORY_EXACT_DISPOSITION_LINEAGE": "CLOSED_CANDIDATE",
        "r5_package_directory": output.name,
        "r5_review_handoff_sha256": sha256_file(archive_path),
        **_execution_boundary(),
        "NEXT_ACTION": NEXT_ACTION,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("materialize", "verify", "authenticate-r4"))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "materialize":
            if args.output_dir is None:
                raise ValueError("--output-dir is required for materialize")
            print(json.dumps(materialize(args.root, args.output_dir), sort_keys=True))
        elif args.command == "verify":
            if args.output_dir is None:
                raise ValueError("--output-dir is required for verify")
            verify_package(args.output_dir)
            print("PASS")
        else:
            print(json.dumps(authenticate_r4_input(args.root), sort_keys=True))
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as exc:
        print(f"FAIL_CLOSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
