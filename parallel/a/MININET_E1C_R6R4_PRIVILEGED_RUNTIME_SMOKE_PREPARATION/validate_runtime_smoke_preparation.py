"""Validate the static-only R6R4 privileged runtime smoke preparation package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


PACKAGE_NAME = "MININET_E1C_R6R4_PRIVILEGED_RUNTIME_SMOKE_PREPARATION"
CONTRACT_FILE = "RUNTIME_SMOKE_PREPARATION_CONTRACT.json"
MANIFEST_FILE = "MATERIALIZATION_MANIFEST.json"
REQUIRED_PACKAGE_FILES = {
    CONTRACT_FILE,
    "EXECUTION_BOUNDARY.md",
    "EXPECTED_RUNTIME_RECEIPT_SCHEMA.json",
    "EVIDENCE_COLLECTION_REQUIREMENTS.md",
    "FAIL_CLOSED_CONDITIONS.json",
    "INDEPENDENT_REVIEW_PACKAGE.md",
    "validate_runtime_smoke_preparation.py",
    "test_runtime_smoke_preparation.py",
}
REQUIRED_RECEIPT_ARTIFACTS = {
    "privileged_result_review",
    "raw_audit_jsonl",
    "normalized_events_jsonl",
    "pid_netns_join_jsonl",
    "coverage_and_loss_json",
    "pcap",
    "pcap_hash_source",
    "post_cleanup_proof",
}
REQUIRED_FAIL_CLOSED_IDS = {
    "RECEIPT_MALFORMED_OR_INCOMPLETE",
    "RUN_ID_MISMATCH",
    "ARTIFACT_HASH_OR_PCAP_BINDING_FAILURE",
    "RAW_NORMALIZED_LINK_FAILURE",
    "PID_NETNS_LOGICAL_HOST_JOIN_FAILURE",
    "FILE_RW_PERMISSION_FILTER_INCOMPLETE",
    "FILE_RW_ABSENT_OR_ZERO",
    "AUDIT_LOSS_OR_BACKLOG_NONZERO",
    "AUSEARCH_DEADLINE_OR_RETURN_FAILURE",
    "POST_CLEANUP_RESTORATION_FAILURE",
    "PREPARATION_PACKAGE_RUNTIME_CLAIM",
    "PROVX_ADAPTER_MUTATION_OR_EXECUTION",
}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        failures.append(f"{path.name} is unreadable JSON: {error}")
        return None
    if not isinstance(value, dict):
        failures.append(f"{path.name} must contain a JSON object")
        return None
    return value


def _require_value(
    document: dict[str, Any], key: str, expected: Any, name: str, failures: list[str]
) -> None:
    if document.get(key) != expected:
        failures.append(f"{name}.{key} must equal {expected!r}")


def _require_members(
    value: Any, required: set[str], name: str, failures: list[str]
) -> None:
    if not isinstance(value, list):
        failures.append(f"{name} must be a list")
        return
    members: list[str] = []
    for item in value:
        if not isinstance(item, str):
            failures.append(f"{name} has non-string member: {item!r}")
            continue
        members.append(item)
    actual = set(members)
    missing = sorted(required - actual)
    extras = sorted(actual - required)
    duplicates = sorted({item for item in actual if members.count(item) > 1})
    for item in missing:
        failures.append(f"{name} missing required artifact: {item}")
    for item in extras:
        failures.append(f"{name} has undeclared artifact: {item}")
    for item in duplicates:
        failures.append(f"{name} has duplicated artifact: {item}")


def _require_text(path: Path, phrases: tuple[str, ...], failures: list[str]) -> None:
    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as error:
        failures.append(f"{path.name} is unreadable: {error}")
        return
    normalized_contents = " ".join(contents.split())
    for phrase in phrases:
        if " ".join(phrase.split()) not in normalized_contents:
            failures.append(f"{path.name} is missing required boundary text: {phrase}")


def _derive_repository_root(package: Path) -> Path | None:
    resolved = package.resolve()
    for candidate in (resolved, *resolved.parents):
        expected = candidate / "parallel" / "a" / PACKAGE_NAME
        if expected.exists() and expected.resolve() == resolved:
            return candidate
    return None


def _validate_package_contents(package: Path, failures: list[str]) -> None:
    if not package.is_dir():
        failures.append(f"package directory is missing: {package}")
        return

    entries = list(package.iterdir())
    actual_files = {entry.name for entry in entries if entry.is_file()}
    actual_directories = sorted(entry.name for entry in entries if entry.is_dir())
    links = sorted(entry.name for entry in entries if entry.is_symlink())
    allowed_files = REQUIRED_PACKAGE_FILES | {MANIFEST_FILE}

    for name in sorted(REQUIRED_PACKAGE_FILES - actual_files):
        failures.append(f"required package file is missing: {name}")
    for name in sorted(actual_files - allowed_files):
        failures.append(f"unexpected package file: {name}")
    for name in actual_directories:
        failures.append(f"unexpected package directory: {name}")
    for name in links:
        failures.append(f"package symlink is prohibited: {name}")


def _validate_contract(
    package: Path,
    repository_root: Path | None,
    failures: list[str],
) -> dict[str, Any] | None:
    contract = _read_json(package / CONTRACT_FILE, failures)
    if contract is None:
        return None

    _require_value(
        contract,
        "schema",
        "MININET_E1C_R6R4_PRIVILEGED_RUNTIME_SMOKE_PREPARATION_CONTRACT_V1",
        CONTRACT_FILE,
        failures,
    )
    _require_value(contract, "package_mode", "STATIC_PREPARATION_AND_REVIEW_ONLY", CONTRACT_FILE, failures)

    preservation = contract.get("preservation_requirements")
    if not isinstance(preservation, dict):
        failures.append(f"{CONTRACT_FILE}.preservation_requirements must be an object")
    else:
        for key in (
            "r6r4_artifacts_modified",
            "provx_r7r1_adapter_modified",
            "runtime_evidence_generated",
            "audit_configuration_modified",
            "formal_experiment_executed",
        ):
            _require_value(preservation, key, "NO", f"{CONTRACT_FILE}.preservation_requirements", failures)

    _require_members(
        contract.get("required_deliverables"),
        {
            "EXECUTION_BOUNDARY.md",
            "EXPECTED_RUNTIME_RECEIPT_SCHEMA.json",
            "EVIDENCE_COLLECTION_REQUIREMENTS.md",
            "FAIL_CLOSED_CONDITIONS.json",
            "INDEPENDENT_REVIEW_PACKAGE.md",
        },
        f"{CONTRACT_FILE}.required_deliverables",
        failures,
    )

    terminal_state = contract.get("terminal_state")
    if not isinstance(terminal_state, dict):
        failures.append(f"{CONTRACT_FILE}.terminal_state must be an object")
    else:
        expected_terminal = {
            "PRIVILEGED_RUNTIME_SMOKE_EXECUTED": "NO",
            "FILE_READ_OR_WRITE_RUNTIME_CLOSURE": "NOT_PROVEN",
            "FORMAL_1796_EXPERIMENT_EXECUTED": "NO",
            "NEXT_ACTION": "HUMAN_REVIEW_OF_STATIC_PREPARATION_PACKAGE",
            "STOP": True,
        }
        for key, expected in expected_terminal.items():
            _require_value(terminal_state, key, expected, f"{CONTRACT_FILE}.terminal_state", failures)

    upstream = contract.get("upstream_authentication")
    if not isinstance(upstream, dict) or not upstream:
        failures.append(f"{CONTRACT_FILE}.upstream_authentication must be a nonempty object")
        return contract
    if repository_root is None:
        failures.append("repository root is required to validate upstream authentication")
        return contract

    for label, descriptor in upstream.items():
        if not isinstance(descriptor, dict):
            failures.append(f"upstream descriptor must be an object: {label}")
            continue
        relative_path = descriptor.get("path")
        expected_hash = descriptor.get("sha256")
        if not isinstance(relative_path, str) or not relative_path:
            failures.append(f"upstream descriptor has invalid path: {label}")
            continue
        if not isinstance(expected_hash, str) or not SHA256_PATTERN.fullmatch(expected_hash):
            failures.append(f"upstream descriptor has invalid sha256: {label}")
            continue
        candidate = (repository_root / relative_path).resolve()
        try:
            candidate.relative_to(repository_root.resolve())
        except ValueError:
            failures.append(f"upstream path escapes repository root: {label}")
            continue
        if not candidate.is_file():
            failures.append(f"pinned upstream artifact is missing: {relative_path}")
            continue
        actual_hash = _sha256(candidate)
        if actual_hash != expected_hash:
            failures.append(
                f"pinned upstream hash mismatch for {relative_path}: {actual_hash} != {expected_hash}"
            )
    return contract


def _validate_receipt_schema(package: Path, failures: list[str]) -> None:
    name = "EXPECTED_RUNTIME_RECEIPT_SCHEMA.json"
    schema = _read_json(package / name, failures)
    if schema is None:
        return
    _require_value(
        schema,
        "schema",
        "MININET_E1C_R6R4_EXPECTED_PRIVILEGED_RUNTIME_SMOKE_RECEIPT_V1",
        name,
        failures,
    )
    _require_value(
        schema,
        "classification",
        "FUTURE_RUNTIME_RECEIPT_REQUIREMENTS_ONLY_NOT_RUNTIME_EVIDENCE",
        name,
        failures,
    )

    receipt = schema.get("receipt")
    if not isinstance(receipt, dict):
        failures.append(f"{name}.receipt must be an object")
        return
    _require_members(
        receipt.get("required_artifacts"),
        REQUIRED_RECEIPT_ARTIFACTS,
        f"{name}.receipt.required_artifacts",
        failures,
    )
    required_top_level = receipt.get("required_top_level_fields")
    if not isinstance(required_top_level, list):
        failures.append(f"{name}.receipt.required_top_level_fields must be a list")
    else:
        for field in (
            "schema",
            "receipt_id",
            "run_id",
            "decision",
            "privileged_result_review",
            "artifacts",
            "normalized_to_raw_link_summary",
            "file_read_or_write",
            "pid_netns_logical_host_join",
            "coverage_and_loss",
            "post_cleanup",
            "declared_runtime_claims",
        ):
            if field not in required_top_level:
                failures.append(f"{name}.receipt.required_top_level_fields missing: {field}")

    file_rw = schema.get("file_read_or_write")
    if not isinstance(file_rw, dict):
        failures.append(f"{name}.file_read_or_write must be an object")
    else:
        _require_value(file_rw, "event_type", "FILE_READ_OR_WRITE", f"{name}.file_read_or_write", failures)
        _require_value(file_rw, "minimum_count", 1, f"{name}.file_read_or_write", failures)
        _require_value(
            file_rw,
            "required_same_serial_raw_record_types",
            ["SYSCALL", "PATH"],
            f"{name}.file_read_or_write",
            failures,
        )
        _require_value(
            file_rw,
            "required_evidence_basis",
            "AUDIT_FILESYSTEM_PERMISSION_FILTER",
            f"{name}.file_read_or_write",
            failures,
        )
        for key in (
            "require_exact_same_serial_key_and_watched_path",
            "require_supported_underlying_syscall",
            "require_authenticated_raw_bytes_and_sha256_link",
            "require_pid_netns_logical_host_join",
        ):
            _require_value(file_rw, key, True, f"{name}.file_read_or_write", failures)
        required_normalized = file_rw.get("required_normalized_fields")
        if not isinstance(required_normalized, list):
            failures.append(f"{name}.file_read_or_write.required_normalized_fields must be a list")
        else:
            for field in ("watched_path", "requested_access", "underlying_syscall", "evidence_basis"):
                if field not in required_normalized:
                    failures.append(f"{name}.file_read_or_write.required_normalized_fields missing: {field}")

    join = schema.get("pid_netns_logical_host_join")
    if not isinstance(join, dict):
        failures.append(f"{name}.pid_netns_logical_host_join must be an object")
    else:
        _require_value(join, "required_join_status", "JOINED", f"{name}.pid_netns_logical_host_join", failures)

    coverage = schema.get("coverage_and_loss")
    if not isinstance(coverage, dict):
        failures.append(f"{name}.coverage_and_loss must be an object")
    else:
        if set(coverage.get("required_zero_fields", [])) != {"audit_loss_count", "audit_backlog_count"}:
            failures.append(f"{name}.coverage_and_loss.required_zero_fields must require loss and backlog zero")
        required_values = coverage.get("ausearch_required_values")
        if required_values != {"deadline_expired": False, "returncode": 0}:
            failures.append(f"{name}.coverage_and_loss.ausearch_required_values must require deadline=false and returncode=0")

    pcap = schema.get("pcap_authentication")
    if not isinstance(pcap, dict):
        failures.append(f"{name}.pcap_authentication must be an object")
    else:
        _require_value(pcap, "pcap_hash_source_must_be_explicitly_bound", True, f"{name}.pcap_authentication", failures)
        _require_value(pcap, "required_hash_field", "pcap_sha256", f"{name}.pcap_authentication", failures)

    cleanup = schema.get("post_cleanup")
    if not isinstance(cleanup, dict):
        failures.append(f"{name}.post_cleanup must be an object")
    else:
        required_values = cleanup.get("required_values")
        if required_values != {
            "audit_baseline_restored_after_r6": True,
            "AUDIT_BASELINE_RESTORED_AFTER_R6": "YES",
        }:
            failures.append(f"{name}.post_cleanup.required_values must require restored baseline")

    consumer_boundary = schema.get("consumer_boundary")
    if not isinstance(consumer_boundary, dict):
        failures.append(f"{name}.consumer_boundary must be an object")
    else:
        _require_value(
            consumer_boundary,
            "provx_r7r1_adapter_invocation",
            "PROHIBITED_IN_THIS_PHASE",
            f"{name}.consumer_boundary",
            failures,
        )


def _validate_fail_closed_conditions(package: Path, failures: list[str]) -> None:
    name = "FAIL_CLOSED_CONDITIONS.json"
    document = _read_json(package / name, failures)
    if document is None:
        return
    _require_value(document, "default_decision", "BLOCKED", name, failures)
    conditions = document.get("conditions")
    if not isinstance(conditions, list):
        failures.append(f"{name}.conditions must be a list")
        return
    identifiers: list[str] = []
    for condition in conditions:
        if not isinstance(condition, dict):
            failures.append(f"{name}.conditions entries must be objects")
            continue
        identifier = condition.get("id")
        if not isinstance(identifier, str):
            failures.append(f"{name}.conditions entry has invalid id")
            continue
        identifiers.append(identifier)
        if condition.get("decision") != "BLOCKED":
            failures.append(f"{name}.conditions[{identifier}].decision must be BLOCKED")
        if not isinstance(condition.get("condition"), str) or not condition["condition"]:
            failures.append(f"{name}.conditions[{identifier}].condition must be nonempty")
    _require_members(identifiers, REQUIRED_FAIL_CLOSED_IDS, f"{name}.conditions ids", failures)


def _validate_documentation(package: Path, failures: list[str]) -> None:
    _require_text(
        package / "EXECUTION_BOUNDARY.md",
        (
            "This package is preparation only.",
            "No privileged command",
            "No R6R4 artifact is edited.",
            "No PROVX-R7R1 adapter or frozen encoder source is edited or invoked.",
            "PRIVILEGED_RUNTIME_SMOKE_EXECUTED = NO",
            "FILE_READ_OR_WRITE_RUNTIME_CLOSURE = NOT_PROVEN",
            "STOP = true",
        ),
        failures,
    )
    _require_text(
        package / "EVIDENCE_COLLECTION_REQUIREMENTS.md",
        (
            "separate from this package",
            "AUDIT_FILESYSTEM_PERMISSION_FILTER",
            "`SYSCALL` and `PATH`",
            "zero audit loss and backlog",
            "PCAP hash-source artifact",
            "preparation package must never be cited as runtime evidence",
        ),
        failures,
    )
    _require_text(
        package / "INDEPENDENT_REVIEW_PACKAGE.md",
        (
            "This is a static preparation package",
            "PASS_STATIC_PREPARATION_ONLY",
            "FILE_READ_OR_WRITE_RUNTIME_CLOSURE = NOT_PROVEN",
            "After the independent static review, stop.",
        ),
        failures,
    )


def _remove_stale_manifest(package: Path) -> None:
    manifest = package / MANIFEST_FILE
    if manifest.is_file() or manifest.is_symlink():
        manifest.unlink()


def _write_manifest(package: Path, contract: dict[str, Any], report: dict[str, Any]) -> None:
    upstream = contract["upstream_authentication"]
    manifest = {
        "schema": "MININET_E1C_R6R4_PRIVILEGED_RUNTIME_SMOKE_PREPARATION_MANIFEST_V1",
        "status": "PASS_STATIC_PREPARATION_ONLY",
        "package_mode": "STATIC_PREPARATION_AND_REVIEW_ONLY",
        "validated_on": contract["prepared_on"],
        "phase_input": contract["phase_input"],
        "validation": {
            "validator": "validate_runtime_smoke_preparation.py",
            "status": report["status"],
            "failure_count": 0,
            "checked_package_files": sorted(REQUIRED_PACKAGE_FILES),
            "upstream_sha256": {
                descriptor["path"]: descriptor["sha256"]
                for descriptor in upstream.values()
            },
        },
        "PRIVILEGED_RUNTIME_SMOKE_EXECUTED": "NO",
        "FILE_READ_OR_WRITE_RUNTIME_CLOSURE": "NOT_PROVEN",
        "FORMAL_1796_EXPERIMENT_EXECUTED": "NO",
        "R6R4_ARTIFACTS_MODIFIED": "NO",
        "PROVX_R7R1_ADAPTER_MODIFIED_OR_INVOKED": "NO",
        "RUNTIME_EVIDENCE_GENERATED": "NO",
        "STOP": True,
        "next_action": "HUMAN_REVIEW_OF_STATIC_PREPARATION_PACKAGE",
    }
    temporary = package / f".{MANIFEST_FILE}.tmp"
    try:
        temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(package / MANIFEST_FILE)
    finally:
        temporary.unlink(missing_ok=True)


def validate_package(
    package: Path,
    materialize: bool = False,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """Return PASS only for a complete static package; materialize only on PASS."""

    package = package.resolve()
    source_root = repository_root.resolve() if repository_root is not None else _derive_repository_root(package)
    failures: list[str] = []

    _validate_package_contents(package, failures)
    contract = _validate_contract(package, source_root, failures)
    _validate_receipt_schema(package, failures)
    _validate_fail_closed_conditions(package, failures)
    _validate_documentation(package, failures)

    report: dict[str, Any] = {
        "status": "PASS" if not failures else "BLOCKED",
        "package": str(package),
        "repository_root": str(source_root) if source_root is not None else None,
        "failures": failures,
    }
    if failures:
        _remove_stale_manifest(package)
        return report
    if materialize:
        if contract is None:
            report["status"] = "BLOCKED"
            report["failures"] = ["contract is unavailable for manifest materialization"]
            _remove_stale_manifest(package)
            return report
        try:
            _write_manifest(package, contract, report)
        except OSError as error:
            _remove_stale_manifest(package)
            report["status"] = "BLOCKED"
            report["failures"] = [f"manifest materialization failed: {error}"]
            return report
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--materialize", action="store_true")
    args = parser.parse_args(argv)
    report = validate_package(args.package, args.materialize, args.repository_root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
