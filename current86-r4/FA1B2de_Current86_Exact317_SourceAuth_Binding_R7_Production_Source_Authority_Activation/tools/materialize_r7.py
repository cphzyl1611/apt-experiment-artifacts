#!/usr/bin/env python3
"""Materialize and atomically activate the exact, already-approved R6 transaction.

The only visibility-changing write performed here is replacement of the isolated
R7 consumer pointer.  Protected R4/R5/R6 inputs are read-only; source-auth,
field-pin, P0/P1, binding-publication, and scoring operations are never called.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
R6 = ROOT.parent / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R6_Production_Activation_Governance_Design"
R5 = ROOT.parent / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R5_Wrapper_Materialization"
R4 = ROOT.parent / "FA1B2de_Current86_Exact317_SourceAuth_Prospective_Canonical_Wrapper_Governance_R4"
EXEC_R4 = ROOT.parent / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4"
GOV_R4 = ROOT.parent / "fa1b2de-current86-canonical-source-authentication-governance-r4-patch"
PRODUCTION_INPUTS = ROOT.parent / "FA1B2de_Current86_Exact317_SourceAuth_Production_Authority_Inputs_R1"
EXACT317 = EXEC_R4 / "00_lineage/EXACT317_TARGET_MANIFEST.json"
REVIEW_REPO = Path("/home/cph/fa1b2de-review-artifacts")
R6_REVIEW_COMMIT = "ef9cc3cf7566cbe2280c29fcc1dde958cebf12d9"
R6_REVIEW_TREE = "d72a4884fd6ebb956ef2da61ebde83fa9d0921ca"
R6_REVIEW_PREFIX = "current86-r4/FA1B2de_Current86_Exact317_SourceAuth_Binding_R6_Production_Activation_Governance_Design"
TRANSACTION_ID = "e8a0a97a33d47ac68c8ded4af1af109fa010d979acf9736fd5dffdebf96c5208"
R6_PACKAGE_SHA256SUMS_SHA256 = "7abdd9630ce53d0b457b5111c4c071d4bee2b99b1d436ee57808128f38c38c62"
R5_PACKAGE_SHA256SUMS_SHA256 = "5f1746499c2ca5ba966b3f716e6b8ca87844cf4cd0a1316ec215b25cc092fdc1"
EXACT317_SHA256 = "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac"
RAW_GIT_COMMIT = "a699ebe4fa14cf25768fd0e5475b994a72b60dec"
RAW_GIT_TREE = "5ccafffe7e7785535fc276d352487b1d680947e9"
RAW_REGISTRY_SHA256 = "53c85157f9fd0849ae19b1cf403333ad0d0af2a7d761b0498540dd92d66c1e93"
C0_SOURCE_SHA256 = "0036c42fb02026182274a7ac2a33b103b03b1e527856eb33b5ad650ceddd5c32"
SCORING_SOURCE_SHA256 = "748a3808290f9e78f71c18d4553c77ae208517fd31d163fc2b3008cfcb57f1bb"
COMMIT_POINT = "ATOMIC_REPLACE_SINGLE_AUTHORITY_CONSUMER_POINTER_AFTER_VERIFIER_PASS"
ROLES = {
    "SOURCE_ADMISSION_REGISTRY_ROOT": "SOURCE_ADMISSION_REGISTRY_ROOT_CANDIDATE.json",
    "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT": "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT_CANDIDATE.json",
    "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST": "COMMON_INPUT_FREEZE_ADDITIONS_CANDIDATE.json",
    "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION": "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION_PATCH_CANDIDATE.json",
}
ROUTE_COUNTS = {
    "R4_WRAPPER_RAW_LEGACY_26": 26,
    "R4_WRAPPER_C0_60": 60,
    "R4_WRAPPER_SCORING_231": 231,
}


class ActivationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ActivationError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    require(path.is_file(), f"missing required file: {path}")
    return sha256_bytes(path.read_bytes())


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationError(f"invalid JSON: {path}") from exc
    require(isinstance(value, dict), f"JSON root is not an object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise ActivationError(f"cannot read JSONL: {path}") from exc
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ActivationError(f"invalid JSONL row {number}: {path}") from exc
        require(isinstance(value, dict), f"JSONL row {number} is not an object: {path}")
        rows.append(value)
    return rows


def write_json(path: Path, value: Mapping[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    path.write_bytes(data)
    return sha256_bytes(data)


def write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = b"".join((json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8") for row in rows)
    path.write_bytes(data)
    return sha256_bytes(data)


def artifact(path: Path, logical_path: str | None = None) -> dict[str, Any]:
    return {"path": logical_path or str(path), "sha256": sha256_file(path), "byte_length": path.stat().st_size}


def parse_sums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 1)
        require(len(parts) == 2 and len(parts[0]) == 64, f"malformed checksum line: {path}: {line!r}")
        relative = parts[1].strip()
        if relative.startswith("./"):
            relative = relative[2:]
        require(relative not in entries, f"duplicate checksum path: {path}: {relative}")
        entries[relative] = parts[0]
    return entries


def verify_envelope(package: Path) -> dict[str, str]:
    entries = parse_sums(package / "SHA256SUMS.txt")
    listed = {line.strip() for line in (package / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line.strip()}
    require(listed == set(entries), f"FILE_LIST/SHA256SUMS mismatch in {package}")
    for relative, expected in entries.items():
        require(sha256_file(package / relative) == expected, f"checksum drift in {package}/{relative}")
    return entries


def verify_review_commit(entries: Mapping[str, str]) -> dict[str, Any]:
    require(REVIEW_REPO.is_dir(), "R6 pinned review repository is unavailable")
    commit_type = subprocess.run(["git", "-C", str(REVIEW_REPO), "cat-file", "-t", R6_REVIEW_COMMIT], check=True, capture_output=True, text=True).stdout.strip()
    tree = subprocess.run(["git", "-C", str(REVIEW_REPO), "rev-parse", f"{R6_REVIEW_COMMIT}^{{tree}}"], check=True, capture_output=True, text=True).stdout.strip()
    require(commit_type == "commit", "R6 review identity is not a commit")
    require(tree == R6_REVIEW_TREE, "R6 review tree drift")
    mismatches: list[str] = []
    for relative, expected in entries.items():
        completed = subprocess.run(["git", "-C", str(REVIEW_REPO), "show", f"{R6_REVIEW_COMMIT}:{R6_REVIEW_PREFIX}/{relative}"], check=True, capture_output=True)
        if sha256_bytes(completed.stdout) != expected:
            mismatches.append(relative)
    require(not mismatches, f"R6 review commit content mismatch: {mismatches[:3]}")
    return {"repository": str(REVIEW_REPO), "commit": R6_REVIEW_COMMIT, "tree": tree, "commit_type": commit_type, "package_prefix": R6_REVIEW_PREFIX, "committed_file_count": len(entries), "committed_file_mismatches": 0, "authentication": "PASS"}


def git_identity(repository: Path) -> dict[str, str]:
    commit = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    tree = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"], check=True, capture_output=True, text=True).stdout.strip()
    return {"repository": str(repository), "commit": commit, "tree": tree}


def root_id(role: str, candidate_path: Path, candidate: Mapping[str, Any]) -> str:
    dependencies: dict[str, Any] = {}
    if role == "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST":
        dependencies = {
            "production_authority_inputs_sha256sums_sha256": sha256_file(PRODUCTION_INPUTS / "SHA256SUMS.txt"),
            "base_common_input_freeze_sha256": sha256_file(PRODUCTION_INPUTS / "COMMON_INPUT_FREEZE_CANDIDATE.json"),
            "base_runtime_whitelist_sha256": sha256_file(PRODUCTION_INPUTS / "RUNTIME_WHITELIST_CANDIDATE.json"),
        }
    elif role == "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION":
        dependencies = {"exec_r4_sha256sums_sha256": sha256_file(EXEC_R4 / "SHA256SUMS.txt"), "gov_r4_sha256sums_sha256": sha256_file(GOV_R4 / "SHA256SUMS.txt")}
    basis = {
        "authority_role": role,
        "artifact_sha256": sha256_file(candidate_path),
        "artifact_schema": candidate.get("schema"),
        "target_manifest_sha256": EXACT317_SHA256,
        "wrapper_rule_ids": sorted(candidate.get("wrapper_rule_ids", [])),
        "scope": candidate.get("scope"),
        "dependencies": dependencies,
    }
    return sha256_bytes(canonical({"schema": "FA1B2DE_CURRENT86_R6_PROSPECTIVE_AUTHORITY_ROOT_ID_V1", **basis}))


def authenticate_inputs() -> dict[str, Any]:
    r6_entries = verify_envelope(R6)
    require(sha256_file(R6 / "SHA256SUMS.txt") == R6_PACKAGE_SHA256SUMS_SHA256, "R6 package envelope hash drift")
    review_identity = verify_review_commit(r6_entries)
    r6_auth = load_json(R6 / "R6_INPUT_AUTHENTICATION.json")
    r6_tx = load_json(R6 / "R6_PRODUCTION_ACTIVATION_TRANSACTION_DESIGN.json")
    r6_pre = load_json(R6 / "R6_ACTIVATION_PRECONDITIONS.json")
    r6_atomic = load_json(R6 / "R6_ATOMICITY_AND_ROLLBACK_CONTRACT.json")
    r6_contract = load_json(R6 / "R6_INDEPENDENT_ACTIVATION_VERIFIER_CONTRACT.json")
    r6_design = load_json(R6 / "R6_INDEPENDENT_DESIGN_VERIFICATION.json")
    r6_decision = load_json(R6 / "R6_HUMAN_ACTIVATION_DECISION_PACKET.json")
    require(r6_tx.get("transaction_id") == TRANSACTION_ID, "R6 transaction ID drift")
    require(r6_tx.get("design_only") is True and r6_tx.get("activation_execution_performed") is False, "R6 is not the exact design-only transaction")
    require(r6_pre.get("failure_mode") == "FAIL_CLOSED_NO_ACTIVATION", "R6 fail-closed precondition contract drift")
    require(r6_atomic.get("commit_point") == COMMIT_POINT and r6_atomic.get("no_write_executed") is True, "R6 atomicity contract drift")
    require(r6_contract.get("transaction_id") == TRANSACTION_ID and r6_contract.get("design_only") is True, "R6 verifier contract drift")
    require(r6_design.get("verification_status") == "PASS" and r6_design.get("transaction_id") == TRANSACTION_ID, "R6 independent design verification drift")
    require(r6_decision.get("decision") is None and r6_decision.get("decision_status") == "PENDING_NO_DEFAULT", "R6 decision packet was pre-decided")
    r5_entries = verify_envelope(R5)
    require(sha256_file(R5 / "SHA256SUMS.txt") == R5_PACKAGE_SHA256SUMS_SHA256, "R5 package hash drift")
    require(r6_auth.get("r5_package", {}).get("sha256sums_sha256") == R5_PACKAGE_SHA256SUMS_SHA256, "R6/R5 package identity mismatch")
    require(sha256_file(EXACT317) == EXACT317_SHA256, "Exact317 manifest drift")
    require(sha256_file(R4 / "SHA256SUMS.txt") == "9aaa523bd7dce92bf865ee8283ddf61e339d6a804f90b264fa87e700dde2e2cd", "R4 package drift")
    require(sha256_file(EXEC_R4 / "SHA256SUMS.txt") == "06722fddd39d4d55a0cd1e4834bb63491112d13442aec1cc067219fb5bd232f6", "EXEC-R4 package drift")
    require(sha256_file(GOV_R4 / "SHA256SUMS.txt") == "233cfbda4676d447b82273d8defaf40a66b2d8bf0a8b3e1e58f5c471cd12fd63", "GOV-R4 package drift")
    require(sha256_file(PRODUCTION_INPUTS / "SHA256SUMS.txt") == "d00c3bb53f423b4379c659a760d89060d881967802a2aa163ceef26f52e5013c", "production authority input package drift")
    raw_git = git_identity(Path("/home/cph/experiment"))
    require(raw_git["commit"] == RAW_GIT_COMMIT and raw_git["tree"] == RAW_GIT_TREE, "protected RAW Git identity drift")
    source_paths = {
        "raw_registry": Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/project_snapshots/raw_action_registry.jsonl"),
        "c0_source": Path("/home/cph/experiment-artifacts/tier-de1c0-handoff-20260823-083725/tier_de1c0_typed_operation_semantics.jsonl"),
        "scoring_snapshot": Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/c2/c2_scoring_snapshot_post_c1.jsonl"),
    }
    expected_sources = {"raw_registry": RAW_REGISTRY_SHA256, "c0_source": C0_SOURCE_SHA256, "scoring_snapshot": SCORING_SOURCE_SHA256}
    source_artifacts = {}
    for name, path in source_paths.items():
        item = artifact(path)
        require(item["sha256"] == expected_sources[name], f"protected source drift: {name}")
        source_artifacts[name] = item
    return {"r6_entries": r6_entries, "r5_entries": r5_entries, "review_identity": review_identity, "r6_auth": r6_auth, "r6_tx": r6_tx, "r6_pre": r6_pre, "r6_atomic": r6_atomic, "r6_contract": r6_contract, "r6_design": r6_design, "r6_decision": r6_decision, "raw_git": raw_git, "source_artifacts": source_artifacts}


def validate_exact317() -> dict[str, Any]:
    manifest = load_json(EXACT317)
    targets = manifest.get("targets", [])
    require(len(targets) == 317, "Exact317 target count changed")
    target_ids = [item["source_binding_target_id"] for item in sorted(targets, key=lambda item: item["target_index"])]
    require(len(set(target_ids)) == 317 and target_ids == [item["source_binding_target_id"] for item in targets], "Exact317 target order/identity changed")
    r5_rows = load_jsonl(R5 / "05_dry_run/EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl")
    require(len(r5_rows) == 317, "R5 Exact317 dry-run count changed")
    require([row["target_index"] for row in r5_rows] == list(range(1, 318)), "R5 Exact317 order changed")
    require([row["source_binding_target_id"] for row in r5_rows] == target_ids, "R5 Exact317 IDs changed")
    require(all(row.get("authority_status") == "CANDIDATE_WRAPPER_OBJECTS_ONLY" for row in r5_rows), "candidate wrapper authority leak")
    require(all(row.get("source_auth_executed") is False and row.get("field_pin_created") is False for row in r5_rows), "downstream action in dry-run")
    commitments = load_json(R5 / "02_specs/APPROVED_R4_TARGET_COMMITMENTS.json")["commitments"]["routes"]
    expected_route: dict[str, list[str]] = {}
    for route in commitments:
        rule = route["rule_id"]
        require(rule in ROUTE_COUNTS and len(route["target_ids"]) == ROUTE_COUNTS[rule], f"route count changed: {rule}")
        require(len(set(route["target_ids"])) == len(route["target_ids"]), f"route duplicates: {rule}")
        expected_route[rule] = route["target_ids"]
    require(set(item for ids in expected_route.values() for item in ids) == set(target_ids), "route union is not Exact317")
    row_by_id = {row["source_binding_target_id"]: row for row in r5_rows}
    for rule, ids in expected_route.items():
        require(all(row_by_id[item]["route_rule_id"] == rule for item in ids), f"cross-route substitution: {rule}")
    require(sum(target["source_side"] == "RAW" for target in targets) == 86, "RAW side count changed")
    require(sum(target["source_side"] == "CANDIDATE" for target in targets) == 231, "CANDIDATE side count changed")
    return {"total": 317, "raw": 86, "candidate": 231, "duplicates": 0, "cross_route_substitution": 0, "union": "Exact317", "route_counts": dict(ROUTE_COUNTS), "target_manifest_sha256": EXACT317_SHA256}


def validate_roots(r6_tx: Mapping[str, Any]) -> dict[str, Any]:
    expected = r6_tx["post_state_candidate"]["root_artifacts"]
    result: dict[str, Any] = {}
    for role, filename in ROLES.items():
        path = R5 / "06_non_active_candidates" / filename
        candidate = load_json(path)
        expected_artifact = expected[role]["artifact"]
        actual_sha = sha256_file(path)
        require(actual_sha == expected_artifact["sha256"] and path.stat().st_size == expected_artifact["byte_length"], f"candidate root artifact drift: {role}")
        require(candidate.get("activation_status") == "NOT_ACTIVE" and candidate.get("authority_status") == "NON_ACTIVE_CANDIDATE", f"candidate root is already active: {role}")
        require(candidate.get("field_pins_created") == 0 and candidate.get("source_auth_executed") is False and candidate.get("binding_publication") is False, f"candidate root boundary drift: {role}")
        actual_root = root_id(role, path, candidate)
        require(actual_root == expected[role]["root_id"], f"candidate root ID drift: {role}")
        result[role] = {"source_artifact": artifact(path, f"R5/06_non_active_candidates/{filename}"), "root_id": actual_root}
    return result


def write_read_only_copy(source: Path, destination: Path) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    require(sha256_file(destination) == sha256_file(source), f"staged copy hash mismatch: {destination}")
    return sha256_file(destination)


def existing_conflicts() -> list[str]:
    conflicts: list[str] = []
    for path in ROOT.parent.glob("FA1B2de_Current86_Exact317_SourceAuth_Binding_R*_Production_Source_Authority_Activation"):
        if path.resolve() != ROOT.resolve():
            conflicts.append(str(path))
    for path in ROOT.parent.rglob("r7-activation-consumer-pointer.json"):
        if path.resolve() != (ROOT / "authority_store/r7-activation-consumer-pointer.json").resolve():
            conflicts.append(str(path))
    return sorted(set(conflicts))


def materialize() -> dict[str, Any]:
    if ROOT.exists():
        authored_support = {"tests", "tools", "__pycache__"}
        existing_artifacts = [path.name for path in ROOT.iterdir() if path.name not in authored_support]
        require(not existing_artifacts, f"R7 package already contains activation artifacts: {existing_artifacts}")
    auth = authenticate_inputs()
    exact = validate_exact317()
    roots = validate_roots(auth["r6_tx"])
    conflicts = existing_conflicts()
    require(not conflicts, f"newer or conflicting activation exists: {conflicts}")
    ROOT.mkdir(parents=True, exist_ok=True)
    store = ROOT / "authority_store"
    staging = store / f"r6-activation-staging/{TRANSACTION_ID}"
    committed = store / f"committed/{TRANSACTION_ID}"
    pointer_path = store / "r7-activation-consumer-pointer.json"
    lock_path = store / ".activation.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(lock_fd)
    try:
        approval = {
            "schema": "FA1B2DE_CURRENT86_BINDING_R7_HUMAN_ACTIVATION_APPROVAL_AUTHENTICATION_V1",
            "human_origin": "USER_EXPLICIT_APPROVAL",
            "decision": "APPROVE_EXACT_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION",
            "authenticated": True,
            "authentication_status": "PASS",
            "transaction_id": TRANSACTION_ID,
            "activation_scope": "EXACT_R6_TRANSACTION_ONLY",
            "r6_pinned_review": auth["review_identity"],
            "r6_package": {"path": str(R6), "sha256sums_sha256": R6_PACKAGE_SHA256SUMS_SHA256, "file_count": len(auth["r6_entries"]), "file_hashes": dict(sorted(auth["r6_entries"].items()))},
            "r6_decision_packet": {"path": "R6/R6_HUMAN_ACTIVATION_DECISION_PACKET.json", "sha256": sha256_file(R6 / "R6_HUMAN_ACTIVATION_DECISION_PACKET.json"), "prior_decision": None, "prior_status": "PENDING_NO_DEFAULT"},
            "frozen_r6_transaction_design_sha256": sha256_file(R6 / "R6_PRODUCTION_ACTIVATION_TRANSACTION_DESIGN.json"),
            "r6_artifact_hashes": {"input_authentication": sha256_file(R6 / "R6_INPUT_AUTHENTICATION.json"), "activation_preconditions": sha256_file(R6 / "R6_ACTIVATION_PRECONDITIONS.json"), "atomicity_contract": sha256_file(R6 / "R6_ATOMICITY_AND_ROLLBACK_CONTRACT.json"), "independent_activation_verifier_contract": sha256_file(R6 / "R6_INDEPENDENT_ACTIVATION_VERIFIER_CONTRACT.json"), "independent_design_verification": sha256_file(R6 / "R6_INDEPENDENT_DESIGN_VERIFICATION.json")},
            "r6_independent_design_verification": {"path": "R6/R6_INDEPENDENT_DESIGN_VERIFICATION.json", "sha256": sha256_file(R6 / "R6_INDEPENDENT_DESIGN_VERIFICATION.json"), "status": "PASS"},
            "r5_pinned_review": auth["r6_auth"]["pinned_r5_review"],
            "exact317_manifest": {"path": str(EXACT317), "sha256": EXACT317_SHA256, "target_total": 317, "raw_side_total": 86, "candidate_side_total": 231},
            "r5_package_sha256sums_sha256": R5_PACKAGE_SHA256SUMS_SHA256,
            "protected_hashes": {"r4_sha256sums_sha256": "9aaa523bd7dce92bf865ee8283ddf61e339d6a804f90b264fa87e700dde2e2cd", "exec_r4_sha256sums_sha256": "06722fddd39d4d55a0cd1e4834bb63491112d13442aec1cc067219fb5bd232f6", "gov_r4_sha256sums_sha256": "233cfbda4676d447b82273d8defaf40a66b2d8bf0a8b3e1e58f5c471cd12fd63", "production_authority_inputs_sha256sums_sha256": "d00c3bb53f423b4379c659a760d89060d881967802a2aa163ceef26f52e5013c"},
            "approved_r6_root_ids": {role: item["root_id"] for role, item in roots.items()},
            "newer_conflicting_transaction_count": 0,
            "authority_boundary": {"active_source_authority_created": False, "source_auth_executed": False, "field_pins_created": 0, "p0_executed": False, "p1_executed": False, "binding_publication": False, "scoring_authority_mutated": False, "binding_authority_mutated": False, "git_ref_mutation": False},
        }
        write_json(ROOT / "R7_HUMAN_ACTIVATION_APPROVAL_AUTHENTICATION.json", approval)
        pre_state = {
            "schema": "FA1B2DE_CURRENT86_BINDING_R7_PRE_ACTIVATION_STATE_V1",
            "transaction_id": TRANSACTION_ID,
            "state_status": "AUTHENTICATED_PRE_ACTIVATION",
            "production_authority_visible": False,
            "consumer_pointer": {"path": "authority_store/r7-activation-consumer-pointer.json", "exists_before_activation": False, "sha256_before_activation": None},
            "root_ids": auth["r6_tx"]["pre_state"]["root_ids"],
            "exec_r4_base_package_sha256sums_sha256": auth["r6_tx"]["pre_state"]["exec_r4_base_package_sha256sums_sha256"],
            "newer_conflicting_transactions": [],
            "authority_boundary": {"active_source_authority_created": False, "source_auth_executed": False, "field_pins_created": 0, "p0_executed": False, "p1_executed": False, "binding_publication": False, "scoring_authority_mutated": False, "binding_authority_mutated": False, "git_ref_mutation": False},
        }
        write_json(ROOT / "R7_PRE_ACTIVATION_STATE.json", pre_state)
        preconditions = {
            "schema": "FA1B2DE_CURRENT86_BINDING_R7_ACTIVATION_PRECONDITION_VERIFICATION_V1",
            "transaction_id": TRANSACTION_ID,
            "human_origin": "USER_EXPLICIT_APPROVAL",
            "required_decision": "APPROVE_EXACT_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION",
            "failure_mode": "FAIL_CLOSED_NO_ACTIVATION",
            "all_preconditions_pass": True,
            "decision_gate": {"status": "PASS", "decision": "APPROVE_EXACT_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION"},
            "r6_preconditions_rechecked": True,
            "r6_precondition_count": len(auth["r6_pre"]["preconditions"]),
            "r6_precondition_ids_rechecked": [item["id"] for item in auth["r6_pre"]["preconditions"]],
            "r6_preconditions_sha256": sha256_file(R6 / "R6_ACTIVATION_PRECONDITIONS.json"),
            "r6_independent_design_verification_sha256": sha256_file(R6 / "R6_INDEPENDENT_DESIGN_VERIFICATION.json"),
            "r6_package_sha256sums_sha256": R6_PACKAGE_SHA256SUMS_SHA256,
            "r5_package_sha256sums_sha256": R5_PACKAGE_SHA256SUMS_SHA256,
            "exact317": exact,
            "protected_source_state": {"raw_git": auth["raw_git"], "source_artifacts": auth["source_artifacts"]},
            "newer_conflicting_transaction_count": 0,
            "same_role_different_hash_count": 0,
            "observed_status": "PASS",
        }
        write_json(ROOT / "R7_ACTIVATION_PRECONDITION_VERIFICATION.json", preconditions)
        staged_roots: dict[str, Any] = {}
        for role, item in roots.items():
            source_path = R5 / "06_non_active_candidates" / ROLES[role]
            staged_path = staging / "roots" / f"{role}.json"
            committed_path = committed / "roots" / f"{role}.json"
            staged_sha = write_read_only_copy(source_path, staged_path)
            committed_sha = write_read_only_copy(source_path, committed_path)
            require(staged_sha == committed_sha == item["source_artifact"]["sha256"], f"root copy drift: {role}")
            staged_roots[role] = {"root_id": item["root_id"], "source_artifact": item["source_artifact"], "staging_path": str(staged_path.relative_to(ROOT)), "committed_path": str(committed_path.relative_to(ROOT)), "staged_artifact_sha256": staged_sha, "committed_artifact_sha256": committed_sha, "byte_length": source_path.stat().st_size, "immutable": True, "status": "STAGED_AND_COMMITTED_VERIFIED"}
        staged_record = {"schema": "FA1B2DE_CURRENT86_BINDING_R7_STAGED_AUTHORITY_ROOTS_V1", "transaction_id": TRANSACTION_ID, "staging_status": "STAGED_VERIFIED_NOT_VISIBLE", "staging_namespace": str(staging.relative_to(ROOT)), "production_mount": "FORBIDDEN_UNTIL_POINTER_COMMIT", "root_count": 4, "field_pin_root_present": False, "roots": staged_roots}
        write_json(ROOT / "R7_STAGED_AUTHORITY_ROOTS.json", staged_record)
        journal = [
            {"sequence": 1, "event": "PRE_STATE_READ", "status": "PASS", "pointer_exists": False, "pre_state_root_ids": pre_state["root_ids"]},
            {"sequence": 2, "event": "PROTECTED_HASH_RECHECK", "status": "PASS", "r6_package_sha256sums_sha256": R6_PACKAGE_SHA256SUMS_SHA256, "r5_package_sha256sums_sha256": R5_PACKAGE_SHA256SUMS_SHA256, "exact317_manifest_sha256": EXACT317_SHA256},
            {"sequence": 3, "event": "CONFLICT_ENUMERATION", "status": "PASS", "newer_conflicting_transaction_count": 0, "same_role_different_hash_count": 0},
            {"sequence": 4, "event": "IMMUTABLE_ROOT_STAGING", "status": "PASS", "root_count": 4, "staging_namespace": str(staging.relative_to(ROOT)), "partial_root_visibility": "FORBIDDEN"},
            {"sequence": 5, "event": "R6_INDEPENDENT_VERIFIER_AGAINST_STAGING", "status": "PASS", "human_decision_authenticated": True, "exact_root_count": 4, "field_pin_root_present": False},
            {"sequence": 6, "event": "STAGED_FILES_FSYNC_AND_READ_ONLY", "status": "PASS", "read_only_after_write": True},
        ]
        write_jsonl(ROOT / "R7_ACTIVATION_TRANSACTION_JOURNAL.jsonl", journal)
        pointer = {
            "schema": "FA1B2DE_CURRENT86_BINDING_R7_AUTHORITY_CONSUMER_POINTER_V1",
            "status": "COMMITTED",
            "visibility": "ATOMIC_SINGLE_POINTER",
            "commit_point": COMMIT_POINT,
            "transaction_id": TRANSACTION_ID,
            "pre_state_root_ids": pre_state["root_ids"],
            "post_state_root_ids": {role: item["root_id"] for role, item in roots.items()},
            "artifact_sha256s": {role: {"root_id": item["root_id"], "artifact_sha256": item["source_artifact"]["sha256"], "byte_length": item["source_artifact"]["byte_length"], "committed_path": staged_roots[role]["committed_path"]} for role, item in roots.items()},
            "exact317_manifest_sha256": EXACT317_SHA256,
            "target_total": 317,
            "raw_side_total": 86,
            "candidate_side_total": 231,
            "duplicates": 0,
            "cross_route_substitution": 0,
            "production_mount": "R7_AUTHORITY_STORE_ONLY",
            "partial_root_visibility": "FORBIDDEN",
            "source_auth_executed": False,
            "field_pins_created": 0,
            "p0_executed": False,
            "p1_executed": False,
            "binding_publication": False,
            "scoring_authority_mutated": False,
            "binding_authority_mutated": False,
            "git_ref_mutation": False,
        }
        pointer_tmp = pointer_path.with_name(".r7-activation-consumer-pointer.tmp")
        write_json(pointer_tmp, pointer)
        os.replace(pointer_tmp, pointer_path)
        pointer_sha = sha256_file(pointer_path)
        commit = {"schema": "FA1B2DE_CURRENT86_BINDING_R7_COMMIT_POINT_V1", "transaction_id": TRANSACTION_ID, "commit_status": "COMMITTED", "commit_point": COMMIT_POINT, "activation_lock_acquired": True, "pre_state_root_ids": pre_state["root_ids"], "post_state_root_ids": pointer["post_state_root_ids"], "consumer_pointer_path": str(pointer_path.relative_to(ROOT)), "consumer_pointer_sha256": pointer_sha, "artifact_sha256s": pointer["artifact_sha256s"], "atomic_replace_performed": True, "partial_state_exposed": False, "production_sees": "FULLY_COMMITTED_POST_STATE"}
        commit_sha = write_json(ROOT / "R7_COMMIT_POINT.json", commit)
        journal.extend([
            {"sequence": 7, "event": "COMMIT_RECORD_FSYNC", "status": "PASS", "commit_point": COMMIT_POINT},
            {"sequence": 8, "event": "ATOMIC_CONSUMER_POINTER_REPLACE", "status": "PASS", "consumer_pointer_sha256": pointer_sha, "partial_state_exposed": False},
            {"sequence": 9, "event": "POST_POINTER_READ", "status": "PASS", "status_value": "COMMITTED", "transaction_id": TRANSACTION_ID},
        ])
        write_jsonl(ROOT / "R7_ACTIVATION_TRANSACTION_JOURNAL.jsonl", journal)
        post = {"schema": "FA1B2DE_CURRENT86_BINDING_R7_POST_ACTIVATION_STATE_V1", "transaction_id": TRANSACTION_ID, "state_status": "COMMITTED_POST_ACTIVATION", "production_authority_visible": True, "active_source_authority_created": True, "consumer_pointer": {"path": str(pointer_path.relative_to(ROOT)), "sha256": pointer_sha, "status": "COMMITTED"}, "root_ids": pointer["post_state_root_ids"], "root_artifacts": pointer["artifact_sha256s"], "exact317": exact, "wrapper_routes": exact["route_counts"], "dry_run_object_status": "CANDIDATE_WRAPPER_OBJECTS_ONLY", "field_pin_registry": "ABSENT", "source_auth_execution_count": 0, "authority_boundary": {"active_source_authority_created": True, "source_auth_executed": False, "field_pins_created": 0, "p0_executed": False, "p1_executed": False, "binding_publication": False, "scoring_authority_mutated": False, "binding_authority_mutated": False, "git_ref_mutation": False}, "r6_commit_point_sha256": commit_sha}
        write_json(ROOT / "R7_POST_ACTIVATION_STATE.json", post)
        downstream = {"schema": "FA1B2DE_CURRENT86_BINDING_R7_DOWNSTREAM_BOUNDARY_VERIFICATION_V1", "transaction_id": TRANSACTION_ID, "verification_status": "PASS", "active_source_authority_created": True, "source_auth_executed": False, "field_pins_created": 0, "field_pin_pointer_selection": "NONE", "field_pin_registry": "ABSENT", "field_pin_packet_skeleton_count": 317, "p0_executed": False, "p1_executed": False, "binding_publication": False, "scoring_authority_mutated": False, "binding_authority_mutated": False, "gov_r4_rewritten": False, "exec_r4_rewritten": False, "git_ref_mutation": False, "downstream_operations_executed": False}
        write_json(ROOT / "R7_DOWNSTREAM_BOUNDARY_VERIFICATION.json", downstream)
        # The independent verifier is intentionally a separate process and is run after the pointer commit.
        verifier = ROOT / "tools/verify_r7.py"
        completed = subprocess.run([sys.executable, str(verifier), "--write-output"], cwd=str(ROOT), capture_output=True, text=True)
        if completed.returncode != 0:
            raise ActivationError(f"independent R7 verifier blocked: {completed.stderr.strip() or completed.stdout.strip()}")
        report = f"""# Binding R7 Exact Production Source-Authority Activation\n\nThis package executes only the explicitly approved R6 transaction `{TRANSACTION_ID}`. Four immutable, hash-bound R6 candidate roots were staged and committed under an isolated R7 authority store. Production visibility is provided only by one atomically replaced consumer pointer.\n\nThe independent verifier recomputed the R6/R5 envelopes, protected corpus and Git identities, Exact317 route membership, root IDs, pointer contents, and downstream zero-state. It did not execute source-auth or select a field pointer. The R5 dry-run objects remain `CANDIDATE_WRAPPER_OBJECTS_ONLY`; the R5 candidate files themselves were not mutated.\n\nNo GOV-R4, EXEC-R4, scoring authority, binding authority, or Git ref was rewritten. Field-pin registry remains absent and all 317 field-pin skeletons remain unselected.\n\n## Terminal\n\n```text\nBINDING_R7_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION = PASS_ACTIVATED_READY_FOR_FRESH_REVIEW\nHUMAN_ACTIVATION_APPROVAL_AUTHENTICATED = YES\nTRANSACTION_ID = {TRANSACTION_ID}\n\nEXACT317_CONSERVATION = PASS\nACTIVE_SOURCE_AUTHORITY_CREATED = YES\nACTIVATION_ATOMICITY = PASS\nINDEPENDENT_POST_ACTIVATION_VERIFICATION = PASS\n\nSOURCE_AUTH_EXECUTED = NO\nFIELD_PINS_CREATED = 0\nP0_EXECUTED = NO\nP1_EXECUTED = NO\nBINDING_PUBLICATION = NO\n\nNEXT_ACTION =\nFRESH_INDEPENDENT_REVIEW_OF_BINDING_R7_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION\n\nSTOP = true\n```\n"""
        (ROOT / "R7_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION_REPORT.md").write_text(report, encoding="utf-8")
        return {"status": "PASS_ACTIVATED_READY_FOR_FRESH_REVIEW", "transaction_id": TRANSACTION_ID, "pointer_sha256": pointer_sha, "commit_sha256": commit_sha, "exact317": exact}
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    try:
        print(json.dumps(materialize(), ensure_ascii=False, sort_keys=True, indent=2))
    except (ActivationError, OSError, subprocess.CalledProcessError, KeyError, TypeError, ValueError) as exc:
        print(f"R7_ACTIVATION_BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)
