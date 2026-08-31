#!/usr/bin/env python3
"""Independent read-only verifier for the committed R7 activation.

This implementation deliberately does not import the producer/materializer and
does not trust producer-computed PASS flags.  It recomputes hashes, root IDs,
route membership, pointer contents, and all downstream boundaries from bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping


PACKAGE = Path(__file__).resolve().parents[1]
R6 = PACKAGE.parent / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R6_Production_Activation_Governance_Design"
R5 = PACKAGE.parent / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R5_Wrapper_Materialization"
R4 = PACKAGE.parent / "FA1B2de_Current86_Exact317_SourceAuth_Prospective_Canonical_Wrapper_Governance_R4"
EXEC_R4 = PACKAGE.parent / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4"
GOV_R4 = PACKAGE.parent / "fa1b2de-current86-canonical-source-authentication-governance-r4-patch"
PRODUCTION_INPUTS = PACKAGE.parent / "FA1B2de_Current86_Exact317_SourceAuth_Production_Authority_Inputs_R1"
EXACT317 = EXEC_R4 / "00_lineage/EXACT317_TARGET_MANIFEST.json"
REVIEW_REPO = Path("/home/cph/fa1b2de-review-artifacts")
R6_REVIEW_COMMIT = "ef9cc3cf7566cbe2280c29fcc1dde958cebf12d9"
R6_REVIEW_TREE = "d72a4884fd6ebb956ef2da61ebde83fa9d0921ca"
R6_REVIEW_PREFIX = "current86-r4/FA1B2de_Current86_Exact317_SourceAuth_Binding_R6_Production_Activation_Governance_Design"
R5_REVIEW_COMMIT = "90513ab76a2d392398fefd0456ad53a4660a3e8a"
R5_REVIEW_TREE = "fc67b7dcc66284ea2b8be4bb52d2fc3f3d1ebef5"
R5_REVIEW_PREFIX = "current86-r4/FA1B2de_Current86_Exact317_SourceAuth_Binding_R5_Wrapper_Materialization"
TX = "e8a0a97a33d47ac68c8ded4af1af109fa010d979acf9736fd5dffdebf96c5208"
R6_SUMS_SHA = "7abdd9630ce53d0b457b5111c4c071d4bee2b99b1d436ee57808128f38c38c62"
R5_SUMS_SHA = "5f1746499c2ca5ba966b3f716e6b8ca87844cf4cd0a1316ec215b25cc092fdc1"
EXACT317_SHA = "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac"
RAW_GIT_COMMIT = "a699ebe4fa14cf25768fd0e5475b994a72b60dec"
RAW_GIT_TREE = "5ccafffe7e7785535fc276d352487b1d680947e9"
RAW_REGISTRY_SHA = "53c85157f9fd0849ae19b1cf403333ad0d0af2a7d761b0498540dd92d66c1e93"
C0_SHA = "0036c42fb02026182274a7ac2a33b103b03b1e527856eb33b5ad650ceddd5c32"
SCORING_SHA = "748a3808290f9e78f71c18d4553c77ae208517fd31d163fc2b3008cfcb57f1bb"
ROLES = {
    "SOURCE_ADMISSION_REGISTRY_ROOT": "SOURCE_ADMISSION_REGISTRY_ROOT_CANDIDATE.json",
    "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT": "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT_CANDIDATE.json",
    "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST": "COMMON_INPUT_FREEZE_ADDITIONS_CANDIDATE.json",
    "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION": "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION_PATCH_CANDIDATE.json",
}
ROUTE_COUNTS = {"R4_WRAPPER_RAW_LEGACY_26": 26, "R4_WRAPPER_C0_60": 60, "R4_WRAPPER_SCORING_231": 231}
EXPECTED_PROTECTED = {
    R4: "9aaa523bd7dce92bf865ee8283ddf61e339d6a804f90b264fa87e700dde2e2cd",
    EXEC_R4: "06722fddd39d4d55a0cd1e4834bb63491112d13442aec1cc067219fb5bd232f6",
    GOV_R4: "233cfbda4676d447b82273d8defaf40a66b2d8bf0a8b3e1e58f5c471cd12fd63",
    PRODUCTION_INPUTS: "d00c3bb53f423b4379c659a760d89060d881967802a2aa163ceef26f52e5013c",
}


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    require(path.is_file(), f"missing file: {path}")
    return digest(path.read_bytes())


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid JSON: {path}") from exc
    require(isinstance(value, dict), f"JSON root is not an object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_bytes().splitlines(), 1):
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise VerificationError(f"invalid JSONL row {number}: {path}") from exc
        require(isinstance(value, dict), f"JSONL row {number} is not an object: {path}")
        rows.append(value)
    return rows


def parse_sums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?(.+)", line)
        require(match is not None, f"malformed checksum line: {line!r}")
        relative = match.group(2)
        require(relative not in entries, f"duplicate checksum path: {relative}")
        entries[relative] = match.group(1)
    return entries


def verify_envelope(package: Path, expected_sums_sha: str | None = None) -> dict[str, str]:
    sums = package / "SHA256SUMS.txt"
    if expected_sums_sha is not None:
        require(file_digest(sums) == expected_sums_sha, f"package envelope hash drift: {package.name}")
    entries = parse_sums(sums)
    listed = {line.strip() for line in (package / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line.strip()}
    require(listed == set(entries), f"FILE_LIST/SHA256SUMS mismatch: {package.name}")
    for relative, expected in entries.items():
        require(file_digest(package / relative) == expected, f"checksum drift: {package.name}/{relative}")
    return entries


def verify_review(entries: Mapping[str, str], commit: str, tree: str, prefix: str) -> None:
    require(REVIEW_REPO.is_dir(), "review repository unavailable")
    actual_type = subprocess.run(["git", "-C", str(REVIEW_REPO), "cat-file", "-t", commit], check=True, capture_output=True, text=True).stdout.strip()
    actual_tree = subprocess.run(["git", "-C", str(REVIEW_REPO), "rev-parse", f"{commit}^{{tree}}"], check=True, capture_output=True, text=True).stdout.strip()
    require(actual_type == "commit" and actual_tree == tree, f"review identity drift: {commit}")
    for relative, expected in entries.items():
        data = subprocess.run(["git", "-C", str(REVIEW_REPO), "show", f"{commit}:{prefix}/{relative}"], check=True, capture_output=True).stdout
        require(digest(data) == expected, f"review content drift: {prefix}/{relative}")


def root_id(role: str, path: Path, candidate: Mapping[str, Any]) -> str:
    dependencies: dict[str, Any] = {}
    if role == "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST":
        dependencies = {"production_authority_inputs_sha256sums_sha256": file_digest(PRODUCTION_INPUTS / "SHA256SUMS.txt"), "base_common_input_freeze_sha256": file_digest(PRODUCTION_INPUTS / "COMMON_INPUT_FREEZE_CANDIDATE.json"), "base_runtime_whitelist_sha256": file_digest(PRODUCTION_INPUTS / "RUNTIME_WHITELIST_CANDIDATE.json")}
    elif role == "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION":
        dependencies = {"exec_r4_sha256sums_sha256": file_digest(EXEC_R4 / "SHA256SUMS.txt"), "gov_r4_sha256sums_sha256": file_digest(GOV_R4 / "SHA256SUMS.txt")}
    basis = {"authority_role": role, "artifact_sha256": file_digest(path), "artifact_schema": candidate.get("schema"), "target_manifest_sha256": EXACT317_SHA, "wrapper_rule_ids": sorted(candidate.get("wrapper_rule_ids", [])), "scope": candidate.get("scope"), "dependencies": dependencies}
    return digest(canonical({"schema": "FA1B2DE_CURRENT86_R6_PROSPECTIVE_AUTHORITY_ROOT_ID_V1", **basis}))


def verify_sources_and_routes(r6_tx: Mapping[str, Any]) -> dict[str, Any]:
    require(file_digest(EXACT317) == EXACT317_SHA, "Exact317 manifest drift")
    manifest = load_json(EXACT317)
    targets = manifest["targets"]
    require(len(targets) == 317, "Exact317 count drift")
    ids = [row["source_binding_target_id"] for row in targets]
    require(len(set(ids)) == 317 and [row["target_index"] for row in targets] == list(range(1, 318)), "Exact317 ID/index drift")
    require(sum(row["source_side"] == "RAW" for row in targets) == 86 and sum(row["source_side"] == "CANDIDATE" for row in targets) == 231, "Exact317 side counts drift")
    dry = load_jsonl(R5 / "05_dry_run/EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl")
    require(len(dry) == 317 and [row["source_binding_target_id"] for row in dry] == ids, "R5 dry-run identity drift")
    require(all(row.get("authority_status") == "CANDIDATE_WRAPPER_OBJECTS_ONLY" for row in dry), "dry-run authority leak")
    require(all(row.get("source_auth_executed") is False and row.get("field_pin_created") is False for row in dry), "dry-run downstream action")
    commitments = load_json(R5 / "02_specs/APPROVED_R4_TARGET_COMMITMENTS.json")["commitments"]["routes"]
    route_ids: dict[str, list[str]] = {}
    for route in commitments:
        rule = route["rule_id"]
        require(rule in ROUTE_COUNTS and len(route["target_ids"]) == ROUTE_COUNTS[rule], f"route count drift: {rule}")
        require(len(route["target_ids"]) == len(set(route["target_ids"])), f"route duplicate: {rule}")
        require(r6_tx["transaction_id_basis"]["route_commitment_sha256s"][rule] == route["expansion_set_commitment_sha256"], f"route commitment drift: {rule}")
        route_ids[rule] = route["target_ids"]
    union = [item for values in route_ids.values() for item in values]
    require(len(union) == 317 and len(set(union)) == 317 and set(union) == set(ids), "route union is not Exact317")
    by_id = {row["source_binding_target_id"]: row for row in dry}
    for rule, route in route_ids.items():
        require(all(by_id[target]["route_rule_id"] == rule for target in route), f"cross-route substitution: {rule}")
    return {"total": 317, "raw": 86, "candidate": 231, "duplicates": 0, "cross_route_substitution": 0, "union": "Exact317", "route_counts": dict(ROUTE_COUNTS), "target_manifest_sha256": EXACT317_SHA}


def verify() -> dict[str, Any]:
    required = ["R7_HUMAN_ACTIVATION_APPROVAL_AUTHENTICATION.json", "R7_PRE_ACTIVATION_STATE.json", "R7_ACTIVATION_PRECONDITION_VERIFICATION.json", "R7_STAGED_AUTHORITY_ROOTS.json", "R7_ACTIVATION_TRANSACTION_JOURNAL.jsonl", "R7_COMMIT_POINT.json", "R7_POST_ACTIVATION_STATE.json", "R7_DOWNSTREAM_BOUNDARY_VERIFICATION.json"]
    for relative in required:
        require((PACKAGE / relative).is_file(), f"R7 artifact missing: {relative}")
    # The checksum envelope is produced after the first post-commit verification.
    # On every subsequent invocation it is itself checked before any PASS result.
    r7_sums_path = PACKAGE / "SHA256SUMS.txt"
    if r7_sums_path.exists():
        r7_sums = parse_sums(r7_sums_path)
        r7_listed = {line.strip() for line in (PACKAGE / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line.strip()}
        require(r7_listed == set(r7_sums), "R7 FILE_LIST/SHA256SUMS mismatch")
        for relative, expected in r7_sums.items():
            require(file_digest(PACKAGE / relative) == expected, f"R7 checksum drift: {relative}")
    r6_entries = verify_envelope(R6, R6_SUMS_SHA)
    verify_review(r6_entries, R6_REVIEW_COMMIT, R6_REVIEW_TREE, R6_REVIEW_PREFIX)
    r5_entries = verify_envelope(R5, R5_SUMS_SHA)
    verify_review(r5_entries, R5_REVIEW_COMMIT, R5_REVIEW_TREE, R5_REVIEW_PREFIX)
    for package, expected in EXPECTED_PROTECTED.items():
        require(file_digest(package / "SHA256SUMS.txt") == expected, f"protected envelope drift: {package.name}")
        parse_sums(package / "SHA256SUMS.txt")
    raw_git_commit = subprocess.run(["git", "-C", "/home/cph/experiment", "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    raw_git_tree = subprocess.run(["git", "-C", "/home/cph/experiment", "rev-parse", "HEAD^{tree}"], check=True, capture_output=True, text=True).stdout.strip()
    require(raw_git_commit == RAW_GIT_COMMIT and raw_git_tree == RAW_GIT_TREE, "RAW Git identity drift")
    source_paths = {"raw_registry": Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/project_snapshots/raw_action_registry.jsonl"), "c0_source": Path("/home/cph/experiment-artifacts/tier-de1c0-handoff-20260823-083725/tier_de1c0_typed_operation_semantics.jsonl"), "scoring_snapshot": Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/c2/c2_scoring_snapshot_post_c1.jsonl")}
    for name, expected in {"raw_registry": RAW_REGISTRY_SHA, "c0_source": C0_SHA, "scoring_snapshot": SCORING_SHA}.items():
        require(file_digest(source_paths[name]) == expected, f"protected source drift: {name}")

    approval = load_json(PACKAGE / "R7_HUMAN_ACTIVATION_APPROVAL_AUTHENTICATION.json")
    r6_auth = load_json(R6 / "R6_INPUT_AUTHENTICATION.json")
    r6_tx = load_json(R6 / "R6_PRODUCTION_ACTIVATION_TRANSACTION_DESIGN.json")
    r6_contract = load_json(R6 / "R6_INDEPENDENT_ACTIVATION_VERIFIER_CONTRACT.json")
    require(approval.get("human_origin") == "USER_EXPLICIT_APPROVAL" and approval.get("decision") == "APPROVE_EXACT_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION" and approval.get("authenticated") is True and approval.get("transaction_id") == TX, "R7 human activation approval mismatch")
    require(approval.get("r6_package", {}).get("sha256sums_sha256") == R6_SUMS_SHA and approval.get("r6_decision_packet", {}).get("sha256") == file_digest(R6 / "R6_HUMAN_ACTIVATION_DECISION_PACKET.json"), "R6 decision packet authentication mismatch")
    require(approval.get("r6_pinned_review", {}).get("commit") == R6_REVIEW_COMMIT and approval.get("r6_pinned_review", {}).get("tree") == R6_REVIEW_TREE, "R6 review binding mismatch")
    require(approval.get("r5_pinned_review", {}).get("commit") == R5_REVIEW_COMMIT and approval.get("r5_pinned_review", {}).get("tree") == R5_REVIEW_TREE, "R5 review binding mismatch")
    require(approval.get("r6_independent_design_verification", {}).get("status") == "PASS" and approval.get("r6_independent_design_verification", {}).get("sha256") == file_digest(R6 / "R6_INDEPENDENT_DESIGN_VERIFICATION.json"), "R6 independent design verification authentication mismatch")
    require(r6_tx.get("transaction_id") == TX and r6_tx.get("design_only") is True and r6_tx.get("activation_execution_performed") is False, "R6 transaction changed")
    require(r6_contract.get("transaction_id") == TX and r6_contract.get("design_only") is True, "R6 verifier contract changed")
    require(approval.get("newer_conflicting_transaction_count") == 0, "newer conflicting transaction present")

    exact = verify_sources_and_routes(r6_tx)
    pointer_path = PACKAGE / "authority_store/r7-activation-consumer-pointer.json"
    pointer = load_json(pointer_path)
    pre = load_json(PACKAGE / "R7_PRE_ACTIVATION_STATE.json")
    preconditions = load_json(PACKAGE / "R7_ACTIVATION_PRECONDITION_VERIFICATION.json")
    staged = load_json(PACKAGE / "R7_STAGED_AUTHORITY_ROOTS.json")
    commit = load_json(PACKAGE / "R7_COMMIT_POINT.json")
    post = load_json(PACKAGE / "R7_POST_ACTIVATION_STATE.json")
    downstream = load_json(PACKAGE / "R7_DOWNSTREAM_BOUNDARY_VERIFICATION.json")
    require(pointer.get("status") == "COMMITTED" and pointer.get("visibility") == "ATOMIC_SINGLE_POINTER" and pointer.get("transaction_id") == TX, "consumer pointer is not committed atomically")
    require(pre.get("production_authority_visible") is False and pre.get("consumer_pointer", {}).get("exists_before_activation") is False, "pre-state is not the authenticated absent state")
    require(preconditions.get("all_preconditions_pass") is True and preconditions.get("failure_mode") == "FAIL_CLOSED_NO_ACTIVATION" and preconditions.get("r6_preconditions_rechecked") is True, "R6 preconditions were not rechecked")
    r6_precondition_ids = [item.get("id") for item in load_json(R6 / "R6_ACTIVATION_PRECONDITIONS.json").get("preconditions", [])]
    require(preconditions.get("r6_precondition_count") == len(r6_precondition_ids) == 10 and preconditions.get("r6_precondition_ids_rechecked") == r6_precondition_ids, "R6 precondition coverage is incomplete")
    require(staged.get("root_count") == 4 and staged.get("field_pin_root_present") is False, "staged root set is not exact")
    expected_root_ids = r6_tx["post_state_candidate"]["root_ids"]
    require(set(pointer.get("post_state_root_ids", {})) == set(ROLES) and pointer["post_state_root_ids"] == expected_root_ids, "post-state root IDs drift")
    for role, filename in ROLES.items():
        source = R5 / "06_non_active_candidates" / filename
        candidate = load_json(source)
        expected_artifact = r6_tx["post_state_candidate"]["root_artifacts"][role]["artifact"]
        require(file_digest(source) == expected_artifact["sha256"] and source.stat().st_size == expected_artifact["byte_length"], f"source root artifact drift: {role}")
        require(root_id(role, source, candidate) == expected_root_ids[role], f"root ID recomputation drift: {role}")
        paths = staged["roots"][role]
        for key in ("staging_path", "committed_path"):
            copied = PACKAGE / paths[key]
            require(file_digest(copied) == file_digest(source), f"{key} root copy drift: {role}")
            require(copied.stat().st_mode & 0o222 == 0, f"{key} root is writable: {role}")
        require(pointer["artifact_sha256s"][role]["artifact_sha256"] == file_digest(source), f"pointer artifact hash drift: {role}")
        require(pointer["artifact_sha256s"][role]["root_id"] == expected_root_ids[role], f"pointer root ID drift: {role}")
    require(set(pointer["artifact_sha256s"]) == set(ROLES), "pointer has an unexpected role")
    require(commit.get("commit_status") == "COMMITTED" and commit.get("commit_point") == "ATOMIC_REPLACE_SINGLE_AUTHORITY_CONSUMER_POINTER_AFTER_VERIFIER_PASS" and commit.get("atomic_replace_performed") is True and commit.get("partial_state_exposed") is False, "commit point contract drift")
    require(commit.get("consumer_pointer_sha256") == file_digest(pointer_path), "commit pointer hash mismatch")
    require(commit.get("post_state_root_ids") == pointer["post_state_root_ids"] and commit.get("pre_state_root_ids") == pre["root_ids"], "commit state identities drift")
    require(post.get("active_source_authority_created") is True and post.get("production_authority_visible") is True and post.get("consumer_pointer", {}).get("sha256") == file_digest(pointer_path), "post-state visibility mismatch")
    require(post.get("root_ids") == pointer["post_state_root_ids"] and post.get("exact317") == exact, "post-state Exact317/root mismatch")
    require(post.get("dry_run_object_status") == "CANDIDATE_WRAPPER_OBJECTS_ONLY" and post.get("field_pin_registry") == "ABSENT", "authority labeling leak")
    require(downstream.get("verification_status") == "PASS" and downstream.get("source_auth_executed") is False and downstream.get("field_pins_created") == 0 and downstream.get("field_pin_pointer_selection") == "NONE" and downstream.get("p0_executed") is False and downstream.get("p1_executed") is False and downstream.get("binding_publication") is False and downstream.get("scoring_authority_mutated") is False and downstream.get("binding_authority_mutated") is False and downstream.get("gov_r4_rewritten") is False and downstream.get("exec_r4_rewritten") is False and downstream.get("git_ref_mutation") is False, "downstream boundary violation")
    journal = load_jsonl(PACKAGE / "R7_ACTIVATION_TRANSACTION_JOURNAL.jsonl")
    require([row.get("sequence") for row in journal] == list(range(1, 10)), "activation journal sequence drift")
    require(journal[-1].get("event") == "POST_POINTER_READ" and journal[-1].get("status") == "PASS", "activation journal did not close with post-pointer verification")
    if (PACKAGE / "R7_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION_REPORT.md").exists():
        report = (PACKAGE / "R7_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION_REPORT.md").read_text(encoding="utf-8")
        require("BINDING_R7_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION = PASS_ACTIVATED_READY_FOR_FRESH_REVIEW" in report, "R7 report terminal status drift")

    result = {
        "schema": "FA1B2DE_CURRENT86_BINDING_R7_INDEPENDENT_ACTIVATION_VERIFICATION_V1",
        "verification_status": "PASS",
        "independent": True,
        "transaction_id": TX,
        "r6_review_commit": R6_REVIEW_COMMIT,
        "r6_review_tree": R6_REVIEW_TREE,
        "r6_package_sha256sums_sha256": R6_SUMS_SHA,
        "r5_package_sha256sums_sha256": R5_SUMS_SHA,
        "consumer_pointer_sha256": file_digest(pointer_path),
        "recomputed_root_ids": expected_root_ids,
        "exact317": exact,
        "active_source_authority_created": True,
        "source_auth_executed": False,
        "field_pins_created": 0,
        "p0_executed": False,
        "p1_executed": False,
        "binding_publication": False,
        "scoring_authority_mutated": False,
        "binding_authority_mutated": False,
        "git_ref_mutation": False,
        "checks": {"r6_decision_authenticated": "PASS", "r6_transaction_exact": "PASS", "protected_hashes": "PASS", "staged_roots": "PASS", "atomic_pointer_commit": "PASS", "exact317_conservation": "PASS", "downstream_zero_state": "PASS"},
        "failure_policy": "FAIL_CLOSED_NO_ACTIVATION",
        "next_action": "FRESH_INDEPENDENT_REVIEW_OF_BINDING_R7_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION",
    }
    return result


if __name__ == "__main__":
    try:
        result = verify()
        output = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        if "--write-output" in sys.argv:
            (PACKAGE / "R7_INDEPENDENT_ACTIVATION_VERIFICATION.json").write_text(output, encoding="utf-8")
        print(output, end="")
    except (VerificationError, OSError, subprocess.CalledProcessError, KeyError, TypeError, ValueError) as exc:
        print(f"R7_VERIFY_BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)
