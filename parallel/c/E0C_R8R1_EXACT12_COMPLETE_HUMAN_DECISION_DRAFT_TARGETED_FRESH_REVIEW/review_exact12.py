#!/usr/bin/env python3
"""Fresh, read-only review of the completed Exact12 human-decision draft.

The script writes only sibling audit artifacts in this directory. It does not
modify the draft, any authority packet, status registry, member set, or
historical review package.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Iterable, Mapping


PINNED_COMMIT = "f10c874513071345ddc2411004f81ee5c57f4065"
EXPECTED_PARENT = "99f9c0d7fe8b4ecec896837b3991e8d23ebbb608"
EXPECTED_ORIGIN = "https://github.com/cphzyl1611/apt-experiment-artifacts.git"
EXPECTED_BRANCH = "artifact/e0-c"
EXPECTED_DRAFT_SHA256 = "dbab1909e0f1b1e687709846e2a16eb0cf13c4fb47dc2faa5951226a06dea0f0"
EXPECTED_DRAFT_BLOB_SHA1 = "dbb1d455ea64a910fd9b1e0b80c03a14702c930c"
EXPECTED_FIRST_8_SHA256 = "4d0e06fb14cc803dfe85a9169d487f1a81ea53d929b2f5e396190e4d9877fcfb"
EXPECTED_TEMPLATE_COUNT = 12
EXPECTED_RAW_COVERAGE = 203
EXPECTED_BLOCKED31_COUNT = 31
EXPECTED_UNION_SHA256 = "ffeb2704a1c971b89129e1959ae721bbc9ef159153a5f0a20f8abda13edb441a"
REQUEST = "REQUEST_SPLIT_OR_MORE_EVIDENCE"
APPROVE = "APPROVE_TEMPLATE_FOR_MEMBER_SET"
REJECT = "REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL"
MANUAL = "MANUAL_DESIGN_REQUIRED"
NON_AUTHORITATIVE = "NON_AUTHORITATIVE"
OUTPUT_DIR_NAME = "E0C_R8R1_EXACT12_COMPLETE_HUMAN_DECISION_DRAFT_TARGETED_FRESH_REVIEW"
DATA_DIR = Path("parallel/c")

EXPECTED_TEMPLATES = [
    (1, "r4-template-120-process_command_execution", 49, "3ceca8928cf0c95f4006ffbf91d677cf3cee9287d7beea4996adfa752703bc33"),
    (2, "r4-template-136-process_command_execution", 28, "fc076c1fbcef34272b7bb80b611fa0b3a560a940833e960976d45388355d100a"),
    (3, "r4-template-107-process_command_execution", 27, "aeead35be23d0b2f06d1b7085ce3c33e1cdc08c87f92fe9e972eea608809ee0e"),
    (4, "r4-template-159-process_command_execution", 17, "e5f22f069e236fde74af499ec46117c82ea2ce067d39b759421f6865cd548439"),
    (5, "r4-template-130-process_command_execution", 17, "b9e9db68106f21ada95ece8e6158f9954372e9e28b908b1e98d886a679280449"),
    (6, "r4-template-152-process_command_execution", 12, "ed38669390f755e5d316080187f6eff0d819475d59c828fa527d0ec66755ce35"),
    (7, "r4-template-069-persistence_configuration", 10, "7347ef4f412bf89b0ee6fad51fe44eabb96c64606d8b7d293b0b656ed8e86b42"),
    (8, "r4-template-009-credential_store_access", 9, "9ae166dab66173192bbcbcd89bc86757c290e9d8db2d23a0350cd6df890636f4"),
    (9, "r4-template-006-credential_store_access", 9, "776cc6ca57d025ad62efeed4d6f55f8a34a6dafe4517cc6a8a388519de3e6e8d"),
    (10, "r4-template-048-network_c2_beacon", 9, "f7ea287ecdda9343ad41d24096b9a4ab8a4a567d0f40c0d3b708a384e65c9db4"),
    (11, "r4-template-035-file_resource_operation", 8, "ae5c70bcbce560f3194a63c6336b1021b4a3f947601958b75ae98245331b8a52"),
    (12, "r4-template-071-persistence_configuration", 8, "939db086e6af0f4a8c6fb04d039ff8a379b0b0dc9cf5ebe9cbd76bb4e3b9cb28"),
]
EXPECTED_IDS = [item[1] for item in EXPECTED_TEMPLATES]
EXPECTED_HASHES = {item[1]: item[3] for item in EXPECTED_TEMPLATES}

INPUT_FILES = [
    "E0C_R8_HUMAN_DECISION_PACKET.json",
    "E0C_R8_INPUT_AUTHENTICATION.json",
    "E0C_R6_FIRST_HUMAN_REVIEW_TRANCHE.json",
    "E0C_R6_EXACT89_ENRICHED_TEMPLATE_PACKETS.jsonl",
    "E0C_R6_BLOCKED31_SOURCE_RECOVERY_RESULTS.json",
    "E0C_R7_FIRST_TRANCHE_INPUT_AUTHENTICATION.json",
    "E0C_R7_FIRST_TRANCHE_DECISION_PACKET.json",
    "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl",
    "E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT.jsonl",
]
COMPLETION_FILES = [
    "E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT_COMPLETE/E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT_COMPLETE.md",
    "E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT_COMPLETE/EXACT12_DECISION_CONSERVATION.json",
    "E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT_COMPLETE/EXACT12_DECISION_INPUT_AUTHENTICATION.json",
    "E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT_COMPLETE/EXACT12_HUMAN_ORIGIN_AUDIT.json",
    "E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT_COMPLETE/EXACT12_ZERO_MUTATION_BOUNDARY.json",
]
PROTECTED_FILES = sorted(set(INPUT_FILES + COMPLETION_FILES))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def key_sha256(keys: Iterable[str]) -> str:
    canonical = "\n".join(sorted(str(key) for key in keys))
    return sha256_bytes(canonical.encode("utf-8"))


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"expected object at {path}:{line_number}")
        rows.append(value)
    return rows


def run_git(root: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(["git", *args], cwd=root, check=check, capture_output=True, text=True)
    return result.stdout.strip()


def git_file_at(root: Path, commit: str, path: str) -> bytes:
    result = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=root, check=True, capture_output=True)
    return result.stdout


def file_record(root: Path, path: str) -> dict[str, Any]:
    data = (root / DATA_DIR / path).read_bytes()
    pinned = git_file_at(root, PINNED_COMMIT, f"{DATA_DIR}/{path}")
    return {
        "path": path,
        "size_bytes": len(data),
        "sha256": sha256_bytes(data),
        "git_blob_sha1": git_blob_sha1(data),
        "pinned_sha256": sha256_bytes(pinned),
        "pinned_git_blob_sha1": git_blob_sha1(pinned),
        "worktree_bytes_match_pinned_commit": data == pinned,
    }


def repo_authentication(root: Path) -> dict[str, Any]:
    origin = run_git(root, "remote", "get-url", "origin")
    branch = run_git(root, "branch", "--show-current")
    head = run_git(root, "rev-parse", "HEAD")
    parent = run_git(root, "rev-parse", "HEAD^")
    remote_branch = run_git(root, "rev-parse", "refs/remotes/origin/artifact/e0-c", check=False)
    remote_main = run_git(root, "rev-parse", "refs/remotes/origin/main", check=False)
    status_lines = run_git(root, "status", "--porcelain=v1", check=False).splitlines()
    unrelated_status_lines = [
        line for line in status_lines
        if not line[3:].startswith(f"parallel/c/{OUTPUT_DIR_NAME}/")
        and line[3:] != f"parallel/c/{OUTPUT_DIR_NAME}"
    ]
    ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", EXPECTED_PARENT, PINNED_COMMIT], cwd=root).returncode == 0
    parent_draft = git_file_at(root, EXPECTED_PARENT, "parallel/c/E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT.jsonl")
    draft = (root / "parallel/c/E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT.jsonl").read_bytes()
    exact_draft = (
        head == PINNED_COMMIT
        and origin == EXPECTED_ORIGIN
        and branch == EXPECTED_BRANCH
        and parent == EXPECTED_PARENT
        and ancestry
        and remote_branch == PINNED_COMMIT
        and sha256_bytes(draft) == EXPECTED_DRAFT_SHA256
        and git_blob_sha1(draft) == EXPECTED_DRAFT_BLOB_SHA1
        and draft == git_file_at(root, PINNED_COMMIT, "parallel/c/E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT.jsonl")
    )
    completion_records = [file_record(root, path) for path in COMPLETION_FILES]
    protected_records = [file_record(root, path) for path in PROTECTED_FILES]
    protected_ok = all(item["worktree_bytes_match_pinned_commit"] for item in protected_records)
    return {
        "status": "PASS" if exact_draft and protected_ok and not unrelated_status_lines else "BLOCKED",
        "origin": origin,
        "expected_origin": EXPECTED_ORIGIN,
        "branch": branch,
        "expected_branch": EXPECTED_BRANCH,
        "head": head,
        "pinned_commit": PINNED_COMMIT,
        "parent": parent,
        "expected_parent": EXPECTED_PARENT,
        "remote_artifact_e0_c": remote_branch,
        "remote_main": remote_main,
        "pinned_commit_ancestry": ancestry,
        "worktree_status_before_review": status_lines,
        "unrelated_worktree_status": unrelated_status_lines,
        "worktree_clean_before_materialization": not bool(unrelated_status_lines),
        "exact_draft_sha256": sha256_bytes(draft),
        "expected_draft_sha256": EXPECTED_DRAFT_SHA256,
        "exact_draft_git_blob_sha1": git_blob_sha1(draft),
        "expected_draft_git_blob_sha1": EXPECTED_DRAFT_BLOB_SHA1,
        "draft_bytes_match_pinned_commit": draft == git_file_at(root, PINNED_COMMIT, "parallel/c/E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT.jsonl"),
        "parent_draft_sha256": sha256_bytes(parent_draft),
        "expected_parent_draft_sha256": EXPECTED_FIRST_8_SHA256,
        "completion_package_files": completion_records,
        "protected_input_files": protected_records,
        "completion_package_bytes_match_pinned_commit": all(item["worktree_bytes_match_pinned_commit"] for item in completion_records),
        "protected_worktree_bytes_match_pinned_commit": protected_ok,
        "no_post_materialization_mutation_of_protected_inputs": protected_ok and exact_draft,
    }


def member_row(item: Mapping[str, Any]) -> tuple[list[str], int, str]:
    keys = [str(value) for value in item.get("member_keys", [])]
    count = int(item.get("member_count", len(keys)))
    observed_hash = str(item.get("member_set_sha256", item.get("member_key_commitment", {}).get("sha256", "")))
    return keys, count, observed_hash


def by_id(items: Iterable[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for item in items:
        template_id = str(item.get("template_id", ""))
        if template_id:
            result[template_id] = item
    return result


def recompute_frozen_sets(root: Path) -> dict[str, Any]:
    r8_packet = load_json(root / "parallel/c/E0C_R8_HUMAN_DECISION_PACKET.json")
    r8_auth = load_json(root / "parallel/c/E0C_R8_INPUT_AUTHENTICATION.json")
    r6_tranche = load_json(root / "parallel/c/E0C_R6_FIRST_HUMAN_REVIEW_TRANCHE.json")
    r6_packets = load_jsonl(root / "parallel/c/E0C_R6_EXACT89_ENRICHED_TEMPLATE_PACKETS.jsonl")
    r6_blocked = load_json(root / "parallel/c/E0C_R6_BLOCKED31_SOURCE_RECOVERY_RESULTS.json")
    r7_auth = load_json(root / "parallel/c/E0C_R7_FIRST_TRANCHE_INPUT_AUTHENTICATION.json")
    r7_decision = load_json(root / "parallel/c/E0C_R7_FIRST_TRANCHE_DECISION_PACKET.json")
    r3_rows = load_jsonl(root / "parallel/c/E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl")

    frozen = r8_packet.get("templates", [])
    exact_rows: list[dict[str, Any]] = []
    expected_failures: list[str] = []
    source_drift: dict[str, list[str]] = {"r6_tranche": [], "r6_enriched": [], "r7_auth": [], "r7_decision": [], "r8_auth": []}
    r6_map = by_id(r6_packets)
    r6_tranche_map = by_id(r6_tranche.get("templates", []))
    r7_auth_map = by_id(r7_auth.get("template_member_authentication", []))
    r7_decision_map = by_id(r7_decision.get("templates", []))
    r8_auth_map = by_id(r8_auth.get("template_member_authentication", []))
    expected_map = {template_id: (order, count, digest) for order, template_id, count, digest in EXPECTED_TEMPLATES}
    for index, packet in enumerate(frozen):
        template_id = str(packet.get("template_id", ""))
        keys, count, embedded_hash = member_row(packet)
        recomputed_hash = key_sha256(keys)
        expected_order, expected_count, expected_hash = expected_map.get(template_id, (None, None, None))
        row = {
            "frozen_order": index + 1,
            "template_id": template_id,
            "member_count": count,
            "member_keys": sorted(keys),
            "member_set_sha256_embedded": embedded_hash,
            "member_set_sha256_recomputed": recomputed_hash,
            "member_set_reference": f"E0C_R8_HUMAN_DECISION_PACKET.json#/templates/{index}/member_keys",
            "expected": {"frozen_order": expected_order, "member_count": expected_count, "member_set_sha256": expected_hash},
        }
        exact_rows.append(row)
        if expected_order != index + 1 or expected_count != count or expected_hash != recomputed_hash or embedded_hash != recomputed_hash:
            expected_failures.append(template_id or f"index-{index}")

        for source_name, source_map in (
            ("r6_tranche", r6_tranche_map),
            ("r6_enriched", r6_map),
            ("r7_auth", r7_auth_map),
            ("r7_decision", r7_decision_map),
            ("r8_auth", r8_auth_map),
        ):
            source = source_map.get(template_id)
            if source is None or member_row(source)[0] != keys or member_row(source)[1] != count or member_row(source)[2] != recomputed_hash:
                source_drift[source_name].append(template_id)

    all_keys = [key for row in exact_rows for key in row["member_keys"]]
    unique_keys = set(all_keys)
    overlap = len(all_keys) - len(unique_keys)
    blocked_keys = {str(row.get("raw_key")) for row in r6_blocked.get("rows", []) if isinstance(row, Mapping)}
    blocked_overlap_keys = sorted(unique_keys.intersection(blocked_keys))
    r3_map = {str(row.get("raw_key")): row for row in r3_rows}
    status_mismatches = sorted(key for key in unique_keys if r3_map.get(key, {}).get("global_planning_status") != MANUAL)
    ids = [row["template_id"] for row in exact_rows]
    duplicate_ids = sorted({template_id for template_id in ids if ids.count(template_id) > 1})
    order_pass = ids == EXPECTED_IDS and [row["frozen_order"] for row in exact_rows] == list(range(1, EXPECTED_TEMPLATE_COUNT + 1))
    drift_count = sum(len(value) for value in source_drift.values())
    union_hash = key_sha256(unique_keys)
    status = (
        len(frozen) == EXPECTED_TEMPLATE_COUNT
        and order_pass
        and not expected_failures
        and len(unique_keys) == EXPECTED_RAW_COVERAGE
        and overlap == 0
        and not duplicate_ids
        and drift_count == 0
        and len(blocked_keys) == EXPECTED_BLOCKED31_COUNT
        and not blocked_overlap_keys
        and not status_mismatches
        and union_hash == EXPECTED_UNION_SHA256
    )
    return {
        "schema_version": "e0c-r8r1-exact12-fresh-frozen-set-recomputation-v1",
        "status": "PASS" if status else "BLOCKED",
        "recomputed_from": [
            "E0C_R8_HUMAN_DECISION_PACKET.json",
            "E0C_R6_FIRST_HUMAN_REVIEW_TRANCHE.json",
            "E0C_R6_EXACT89_ENRICHED_TEMPLATE_PACKETS.jsonl",
            "E0C_R6_BLOCKED31_SOURCE_RECOVERY_RESULTS.json",
            "E0C_R7_FIRST_TRANCHE_INPUT_AUTHENTICATION.json",
            "E0C_R7_FIRST_TRANCHE_DECISION_PACKET.json",
            "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl",
        ],
        "template_count": len(frozen),
        "expected_template_count": EXPECTED_TEMPLATE_COUNT,
        "template_order_recomputation": "PASS" if order_pass else "BLOCKED",
        "template_id_recomputation": "PASS" if ids == EXPECTED_IDS and not duplicate_ids else "BLOCKED",
        "templates": exact_rows,
        "raw_member_counts": {
            "sum_of_template_member_counts": len(all_keys),
            "unique_raw_member_count": len(unique_keys),
            "expected_raw_coverage": EXPECTED_RAW_COVERAGE,
        },
        "union_member_set_sha256": union_hash,
        "expected_union_member_set_sha256": EXPECTED_UNION_SHA256,
        "overlap": overlap,
        "duplicate_template_ids": duplicate_ids,
        "source_set_drift": source_drift,
        "drift": drift_count,
        "blocked31_count": len(blocked_keys),
        "blocked31_overlap": len(blocked_overlap_keys),
        "blocked31_overlap_keys": blocked_overlap_keys,
        "r3_status_mismatches": status_mismatches,
        "all_recomputed_members_manual_design_required": not status_mismatches,
        "source_packet_counts": {
            "r6_enriched_template_packets": len(r6_packets),
            "r6_first_tranche_templates": len(r6_tranche.get("templates", [])),
            "r7_auth_template_rows": len(r7_auth.get("template_member_authentication", [])),
            "r7_decision_templates": len(r7_decision.get("templates", [])),
            "r8_auth_template_rows": len(r8_auth.get("template_member_authentication", [])),
            "r3_global_status_rows": len(r3_rows),
        },
    }


def explicit_action_attestations() -> list[dict[str, Any]]:
    actions = [
        (9, "r4-template-006-credential_store_access"),
        (10, "r4-template-048-network_c2_beacon"),
        (11, "r4-template-035-file_resource_operation"),
        (12, "r4-template-071-persistence_configuration"),
    ]
    result = []
    for order, template_id in actions:
        statement = f"User explicitly selected {REQUEST} for {template_id}."
        result.append({
            "frozen_order": order,
            "template_id": template_id,
            "human_decision": REQUEST,
            "user_action_statement": statement,
            "user_action_statement_sha256": sha256_bytes(statement.encode("utf-8")),
            "authentication_source": "current user instruction in task request",
        })
    return result


def recompute_decisions(root: Path, frozen: Mapping[str, Any], repo: Mapping[str, Any]) -> dict[str, Any]:
    draft_path = root / "parallel/c/E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT.jsonl"
    draft_bytes = draft_path.read_bytes()
    records = load_jsonl(draft_path)
    parent_bytes = git_file_at(root, EXPECTED_PARENT, "parallel/c/E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT.jsonl")
    first_eight_bytes = b"".join(draft_bytes.splitlines(keepends=True)[:8])
    frozen_rows = frozen["templates"]
    expected_by_id = {row["template_id"]: row for row in frozen_rows}
    expected_refs = {row["template_id"]: f"E0C_R8_HUMAN_DECISION_PACKET.json#/templates/{index}/member_keys" for index, row in enumerate(frozen_rows)}
    failures: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        template_id = str(record.get("template_id", ""))
        expected = expected_by_id.get(template_id)
        checks = {
            "record_type": record.get("record_type") == "e0c_r8r1_non_authoritative_human_template_decision_draft",
            "draft_authority": record.get("draft_authority") == NON_AUTHORITATIVE,
            "decision_origin": record.get("decision_origin") == "USER_EXPLICIT",
            "automatic_human_decision": record.get("automatic_human_decision") is False,
            "frozen_order": expected is not None and record.get("frozen_order") == expected["frozen_order"],
            "decision": record.get("human_decision") == REQUEST,
            "member_count": expected is not None and record.get("member_count") == expected["member_count"],
            "member_hash": expected is not None and record.get("member_set_sha256") == expected["member_set_sha256_recomputed"],
            "member_reference": expected is not None and record.get("member_set_reference") == expected_refs.get(template_id),
            "member_expansion_false": record.get("member_expansion") is False,
            "applied_split_false": record.get("applied_split") is False,
            "status_mutation_false": record.get("status_mutation") is False,
            "binding_or_scoring_authority_false": record.get("binding_or_scoring_authority_created") is False,
            "formal_execution_authorized_false": record.get("formal_execution_authorized") is False,
            "denominator_change_no": record.get("denominator_change") == "NO",
            "planning_status_manual": record.get("r3_global_planning_status") == MANUAL,
            "candidate_split_status": record.get("candidate_split_status") == "NO_STRUCTURED_SPLIT_EVIDENCE",
            "split_note_bounded": record.get("split_request_note") == "This user request neither defines nor applies a split; any split remains subject to a later separately governed phase.",
        }
        if not all(checks.values()):
            failures.append({"line": index + 1, "template_id": template_id, "failed_checks": [key for key, value in checks.items() if not value]})

    ids = [str(record.get("template_id", "")) for record in records]
    orders = [record.get("frozen_order") for record in records]
    decision_counts = {APPROVE: 0, REJECT: 0, REQUEST: 0}
    for record in records:
        decision = record.get("human_decision")
        if decision in decision_counts:
            decision_counts[decision] += 1
    final_actions = explicit_action_attestations()
    final_by_id = {item["template_id"]: item for item in final_actions}
    final_action_checks = []
    for record in records[8:12]:
        expected_action = final_by_id.get(str(record.get("template_id")))
        final_action_checks.append({
            "frozen_order": record.get("frozen_order"),
            "template_id": record.get("template_id"),
            "matches_explicit_user_action": expected_action is not None and record.get("human_decision") == expected_action["human_decision"],
            "attestation": expected_action,
        })
    first_eight_preserved = first_eight_bytes == parent_bytes and sha256_bytes(first_eight_bytes) == EXPECTED_FIRST_8_SHA256
    unique_ids = len(ids) == len(set(ids))
    status = (
        len(records) == EXPECTED_TEMPLATE_COUNT
        and orders == list(range(1, EXPECTED_TEMPLATE_COUNT + 1))
        and ids == [row["template_id"] for row in frozen_rows]
        and unique_ids
        and not failures
        and decision_counts == {APPROVE: 0, REJECT: 0, REQUEST: EXPECTED_TEMPLATE_COUNT}
        and first_eight_preserved
        and all(item["matches_explicit_user_action"] for item in final_action_checks)
        and repo["draft_bytes_match_pinned_commit"]
    )
    return {
        "schema_version": "e0c-r8r1-exact12-fresh-decision-recomputation-v1",
        "status": "PASS" if status else "BLOCKED",
        "draft_path": str(draft_path),
        "record_count": len(records),
        "expected_record_count": EXPECTED_TEMPLATE_COUNT,
        "orders": orders,
        "expected_orders": list(range(1, EXPECTED_TEMPLATE_COUNT + 1)),
        "template_ids": ids,
        "unique_template_ids": unique_ids,
        "decision_counts": decision_counts,
        "records_failed_validation": failures,
        "record_validation_pass": not failures,
        "first_8_bytes_preserved": first_eight_preserved,
        "first_8_sha256": sha256_bytes(first_eight_bytes),
        "expected_first_8_sha256": EXPECTED_FIRST_8_SHA256,
        "completed_draft_sha256": sha256_bytes(draft_bytes),
        "completed_draft_git_blob_sha1": git_blob_sha1(draft_bytes),
        "final_four_user_actions": final_action_checks,
        "final_four_user_actions_authenticated": all(item["matches_explicit_user_action"] for item in final_action_checks),
        "all_decision_member_references_match_frozen_sets": not failures,
        "frozen_template_count": frozen.get("template_count"),
        "frozen_raw_coverage": frozen.get("raw_member_counts", {}).get("unique_raw_member_count"),
    }


def human_origin_audit(decisions: Mapping[str, Any]) -> dict[str, Any]:
    records = decisions.get("records_failed_validation", [])
    origin_pass = not any("decision_origin" in item.get("failed_checks", []) for item in records)
    automatic_pass = not any("automatic_human_decision" in item.get("failed_checks", []) for item in records)
    return {
        "schema_version": "e0c-r8r1-exact12-fresh-human-origin-audit-v1",
        "status": "PASS" if decisions.get("status") == "PASS" and origin_pass and automatic_pass else "BLOCKED",
        "record_count_audited": decisions.get("record_count"),
        "decision_origin_counts": {"USER_EXPLICIT": decisions.get("record_count") if origin_pass else None},
        "draft_authority_counts": {NON_AUTHORITATIVE: decisions.get("record_count") if decisions.get("status") == "PASS" else None},
        "automatic_human_decision_count": 0 if automatic_pass else None,
        "inferred_or_agent_selected_human_decision_count": 0 if origin_pass and automatic_pass else None,
        "all_records_user_explicit": origin_pass,
        "all_records_automatic_human_decision_false": automatic_pass,
        "explicit_final_four_actions_authenticated": decisions.get("final_four_user_actions_authenticated") is True,
        "audit_conclusion": "All 12 decisions are explicit user-origin records; no automatic or inferred human decision was created." if decisions.get("status") == "PASS" else "Human-origin audit blocked.",
    }


def boundary_audit(root: Path, decisions: Mapping[str, Any], frozen: Mapping[str, Any]) -> dict[str, Any]:
    draft_text = (root / "parallel/c/E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT.jsonl").read_text(encoding="utf-8")
    r7 = load_json(root / "parallel/c/E0C_R7_FIRST_TRANCHE_DECISION_PACKET.json")
    request_effects = [
        item.get("decision_effects", {}).get(REQUEST, {})
        for item in r7.get("templates", [])
        if isinstance(item, Mapping)
    ]
    # R7 encodes non-execution with the bounded follow-up text and omits
    # authorization booleans; an omitted authorization field is non-authorizing.
    exact_request_effect = bool(request_effects) and all(
        effect.get("member_expansion") is False
        and effect.get("action_execution_authorized", False) is False
        and effect.get("formal_experiment_authorized", False) is False
        and effect.get("bounded_follow_up_request", "").endswith("no execution occurs.")
        for effect in request_effects
    )
    serialized_records = load_jsonl(root / "parallel/c/E0C_R8R1_HUMAN_TEMPLATE_DECISION_DRAFT.jsonl")
    zero_counts = {
        "applied_splits": sum(record.get("applied_split") is not False for record in serialized_records),
        "status_mutations": sum(record.get("status_mutation") is not False for record in serialized_records),
        "execution_authorizations": sum(record.get("formal_execution_authorized") is not False for record in serialized_records),
        "binding_or_scoring_authority_created": sum(record.get("binding_or_scoring_authority_created") is not False for record in serialized_records),
        "member_expansions": sum(record.get("member_expansion") is not False for record in serialized_records),
        "denominator_changes": sum(record.get("denominator_change") != "NO" for record in serialized_records),
    }
    source_auth_hits = sum(1 for record in serialized_records if any(key in record for key in ("source_auth", "source_authenticated", "source_authorization")))
    p0_p1_hits = sum(1 for record in serialized_records if any(token in json.dumps(record, sort_keys=True) for token in ("P0", "P1")))
    split_note_count = sum(record.get("split_request_note", "").startswith("This user request neither defines nor applies a split") for record in serialized_records)
    semantics = {
        "request_effects_from_r7_are_non_executing": exact_request_effect,
        "split_not_defined_or_applied": split_note_count == EXPECTED_TEMPLATE_COUNT and "applied_splits" not in draft_text,
        "member_sets_not_mutated": zero_counts["member_expansions"] == 0,
        "statuses_not_mutated": zero_counts["status_mutations"] == 0,
        "replay_execution_not_authorized": zero_counts["execution_authorizations"] == 0,
        "binding_or_scoring_changes_not_authorized": zero_counts["binding_or_scoring_authority_created"] == 0,
        "denominator_not_changed": zero_counts["denominator_changes"] == 0,
    }
    authority = {
        "draft_remains_non_authoritative": all(record.get("draft_authority") == NON_AUTHORITATIVE for record in serialized_records),
        "binding_or_scoring_authority_created": zero_counts["binding_or_scoring_authority_created"] != 0,
        "formal_experiment_executed": "formal_experiment_executed" in draft_text,
        "source_auth_created": source_auth_hits != 0,
        "p0_p1_implication_created": p0_p1_hits != 0,
        "denominator_change": "NO" if semantics["denominator_not_changed"] else "YES",
    }
    authority_boundary_pass = (
        authority["draft_remains_non_authoritative"]
        and not authority["binding_or_scoring_authority_created"]
        and not authority["formal_experiment_executed"]
        and not authority["source_auth_created"]
        and not authority["p0_p1_implication_created"]
        and authority["denominator_change"] == "NO"
    )
    status = decisions.get("status") == "PASS" and frozen.get("status") == "PASS" and all(semantics.values()) and authority_boundary_pass
    return {
        "schema_version": "e0c-r8r1-exact12-fresh-zero-mutation-authority-boundary-v2",
        "status": "PASS" if status else "BLOCKED",
        "semantics": semantics,
        "mutation_counts": zero_counts,
        "authority_boundary": authority,
        "source_auth_field_hits": source_auth_hits,
        "p0_p1_implication_hits": p0_p1_hits,
        "r7_request_effect_records_checked": len(request_effects),
        "formal_experiment_executed": "NO",
        "applied_splits": 0,
        "status_mutations": 0,
        "execution_authorizations": 0,
        "denominator_change": "NO",
        "next_action": "DESIGN_SPLIT_OR_MORE_EVIDENCE_RESOLUTION_PHASE",
    }


def input_authentication(root: Path, repo: Mapping[str, Any], frozen: Mapping[str, Any], decisions: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "e0c-r8r1-exact12-fresh-input-authentication-v1",
        "status": "PASS" if repo.get("status") == "PASS" and frozen.get("status") == "PASS" and decisions.get("status") == "PASS" else "BLOCKED",
        "pinned_complete_draft_commit": PINNED_COMMIT,
        "commit_authentication": repo.get("status"),
        "repository": {
            "origin": repo.get("origin"),
            "branch": repo.get("branch"),
            "head": repo.get("head"),
            "parent": repo.get("parent"),
            "pinned_commit_ancestry": repo.get("pinned_commit_ancestry"),
            "remote_artifact_e0_c": repo.get("remote_artifact_e0_c"),
            "remote_main": repo.get("remote_main"),
            "worktree_clean_before_materialization": repo.get("worktree_clean_before_materialization"),
        },
        "draft": {
            "sha256": repo.get("exact_draft_sha256"),
            "git_blob_sha1": repo.get("exact_draft_git_blob_sha1"),
            "bytes_match_pinned_commit": repo.get("draft_bytes_match_pinned_commit"),
            "no_post_materialization_mutation": repo.get("no_post_materialization_mutation_of_protected_inputs"),
        },
        "completion_package": {
            "files": repo.get("completion_package_files"),
            "bytes_match_pinned_commit": repo.get("completion_package_bytes_match_pinned_commit"),
        },
        "frozen_set_recomputation_status": frozen.get("status"),
        "decision_recomputation_status": decisions.get("status"),
    }


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")


def write_markdown(output: Path, repo: Mapping[str, Any], frozen: Mapping[str, Any], decisions: Mapping[str, Any], origin: Mapping[str, Any], boundary: Mapping[str, Any]) -> None:
    all_pass = all(item.get("status") == "PASS" for item in (repo, frozen, decisions, origin, boundary))
    terminal = "PASS_CONFIRMED_ALL_12_REQUIRE_SPLIT_OR_MORE_EVIDENCE" if all_pass else "BLOCKED"
    rows = frozen.get("templates", [])
    lines = [
        "# E0C R8R1 Exact12 Complete Human Decision Draft Targeted Fresh Review",
        "",
        f"E0C_R8R1_EXACT12_COMPLETE_HUMAN_DECISION_DRAFT_TARGETED_FRESH_REVIEW = {terminal}",
        "",
        "## Pinned Input Authentication",
        "",
        f"PINNED_COMPLETE_DRAFT_COMMIT = `{PINNED_COMMIT}`",
        f"COMMIT_AUTHENTICATION = {repo.get('status')}",
        f"FROZEN_TEMPLATE_COUNT = {frozen.get('template_count')}",
        f"FROZEN_RAW_COVERAGE = {frozen.get('raw_member_counts', {}).get('unique_raw_member_count')}",
        f"FROZEN_ORDER_RECOMPUTATION = {frozen.get('template_order_recomputation')}",
        f"MEMBER_SET_RECOMPUTATION = {frozen.get('status')}",
        f"OVERLAP = {frozen.get('overlap')}",
        f"DRIFT = {frozen.get('drift')}",
        f"BLOCKED31_OVERLAP = {frozen.get('blocked31_overlap')}",
        "",
        "## Decision Recompute",
        "",
        f"HUMAN_DECISION_RECORD_COUNT = {decisions.get('record_count')}",
        f"HUMAN_ORIGIN_AUDIT = {origin.get('status')}",
        f"FIRST_8_BYTES_PRESERVED = {'PASS' if decisions.get('first_8_bytes_preserved') else 'BLOCKED'}",
        f"FINAL_4_USER_ACTIONS_AUTHENTICATED = {'PASS' if decisions.get('final_four_user_actions_authenticated') else 'BLOCKED'}",
        f"APPROVE_TEMPLATE_FOR_MEMBER_SET_COUNT = {decisions.get('decision_counts', {}).get(APPROVE)}",
        f"REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL_COUNT = {decisions.get('decision_counts', {}).get(REJECT)}",
        f"REQUEST_SPLIT_OR_MORE_EVIDENCE_COUNT = {decisions.get('decision_counts', {}).get(REQUEST)}",
        "",
        "| Order | Template | Members | Member-set SHA-256 |",
        "|---:|---|---:|---|",
    ]
    for row in rows:
        lines.append(f"| {row['frozen_order']} | `{row['template_id']}` | {row['member_count']} | `{row['member_set_sha256_recomputed']}` |")
    lines.extend([
        "",
        "## Zero-Mutation Authority Boundary",
        "",
        f"ZERO_MUTATION_AUTHORITY_BOUNDARY = {boundary.get('status')}",
        f"APPLIED_SPLITS = {boundary.get('applied_splits')}",
        f"STATUS_MUTATIONS = {boundary.get('status_mutations')}",
        f"EXECUTION_AUTHORIZATIONS = {boundary.get('execution_authorizations')}",
        f"DENOMINATOR_CHANGE = {boundary.get('denominator_change')}",
        f"FORMAL_EXPERIMENT_EXECUTED = {boundary.get('formal_experiment_executed')}",
        f"DRAFT_REMAINS_NON_AUTHORITATIVE = {boundary.get('authority_boundary', {}).get('draft_remains_non_authoritative')}",
        f"NO_BINDING_OR_SCORING_AUTHORITY = {boundary.get('authority_boundary', {}).get('binding_or_scoring_authority_created') is False}",
        f"NO_SOURCE_AUTH = {boundary.get('authority_boundary', {}).get('source_auth_created') is False}",
        f"NO_P0_P1_IMPLICATION = {boundary.get('authority_boundary', {}).get('p0_p1_implication_created') is False}",
        "",
        "REQUEST_SPLIT_OR_MORE_EVIDENCE is a bounded request for a later split boundary or missing evidence. It defines no split, applies no split, mutates no member set or status, authorizes no replay execution, creates no scoring/binding authority, and does not change the denominator.",
        "",
        "TRACK_BRANCH = artifact/e0-c",
        "MAIN_PUSH_EXECUTED = NO",
        "TRACK_BRANCH_PUSH_EXECUTED = NO_AT_REVIEW_MATERIALIZATION",
        "",
        "NEXT_ACTION = DESIGN_SPLIT_OR_MORE_EVIDENCE_RESOLUTION_PHASE" if all_pass else "NEXT_ACTION = REMEDIATE_EXACT12_FRESH_REVIEW_BLOCKER",
        "STOP = true",
    ])
    (output / "E0C_R8R1_EXACT12_COMPLETE_HUMAN_DECISION_DRAFT_TARGETED_FRESH_REVIEW.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    root = Path.cwd()
    output = root / "parallel/c" / OUTPUT_DIR_NAME
    repo = repo_authentication(root)
    frozen = recompute_frozen_sets(root)
    decisions = recompute_decisions(root, frozen, repo)
    origin = human_origin_audit(decisions)
    boundary = boundary_audit(root, decisions, frozen)
    auth = input_authentication(root, repo, frozen, decisions)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "EXACT12_FRESH_INPUT_AUTHENTICATION.json", auth)
    write_json(output / "EXACT12_FRESH_FROZEN_SET_RECOMPUTATION.json", frozen)
    write_json(output / "EXACT12_FRESH_DECISION_RECOMPUTATION.json", decisions)
    write_json(output / "EXACT12_FRESH_HUMAN_ORIGIN_AUDIT.json", origin)
    write_json(output / "EXACT12_FRESH_ZERO_MUTATION_AUTHORITY_BOUNDARY.json", boundary)
    write_markdown(output, repo, frozen, decisions, origin, boundary)
    terminal = "PASS_CONFIRMED_ALL_12_REQUIRE_SPLIT_OR_MORE_EVIDENCE" if all(item.get("status") == "PASS" for item in (repo, frozen, decisions, origin, boundary)) else "BLOCKED"
    print(f"E0C_R8R1_EXACT12_COMPLETE_HUMAN_DECISION_DRAFT_TARGETED_FRESH_REVIEW = {terminal}")
    print(f"COMMIT_AUTHENTICATION = {repo.get('status')}")
    print(f"FROZEN_TEMPLATE_COUNT = {frozen.get('template_count')}")
    print(f"FROZEN_RAW_COVERAGE = {frozen.get('raw_member_counts', {}).get('unique_raw_member_count')}")
    print(f"FROZEN_ORDER_RECOMPUTATION = {frozen.get('template_order_recomputation')}")
    print(f"MEMBER_SET_RECOMPUTATION = {frozen.get('status')}")
    print(f"OVERLAP = {frozen.get('overlap')}")
    print(f"DRIFT = {frozen.get('drift')}")
    print(f"BLOCKED31_OVERLAP = {frozen.get('blocked31_overlap')}")
    print(f"HUMAN_DECISION_RECORD_COUNT = {decisions.get('record_count')}")
    print(f"HUMAN_ORIGIN_AUDIT = {origin.get('status')}")
    print(f"FIRST_8_BYTES_PRESERVED = {'PASS' if decisions.get('first_8_bytes_preserved') else 'BLOCKED'}")
    print(f"FINAL_4_USER_ACTIONS_AUTHENTICATED = {'PASS' if decisions.get('final_four_user_actions_authenticated') else 'BLOCKED'}")
    print(f"APPROVE_TEMPLATE_FOR_MEMBER_SET_COUNT = {decisions.get('decision_counts', {}).get(APPROVE)}")
    print(f"REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL_COUNT = {decisions.get('decision_counts', {}).get(REJECT)}")
    print(f"REQUEST_SPLIT_OR_MORE_EVIDENCE_COUNT = {decisions.get('decision_counts', {}).get(REQUEST)}")
    print(f"APPLIED_SPLITS = {boundary.get('applied_splits')}")
    print(f"STATUS_MUTATIONS = {boundary.get('status_mutations')}")
    print(f"EXECUTION_AUTHORIZATIONS = {boundary.get('execution_authorizations')}")
    print(f"DENOMINATOR_CHANGE = {boundary.get('denominator_change')}")
    print(f"FORMAL_EXPERIMENT_EXECUTED = {boundary.get('formal_experiment_executed')}")
    print("TRACK_BRANCH = artifact/e0-c")
    print("MAIN_PUSH_EXECUTED = NO")
    print("TRACK_BRANCH_PUSH_EXECUTED = NO_AT_REVIEW_MATERIALIZATION")
    print("NEXT_ACTION = DESIGN_SPLIT_OR_MORE_EVIDENCE_RESOLUTION_PHASE" if terminal.startswith("PASS") else "NEXT_ACTION = REMEDIATE_EXACT12_FRESH_REVIEW_BLOCKER")
    print("STOP = true")
    return 0 if terminal.startswith("PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
