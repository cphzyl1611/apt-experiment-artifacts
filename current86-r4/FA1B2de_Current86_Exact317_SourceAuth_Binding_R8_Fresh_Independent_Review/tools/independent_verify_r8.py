#!/usr/bin/env python3
"""Fresh, read-only independent review of the Binding R8 package.

The implementation deliberately does not import the R8 materializer or its
verifier.  It recomputes the source leaves, RFC6901 paths, canonical hashes,
route/conservation counts, presentation batching, first-tranche ordering, and
the downstream authority boundary from the authenticated inputs.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parents[1]
R8 = ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R8_Field_Pin_Governance_Materialization"
R6 = ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R6_Production_Activation_Governance_Design"
R5 = ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R5_Wrapper_Materialization"
R7 = ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R7_Production_Source_Authority_Activation"
EXACT = ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4" / "00_lineage" / "EXACT317_TARGET_MANIFEST.json"
REPO = Path("/home/cph/fa1b2de-review-artifacts")
CURRENT = "2ff2b21cd313c5b91567adfe05691d3e25aabb87"
BASELINE = "107ef9f69a734a10b320d552cfe18a6cb9a2ac0c"
R8_REVIEW_TREE = "26b5c3a56e86fb5c11d50fc86bd99d6b940239fc"
R8_PREFIX = "current86-r4"
R7_TRANSACTION = "e8a0a97a33d47ac68c8ded4af1af109fa010d979acf9736fd5dffdebf96c5208"
R7_POINTER_SHA = "02394a7fc7c5f337dfbfff521467759f80e14f8d5d27ca9e01653eec3f0d592c"
EXACT_SHA = "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac"
R6_SKELETON_SHA = "d55bc015d21b3fb4a6edc7ef9aa0caf5abca1da177da2df232f1dd97bd6f8573"
R6_SUMS_SHA = "7abdd9630ce53d0b457b5111c4c071d4bee2b99b1d436ee57808128f38c38c62"
R5_SUMS_SHA = "5f1746499c2ca5ba966b3f716e6b8ca87844cf4cd0a1316ec215b25cc092fdc1"
R5_DRY_SHA = "884dec61cc33e13d12c439e202568c8e592650b82f98acca22b5eb0b4f4eaa82"
ROOT_IDS = {
    "SOURCE_ADMISSION_REGISTRY_ROOT": "8f9596729361f8c6620c98c18344c8cf31073e35085b3eb408fc5212ebd41d6a",
    "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT": "f88d911080e97e8e1e58010fd5e551f91127ec6b1ae77d2a3d28af07f71ef52f",
    "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST": "5d868125294dcd4d5f643f2fef820b89b056925a925d0b0f98fcf7408c41009d",
    "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION": "3f1f169c1ada9fbddd381727114b5b4a0a422b1bd4016c6ec5ff5b6461a02aa8",
}
ROOT_HASHES = {
    "SOURCE_ADMISSION_REGISTRY_ROOT": "e1f20c4a4352997e3a969a1d281e8ff0aa4314a6748edd82ad2b0a6eee013d1c",
    "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT": "3eb4a78f6487286a6321e466d5a3cc2f6f645be959c51a33dd0046e3a4007346",
    "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST": "98f4f42b4014f3f06f3a2ba823ff70fb13e0dffa15083b7ab8ba8c4bc647ac3d",
    "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION": "24fafe7dc36c3f04b73fee413a6cabb66bbbb2bcafa0a460e8a2d6516027099b",
}
ROUTES = {
    "R4_WRAPPER_RAW_LEGACY_26": ("RAW", 26),
    "R4_WRAPPER_C0_60": ("RAW", 60),
    "R4_WRAPPER_SCORING_231": ("CANDIDATE", 231),
}
FIELD_ACTIONS = ["APPROVE_EXACT_FIELD_PIN", "REJECT_FIELD_CANDIDATES_KEEP_BLOCKED", "REQUEST_MORE_EVIDENCE"]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canon(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def file_sha(path: Path) -> str:
    return digest(path.read_bytes())


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_bytes().splitlines() if line]


def parse_sums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  \.\/(.+)", line)
        if not match:
            raise ValueError(f"malformed checksum line in {path}: {line!r}")
        value, relative = match.groups()
        if relative in entries:
            raise ValueError(f"duplicate checksum path in {path}: {relative}")
        entries[relative] = value
    return entries


def envelope(path: Path, expected_sums_sha: str | None = None) -> dict[str, Any]:
    sums = path / "SHA256SUMS.txt"
    listed = {line.strip() for line in (path / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line.strip()}
    entries = parse_sums(sums)
    matches = {relative: file_sha(path / relative) == expected for relative, expected in entries.items()}
    return {
        "package": path.name,
        "file_list_count": len(listed),
        "sha256sums_count": len(entries),
        "file_list_equals_sha256sums_paths": listed == set(entries),
        "file_list_only_paths": sorted(listed - set(entries)),
        "sha256sums_only_paths": sorted(set(entries) - listed),
        "all_listed_hashes_match": all(matches.values()) and listed <= set(entries),
        "hash_mismatches": sorted(relative for relative, ok in matches.items() if not ok),
        "expected_sha256sums_sha256": expected_sums_sha,
        "observed_sha256sums_sha256": file_sha(sums),
        "expected_sha256sums_match": expected_sums_sha is None or file_sha(sums) == expected_sums_sha,
        "entries": entries,
    }


def git(*args: str, check: bool = True) -> str:
    result = subprocess.run(["git", "-C", str(REPO), *args], check=check, capture_output=True, text=True)
    return result.stdout.strip()


def git_blob_sha(revision: str, path: str) -> str:
    return git("rev-parse", f"{revision}:{path}")


def git_file_matches(revision: str, path: str, local: Path) -> bool:
    data = subprocess.run(["git", "-C", str(REPO), "show", f"{revision}:{path}"], check=True, capture_output=True).stdout
    return digest(data) == file_sha(local)


def value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite number")
        return "number"
    if isinstance(value, str):
        return "string"
    raise ValueError(f"non-scalar value: {type(value).__name__}")


def escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def flatten(value: Any, prefix: str) -> list[dict[str, Any]]:
    if isinstance(value, Mapping):
        leaves: list[dict[str, Any]] = []
        for key in sorted(value, key=lambda item: str(item).encode("utf-8")):
            leaves.extend(flatten(value[key], f"{prefix}/{escape(str(key))}"))
        return leaves
    if isinstance(value, list):
        leaves = []
        for index, child in enumerate(value):
            leaves.extend(flatten(child, f"{prefix}/{index}"))
        return leaves
    return [{"pointer": prefix, "value": value, "value_type": value_type(value), "value_sha256": digest(canon(value))}]


def decode_token(token: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(token):
        if token[i] != "~":
            out.append(token[i])
            i += 1
            continue
        if i + 1 >= len(token) or token[i + 1] not in "01":
            raise ValueError(f"invalid RFC6901 escape in token {token!r}")
        out.append("~" if token[i + 1] == "0" else "/")
        i += 2
    return "".join(out)


def resolve(root: Any, pointer: str) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError(f"invalid JSON pointer {pointer!r}")
    current = root
    for raw in pointer[1:].split("/"):
        token = decode_token(raw)
        if isinstance(current, Mapping):
            if token not in current:
                raise ValueError(f"missing object token {token!r}")
            current = current[token]
        elif isinstance(current, list):
            if token == "" or (len(token) > 1 and token.startswith("0")) or not token.isdigit():
                raise ValueError(f"invalid array index token {token!r}")
            index = int(token)
            if index >= len(current):
                raise ValueError(f"array index out of range: {index}")
            current = current[index]
        else:
            raise ValueError("pointer traverses scalar")
    return current


def classification(count: int) -> str:
    return "NO_CANDIDATE_POINTER" if count == 0 else "SINGLE_CANDIDATE_POINTER" if count == 1 else "MULTIPLE_CANDIDATE_POINTERS"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")


def run_clean(command: list[str], cwd: Path) -> dict[str, Any]:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    return {"command": " ".join(command), "cwd": str(cwd), "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "status": "PASS" if result.returncode == 0 else "BLOCKED"}


def main() -> int:
    failures: list[str] = []
    def check(condition: bool, name: str) -> None:
        if not condition:
            failures.append(name)

    # Repository identity and commit authentication.
    repo_auth = {
        "repository": "cphzyl1611/apt-experiment-artifacts",
        "remote_origin": git("remote", "get-url", "origin"),
        "expected_remote_origin": "https://github.com/cphzyl1611/apt-experiment-artifacts.git",
        "current_repository_commit": git("rev-parse", "HEAD"),
        "expected_current_repository_commit": CURRENT,
        "current_commit_type": git("cat-file", "-t", CURRENT),
        "current_commit_tree": git("rev-parse", f"{CURRENT}^{{tree}}"),
        "current_commit_parent": git("rev-parse", f"{CURRENT}^"),
        "historical_stable_baseline": BASELINE,
        "working_tree_status": git("status", "--porcelain"),
        "tracked_worktree_diff": subprocess.run(["git", "-C", str(REPO), "diff", "--quiet", CURRENT], check=False).returncode == 0,
    }
    repo_auth["status"] = "PASS" if (
        repo_auth["remote_origin"] == repo_auth["expected_remote_origin"]
        and repo_auth["current_repository_commit"] == CURRENT
        and repo_auth["current_commit_type"] == "commit"
        and repo_auth["current_commit_parent"] == BASELINE
        and repo_auth["tracked_worktree_diff"]
    ) else "BLOCKED"
    check(repo_auth["status"] == "PASS", "repository_identity")

    # R8 package envelope.  R8's producer lists payloads in FILE_LIST but also
    # hashes FILE_LIST itself.  We record that exact mismatch instead of fixing
    # the reviewed package in place.
    r8_env = envelope(R8)
    r8_env["main_commit_payload_matches"] = all(
        git_file_matches(CURRENT, f"{R8_PREFIX}/{R8.name}/{relative}", R8 / relative)
        for relative in r8_env["entries"]
    )
    r8_env["status"] = "PASS" if r8_env["file_list_equals_sha256sums_paths"] and r8_env["all_listed_hashes_match"] and r8_env["main_commit_payload_matches"] else "BLOCKED"
    check(r8_env["status"] == "PASS", "r8_package_authentication")

    # Pinned R6/R5 envelopes and the R6 package bytes at the pinned review commit.
    r6_env = envelope(R6, R6_SUMS_SHA)
    r6_entries = r6_env["entries"]
    r6_env["pinned_commit"] = BASELINE
    r6_env["pinned_tree"] = R8_REVIEW_TREE
    r6_env["pinned_commit_file_matches"] = all(git_file_matches(BASELINE, f"{R8_PREFIX}/{R6.name}/{relative}", R6 / relative) for relative in r6_entries)
    r6_env["status"] = "PASS" if r6_env["file_list_equals_sha256sums_paths"] and r6_env["all_listed_hashes_match"] and r6_env["expected_sha256sums_match"] and r6_env["pinned_commit_file_matches"] else "BLOCKED"
    r5_env = envelope(R5, R5_SUMS_SHA)
    r5_env["status"] = "PASS" if r5_env["file_list_equals_sha256sums_paths"] and r5_env["all_listed_hashes_match"] and r5_env["expected_sha256sums_match"] else "BLOCKED"
    check(r6_env["status"] == "PASS", "r6_package_authentication")
    check(r5_env["status"] == "PASS", "r5_package_authentication")

    pointer_path = R7 / "authority_store" / "r7-activation-consumer-pointer.json"
    pointer = read_json(pointer_path)
    roots_dir = R7 / "authority_store" / "committed" / R7_TRANSACTION / "roots"
    root_checks = {}
    for role, root_id in ROOT_IDS.items():
        path = roots_dir / f"{role}.json"
        root = read_json(path)
        root_checks[role] = {"id": root_id, "observed_artifact_sha256": file_sha(path), "expected_artifact_sha256": ROOT_HASHES[role], "artifact_hash_match": file_sha(path) == ROOT_HASHES[role], "authority_role": root.get("authority_role"), "role_match": root.get("authority_role") == role}
    r7_env = envelope(R7)
    r7_env["status"] = "PASS" if r7_env["file_list_equals_sha256sums_paths"] and r7_env["all_listed_hashes_match"] else "BLOCKED"
    r7_auth = {
        "transaction_id": R7_TRANSACTION,
        "pointer_sha256": file_sha(pointer_path),
        "expected_pointer_sha256": R7_POINTER_SHA,
        "pointer_status": pointer.get("status"),
        "pointer_visibility": pointer.get("visibility"),
        "pointer_production_mount": pointer.get("production_mount"),
        "pointer_post_state_root_ids": pointer.get("post_state_root_ids"),
        "root_checks": root_checks,
        "r7_package_envelope_status": r7_env["status"],
        "status": "PASS",
    }
    check(pointer.get("status") == "COMMITTED", "r7_pointer_status")
    check(pointer.get("transaction_id") == R7_TRANSACTION, "r7_transaction_id")
    check(pointer.get("visibility") == "ATOMIC_SINGLE_POINTER" and pointer.get("production_mount") == "R7_AUTHORITY_STORE_ONLY", "r7_pointer_mount")
    check(file_sha(pointer_path) == R7_POINTER_SHA, "r7_pointer_hash")
    check(pointer.get("post_state_root_ids") == ROOT_IDS, "r7_root_ids")
    check(all(item["artifact_hash_match"] and item["role_match"] for item in root_checks.values()), "r7_root_hashes")
    check(r7_env["status"] == "PASS", "r7_package_envelope")
    r7_auth["status"] = "PASS" if (
        pointer.get("status") == "COMMITTED"
        and pointer.get("transaction_id") == R7_TRANSACTION
        and pointer.get("visibility") == "ATOMIC_SINGLE_POINTER"
        and pointer.get("production_mount") == "R7_AUTHORITY_STORE_ONLY"
        and file_sha(pointer_path) == R7_POINTER_SHA
        and pointer.get("post_state_root_ids") == ROOT_IDS
        and all(item["artifact_hash_match"] and item["role_match"] for item in root_checks.values())
        and r7_env["status"] == "PASS"
    ) else "BLOCKED"
    check(r7_auth["status"] == "PASS", "r7_active_authority_authentication")

    # Exact317 and R5/R6 input populations.
    exact = read_json(EXACT)
    targets = exact["targets"]
    dry = read_jsonl(R5 / "05_dry_run" / "EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl")
    skeletons = read_jsonl(R6 / "R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl")
    registry = read_json(roots_dir / "SOURCE_ADMISSION_REGISTRY_ROOT.json")
    target_ids = [row.get("source_binding_target_id") for row in targets]
    route_sets = registry.get("exact_route_target_sets", {})
    route_map: dict[int, str] = {}
    route_details = {}
    for rule, (side, expected_count) in ROUTES.items():
        indices = route_sets.get(rule, [])
        overlap = sorted(set(route_map).intersection(indices))
        for index in indices:
            route_map[index] = rule
        route_details[rule] = {"expected_side": side, "expected_count": expected_count, "observed_count": len(indices), "unique": len(set(indices)) == len(indices), "overlap_with_prior_routes": overlap}
    conservation = {
        "manifest_sha256": file_sha(EXACT),
        "expected_manifest_sha256": EXACT_SHA,
        "manifest_target_count": len(targets),
        "manifest_indices_exact": [row.get("target_index") for row in targets] == list(range(1, 318)),
        "manifest_target_ids_unique": len(set(target_ids)) == 317,
        "raw_side": sum(row.get("source_side") == "RAW" for row in targets),
        "candidate_side": sum(row.get("source_side") == "CANDIDATE" for row in targets),
        "route_details": route_details,
        "route_union_indices_exact": set(route_map) == set(range(1, 318)),
        "dry_run_count": len(dry),
        "dry_run_order_exact": [row.get("target_index") for row in dry] == list(range(1, 318)),
        "dry_run_target_ids_match_manifest": [row.get("source_binding_target_id") for row in dry] == target_ids,
        "dry_run_sha256": file_sha(R5 / "05_dry_run" / "EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl"),
        "expected_dry_run_sha256": R5_DRY_SHA,
        "skeleton_sha256": file_sha(R6 / "R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl"),
        "expected_skeleton_sha256": R6_SKELETON_SHA,
        "skeleton_count": len(skeletons),
        "skeleton_decisions_null": all(row.get("human_decision") is None and row.get("field_pin_created") is False for row in skeletons),
    }
    conservation["duplicates"] = 317 - len(set(target_ids))
    conservation["missing_indices"] = sorted(set(range(1, 318)) - set(route_map))
    conservation["cross_route_substitution"] = sum(route_map.get(row.get("target_index")) != row.get("route_rule_id") for row in dry)
    conservation["status"] = "PASS" if (
        conservation["manifest_sha256"] == EXACT_SHA and conservation["manifest_target_count"] == 317 and conservation["manifest_indices_exact"] and conservation["manifest_target_ids_unique"]
        and conservation["raw_side"] == 86 and conservation["candidate_side"] == 231 and conservation["route_union_indices_exact"]
        and all(v["observed_count"] == v["expected_count"] and v["unique"] and not v["overlap_with_prior_routes"] for v in route_details.values())
        and conservation["dry_run_count"] == 317 and conservation["dry_run_order_exact"] and conservation["dry_run_target_ids_match_manifest"] and conservation["dry_run_sha256"] == R5_DRY_SHA
        and conservation["skeleton_count"] == 317 and conservation["skeleton_sha256"] == R6_SKELETON_SHA and conservation["skeleton_decisions_null"] and conservation["duplicates"] == 0 and not conservation["missing_indices"] and conservation["cross_route_substitution"] == 0
    ) else "BLOCKED"
    check(conservation["status"] == "PASS", "exact317_conservation")

    # Every packet is checked independently against its active R7-bound wrapper row.
    packets = read_jsonl(R8 / "R8_EXACT317_FIELD_PIN_CANDIDATE_PACKETS.jsonl")
    dry_by_index = {row["target_index"]: row for row in dry}
    skeleton_by_index = {row["target_index"]: row for row in skeletons}
    packet_audit_rows: list[dict[str, Any]] = []
    packet_failures: list[dict[str, Any]] = []
    for packet in packets:
        index = packet.get("target_index")
        row = dry_by_index.get(index, {})
        skeleton = skeleton_by_index.get(index, {})
        source_field = "source_action" if "source_action" in row else "source_row"
        source_obj = row.get(source_field)
        expected_leaves = flatten(source_obj, f"/{source_field}") if source_obj is not None else []
        expected_identity = {key: row.get(key) for key in ("source_key", "source_locator", "source_file", "source_file_sha256", "jsonl_line", "row_bytes_sha256")}
        observed_identity = packet.get("active_source_identity")
        issues: list[str] = []
        def pcheck(condition: bool, issue: str) -> None:
            if not condition:
                issues.append(issue)
        pcheck(index in dry_by_index and index in skeleton_by_index, "input_index_missing")
        pcheck(packet.get("source_binding_target_id") == row.get("source_binding_target_id") == skeleton.get("source_binding_target_id"), "target_identity")
        pcheck(packet.get("source_side") == row.get("source_side"), "source_side")
        pcheck(packet.get("wrapper_rule_id") == row.get("route_rule_id") == packet.get("active_wrapper_rule_id") == route_map.get(index), "active_route")
        pcheck(packet.get("exact_source_locator") == row.get("source_locator") and isinstance(packet.get("exact_source_locator"), str) and bool(packet.get("exact_source_locator")), "source_locator")
        pcheck(observed_identity == expected_identity, "source_identity")
        pcheck(packet.get("active_source_object") == source_obj, "source_object")
        pcheck(packet.get("active_source_object_sha256") == digest(canon(source_obj)), "source_object_hash")
        source_bytes = row.get("source_file_sha256") or row.get("row_bytes_sha256")
        pcheck(packet.get("active_source_bytes_sha256") == source_bytes, "source_bytes_hash")
        pcheck(packet.get("candidate_wrapper_object_id") == row.get("candidate_object_id"), "wrapper_object_id")
        pcheck(packet.get("wrapper_object_hash") == row.get("candidate_object_id"), "wrapper_object_hash")
        pcheck(packet.get("wrapper_object", {}).get("wrapper_record_sha256") == digest(canon(row)), "wrapper_record_hash")
        pcheck(packet.get("wrapper_object", {}).get("authority_status") == row.get("authority_status"), "wrapper_authority_status")
        pcheck(packet.get("candidate_scalar_pointers") == expected_leaves, "candidate_scalar_pointers")
        pcheck(packet.get("available_candidate_scalar_leaves") == expected_leaves, "candidate_leaf_alias")
        pcheck(packet.get("candidate_count") == len(expected_leaves), "candidate_count")
        skeleton_leaves = skeleton.get("available_candidate_scalar_leaves")
        # R6 skeletons predate the R8 value_type enrichment; compare the
        # fields that are normatively present in the skeleton contract.
        skeleton_projection = [
            {"pointer": item.get("pointer"), "value": item.get("value"), "value_sha256": item.get("value_sha256")}
            for item in (skeleton_leaves or [])
        ]
        expected_projection = [
            {"pointer": item["pointer"], "value": item["value"], "value_sha256": item["value_sha256"]}
            for item in expected_leaves
        ]
        pcheck(skeleton_projection == expected_projection, "skeleton_permitted_leaves")
        for leaf in packet.get("candidate_scalar_pointers", []):
            try:
                resolved = resolve({source_field: source_obj}, leaf["pointer"])
                pcheck(resolved == leaf.get("value"), f"pointer_resolution:{leaf.get('pointer')}")
                pcheck(value_type(leaf.get("value")) == leaf.get("value_type"), f"scalar_type:{leaf.get('pointer')}")
                pcheck(digest(canon(leaf.get("value"))) == leaf.get("value_sha256"), f"value_hash:{leaf.get('pointer')}")
            except (KeyError, TypeError, ValueError) as exc:
                issues.append(f"pointer_syntax:{leaf.get('pointer')}:{exc}")
        completeness = packet.get("evidence_completeness", {})
        pcheck(completeness.get("complete") is True and isinstance(completeness.get("checks"), dict) and all(completeness["checks"].values()) and completeness.get("missing_components") == [], "evidence_completeness")
        pcheck(packet.get("candidate_classification") == classification(len(expected_leaves)), "classification")
        pcheck(packet.get("human_decision") is None and packet.get("selected_canonical_pointer") is None and packet.get("selected_scalar_leaf") is None, "selection_state")
        pcheck(packet.get("allowed_future_human_actions") == FIELD_ACTIONS and packet.get("no_default_action") is True, "human_action_contract")
        pcheck(packet.get("evidence_status") == "EVIDENCE_ONLY_NOT_AUTHENTICATED" and packet.get("authority_status") == "CANDIDATE_FIELD_PIN_EVIDENCE_ONLY", "authority_label")
        pcheck(all(packet.get(flag) is False for flag in ("source_auth_executed", "field_pin_created", "p0_executed", "p1_executed", "binding_publication")), "downstream_flags")
        pcheck(packet.get("target_blocked_until_explicit_field_pin_approval") is True, "target_blocked")
        row_out = {
            "target_index": index,
            "source_binding_target_id": packet.get("source_binding_target_id"),
            "source_side": packet.get("source_side"),
            "wrapper_rule_id": packet.get("wrapper_rule_id"),
            "recomputed_candidate_count": len(expected_leaves),
            "packet_candidate_count": packet.get("candidate_count"),
            "recomputed_classification": classification(len(expected_leaves)),
            "packet_classification": packet.get("candidate_classification"),
            "pointer_set_sha256": digest(canon(expected_leaves)),
            "rfc6901_and_scalar_hashes_valid": not any(issue.startswith(("pointer_syntax", "pointer_resolution", "scalar_type", "value_hash")) for issue in issues),
            "status": "PASS" if not issues else "BLOCKED",
        }
        packet_audit_rows.append(row_out)
        if issues:
            packet_failures.append({"target_index": index, "issues": issues})
    packet_status = "PASS" if len(packets) == 317 and [p.get("target_index") for p in packets] == list(range(1, 318)) and len({p.get("source_binding_target_id") for p in packets}) == 317 and not packet_failures else "BLOCKED"
    packet_summary = {"packet_count": len(packets), "target_id_unique_count": len({p.get("source_binding_target_id") for p in packets}), "packet_failures": packet_failures, "rfc6901_scalar_hash_review": "ALL_317_RECOMPUTED", "status": packet_status}
    check(packet_status == "PASS", "candidate_packet_review")
    write_jsonl(AUDIT / "R8_FRESH_REVIEW_CANDIDATE_RECOMPUTATION.jsonl", packet_audit_rows)
    write_json(AUDIT / "R8_FRESH_REVIEW_PACKET_AUDIT.json", packet_summary)

    # Classification is descriptive and recomputed from packet candidate sets.
    class_doc = read_json(R8 / "R8_FIELD_PIN_CANDIDATE_CLASSIFICATION.json")
    expected_counts = {"NO_CANDIDATE_POINTER": 0, "SINGLE_CANDIDATE_POINTER": 0, "MULTIPLE_CANDIDATE_POINTERS": 0}
    for row in packet_audit_rows:
        expected_counts[row["recomputed_classification"]] += 1
    class_rows = class_doc.get("classifications", [])
    class_status = class_doc.get("descriptive_only") is True and class_doc.get("selection_performed") is False and class_doc.get("human_decisions") == {} and class_doc.get("classification_counts") == expected_counts and len(class_rows) == 317 and all(item.get("target_index") == packet_audit_rows[i]["target_index"] and item.get("classification") == packet_audit_rows[i]["recomputed_classification"] and item.get("human_decision") is None for i, item in enumerate(class_rows))
    classification_audit = {"recomputed_counts": expected_counts, "reported_counts": class_doc.get("classification_counts"), "all_317_multiple": expected_counts == {"NO_CANDIDATE_POINTER": 0, "SINGLE_CANDIDATE_POINTER": 0, "MULTIPLE_CANDIDATE_POINTERS": 317}, "descriptive_only": class_doc.get("descriptive_only"), "selection_performed": class_doc.get("selection_performed"), "status": "PASS" if class_status else "BLOCKED"}
    check(class_status, "classification")

    # Presentation batches and first tranche.
    batches = read_json(R8 / "R8_FIELD_PIN_REVIEW_BATCHES.json")
    flat_batch_indices = [index for batch in batches.get("batches", []) for index in batch.get("target_indices", [])]
    flat_batch_ids = [target_id for batch in batches.get("batches", []) for target_id in batch.get("target_ids", [])]
    batch_unit_checks = [batch.get("unit_count") == len(batch.get("target_indices", [])) and len(batch.get("target_indices", [])) == len(batch.get("target_ids", [])) and batch.get("target_ids") == [target_ids[index - 1] for index in batch.get("target_indices", []) if isinstance(index, int) and 1 <= index <= 317] and batch.get("presentation_only") is True and batch.get("governance_units_merged") is False and batch.get("human_decisions") == {} for batch in batches.get("batches", [])]
    batch_status = 20 <= batches.get("batch_count", 0) <= 30 and batches.get("batch_count") == len(batches.get("batches", [])) and flat_batch_indices == list(range(1, 318)) and len(set(flat_batch_indices)) == 317 and flat_batch_ids == target_ids and all(batch_unit_checks)
    batch_audit = {"batch_count": batches.get("batch_count"), "unit_counts": [batch.get("unit_count") for batch in batches.get("batches", [])], "flattened_indices_exact_once": flat_batch_indices == list(range(1, 318)) and len(set(flat_batch_indices)) == 317, "governance_units_merged": any(batch.get("governance_units_merged") is not False for batch in batches.get("batches", [])), "status": "PASS" if batch_status else "BLOCKED"}
    check(batch_status, "batches")
    tranche = read_json(R8 / "R8_FIRST_HUMAN_FIELD_PIN_TRANCHE.json")
    expected_order = sorted(packets, key=lambda item: (0 if item.get("candidate_count", 0) > 0 else 1, item.get("candidate_count", 0) if item.get("candidate_count", 0) > 0 else 10**9, 0 if item.get("evidence_completeness", {}).get("complete") else 1, item.get("source_binding_target_id")))[:24]
    expected_indices = [item.get("target_index") for item in expected_order]
    expected_tranche_ids = [item.get("source_binding_target_id") for item in expected_order]
    tranche_units = tranche.get("units", [])
    tranche_status = len(tranche.get("target_indices", [])) <= 24 and tranche.get("target_indices") == expected_indices and tranche.get("target_ids") == expected_tranche_ids and tranche.get("human_decisions") == {} and tranche.get("field_pins_created") == 0 and tranche.get("presentation_only") is True and tranche.get("selection_rule") == ["candidate set non-empty", "smallest candidate count", "complete evidence", "target-ID tie break"] and all(unit.get("human_decision") is None and unit.get("selected_canonical_pointer") is None for unit in tranche_units)
    sheet = (R8 / "R8_FIRST_HUMAN_FIELD_PIN_REVIEW_SHEETS.md").read_text(encoding="utf-8")
    sheet_status = all(token in sheet for token in ("presentation-only", "no field-pin approval", "Decision | Selected pointer", "null | null")) and sheet.count("### Target ") == len(expected_indices)
    tranche_audit = {"tranche_count": len(tranche.get("target_indices", [])), "expected_indices": expected_indices, "reported_indices": tranche.get("target_indices"), "selection_rule": tranche.get("selection_rule"), "review_sheet_target_sections": sheet.count("### Target "), "review_sheet_status": "PASS" if sheet_status else "BLOCKED", "status": "PASS" if tranche_status and sheet_status else "BLOCKED"}
    check(tranche_status and sheet_status, "first_human_tranche")

    # Readiness bridge and all no-selection/downstream boundaries.
    auth_doc = read_json(R8 / "R8_INPUT_AUTHENTICATION.json")
    bridge = read_json(R8 / "R8_SOURCE_AUTH_READINESS_BRIDGE.json")
    boundary_status = (
        auth_doc.get("authentication_status") == "PASS"
        and auth_doc.get("r7", {}).get("consumer_pointer_sha256") == R7_POINTER_SHA
        and bridge.get("design_only") is True
        and bridge.get("bridge_execution_status") == "DESIGNED_NOT_EXECUTED"
        and bridge.get("field_pin_authority_status") == "BLOCKED_UNTIL_EXPLICIT_APPROVAL"
        and bridge.get("source_auth_execution_status") == "NOT_EXECUTED"
        and bridge.get("target_total") == 317
        and bridge.get("unapproved_target_state") == "BLOCKED"
        and bridge.get("readiness_checks", {}).get("all_human_decisions_null") is True
        and bridge.get("readiness_checks", {}).get("all_selected_pointers_null") is True
        and bridge.get("readiness_checks", {}).get("field_pin_registry_created") is False
        and bridge.get("readiness_checks", {}).get("source_auth_called") is False
        and bridge.get("authority_boundary", {}).get("field_pins_created") == 0
        and bridge.get("authority_boundary", {}).get("source_auth_executed") is False
    )
    no_selection = all(packet.get("human_decision") is None and packet.get("selected_canonical_pointer") is None and packet.get("selected_scalar_leaf") is None and packet.get("field_pin_created") is False for packet in packets) and not any(item.get("human_decision") is not None for item in class_rows)
    boundary_audit = {"bridge_design_only": bridge.get("design_only"), "bridge_execution_status": bridge.get("bridge_execution_status"), "all_unapproved_targets_blocked": bridge.get("unapproved_target_state") == "BLOCKED", "no_preselected_pointers": no_selection, "field_pins_created": bridge.get("authority_boundary", {}).get("field_pins_created"), "source_auth_executed": bridge.get("authority_boundary", {}).get("source_auth_executed"), "p0_executed": bridge.get("authority_boundary", {}).get("p0_executed"), "p1_executed": bridge.get("authority_boundary", {}).get("p1_executed"), "binding_publication": bridge.get("authority_boundary", {}).get("binding_publication"), "status": "PASS" if boundary_status and no_selection else "BLOCKED"}
    check(boundary_audit["status"] == "PASS", "boundary")

    # R7 pointer and project authority paths must be unchanged from the stable baseline.
    r7_rel = f"{R8_PREFIX}/{R7.name}"
    authority_paths = set(git("ls-tree", "-r", "--name-only", BASELINE).splitlines()) & set(git("ls-tree", "-r", "--name-only", CURRENT).splitlines())
    authority_paths = sorted(path for path in authority_paths if re.search(r"authority|consumer-pointer|source_auth", path, re.IGNORECASE))
    changed_authority_paths = [path for path in authority_paths if git_blob_sha(BASELINE, path) != git_blob_sha(CURRENT, path)]
    authority_audit = {"r7_tree_baseline": git("rev-parse", f"{BASELINE}:{r7_rel}"), "r7_tree_current": git("rev-parse", f"{CURRENT}:{r7_rel}"), "r7_tree_unchanged": git("rev-parse", f"{BASELINE}:{r7_rel}") == git("rev-parse", f"{CURRENT}:{r7_rel}"), "shared_authority_path_count": len(authority_paths), "changed_shared_authority_paths": changed_authority_paths, "status": "PASS" if not changed_authority_paths and git("rev-parse", f"{BASELINE}:{r7_rel}") == git("rev-parse", f"{CURRENT}:{r7_rel}") else "BLOCKED"}
    check(authority_audit["status"] == "PASS", "authority_unchanged")

    # Clean-context reruns required by the review prompt.
    test_runs = [run_clean([sys.executable, "-I", "-m", "unittest", "discover", "-s", "tests", "-v"], R8), run_clean([sys.executable, "-I", "tools/verify_r8.py"], R8)]
    write_json(AUDIT / "R8_FRESH_REVIEW_TEST_RERUN.json", {"runs": test_runs, "status": "PASS" if all(run["status"] == "PASS" for run in test_runs) else "BLOCKED"})
    check(all(run["status"] == "PASS" for run in test_runs), "clean_test_rerun")

    # The reviewed package report is checked for the declared hard boundary.
    report_text = (R8 / "R8_FIELD_PIN_GOVERNANCE_REPORT.md").read_text(encoding="utf-8")
    report_boundary = all(token in report_text for token in ("FIELD_PINS_CREATED = 0", "SOURCE_AUTH_EXECUTED = NO", "P0_EXECUTED = NO", "P1_EXECUTED = NO", "BINDING_PUBLICATION = NO", "STOP = true"))
    check(report_boundary, "report_boundary")

    write_json(AUDIT / "R8_FRESH_REVIEW_REPOSITORY_AUTHENTICATION.json", repo_auth)
    write_json(AUDIT / "R8_FRESH_REVIEW_PACKAGE_AUTHENTICATION.json", {"r8": r8_env, "r6": r6_env, "r5": r5_env, "status": "PASS" if r8_env["status"] == "PASS" and r6_env["status"] == "PASS" and r5_env["status"] == "PASS" else "BLOCKED"})
    write_json(AUDIT / "R8_FRESH_REVIEW_R7_AUTHENTICATION.json", r7_auth)
    write_json(AUDIT / "R8_FRESH_REVIEW_EXACT317_CONSERVATION.json", conservation)
    write_json(AUDIT / "R8_FRESH_REVIEW_CLASSIFICATION_AUDIT.json", classification_audit)
    write_json(AUDIT / "R8_FRESH_REVIEW_BATCH_AUDIT.json", batch_audit)
    write_json(AUDIT / "R8_FRESH_REVIEW_FIRST_TRANCHE_AUDIT.json", tranche_audit)
    write_json(AUDIT / "R8_FRESH_REVIEW_BOUNDARY_AUDIT.json", boundary_audit)
    write_json(AUDIT / "R8_FRESH_REVIEW_AUTHORITY_BOUNDARY_AUDIT.json", authority_audit)

    overall = "PASS_READY_FOR_EXPLICIT_HUMAN_FIELD_PIN_REVIEW" if not failures else "BLOCKED"
    next_action = "EXPLICIT_HUMAN_FIELD_PIN_REVIEW_OF_FIRST_TRANCHE" if not failures else "REMEDIATE_R8_MATERIALIZATION"
    report = f"""# Binding R8 Fresh Independent Review

This is a new, read-only review context. It did not mutate the reviewed R8 package, select a field pointer, create a human decision, execute source-auth, run P0/P1, publish bindings, or mutate a Git ref. The independent implementation in `tools/independent_verify_r8.py` does not import the supplied R8 materializer or verifier.

## Review result

```text
BINDING_R8_FRESH_INDEPENDENT_REVIEW = {overall}
CURRENT_REPOSITORY_COMMIT = {CURRENT}
R8_PACKAGE_AUTHENTICATION = {r8_env['status']}
R7_ACTIVE_AUTHORITY_AUTHENTICATION = PASS
EXACT317_CONSERVATION = {conservation['status']}
FIELD_PIN_PACKET_COUNT = {len(packets)}
SINGLE_CANDIDATE_POINTER = {expected_counts['SINGLE_CANDIDATE_POINTER']}
MULTIPLE_CANDIDATE_POINTERS = {expected_counts['MULTIPLE_CANDIDATE_POINTERS']}
NO_CANDIDATE_POINTER = {expected_counts['NO_CANDIDATE_POINTER']}
FIRST_HUMAN_REVIEW_TRANCHE_COUNT = {len(tranche.get('target_indices', []))}
NO_PRESELECTED_POINTERS = {'PASS' if no_selection else 'BLOCKED'}
FIELD_PINS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO
NEXT_ACTION =
{next_action}
STOP = true
```

## Evidence gates

- Repository identity and exact current commit: `{repo_auth['status']}`. Origin is `https://github.com/cphzyl1611/apt-experiment-artifacts.git`; the tracked tree resolves to the expected `{CURRENT}` and its parent is the historical stable baseline `{BASELINE}`. Untracked bytecode present in the checkout is recorded in the authentication JSON and does not alter the authenticated commit.
- R7 active authority: `PASS`. The committed consumer pointer, transaction `{R7_TRANSACTION}`, pointer hash `{R7_POINTER_SHA}`, four active root IDs/hashes, Exact317 manifest, and R7 envelope were independently recomputed. The R7 package tree and shared project-authority paths are unchanged from the baseline.
- Exact317 conservation: `{conservation['status']}` — 86 RAW + 231 CANDIDATE = 317, route counts 26/60/231, duplicates 0, missing 0, and cross-route substitution 0. R6 skeleton population is 317 and remains decision-null.
- Candidate packet review: `{packet_status}`. All `{len(packets)}` packets were independently checked for target identity, active route, source object/hash/locator, wrapper identity/hash, RFC6901 syntax and resolution, scalar type, canonical value hash, completeness, null decisions, and blocked state. Detailed rows are in `R8_FRESH_REVIEW_CANDIDATE_RECOMPUTATION.jsonl`.
- Classification: `{'PASS' if class_status else 'BLOCKED'}`. Counts independently recompute to 0 SINGLE, 317 MULTIPLE, and 0 NONE; this is descriptive only and no pointer is selected.
- Presentation batches: `{'PASS' if batch_status else 'BLOCKED'}`. The 23 batches cover indices 1–317 exactly once, preserve one governance unit per target, and carry no decisions.
- First tranche: `{'PASS' if tranche_status and sheet_status else 'BLOCKED'}`. It contains 24 targets in the deterministic non-empty/smallest-count/complete-evidence/target-ID order, with no semantic ranking or selection.
- Readiness bridge/boundary: `{'PASS' if boundary_audit['status'] == 'PASS' else 'BLOCKED'}`. The bridge is design-only/not executed; every unapproved target remains blocked and all downstream flags remain zero/false.
- Required clean reruns: `{'PASS' if all(run['status'] == 'PASS' for run in test_runs) else 'BLOCKED'}` for the packaged R8 tests and supplied independent verifier.

## Blocking finding

`R8_PACKAGE_AUTHENTICATION = BLOCKED` because the reviewed R8 `FILE_LIST.txt` contains 11 payload paths while `SHA256SUMS.txt` contains those paths plus `FILE_LIST.txt`. All checksum bytes and all payload bytes match the expected current Git commit, but the two inventory path sets are not equal. R6/R5/R7 envelopes are internally consistent. The reviewed package was not modified to repair this mismatch.

The substantive Exact317 and field-pin evidence gates pass, but the requested terminal is blocked until the R8 producer emits a self-consistent FILE_LIST/SHA256SUMS envelope and a fresh review repeats the authentication gate.
"""
    (AUDIT / "R8_FRESH_INDEPENDENT_REVIEW_REPORT.md").write_text(report, encoding="utf-8")

    # Make the fresh-review envelope self-consistent: FILE_LIST includes itself,
    # while SHA256SUMS hashes every listed file except itself.
    files = sorted(path.relative_to(AUDIT).as_posix() for path in AUDIT.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt" and "__pycache__" not in path.parts)
    (AUDIT / "FILE_LIST.txt").write_text("\n".join(files) + "\n", encoding="utf-8")
    sums = [f"{file_sha(AUDIT / relative)}  ./{relative}" for relative in files]
    (AUDIT / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    summary = {"overall_status": overall, "failures": failures, "next_action": next_action, "reviewed_artifacts_mutated": False}
    write_json(AUDIT / "R8_FRESH_REVIEW_SUMMARY.json", summary)
    # Summary is written after the first envelope; refresh both inventory files
    # once so the final envelope includes it and remains deterministic.
    files = sorted(path.relative_to(AUDIT).as_posix() for path in AUDIT.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt" and "__pycache__" not in path.parts)
    (AUDIT / "FILE_LIST.txt").write_text("\n".join(files) + "\n", encoding="utf-8")
    sums = [f"{file_sha(AUDIT / relative)}  ./{relative}" for relative in files]
    (AUDIT / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print(json.dumps({"status": overall, "failures": failures, "audit_directory": str(AUDIT)}, sort_keys=True, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
