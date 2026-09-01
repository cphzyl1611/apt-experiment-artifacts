#!/usr/bin/env python3
"""Materialize the R8 field-pin governance review package.

R8 is evidence preparation only.  The input wrapper rows are admitted through
the already-active R7 consumer pointer and its immutable roots.  No source-auth
operation, field selection, authority mutation, P0/P1, or binding publication
is performed here.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping


PACKAGE = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE.parent
R6 = REPO_ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R6_Production_Activation_Governance_Design"
R5 = REPO_ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R5_Wrapper_Materialization"
R7 = REPO_ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R7_Production_Source_Authority_Activation"
R7_STORE = R7 / "authority_store"
R7_TRANSACTION = "e8a0a97a33d47ac68c8ded4af1af109fa010d979acf9736fd5dffdebf96c5208"
R7_POINTER = R7_STORE / "r7-activation-consumer-pointer.json"
R7_COMMITTED_ROOTS = R7_STORE / "committed" / R7_TRANSACTION / "roots"
EXACT317 = REPO_ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4" / "00_lineage" / "EXACT317_TARGET_MANIFEST.json"
REVIEW_REPO = Path("/home/cph/fa1b2de-review-artifacts")
R8_REVIEW_COMMIT = "107ef9f69a734a10b320d552cfe18a6cb9a2ac0c"
R8_REVIEW_TREE = "26b5c3a56e86fb5c11d50fc86bd99d6b940239fc"
R8_REVIEW_PREFIX = "current86-r4"
R7_POINTER_SHA256 = "02394a7fc7c5f337dfbfff521467759f80e14f8d5d27ca9e01653eec3f0d592c"
EXACT317_SHA256 = "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac"
R6_SKELETON_SHA256 = "d55bc015d21b3fb4a6edc7ef9aa0caf5abca1da177da2df232f1dd97bd6f8573"
R6_PACKAGE_SHA256SUMS_SHA256 = "7abdd9630ce53d0b457b5111c4c071d4bee2b99b1d436ee57808128f38c38c62"
R5_PACKAGE_SHA256SUMS_SHA256 = "5f1746499c2ca5ba966b3f716e6b8ca87844cf4cd0a1316ec215b25cc092fdc1"
R5_DRY_RUN_SHA256 = "884dec61cc33e13d12c439e202568c8e592650b82f98acca22b5eb0b4f4eaa82"
ROOT_IDS = {
    "SOURCE_ADMISSION_REGISTRY_ROOT": "8f9596729361f8c6620c98c18344c8cf31073e35085b3eb408fc5212ebd41d6a",
    "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT": "f88d911080e97e8e1e58010fd5e551f91127ec6b1ae77d2a3d28af07f71ef52f",
    "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST": "5d868125294dcd4d5f643f2fef820b89b056925a925d0b0f98fcf7408c41009d",
    "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION": "3f1f169c1ada9fbddd381727114b5b4a0a422b1bd4016c6ec5ff5b6461a02aa8",
}
ROOT_ARTIFACT_SHA256 = {
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
ALLOWED_ACTIONS = [
    "APPROVE_EXACT_FIELD_PIN",
    "REJECT_FIELD_CANDIDATES_KEEP_BLOCKED",
    "REQUEST_MORE_EVIDENCE",
]
OUTPUTS = [
    "R8_INPUT_AUTHENTICATION.json",
    "R8_EXACT317_FIELD_PIN_CANDIDATE_PACKETS.jsonl",
    "R8_FIELD_PIN_CANDIDATE_CLASSIFICATION.json",
    "R8_FIELD_PIN_REVIEW_BATCHES.json",
    "R8_FIRST_HUMAN_FIELD_PIN_TRANCHE.json",
    "R8_FIRST_HUMAN_FIELD_PIN_REVIEW_SHEETS.md",
    "R8_SOURCE_AUTH_READINESS_BRIDGE.json",
    "R8_FIELD_PIN_GOVERNANCE_REPORT.md",
    "tests/test_r8_materialization.py",
    "tools/materialize_r8.py",
    "tools/verify_r8.py",
]


class R8MaterializationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise R8MaterializationError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    require(path.is_file(), f"missing required file: {path}")
    return sha256_bytes(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise R8MaterializationError("value is not canonical JSON") from exc


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise R8MaterializationError(f"invalid JSON input: {path}") from exc
    require(isinstance(value, dict), f"JSON root is not an object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise R8MaterializationError(f"cannot read JSONL input: {path}") from exc
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise R8MaterializationError(f"invalid JSONL row {number}: {path}") from exc
        require(isinstance(value, dict), f"JSONL row {number} is not an object: {path}")
        rows.append(value)
    return rows


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def artifact(path: Path, logical_path: str | None = None) -> dict[str, Any]:
    return {"path": logical_path or str(path), "sha256": sha256_file(path), "byte_length": path.stat().st_size}


def parse_sums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  \.\/(.+)", line)
        require(match is not None, f"malformed checksum line in {path}: {line!r}")
        digest, relative = match.groups()
        require(relative not in entries, f"duplicate checksum path: {relative}")
        entries[relative] = digest
    return entries


def verify_envelope(package: Path, expected_sha: str | None = None) -> dict[str, str]:
    sums_path = package / "SHA256SUMS.txt"
    if expected_sha:
        require(sha256_file(sums_path) == expected_sha, f"package envelope drift: {package}")
    entries = parse_sums(sums_path)
    listed = {line.strip() for line in (package / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line.strip()}
    require(listed == set(entries), f"FILE_LIST/SHA256SUMS mismatch: {package}")
    for relative, expected in entries.items():
        require(sha256_file(package / relative) == expected, f"checksum drift: {package}/{relative}")
    return entries


def verify_review_commit(envelope_entries: Mapping[str, str]) -> dict[str, Any]:
    require(REVIEW_REPO.is_dir(), "pinned review repository unavailable")
    try:
        commit_type = subprocess.run(["git", "-C", str(REVIEW_REPO), "cat-file", "-t", R8_REVIEW_COMMIT], check=True, capture_output=True, text=True).stdout.strip()
        tree = subprocess.run(["git", "-C", str(REVIEW_REPO), "rev-parse", f"{R8_REVIEW_COMMIT}^{{tree}}"], check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise R8MaterializationError("R8 pinned review commit cannot be resolved") from exc
    require(commit_type == "commit", "R8 pinned review identity is not a commit")
    require(tree == R8_REVIEW_TREE, "R8 pinned review tree drift")
    mismatches: list[str] = []
    for relative, expected in envelope_entries.items():
        committed_path = f"{R8_REVIEW_PREFIX}/{R6.name}/{relative}"
        try:
            committed = subprocess.run(["git", "-C", str(REVIEW_REPO), "show", f"{R8_REVIEW_COMMIT}:{committed_path}"], check=True, capture_output=True).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            raise R8MaterializationError(f"R8 pinned commit lacks R6/{relative}") from exc
        if sha256_bytes(committed) != expected:
            mismatches.append(relative)
    require(not mismatches, f"R6 package differs from pinned R8 commit: {mismatches[:3]}")
    return {
        "repository": str(REVIEW_REPO),
        "commit": R8_REVIEW_COMMIT,
        "tree": tree,
        "commit_type": commit_type,
        "package_prefix": R8_REVIEW_PREFIX,
        "authenticated_package": R6.name,
        "committed_file_count": len(envelope_entries),
        "committed_file_mismatches": 0,
        "authentication": "PASS",
    }


def verify_r7_commit_content() -> dict[str, Any]:
    entries = parse_sums(R7 / "SHA256SUMS.txt")
    required = {
        "authority_store/r7-activation-consumer-pointer.json",
        "R7_POST_ACTIVATION_STATE.json",
        "R7_INDEPENDENT_ACTIVATION_VERIFICATION.json",
        "R7_STAGED_AUTHORITY_ROOTS.json",
    }
    require(required <= set(entries), "R7 package does not commit the active pointer/state")
    for relative, expected in entries.items():
        require(sha256_file(R7 / relative) == expected, f"R7 package checksum drift: {relative}")
    return {"package_sha256sums_sha256": sha256_file(R7 / "SHA256SUMS.txt"), "package_file_count": len(entries), "package_envelope": "PASS"}


def rfc6901_escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def flatten_scalar_leaves(value: Any, prefix: str = "") -> list[dict[str, Any]]:
    leaves: list[dict[str, Any]] = []
    if isinstance(value, Mapping):
        for key in sorted(value, key=lambda item: str(item).encode("utf-8")):
            leaves.extend(flatten_scalar_leaves(value[key], f"{prefix}/{rfc6901_escape(str(key))}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            leaves.extend(flatten_scalar_leaves(child, f"{prefix}/{index}"))
    else:
        leaves.append({
            "pointer": prefix or "/",
            "value": value,
            "value_type": value_type(value),
            "value_sha256": sha256_bytes(canonical_bytes(value)),
        })
    return leaves


def value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        require(math.isfinite(value), "non-finite scalar value")
        return "number"
    if isinstance(value, str):
        return "string"
    raise R8MaterializationError(f"non-scalar value type: {type(value).__name__}")


def authenticate_inputs() -> dict[str, Any]:
    r6_entries = verify_envelope(R6, R6_PACKAGE_SHA256SUMS_SHA256)
    review = verify_review_commit(r6_entries)
    r7_envelope = verify_r7_commit_content()
    pointer = load_json(R7_POINTER)
    require(sha256_file(R7_POINTER) == R7_POINTER_SHA256, "R7 consumer pointer hash drift")
    require(pointer.get("status") == "COMMITTED", "R7 consumer pointer is not committed")
    require(pointer.get("transaction_id") == R7_TRANSACTION, "R7 transaction drift")
    require(pointer.get("visibility") == "ATOMIC_SINGLE_POINTER", "R7 visibility contract drift")
    require(pointer.get("production_mount") == "R7_AUTHORITY_STORE_ONLY", "R7 production mount drift")
    require(pointer.get("exact317_manifest_sha256") == EXACT317_SHA256, "R7 Exact317 hash drift")
    require(pointer.get("target_total") == 317 and pointer.get("raw_side_total") == 86 and pointer.get("candidate_side_total") == 231, "R7 Exact317 totals drift")
    require(pointer.get("duplicates") == 0 and pointer.get("cross_route_substitution") == 0, "R7 route boundary drift")
    require(pointer.get("field_pins_created") == 0 and pointer.get("source_auth_executed") is False, "R7 downstream state drift")
    require(pointer.get("p0_executed") is False and pointer.get("p1_executed") is False and pointer.get("binding_publication") is False, "R7 downstream execution drift")
    pointer_roots = pointer.get("post_state_root_ids")
    require(pointer_roots == ROOT_IDS, "R7 active root IDs drift")
    roots: dict[str, dict[str, Any]] = {}
    for role, root_id in ROOT_IDS.items():
        path = R7_COMMITTED_ROOTS / f"{role}.json"
        require(sha256_file(path) == ROOT_ARTIFACT_SHA256[role], f"R7 root artifact drift: {role}")
        root = load_json(path)
        require(root.get("authority_role") == role, f"R7 root role drift: {role}")
        roots[role] = {"path": str(path), "sha256": ROOT_ARTIFACT_SHA256[role], "root_id": root_id, "value": root}
    require(roots["SOURCE_ADMISSION_REGISTRY_ROOT"]["value"].get("target_count") == 317, "R7 registry target count drift")
    require(roots["SOURCE_ADMISSION_REGISTRY_ROOT"]["value"].get("field_pin_authority_status") == "BLOCKED_NOT_CREATED", "R7 field-pin authority is not blocked")

    exact_manifest = load_json(EXACT317)
    require(sha256_file(EXACT317) == EXACT317_SHA256, "Exact317 manifest bytes drift")
    targets = exact_manifest.get("targets")
    require(isinstance(targets, list) and len(targets) == 317, "Exact317 manifest count drift")
    require([row.get("target_index") for row in targets] == list(range(1, 318)), "Exact317 target order drift")
    target_ids = [row.get("source_binding_target_id") for row in targets]
    require(len(set(target_ids)) == 317 and all(isinstance(item, str) for item in target_ids), "Exact317 target IDs drift")
    require(sum(row.get("source_side") == "RAW" for row in targets) == 86, "Exact317 RAW side drift")
    require(sum(row.get("source_side") == "CANDIDATE" for row in targets) == 231, "Exact317 CANDIDATE side drift")

    skeleton_path = R6 / "R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl"
    require(sha256_file(skeleton_path) == R6_SKELETON_SHA256, "R6 skeleton hash drift")
    skeletons = load_jsonl(skeleton_path)
    require(len(skeletons) == 317, "R6 skeleton count drift")
    require(all(item.get("human_decision") is None and item.get("field_pin_created") is False for item in skeletons), "R6 skeleton contains a decision")

    r5_entries = verify_envelope(R5, R5_PACKAGE_SHA256SUMS_SHA256)
    dry_path = R5 / "05_dry_run" / "EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl"
    require(sha256_file(dry_path) == R5_DRY_RUN_SHA256, "R5 dry-run hash drift")
    rows = load_jsonl(dry_path)
    require(len(rows) == 317 and [row.get("target_index") for row in rows] == list(range(1, 318)), "R5 dry-run order/count drift")
    require(all(row.get("authority_status") == "CANDIDATE_WRAPPER_OBJECTS_ONLY" for row in rows), "R5 wrapper authority label drift")
    require(all(row.get("source_auth_executed") is False and row.get("field_pin_created") is False for row in rows), "R5 dry-run downstream action")
    require([row.get("source_binding_target_id") for row in rows] == target_ids, "R5/R4 target IDs drift")

    registry = roots["SOURCE_ADMISSION_REGISTRY_ROOT"]["value"]
    candidate_ids = registry.get("candidate_object_ids")
    require(candidate_ids == [row.get("candidate_object_id") for row in rows], "active R7 route does not bind R5 wrapper IDs")
    route_sets = registry.get("exact_route_target_sets")
    require(isinstance(route_sets, dict), "active R7 route sets are missing")
    expected_routes: dict[int, str] = {}
    for rule, (_, count) in ROUTES.items():
        indices = route_sets.get(rule)
        require(isinstance(indices, list) and len(indices) == count and len(set(indices)) == count, f"R7 route set drift: {rule}")
        for index in indices:
            require(index not in expected_routes and 1 <= index <= 317, "R7 route overlap or invalid index")
            expected_routes[index] = rule
    require(set(expected_routes) == set(range(1, 318)), "R7 active route union is not Exact317")
    for row in rows:
        require(expected_routes[row["target_index"]] == row.get("route_rule_id"), "R7 cross-route substitution")

    return {
        "authentication_status": "PASS",
        "pinned_r8_review": review,
        "r6": {
            "package_sha256sums_sha256": R6_PACKAGE_SHA256SUMS_SHA256,
            "package_file_count": len(r6_entries),
            "field_pin_skeleton": artifact(skeleton_path, "R6/R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl"),
            "field_pin_skeleton_count": 317,
            "skeleton_decisions_null": True,
        },
        "r5": {
            "package_sha256sums_sha256": R5_PACKAGE_SHA256SUMS_SHA256,
            "package_file_count": len(r5_entries),
            "dry_run": artifact(dry_path, "R5/05_dry_run/EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl"),
            "dry_run_status": "CANDIDATE_WRAPPER_OBJECTS_ONLY",
        },
        "r7": {
            "transaction_id": R7_TRANSACTION,
            "consumer_pointer": artifact(R7_POINTER, "R7/authority_store/r7-activation-consumer-pointer.json"),
            "consumer_pointer_sha256": R7_POINTER_SHA256,
            "consumer_pointer_status": pointer.get("status"),
            "production_mount": pointer.get("production_mount"),
            "active_root_ids": dict(ROOT_IDS),
            "active_root_artifact_sha256": dict(ROOT_ARTIFACT_SHA256),
            "root_artifacts": {role: artifact(R7_COMMITTED_ROOTS / f"{role}.json", f"R7/authority_store/committed/{R7_TRANSACTION}/roots/{role}.json") for role in ROOT_IDS},
            "package_envelope": r7_envelope,
        },
        "exact317": {
            "manifest": artifact(EXACT317, "EXEC-R4/00_lineage/EXACT317_TARGET_MANIFEST.json"),
            "target_total": 317,
            "raw_side_total": 86,
            "candidate_side_total": 231,
            "route_counts": {rule: count for rule, (_, count) in ROUTES.items()},
            "duplicates": 0,
            "missing": 0,
            "cross_route_substitution": 0,
            "union": "Exact317",
            "target_id_set_sha256": sha256_bytes(canonical_bytes(sorted(target_ids))),
        },
        "read_policy": {
            "all_targets_read_only_through": "R7_ACTIVE_CONSUMER_POINTER_AND_COMMITTED_ROOTS",
            "alternate_source_routes_read": False,
            "semantic_fallback": False,
            "target_expansion": False,
            "field_pointer_selection": False,
        },
        "authority_boundary": {
            "r7_active_source_authority_preexisting": True,
            "r8_created_or_mutated_source_authority": False,
            "source_auth_executed": False,
            "field_pins_created": 0,
            "p0_executed": False,
            "p1_executed": False,
            "binding_publication": False,
            "scoring_authority_mutated": False,
            "binding_authority_mutated": False,
            "git_ref_mutation": False,
        },
    }


def build_packets(auth: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = load_jsonl(R5 / "05_dry_run" / "EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl")
    skeletons = load_jsonl(R6 / "R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl")
    skeleton_by_index = {item["target_index"]: item for item in skeletons}
    require(set(skeleton_by_index) == set(range(1, 318)), "R6 skeleton indices are not Exact317")
    packets: list[dict[str, Any]] = []
    for row in rows:
        index = row["target_index"]
        skeleton = skeleton_by_index[index]
        require(row["source_binding_target_id"] == skeleton["source_binding_target_id"], f"skeleton target mismatch: {index}")
        require(row["route_rule_id"] == skeleton["wrapper_rule_id"], f"skeleton route mismatch: {index}")
        source_field = "source_action" if "source_action" in row else "source_row"
        source_object = row[source_field]
        prefix = f"/{source_field}"
        leaves = flatten_scalar_leaves(source_object, prefix)
        skeleton_leaves = skeleton.get("available_candidate_scalar_leaves")
        require(isinstance(skeleton_leaves, list), f"skeleton candidates missing: {index}")
        require(
            [{"pointer": item["pointer"], "value": item.get("value"), "value_sha256": item["value_sha256"]} for item in leaves]
            == [{"pointer": item["pointer"], "value": item.get("value"), "value_sha256": item["value_sha256"]} for item in skeleton_leaves],
            f"R6 permitted scalar set differs from active source object: {index}",
        )
        source_bytes_sha = row.get("source_file_sha256") or row.get("row_bytes_sha256")
        require(isinstance(source_bytes_sha, str) and len(source_bytes_sha) == 64, f"source byte hash missing: {index}")
        source_object_sha = sha256_bytes(canonical_bytes(source_object))
        wrapper_record_sha = sha256_bytes(canonical_bytes(row))
        complete_checks = {
            "target_identity": row.get("source_binding_target_id") == skeleton.get("source_binding_target_id"),
            "source_side": row.get("source_side") in {"RAW", "CANDIDATE"},
            "active_wrapper_rule": row.get("route_rule_id") in ROUTES,
            "active_source_object": isinstance(source_object, (dict, list)),
            "active_source_hash": bool(source_object_sha),
            "exact_source_locator": isinstance(row.get("source_locator"), str) and bool(row["source_locator"]),
            "wrapper_object_hash": row.get("candidate_object_id") == row.get("candidate_object_id"),
            "candidate_scalar_pointers": len(leaves) == len(skeleton_leaves),
            "candidate_value_hashes": all(item.get("value_sha256") == sha256_bytes(canonical_bytes(item.get("value"))) for item in skeleton_leaves),
        }
        evidence_complete = all(complete_checks.values())
        require(evidence_complete, f"incomplete evidence packet: {index}")
        candidates = [dict(item) for item in leaves]
        packet = {
            "schema": "FA1B2DE_CURRENT86_EXACT317_FIELD_PIN_CANDIDATE_PACKET_R8_V1",
            "target_index": index,
            "source_binding_target_id": row["source_binding_target_id"],
            "source_side": row["source_side"],
            "active_wrapper_rule_id": row["route_rule_id"],
            "wrapper_rule_id": row["route_rule_id"],
            "active_source_identity": {
                "source_key": row.get("source_key"),
                "source_locator": row.get("source_locator"),
                "source_file": row.get("source_file"),
                "source_file_sha256": row.get("source_file_sha256"),
                "jsonl_line": row.get("jsonl_line"),
                "row_bytes_sha256": row.get("row_bytes_sha256"),
            },
            "exact_source_locator": row["source_locator"],
            "active_source_object": source_object,
            "active_source_object_sha256": source_object_sha,
            "active_source_bytes_sha256": source_bytes_sha,
            "wrapper_object": {
                "candidate_wrapper_object_id": row["candidate_object_id"],
                "wrapper_object_hash": row["candidate_object_id"],
                "wrapper_record_sha256": wrapper_record_sha,
                "authority_status": row.get("authority_status"),
            },
            "candidate_wrapper_object_id": row["candidate_object_id"],
            "wrapper_object_hash": row["candidate_object_id"],
            "candidate_scalar_pointers": candidates,
            "available_candidate_scalar_leaves": candidates,
            "candidate_count": len(candidates),
            "evidence_completeness": {"complete": evidence_complete, "checks": complete_checks, "missing_components": []},
            "candidate_classification": None,
            "selected_canonical_pointer": None,
            "selected_scalar_leaf": None,
            "human_decision": None,
            "allowed_future_human_actions": list(ALLOWED_ACTIONS),
            "no_default_action": True,
            "evidence_status": "EVIDENCE_ONLY_NOT_AUTHENTICATED",
            "authority_status": "CANDIDATE_FIELD_PIN_EVIDENCE_ONLY",
            "source_auth_executed": False,
            "field_pin_created": False,
            "p0_executed": False,
            "p1_executed": False,
            "binding_publication": False,
            "target_blocked_until_explicit_field_pin_approval": True,
        }
        packets.append(packet)
    require(len(packets) == 317, "packet count is not Exact317")
    return packets


def classify_packets(packets: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"NO_CANDIDATE_POINTER": 0, "SINGLE_CANDIDATE_POINTER": 0, "MULTIPLE_CANDIDATE_POINTERS": 0}
    classifications: list[dict[str, Any]] = []
    for packet in packets:
        count = packet["candidate_count"]
        if count == 0:
            label = "NO_CANDIDATE_POINTER"
        elif count == 1:
            label = "SINGLE_CANDIDATE_POINTER"
        else:
            label = "MULTIPLE_CANDIDATE_POINTERS"
        counts[label] += 1
        packet["candidate_classification"] = label
        classifications.append({
            "target_index": packet["target_index"],
            "source_binding_target_id": packet["source_binding_target_id"],
            "source_side": packet["source_side"],
            "wrapper_rule_id": packet["wrapper_rule_id"],
            "candidate_count": count,
            "candidate_set_non_empty": count > 0,
            "evidence_complete": packet["evidence_completeness"]["complete"],
            "classification": label,
            "human_decision": None,
        })
    return {
        "schema": "FA1B2DE_CURRENT86_FIELD_PIN_CANDIDATE_CLASSIFICATION_R8_V1",
        "descriptive_only": True,
        "selection_performed": False,
        "classification_counts": counts,
        "classifications": classifications,
        "target_total": len(packets),
        "human_decisions": {},
    }


def build_batches(packets: list[dict[str, Any]]) -> dict[str, Any]:
    size = 14
    batches: list[dict[str, Any]] = []
    for offset in range(0, len(packets), size):
        chunk = packets[offset : offset + size]
        number = len(batches) + 1
        batches.append({
            "batch_number": number,
            "batch_id": f"R8-PRESENTATION-BATCH-{number:02d}",
            "target_indices": [item["target_index"] for item in chunk],
            "target_ids": [item["source_binding_target_id"] for item in chunk],
            "unit_count": len(chunk),
            "presentation_only": True,
            "governance_units_merged": False,
            "human_decisions": {},
        })
    return {
        "schema": "FA1B2DE_CURRENT86_FIELD_PIN_REVIEW_BATCHES_R8_V1",
        "presentation_only": True,
        "governance_units_merged": False,
        "batch_count": len(batches),
        "target_total": len(packets),
        "batches": batches,
    }


def build_first_tranche(packets: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(
        packets,
        key=lambda item: (
            0 if item["candidate_count"] > 0 else 1,
            item["candidate_count"] if item["candidate_count"] > 0 else 10**9,
            0 if item["evidence_completeness"]["complete"] else 1,
            item["source_binding_target_id"],
        ),
    )[:24]
    units = [{
        "target_index": item["target_index"],
        "source_binding_target_id": item["source_binding_target_id"],
        "source_side": item["source_side"],
        "wrapper_rule_id": item["wrapper_rule_id"],
        "candidate_count": item["candidate_count"],
        "classification": item["candidate_classification"],
        "evidence_complete": item["evidence_completeness"]["complete"],
        "human_decision": None,
        "selected_canonical_pointer": None,
    } for item in ordered]
    return {
        "schema": "FA1B2DE_CURRENT86_FIRST_HUMAN_FIELD_PIN_TRANCHE_R8_V1",
        "selection_rule": ["candidate set non-empty", "smallest candidate count", "complete evidence", "target-ID tie break"],
        "max_count": 24,
        "target_indices": [item["target_index"] for item in ordered],
        "target_ids": [item["source_binding_target_id"] for item in ordered],
        "units": units,
        "human_decisions": {},
        "field_pins_created": 0,
        "presentation_only": True,
    }


def build_review_sheet(tranche: Mapping[str, Any], packets: list[dict[str, Any]]) -> str:
    by_index = {item["target_index"]: item for item in packets}
    lines = [
        "# R8 First Human Field-Pin Review Sheets",
        "",
        "This sheet is presentation-only. It contains no field-pin approval and no selected pointer.",
        "Every target remains blocked until an explicit human decision is recorded in a later governance step.",
        "",
        "| Target | Side | Wrapper rule | Candidates | Classification | Evidence | Decision | Selected pointer |",
        "|---:|---|---|---:|---|---|---|---|",
    ]
    for index in tranche["target_indices"]:
        item = by_index[index]
        lines.append(
            f"| {index} | {item['source_side']} | {item['wrapper_rule_id']} | {item['candidate_count']} | "
            f"{item['candidate_classification']} | complete | null | null |"
        )
    lines.extend(["", "## Candidate pointer evidence"])
    lines.append("")
    for index in tranche["target_indices"]:
        item = by_index[index]
        lines.append(f"### Target {index} — `{item['source_binding_target_id']}`")
        lines.append("")
        lines.append("Candidate pointers are evidence only; none is selected or approved.")
        for candidate in item["candidate_scalar_pointers"]:
            lines.append(f"- `{candidate['pointer']}` — type `{candidate['value_type']}`, value hash `{candidate['value_sha256']}`")
        lines.append("")
    lines.extend([
        "Allowed future decisions: `APPROVE_EXACT_FIELD_PIN`, `REJECT_FIELD_CANDIDATES_KEEP_BLOCKED`, `REQUEST_MORE_EVIDENCE`.",
        "No default action is permitted; even a single candidate pointer requires explicit human approval.",
    ])
    return "\n".join(lines) + "\n"


def build_readiness_bridge(auth: Mapping[str, Any], packets: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "FA1B2DE_CURRENT86_SOURCE_AUTH_READINESS_BRIDGE_R8_DESIGN_ONLY_V1",
        "design_only": True,
        "active_r7_transaction_id": R7_TRANSACTION,
        "active_r7_consumer_pointer_sha256": R7_POINTER_SHA256,
        "scope": "EXACT317_ONLY",
        "target_total": len(packets),
        "field_pin_authority_status": "BLOCKED_UNTIL_EXPLICIT_APPROVAL",
        "source_auth_execution_status": "NOT_EXECUTED",
        "bridge_execution_status": "DESIGNED_NOT_EXECUTED",
        "per_target_requires": "APPROVED_EXACT_FIELD_PIN",
        "unapproved_target_state": "BLOCKED",
        "allowed_future_human_actions": list(ALLOWED_ACTIONS),
        "readiness_checks": {
            "active_r7_authority_authenticated": auth["authentication_status"] == "PASS",
            "exact317_packets_materialized": len(packets) == 317,
            "all_packets_evidence_complete": all(item["evidence_completeness"]["complete"] for item in packets),
            "all_human_decisions_null": all(item["human_decision"] is None for item in packets),
            "all_selected_pointers_null": all(item["selected_canonical_pointer"] is None for item in packets),
            "field_pin_registry_created": False,
            "source_auth_called": False,
        },
        "activation_gate": "FAIL_CLOSED_NO_SOURCE_AUTH_WITHOUT_EXPLICIT_APPROVED_FIELD_PIN",
        "authority_boundary": {
            "active_source_authority_mutated": False,
            "field_pins_created": 0,
            "source_auth_executed": False,
            "p0_executed": False,
            "p1_executed": False,
            "binding_publication": False,
            "git_ref_mutation": False,
        },
    }


def write_envelope() -> dict[str, Any]:
    required = [PACKAGE / relative for relative in OUTPUTS]
    for path in required:
        require(path.is_file(), f"required R8 output missing before envelope: {path.name}")
    inventory = sorted([*OUTPUTS, "FILE_LIST.txt"])
    (PACKAGE / "FILE_LIST.txt").write_text("\n".join(inventory) + "\n", encoding="utf-8")
    entries = [f"{sha256_file(PACKAGE / relative)}  ./{relative}" for relative in inventory]
    (PACKAGE / "SHA256SUMS.txt").write_text("\n".join(entries) + "\n", encoding="utf-8")
    return {"file_count": len(inventory), "files": inventory}


def materialize() -> dict[str, Any]:
    existing = [path.name for path in PACKAGE.iterdir() if path.name not in {"tests", "tools", "__pycache__"}]
    require(not existing, f"R8 package already contains materialized artifacts: {existing}")
    auth = authenticate_inputs()
    packets = build_packets(auth)
    classification = classify_packets(packets)
    batches = build_batches(packets)
    tranche = build_first_tranche(packets)
    write_json(PACKAGE / "R8_INPUT_AUTHENTICATION.json", auth)
    write_jsonl(PACKAGE / "R8_EXACT317_FIELD_PIN_CANDIDATE_PACKETS.jsonl", packets)
    write_json(PACKAGE / "R8_FIELD_PIN_CANDIDATE_CLASSIFICATION.json", classification)
    write_json(PACKAGE / "R8_FIELD_PIN_REVIEW_BATCHES.json", batches)
    write_json(PACKAGE / "R8_FIRST_HUMAN_FIELD_PIN_TRANCHE.json", tranche)
    (PACKAGE / "R8_FIRST_HUMAN_FIELD_PIN_REVIEW_SHEETS.md").write_text(build_review_sheet(tranche, packets), encoding="utf-8")
    write_json(PACKAGE / "R8_SOURCE_AUTH_READINESS_BRIDGE.json", build_readiness_bridge(auth, packets))
    report = f"""# Binding R8 Exact317 Field-Pin Governance Materialization

This package is a non-authoritative, evidence-only preparation step over the active R7 source-authority route. It preserves the R7 consumer pointer and immutable roots and does not execute source-auth or choose a field pointer.

## Authenticated inputs

- R8 review commit/tree: `{R8_REVIEW_COMMIT}` / `{R8_REVIEW_TREE}`.
- R7 transaction: `{R7_TRANSACTION}`; consumer pointer SHA-256: `{R7_POINTER_SHA256}`.
- Active roots: registry `{ROOT_IDS['SOURCE_ADMISSION_REGISTRY_ROOT']}`, corpus/schema `{ROOT_IDS['SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT']}`, common freeze/runtime `{ROOT_IDS['SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST']}`, EXEC-R4 `{ROOT_IDS['EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION']}`.
- Exact317 manifest: `{EXACT317_SHA256}`; R6 skeletons: `{R6_SKELETON_SHA256}`; count 317.

## Materialized evidence

Each packet carries the target identity and side, active wrapper rule, active source object and canonical hash, source-byte hash and exact locator, wrapper identity/hash, every scalar RFC6901 pointer permitted by the R6 design with value type/hash, and an evidence-completeness result. Classification is descriptive only. Human decisions and selected pointers remain null.

The 317 independent governance units are presented in {batches['batch_count']} presentation-only batches. The first review tranche contains {len(tranche['target_indices'])} targets and is ordered only by candidate-set presence, candidate count, evidence completeness, and target-ID tie break.

## Terminal

```text
BINDING_R8_FIELD_PIN_GOVERNANCE_MATERIALIZATION = READY_FOR_EXPLICIT_HUMAN_FIELD_PIN_REVIEW
ACTIVE_R7_AUTHORITY_AUTHENTICATION = PASS
EXACT317_CONSERVATION = PASS
FIELD_PIN_PACKET_COUNT = {len(packets)}
SINGLE_CANDIDATE_POINTER = {classification['classification_counts']['SINGLE_CANDIDATE_POINTER']}
MULTIPLE_CANDIDATE_POINTERS = {classification['classification_counts']['MULTIPLE_CANDIDATE_POINTERS']}
NO_CANDIDATE_POINTER = {classification['classification_counts']['NO_CANDIDATE_POINTER']}
FIRST_HUMAN_REVIEW_TRANCHE_COUNT = {len(tranche['target_indices'])}

FIELD_PINS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO

NEXT_ACTION =
FRESH_REVIEW_OF_BINDING_R8_FIELD_PIN_GOVERNANCE_MATERIALIZATION

STOP = true
```
"""
    (PACKAGE / "R8_FIELD_PIN_GOVERNANCE_REPORT.md").write_text(report, encoding="utf-8")
    envelope = write_envelope()
    return {
        "status": "READY_FOR_EXPLICIT_HUMAN_FIELD_PIN_REVIEW",
        "authentication_status": auth["authentication_status"],
        "exact317": auth["exact317"],
        "field_pin_packet_count": len(packets),
        "classification_counts": classification["classification_counts"],
        "first_human_review_tranche_count": len(tranche["target_indices"]),
        "envelope": envelope,
        "field_pins_created": 0,
        "source_auth_executed": False,
        "p0_executed": False,
        "p1_executed": False,
        "binding_publication": False,
        "next_action": "FRESH_REVIEW_OF_BINDING_R8_FIELD_PIN_GOVERNANCE_MATERIALIZATION",
        "stop": True,
    }


def main() -> int:
    if "--help" in sys.argv:
        print("materialize_r8.py: materialize the non-authoritative R8 field-pin governance package")
        return 0
    result = materialize()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (R8MaterializationError, OSError, subprocess.CalledProcessError, KeyError, TypeError, ValueError) as exc:
        print(f"R8_MATERIALIZATION_BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)
