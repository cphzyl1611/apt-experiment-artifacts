#!/usr/bin/env python3
"""Independent verifier for the R8 field-pin governance package.

This module intentionally duplicates the validation primitives it needs rather
than importing the materializer, so a second process checks the emitted bytes.
It never creates a field pin, runs source-auth, or mutates an authority.
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
R7_TRANSACTION = "e8a0a97a33d47ac68c8ded4af1af109fa010d979acf9736fd5dffdebf96c5208"
R7_POINTER = R7 / "authority_store" / "r7-activation-consumer-pointer.json"
R7_ROOTS = R7 / "authority_store" / "committed" / R7_TRANSACTION / "roots"
EXACT317 = REPO_ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4" / "00_lineage" / "EXACT317_TARGET_MANIFEST.json"
REVIEW_REPO = Path("/home/cph/fa1b2de-review-artifacts")
R8_REVIEW_COMMIT = "107ef9f69a734a10b320d552cfe18a6cb9a2ac0c"
R8_REVIEW_TREE = "26b5c3a56e86fb5c11d50fc86bd99d6b940239fc"
R8_REVIEW_PREFIX = "current86-r4"
R7_POINTER_SHA256 = "02394a7fc7c5f337dfbfff521467759f80e14f8d5d27ca9e01653eec3f0d592c"
EXACT317_SHA256 = "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac"
R6_SKELETON_SHA256 = "d55bc015d21b3fb4a6edc7ef9aa0caf5abca1da177da2df232f1dd97bd6f8573"
R6_SUMS_SHA256 = "7abdd9630ce53d0b457b5111c4c071d4bee2b99b1d436ee57808128f38c38c62"
R5_SUMS_SHA256 = "5f1746499c2ca5ba966b3f716e6b8ca87844cf4cd0a1316ec215b25cc092fdc1"
R5_DRY_RUN_SHA256 = "884dec61cc33e13d12c439e202568c8e592650b82f98acca22b5eb0b4f4eaa82"
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
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise VerificationError(f"cannot read JSONL: {path}") from exc
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise VerificationError(f"invalid JSONL row {number}: {path}") from exc
        require(isinstance(value, dict), f"JSONL row {number} is not an object")
        rows.append(value)
    return rows


def parse_sums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  \.\/(.+)", line)
        require(match is not None, f"malformed checksum line: {line!r}")
        value, relative = match.groups()
        require(relative not in entries, f"duplicate checksum path: {relative}")
        entries[relative] = value
    return entries


def verify_envelope(package: Path, expected_sha: str) -> dict[str, str]:
    require(file_digest(package / "SHA256SUMS.txt") == expected_sha, f"package envelope drift: {package}")
    entries = parse_sums(package / "SHA256SUMS.txt")
    listed = {line.strip() for line in (package / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line.strip()}
    require(listed == set(entries), f"FILE_LIST/SHA256SUMS mismatch: {package}")
    for relative, expected in entries.items():
        require(file_digest(package / relative) == expected, f"checksum mismatch: {package}/{relative}")
    return entries


def verify_pinned_r8_commit(r6_entries: Mapping[str, str]) -> dict[str, Any]:
    require(REVIEW_REPO.is_dir(), "review repository unavailable")
    try:
        commit_type = subprocess.run(["git", "-C", str(REVIEW_REPO), "cat-file", "-t", R8_REVIEW_COMMIT], check=True, capture_output=True, text=True).stdout.strip()
        tree = subprocess.run(["git", "-C", str(REVIEW_REPO), "rev-parse", f"{R8_REVIEW_COMMIT}^{{tree}}"], check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise VerificationError("cannot resolve pinned R8 review commit") from exc
    require(commit_type == "commit" and tree == R8_REVIEW_TREE, "pinned R8 commit/tree mismatch")
    for relative, expected in r6_entries.items():
        path = f"{R8_REVIEW_PREFIX}/{R6.name}/{relative}"
        try:
            data = subprocess.run(["git", "-C", str(REVIEW_REPO), "show", f"{R8_REVIEW_COMMIT}:{path}"], check=True, capture_output=True).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            raise VerificationError(f"pinned commit lacks R6/{relative}") from exc
        require(digest(data) == expected, f"pinned R8 commit content drift: R6/{relative}")
    return {"repository": str(REVIEW_REPO), "commit": R8_REVIEW_COMMIT, "tree": tree, "commit_type": commit_type, "authentication": "PASS"}


def rfc6901_escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def scalar_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        require(math.isfinite(value), "non-finite value")
        return "number"
    if isinstance(value, str):
        return "string"
    raise VerificationError(f"non-scalar value encountered: {type(value).__name__}")


def flatten(value: Any, prefix: str) -> list[dict[str, Any]]:
    leaves: list[dict[str, Any]] = []
    if isinstance(value, Mapping):
        for key in sorted(value, key=lambda item: str(item).encode("utf-8")):
            leaves.extend(flatten(value[key], f"{prefix}/{rfc6901_escape(str(key))}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            leaves.extend(flatten(child, f"{prefix}/{index}"))
    else:
        leaves.append({"pointer": prefix, "value": value, "value_type": scalar_type(value), "value_sha256": digest(canonical(value))})
    return leaves


def verify_inputs() -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    r6_entries = verify_envelope(R6, R6_SUMS_SHA256)
    review = verify_pinned_r8_commit(r6_entries)
    require(file_digest(R6 / "R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl") == R6_SKELETON_SHA256, "R6 skeleton hash drift")
    r7_pointer = load_json(R7_POINTER)
    require(file_digest(R7_POINTER) == R7_POINTER_SHA256, "R7 pointer hash drift")
    require(r7_pointer.get("status") == "COMMITTED" and r7_pointer.get("transaction_id") == R7_TRANSACTION, "R7 pointer state drift")
    require(r7_pointer.get("post_state_root_ids") == ROOT_IDS, "R7 root IDs drift")
    require(r7_pointer.get("exact317_manifest_sha256") == EXACT317_SHA256 and r7_pointer.get("target_total") == 317, "R7 Exact317 binding drift")
    require(r7_pointer.get("raw_side_total") == 86 and r7_pointer.get("candidate_side_total") == 231, "R7 side counts drift")
    require(r7_pointer.get("duplicates") == 0 and r7_pointer.get("cross_route_substitution") == 0, "R7 route boundary drift")
    for role, expected in ROOT_HASHES.items():
        path = R7_ROOTS / f"{role}.json"
        require(file_digest(path) == expected, f"R7 root hash drift: {role}")
        root = load_json(path)
        require(root.get("authority_role") == role, f"R7 root role drift: {role}")
    exact = load_json(EXACT317)
    require(file_digest(EXACT317) == EXACT317_SHA256, "Exact317 manifest drift")
    targets = exact.get("targets")
    require(isinstance(targets, list) and len(targets) == 317, "Exact317 target count drift")
    require([item.get("target_index") for item in targets] == list(range(1, 318)), "Exact317 target order drift")
    require(sum(item.get("source_side") == "RAW" for item in targets) == 86 and sum(item.get("source_side") == "CANDIDATE" for item in targets) == 231, "Exact317 source-side drift")
    require(len({item.get("source_binding_target_id") for item in targets}) == 317, "Exact317 target IDs are not unique")
    r5_entries = verify_envelope(R5, R5_SUMS_SHA256)
    dry_path = R5 / "05_dry_run" / "EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl"
    require(file_digest(dry_path) == R5_DRY_RUN_SHA256, "R5 dry-run drift")
    rows = load_jsonl(dry_path)
    require(len(rows) == 317 and [item.get("target_index") for item in rows] == list(range(1, 318)), "R5 dry-run count/order drift")
    require(all(item.get("authority_status") == "CANDIDATE_WRAPPER_OBJECTS_ONLY" for item in rows), "R5 authority label drift")
    registry = load_json(R7_ROOTS / "SOURCE_ADMISSION_REGISTRY_ROOT.json")
    require(registry.get("candidate_object_ids") == [item.get("candidate_object_id") for item in rows], "R7 active route does not bind wrapper rows")
    route_sets = registry.get("exact_route_target_sets")
    require(isinstance(route_sets, dict), "R7 route sets missing")
    routes: dict[int, str] = {}
    for rule, (_, count) in ROUTES.items():
        indices = route_sets.get(rule)
        require(isinstance(indices, list) and len(indices) == count and len(set(indices)) == count, f"R7 route count drift: {rule}")
        for index in indices:
            require(index not in routes and 1 <= index <= 317, "R7 route overlap")
            routes[index] = rule
    require(set(routes) == set(range(1, 318)), "R7 route union drift")
    for row in rows:
        require(routes[row["target_index"]] == row.get("route_rule_id"), "R7 cross-route substitution")
    return {"review": review, "r7_pointer": r7_pointer, "r7_roots": registry, "exact": exact, "r5_entries": r5_entries}, rows, load_jsonl(R6 / "R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl"), exact, r7_pointer


def verify_outputs() -> dict[str, Any]:
    auth, rows, skeletons, exact, pointer = verify_inputs()
    auth_out = load_json(PACKAGE / "R8_INPUT_AUTHENTICATION.json")
    require(auth_out.get("authentication_status") == "PASS", "R8 authentication status is not PASS")
    require(auth_out.get("pinned_r8_review", {}).get("commit") == R8_REVIEW_COMMIT and auth_out.get("pinned_r8_review", {}).get("tree") == R8_REVIEW_TREE, "R8 auth commit binding drift")
    require(auth_out.get("r7", {}).get("consumer_pointer_sha256") == R7_POINTER_SHA256, "R8 auth pointer binding drift")
    require(auth_out.get("exact317", {}).get("target_total") == 317 and auth_out.get("exact317", {}).get("raw_side_total") == 86 and auth_out.get("exact317", {}).get("candidate_side_total") == 231, "R8 auth Exact317 drift")
    packets = load_jsonl(PACKAGE / "R8_EXACT317_FIELD_PIN_CANDIDATE_PACKETS.jsonl")
    require(len(packets) == 317, "R8 packet count drift")
    targets = exact["targets"]
    target_ids = [item["source_binding_target_id"] for item in targets]
    require([item.get("target_index") for item in packets] == list(range(1, 318)), "R8 packet index order drift")
    require([item.get("source_binding_target_id") for item in packets] == target_ids, "R8 packet target identity drift")
    skeleton_by_index = {item["target_index"]: item for item in skeletons}
    row_by_index = {item["target_index"]: item for item in rows}
    require(len(row_by_index) == 317 and len(skeleton_by_index) == 317, "input index universe drift")
    for packet in packets:
        index = packet["target_index"]
        row = row_by_index[index]
        skeleton = skeleton_by_index[index]
        source_field = "source_action" if "source_action" in row else "source_row"
        source_obj = row[source_field]
        require(packet["source_binding_target_id"] == row["source_binding_target_id"] == skeleton["source_binding_target_id"], f"target identity mismatch: {index}")
        require(packet["source_side"] == row["source_side"] and packet["wrapper_rule_id"] == row["route_rule_id"] and packet["active_wrapper_rule_id"] == row["route_rule_id"], f"route mismatch: {index}")
        require(packet["exact_source_locator"] == row["source_locator"], f"locator mismatch: {index}")
        require(packet["active_source_object"] == source_obj, f"active source object mismatch: {index}")
        require(packet["active_source_object_sha256"] == digest(canonical(source_obj)), f"active source object hash mismatch: {index}")
        source_bytes = row.get("source_file_sha256") or row.get("row_bytes_sha256")
        require(packet["active_source_bytes_sha256"] == source_bytes, f"active source bytes hash mismatch: {index}")
        require(packet["candidate_wrapper_object_id"] == row["candidate_object_id"] and packet["wrapper_object_hash"] == row["candidate_object_id"], f"wrapper identity mismatch: {index}")
        require(packet["wrapper_object"]["wrapper_record_sha256"] == digest(canonical(row)), f"wrapper record hash mismatch: {index}")
        expected_leaves = flatten(source_obj, f"/{source_field}")
        require(packet["candidate_scalar_pointers"] == expected_leaves, f"candidate scalar evidence mismatch: {index}")
        require(packet["available_candidate_scalar_leaves"] == expected_leaves, f"candidate alias mismatch: {index}")
        require(packet["candidate_count"] == len(expected_leaves), f"candidate count mismatch: {index}")
        require(packet["evidence_completeness"]["complete"] is True and all(packet["evidence_completeness"]["checks"].values()), f"evidence incomplete: {index}")
        require(packet["human_decision"] is None and packet["selected_canonical_pointer"] is None and packet["selected_scalar_leaf"] is None, f"selection leak: {index}")
        require(packet["allowed_future_human_actions"] == FIELD_ACTIONS and packet["no_default_action"] is True, f"decision contract drift: {index}")
        require(packet["evidence_status"] == "EVIDENCE_ONLY_NOT_AUTHENTICATED" and packet["authority_status"] == "CANDIDATE_FIELD_PIN_EVIDENCE_ONLY", f"packet authority label drift: {index}")
        require(packet["source_auth_executed"] is False and packet["field_pin_created"] is False and packet["p0_executed"] is False and packet["p1_executed"] is False and packet["binding_publication"] is False, f"downstream action leak: {index}")
        require(packet["target_blocked_until_explicit_field_pin_approval"] is True, f"blocked state drift: {index}")

    classification = load_json(PACKAGE / "R8_FIELD_PIN_CANDIDATE_CLASSIFICATION.json")
    require(classification.get("descriptive_only") is True and classification.get("selection_performed") is False and classification.get("human_decisions") == {}, "classification authority leak")
    expected_counts = {"NO_CANDIDATE_POINTER": 0, "SINGLE_CANDIDATE_POINTER": 0, "MULTIPLE_CANDIDATE_POINTERS": 0}
    for packet in packets:
        count = packet["candidate_count"]
        label = "NO_CANDIDATE_POINTER" if count == 0 else "SINGLE_CANDIDATE_POINTER" if count == 1 else "MULTIPLE_CANDIDATE_POINTERS"
        expected_counts[label] += 1
        require(packet["candidate_classification"] == label, f"packet classification drift: {packet['target_index']}")
    require(classification.get("classification_counts") == expected_counts, "classification counts drift")
    class_rows = classification.get("classifications")
    require(isinstance(class_rows, list) and len(class_rows) == 317, "classification row count drift")
    for item, packet in zip(class_rows, packets):
        require(item.get("target_index") == packet["target_index"] and item.get("classification") == packet["candidate_classification"], "classification identity drift")
        require(item.get("human_decision") is None, "classification decision leak")

    batches = load_json(PACKAGE / "R8_FIELD_PIN_REVIEW_BATCHES.json")
    require(batches.get("presentation_only") is True and batches.get("governance_units_merged") is False, "batch authority leak")
    batch_ids = [index for batch in batches.get("batches", []) for index in batch.get("target_indices", [])]
    require(20 <= batches.get("batch_count", 0) <= 30 and len(batch_ids) == 317 and batch_ids == list(range(1, 318)) and len(set(batch_ids)) == 317, "batch coverage drift")
    require(all(batch.get("human_decisions") == {} for batch in batches["batches"]), "batch decision leak")

    tranche = load_json(PACKAGE / "R8_FIRST_HUMAN_FIELD_PIN_TRANCHE.json")
    require(len(tranche.get("target_indices", [])) <= 24 and tranche.get("human_decisions") == {} and tranche.get("field_pins_created") == 0, "tranche boundary drift")
    expected_order = sorted(packets, key=lambda item: (0 if item["candidate_count"] > 0 else 1, item["candidate_count"] if item["candidate_count"] > 0 else 10**9, 0 if item["evidence_completeness"]["complete"] else 1, item["source_binding_target_id"]))[:24]
    require(tranche.get("target_indices") == [item["target_index"] for item in expected_order], "tranche ordering drift")
    require(tranche.get("target_ids") == [item["source_binding_target_id"] for item in expected_order], "tranche target drift")
    require(all(item.get("human_decision") is None and item.get("selected_canonical_pointer") is None for item in tranche.get("units", [])), "tranche selection leak")

    bridge = load_json(PACKAGE / "R8_SOURCE_AUTH_READINESS_BRIDGE.json")
    require(bridge.get("design_only") is True and bridge.get("bridge_execution_status") == "DESIGNED_NOT_EXECUTED", "bridge was executed")
    require(bridge.get("field_pin_authority_status") == "BLOCKED_UNTIL_EXPLICIT_APPROVAL" and bridge.get("source_auth_execution_status") == "NOT_EXECUTED", "bridge boundary drift")
    require(bridge.get("authority_boundary", {}).get("field_pins_created") == 0 and bridge.get("authority_boundary", {}).get("source_auth_executed") is False, "bridge downstream leak")
    report = (PACKAGE / "R8_FIELD_PIN_GOVERNANCE_REPORT.md").read_text(encoding="utf-8")
    for token in ["FIELD_PINS_CREATED = 0", "SOURCE_AUTH_EXECUTED = NO", "P0_EXECUTED = NO", "P1_EXECUTED = NO", "BINDING_PUBLICATION = NO", "STOP = true"]:
        require(token in report, f"report terminal missing: {token}")
    return {
        "schema": "FA1B2DE_CURRENT86_BINDING_R8_INDEPENDENT_VERIFICATION_V1",
        "verification_status": "PASS",
        "independent": True,
        "pinned_r8_review_commit": R8_REVIEW_COMMIT,
        "pinned_r8_review_tree": R8_REVIEW_TREE,
        "active_r7_consumer_pointer_sha256": R7_POINTER_SHA256,
        "exact317": {"total": 317, "raw": 86, "candidate": 231, "routes": {rule: count for rule, (_, count) in ROUTES.items()}, "duplicates": 0, "missing": 0, "cross_route_substitution": 0, "union": "Exact317"},
        "field_pin_packets": 317,
        "classification_counts": expected_counts,
        "first_human_review_tranche_count": len(tranche["target_indices"]),
        "authority_boundary": {"active_r7_authority_authenticated": True, "source_auth_executed": False, "field_pins_created": 0, "p0_executed": False, "p1_executed": False, "binding_publication": False, "scoring_authority_mutated": False, "binding_authority_mutated": False, "git_ref_mutation": False},
        "next_action": "FRESH_REVIEW_OF_BINDING_R8_FIELD_PIN_GOVERNANCE_MATERIALIZATION",
        "stop": True,
    }


def main() -> int:
    result = verify_outputs()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (VerificationError, OSError, subprocess.CalledProcessError, KeyError, TypeError, ValueError) as exc:
        print(f"R8_VERIFY_BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)
