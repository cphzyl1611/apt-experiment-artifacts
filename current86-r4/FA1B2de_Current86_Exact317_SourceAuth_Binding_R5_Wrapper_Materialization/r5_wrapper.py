"""Fail-closed, non-authoritative R5 wrapper extraction primitives."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Iterable, Mapping, Sequence


class WrapperError(ValueError):
    """Raised when an approved wrapper contract cannot be satisfied exactly."""


RAW_LEGACY_INDICES = frozenset(
    {1, 2, 3, 4, 5, 6, 14, 16, 17, 20, 21, 22, 24, 30, 33, 36, 37, 40, 42, 53, 56, 57, 70, 76, 81, 82}
)
C0_INDICES = frozenset(range(1, 87)) - RAW_LEGACY_INDICES
SCORING_INDICES = frozenset(range(87, 318))
EXPECTED_RULES = frozenset(
    {"R4_WRAPPER_RAW_LEGACY_26", "R4_WRAPPER_C0_60", "R4_WRAPPER_SCORING_231"}
)
APPROVAL = "APPROVE_EXACT_CANONICAL_WRAPPER_RULE"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise WrapperError(f"cannot read committed input: {path}") from exc


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise WrapperError(message)


def candidate_object_id(record: Mapping[str, object]) -> str:
    """Derive a candidate-only wrapper identity from exact target/source commitments."""
    basis = {
        "schema": "FA1B2DE_CURRENT86_R5_CANDIDATE_WRAPPER_OBJECT_ID_V1",
        "authority_status": "CANDIDATE_WRAPPER_OBJECTS_ONLY",
        "route_rule_id": record.get("route_rule_id"),
        "source_binding_target_id": record.get("source_binding_target_id"),
        "source_side": record.get("source_side"),
        "source_key": record.get("source_key"),
        "source_locator": record.get("source_locator"),
        "source_file_sha256": record.get("source_file_sha256"),
        "row_bytes_sha256": record.get("row_bytes_sha256"),
    }
    _require(all(basis[key] is not None for key in ("route_rule_id", "source_binding_target_id", "source_side", "source_key", "source_locator")), "candidate object identity basis is incomplete")
    encoded = json.dumps(basis, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256_bytes(encoded)


def _candidate_record(record: dict) -> dict:
    record["candidate_object_id"] = candidate_object_id(record)
    return record


def authenticate_human_approval(
    approval: Mapping[str, object], rules: Mapping[str, object], frozen_r4_sha256sums_sha256: str
) -> dict:
    """Authenticate exactly the user approval against the frozen R4 rule package."""
    _require(approval.get("HUMAN_ORIGIN") == "USER_EXPLICIT_APPROVAL", "human origin is not explicit user approval")
    decisions = approval.get("decisions")
    _require(isinstance(decisions, Mapping), "approval decisions must be an object")
    _require(set(decisions) == EXPECTED_RULES, "approval must enumerate exactly the three R4 wrapper rules")
    _require(all(value == APPROVAL for value in decisions.values()), "each R4 rule requires the exact approval decision")
    listed = rules.get("rules")
    _require(isinstance(listed, list), "R4 rules package is malformed")
    rule_ids = {r.get("rule_id") for r in listed if isinstance(r, Mapping)}
    _require(rule_ids == EXPECTED_RULES, "frozen R4 package rule IDs do not match the approved set")
    for rule in listed:
        if rule.get("rule_id") in EXPECTED_RULES:
            if "human_approval_required" in rule:
                _require(rule.get("human_approval_required") is True, "R4 rule is not approval-gated")
            _require(rule.get("execution_status") == "NOT_EXECUTED", "R4 rule has already executed")
            _require(rule.get("failure_mode") == "FAIL_CLOSED", "R4 rule is not fail-closed")
    _require(bool(re.fullmatch(r"[0-9a-f]{64}", frozen_r4_sha256sums_sha256)), "invalid frozen R4 package digest")
    return {
        "authenticated": True,
        "human_origin": "USER_EXPLICIT_APPROVAL",
        "approved_rule_ids": sorted(EXPECTED_RULES),
        "frozen_r4_sha256sums_sha256": frozen_r4_sha256sums_sha256,
    }


def _target_indices(targets: Sequence[Mapping[str, object]]) -> list[int]:
    indices = [t.get("target_index") for t in targets]
    _require(all(isinstance(i, int) for i in indices), "target indices must be integers")
    _require(len(indices) == len(set(indices)), "duplicate target indices")
    return indices


def _validate_route_targets(targets: Sequence[Mapping[str, object]], expected: frozenset[int], count: int, side: str) -> None:
    _require(len(targets) == count, "route target count mismatch")
    _require(set(_target_indices(targets)) == set(expected), "route target commitment mismatch")
    _require(all(t.get("source_side") == side for t in targets), "cross-route source-side substitution")
    ids = [t.get("source_binding_target_id") for t in targets]
    _require(all(isinstance(i, str) and i for i in ids), "missing target identity")
    _require(len(ids) == len(set(ids)), "duplicate target identity")


def _safe_source_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    root_resolved = root.resolve()
    _require(candidate == root_resolved or root_resolved in candidate.parents, "source path escapes pinned corpus")
    return candidate


def _load_playbook(path: Path, expected_hash: str, git_commit: str | None = None) -> dict:
    if git_commit is None:
        data = path.read_bytes()
    else:
        relative = path.relative_to(Path("/home/cph/experiment"))
        try:
            data = subprocess.run(
                ["git", "-C", "/home/cph/experiment", "show", f"{git_commit}:{relative.as_posix()}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            raise WrapperError("pinned RAW Git source cannot be read") from exc
    _require(_sha256_bytes(data) == expected_hash, "playbook byte hash mismatch")
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WrapperError("playbook is not valid UTF-8 JSON") from exc
    _require(isinstance(parsed, dict), "playbook root must be an object")
    return parsed


def extract_raw(
    targets: Sequence[Mapping[str, object]],
    registry_rows: Sequence[Mapping[str, object]],
    playbook_root: Path,
    expected_git_commit: str | None = None,
) -> list[dict]:
    """Extract the 26 legacy RAW targets by their committed positional key."""
    _validate_route_targets(targets, RAW_LEGACY_INDICES, 26, "RAW")
    by_key: dict[str, list[Mapping[str, object]]] = {}
    for row in registry_rows:
        key = row.get("raw_action_key")
        if isinstance(key, str):
            by_key.setdefault(key, []).append(row)
    output = []
    for target in targets:
        key = target.get("bound_raw_key")
        _require(isinstance(key, str), "RAW target lacks committed raw key")
        matches = by_key.get(key, [])
        _require(len(matches) == 1, "RAW lookup does not have exactly one registry row")
        row = matches[0]
        required = ("playbook_id", "stage_identifier", "stage_index", "action_index", "source_file", "source_file_sha256")
        _require(all(field in row for field in required), "RAW registry row is incomplete")
        stage = row["stage_identifier"]
        _require(isinstance(stage, str) and re.fullmatch(r"S\d{2}", stage), "invalid RAW stage identifier")
        _require(isinstance(row["stage_index"], int) and isinstance(row["action_index"], int), "invalid RAW positional indices")
        _require(key == f'{row["playbook_id"]}::{stage}::A{row["action_index"]:03d}', "RAW positional key mismatch")
        source_file = row["source_file"]
        _require(isinstance(source_file, str) and not Path(source_file).is_absolute(), "invalid RAW source path")
        source = _safe_source_path(playbook_root, source_file)
        playbook = _load_playbook(source, row["source_file_sha256"], expected_git_commit)
        pipeline = playbook.get("pipeline")
        _require(isinstance(pipeline, list), "RAW playbook pipeline is missing")
        si, ai = row["stage_index"], row["action_index"]
        _require(1 <= si <= len(pipeline), "RAW stage position out of range")
        stage_obj = pipeline[si - 1]
        _require(isinstance(stage_obj, Mapping) and isinstance(stage_obj.get("actions"), list), "RAW stage actions are missing")
        actions = stage_obj["actions"]
        _require(1 <= ai <= len(actions), "RAW action position out of range")
        action = actions[ai - 1]
        _require(isinstance(action, Mapping), "RAW action is not an object")
        locator = f"$.pipeline[{si - 1}].actions[{ai - 1}]"
        _require(row.get("source_locator") == locator, "RAW registry locator mismatch")
        output.append(
            _candidate_record({
                "target_index": target["target_index"],
                "source_binding_target_id": target["source_binding_target_id"],
                "route_rule_id": "R4_WRAPPER_RAW_LEGACY_26",
                "source_side": "RAW",
                "authority_status": "CANDIDATE_WRAPPER_OBJECTS_ONLY",
                "source_key": key,
                "source_locator": locator,
                "source_file": source_file,
                "source_file_sha256": row["source_file_sha256"],
                "source_action": dict(action),
                "historical_producer_identity_recovered": False,
                "source_auth_executed": False,
                "field_pin_created": False,
            })
        )
    return output


def _jsonl_rows(path: Path, expected_hash: str) -> list[tuple[int, bytes, dict]]:
    data = path.read_bytes()
    _require(_sha256_bytes(data) == expected_hash, "JSONL source byte hash mismatch")
    rows = []
    for number, raw in enumerate(data.splitlines(keepends=True), 1):
        content = raw[:-1] if raw.endswith(b"\n") else raw
        if content.endswith(b"\r"):
            content = content[:-1]
        try:
            parsed = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WrapperError(f"invalid JSONL row {number}") from exc
        _require(isinstance(parsed, dict), f"JSONL row {number} is not an object")
        rows.append((number, content, parsed))
    return rows


def extract_c0(
    targets: Sequence[Mapping[str, object]],
    source_path: Path,
    expected_source_sha256: str,
    row_commitments: Mapping[str, Mapping[str, object]] | None = None,
) -> list[dict]:
    """Extract the exact 60 C0 rows while preserving historical C0 identity."""
    _validate_route_targets(targets, C0_INDICES, 60, "RAW")
    rows = _jsonl_rows(source_path, expected_source_sha256)
    by_identity: dict[str, list[tuple[int, bytes, dict]]] = {}
    for row in rows:
        identity = row[2].get("identity")
        if isinstance(identity, str):
            by_identity.setdefault(identity, []).append(row)
    output = []
    for target in targets:
        identity = target.get("bound_raw_key")
        _require(isinstance(identity, str), "C0 target lacks committed lookup key")
        matches = by_identity.get(identity, [])
        _require(len(matches) == 1, "C0 lookup does not have exactly one row")
        line, raw, parsed = matches[0]
        if row_commitments is not None:
            commitment = row_commitments.get(identity)
            _require(commitment is not None, "C0 committed row is missing")
            _require(commitment.get("jsonl_line") == line, "C0 committed JSONL line mismatch")
            _require(commitment.get("row_bytes_sha256") == _sha256_bytes(raw), "C0 committed row bytes mismatch")
        output.append(
            _candidate_record({
                "target_index": target["target_index"],
                "source_binding_target_id": target["source_binding_target_id"],
                "route_rule_id": "R4_WRAPPER_C0_60",
                "source_side": "RAW",
                "authority_status": "CANDIDATE_WRAPPER_OBJECTS_ONLY",
                "source_key": identity,
                "source_locator": f"jsonl:{line}",
                "jsonl_line": line,
                "row_bytes_sha256": _sha256_bytes(raw),
                "source_row": parsed,
                "historical_source_identity": "C0_TYPED_OPERATION_SEMANTICS",
                "historical_source_identity_preserved": True,
                "source_auth_executed": False,
                "field_pin_created": False,
            })
        )
    return output


def extract_scoring(
    targets: Sequence[Mapping[str, object]],
    source_path: Path,
    expected_source_sha256: str,
    row_commitments: Mapping[str, Mapping[str, object]] | None = None,
) -> list[dict]:
    """Extract the exact 231 scoring rows by their committed scoring ID."""
    _validate_route_targets(targets, SCORING_INDICES, 231, "CANDIDATE")
    rows = _jsonl_rows(source_path, expected_source_sha256)
    by_id: dict[str, list[tuple[int, bytes, dict]]] = {}
    for row in rows:
        scoring_id = row[2].get("scoring_id")
        if isinstance(scoring_id, str):
            by_id.setdefault(scoring_id, []).append(row)
    output = []
    for target in targets:
        bare = target.get("bound_candidate_scoring_id")
        _require(isinstance(bare, str), "scoring target lacks committed ID")
        lookup = f"scoring:{bare}"
        matches = by_id.get(lookup, [])
        _require(len(matches) == 1, "scoring lookup does not have exactly one row")
        line, raw, parsed = matches[0]
        if row_commitments is not None:
            commitment = row_commitments.get(lookup)
            _require(commitment is not None, "scoring committed row is missing")
            _require(commitment.get("jsonl_line") == line, "scoring committed JSONL line mismatch")
            _require(commitment.get("row_bytes_sha256") == _sha256_bytes(raw), "scoring committed row bytes mismatch")
        output.append(
            _candidate_record({
                "target_index": target["target_index"],
                "source_binding_target_id": target["source_binding_target_id"],
                "route_rule_id": "R4_WRAPPER_SCORING_231",
                "source_side": "CANDIDATE",
                "authority_status": "CANDIDATE_WRAPPER_OBJECTS_ONLY",
                "source_key": lookup,
                "source_locator": f"jsonl:{line}",
                "jsonl_line": line,
                "row_bytes_sha256": _sha256_bytes(raw),
                "source_row": parsed,
                "historical_scoring_artifact_preserved": True,
                "scoring_authority_mutated": False,
                "source_auth_executed": False,
                "field_pin_created": False,
            })
        )
    return output


def validate_exact317_conservation(
    targets: Sequence[Mapping[str, object]], route_records: Mapping[str, Sequence[Mapping[str, object]]]
) -> dict:
    """Verify route commitments conserve Exact317 without duplicate or substitution."""
    _require(len(targets) == 317, "Exact317 manifest total mismatch")
    target_ids = [t.get("source_binding_target_id") for t in targets]
    _require(len(set(target_ids)) == 317, "duplicate Exact317 target identity")
    expected_route = {
        "R4_WRAPPER_RAW_LEGACY_26": RAW_LEGACY_INDICES,
        "R4_WRAPPER_C0_60": C0_INDICES,
        "R4_WRAPPER_SCORING_231": SCORING_INDICES,
    }
    _require(set(route_records) == set(expected_route), "route set mismatch")
    seen: list[str] = []
    raw_count = 0
    candidate_count = 0
    for rule_id, records in route_records.items():
        _require({r.get("target_index") for r in records} == set(expected_route[rule_id]), f"{rule_id} target commitment mismatch")
        for record in records:
            _require(record.get("route_rule_id") == rule_id, "cross-route substitution")
            _require(record.get("authority_status") == "CANDIDATE_WRAPPER_OBJECTS_ONLY", "non-candidate output object")
            seen.append(record.get("source_binding_target_id"))
            if record.get("source_side") == "RAW":
                raw_count += 1
            elif record.get("source_side") == "CANDIDATE":
                candidate_count += 1
            else:
                raise WrapperError("invalid source side")
    _require(len(seen) == 317 and len(set(seen)) == 317, "duplicate or missing route output identity")
    _require(set(seen) == set(target_ids), "route union is not Exact317")
    _require(raw_count == 86 and candidate_count == 231, "Exact317 side counts mismatch")
    return {
        "targets_total": 317,
        "raw": raw_count,
        "candidate": candidate_count,
        "duplicates": len(seen) - len(set(seen)),
        "cross_route_substitution": 0,
        "union": "Exact317",
        "exact": True,
    }
