#!/usr/bin/env python3
"""Recover source detail and enrich the E0C-R5 human review substrate."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


EXPECTED_MANUAL_COUNT = 589
EXPECTED_RAW_COUNT = 1796
EXPECTED_SHARED_TEMPLATE_COUNT = 89
EXPECTED_SHARED_COVERED_ROWS = 494
EXPECTED_RAW_SPECIFIC_COUNT = 64
EXPECTED_BLOCKED_COUNT = 31
EXPECTED_REVIEW_BATCH_COUNT = 9
FIRST_TRANCHE_TEMPLATE_COUNT = 12
PINNED_REVIEW_COMMIT = "90513ab76a2d392398fefd0456ad53a4660a3e8a"

R1_FILE = "EXP_E0C_R1_1796_ENRICHED_READINESS.jsonl"
R2_FILE = "E0C_R2_MANUAL_DESIGN_BLOCKERS.json"
R3_FILE = "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl"
R4_EXACT_FILE = "E0C_R4_EXACT589_MANUAL_SET.json"
R4_TEMPLATES_FILE = "E0C_R4_SHARED_MANUAL_DESIGN_TEMPLATES.json"
R4_MAP_FILE = "E0C_R4_RAW_TO_TEMPLATE_MAP.jsonl"
R4_PACKETS_FILE = "E0C_R4_HUMAN_TEMPLATE_REVIEW_PACKETS.jsonl"
R4_AUDIT_FILE = "E0C_R4_MANUAL_WORKLOAD_AUDIT.json"
R4_OUTLIERS_FILE = "E0C_R4_MANUAL_OUTLIERS.json"
R5_AUTH_FILE = "E0C_R5_EXACT89_TEMPLATE_AUDIT.json"
R5_PRIORITY_FILE = "E0C_R5_TEMPLATE_PRIORITY.json"
R5_BATCHES_FILE = "E0C_R5_REVIEW_BATCHES.json"
R5_SHEETS_FILE = "E0C_R5_HUMAN_REVIEW_SHEETS.md"
R5_RECOVERY_FILE = "E0C_R5_BLOCKED31_SOURCE_DETAIL_RECOVERY.json"
R5_RAW_SPECIFIC_FILE = "E0C_R5_RAW_SPECIFIC64_PRIORITY.json"
R5_REPORT_FILE = "E0C_R5_REVIEW_BATCHING_REPORT.md"

SHARED_TEMPLATE = "CANDIDATE_FOR_SHARED_HUMAN_TEMPLATE"
RAW_SPECIFIC = "RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED"
BLOCKED_DETAIL = "BLOCKED_NEED_MORE_SOURCE_DETAIL"
MANUAL_STATUS = "MANUAL_DESIGN_REQUIRED"
RECOVERY_STATUSES = {
    "RECOVERED_FROM_AUTHENTICATED_EXISTING_SOURCE",
    "NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE",
    "CONFLICTING_EXISTING_SOURCE_DETAIL",
}
DECISION_OPTIONS = [
    "APPROVE_TEMPLATE_FOR_MEMBER_SET",
    "REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL",
    "REQUEST_SPLIT_OR_MORE_EVIDENCE",
]

R5_ARTIFACTS = (
    R5_AUTH_FILE,
    R5_PRIORITY_FILE,
    R5_BATCHES_FILE,
    R5_SHEETS_FILE,
    R5_RECOVERY_FILE,
    R5_RAW_SPECIFIC_FILE,
    R5_REPORT_FILE,
)
SOURCE_DETAIL_FIELDS = ("named_protocols_or_services", "service_prerequisites")
SOURCE_FIELD_PATHS = {
    "named_protocols_or_services": "R1.named_protocols_or_services / source action has no named_protocols_or_services key",
    "service_prerequisites": "R1.service_prerequisites / source action has no service_prerequisites key",
}


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path.name}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"expected JSON object at {path.name}:{number}")
            rows.append(value)
    return rows


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _sha256_bytes(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _sha256_keys(keys: list[str]) -> str:
    return _sha256_bytes("\n".join(sorted(keys)).encode("utf-8"))


def _sorted_strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return sorted(str(item) for item in value)
    if value is None:
        return ["UNKNOWN"]
    return [str(value)]


def _unknown(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, list):
        return not value or all(str(item).startswith("UNKNOWN") for item in value)
    return str(value).startswith("UNKNOWN")


def _source_root(root: Path) -> Path:
    candidates = [
        root / "full-action-protocol-binding",
        root.parent / "full-action-protocol-binding",
        Path("/home/cph/experiment-worktrees/full-action-protocol-binding"),
    ]
    for candidate in candidates:
        if (candidate / "APT数据集").is_dir() and (candidate / "data/full_action/raw_action_registry.jsonl").is_file():
            return candidate
    raise ValueError("authenticated raw source corpus and verified registry are unavailable")


def _parse_locator(locator: str) -> tuple[int, int]:
    match = re.fullmatch(r"\$\.pipeline\[(\d+)\]\.actions\[(\d+)\]", str(locator))
    if not match:
        raise ValueError(f"unsupported source locator: {locator}")
    return int(match.group(1)), int(match.group(2))


def _source_action(project_root: Path, r1: Mapping[str, Any], registry: Mapping[str, Any]) -> dict[str, Any]:
    source_file = str(r1.get("source_file"))
    if source_file != str(registry.get("source_file")):
        raise ValueError(f"source file mismatch for {r1.get('raw_key')}")
    source_path = project_root / source_file
    if not source_path.is_file():
        raise ValueError(f"source file missing: {source_file}")
    source_sha = _sha256_file(source_path)
    expected_sha = str(r1.get("source_file_sha256"))
    if source_sha != expected_sha or source_sha != str(registry.get("source_file_sha256")):
        raise ValueError(f"source file hash mismatch for {r1.get('raw_key')}")
    stage_index, action_index = _parse_locator(str(r1.get("source_locator")))
    source_doc = _load_json(source_path)
    try:
        action = source_doc["pipeline"][stage_index]["actions"][action_index]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"source locator does not resolve for {r1.get('raw_key')}") from exc
    if not isinstance(action, dict):
        raise ValueError(f"source action is not an object for {r1.get('raw_key')}")
    comparisons = {
        "name": (action.get("name"), registry.get("action_name"), r1.get("action_name")),
        "desc": (action.get("desc"), registry.get("action_description"), r1.get("action_description")),
        "action_type": (action.get("action_type"), registry.get("action_type"), r1.get("action_type")),
        "os": (action.get("os"), registry.get("os"), (r1.get("os_platform_hints") or [None])[0]),
    }
    for field, values in comparisons.items():
        if not (values[0] == values[1] == values[2]):
            raise ValueError(f"source field mismatch for {r1.get('raw_key')} field={field}")
    validation_rule_evidence = _validation_rule_evidence(project_root, registry, source_file, str(r1.get("raw_key")))
    return {
        "source_file": source_file,
        "source_locator": str(r1.get("source_locator")),
        "source_file_sha256": source_sha,
        "source_action_sha256": _canonical_sha256(action),
        "action_name": action.get("name"),
        "action_description": action.get("desc"),
        "action_type": action.get("action_type"),
        "os": action.get("os"),
        "source_action_fields": {
            "name": action.get("name"),
            "desc": action.get("desc"),
            "action_type": action.get("action_type"),
            "os": action.get("os"),
            "uuid": action.get("uuid"),
            "vid": action.get("vid"),
            "required_parms": action.get("required_parms"),
            "args": action.get("args"),
            "is_http": action.get("is_http"),
            "is_net_host_cli": action.get("is_net_host_cli"),
            "must_sandbox": action.get("must_sandbox"),
            "is_endpoint": action.get("is_endpoint"),
        },
        "validation_rule_evidence": validation_rule_evidence,
    }


def _validation_rule_evidence(
    project_root: Path,
    registry: Mapping[str, Any],
    playbook_source_file: str,
    raw_key: str,
) -> dict[str, Any]:
    """Read the immutable Validation_rules sidecar without inferring fields."""
    vid = str(registry.get("dataset_vid", ""))
    if not vid:
        return {
            "source_file": "",
            "source_locator": "$.data",
            "source_file_sha256": "",
            "exact_source_fields": {},
            "availability": "NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE",
        }
    sidecar_path = project_root / "APT数据集" / "Validation_rules" / f"{vid}.json"
    if not sidecar_path.is_file():
        return {
            "source_file": f"APT数据集/Validation_rules/{vid}.json",
            "source_locator": "$.data",
            "source_file_sha256": "",
            "exact_source_fields": {},
            "availability": "NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE",
        }
    sidecar = _load_json(sidecar_path)
    data = sidecar.get("data", {})
    if not isinstance(data, dict):
        raise ValueError(f"validation rule sidecar data is not an object: {raw_key}")
    # Sidecars may be shared by several raw occurrences. Verify the identity
    # fields that are available, but never let sidecar prose override the
    # authoritative playbook/R1 fields.
    if data.get("name") not in {None, registry.get("action_name")}:
        raise ValueError(f"validation rule name mismatch: {raw_key}")
    if data.get("action_type") not in {None, registry.get("action_type")}:
        raise ValueError(f"validation rule action type mismatch: {raw_key}")
    if data.get("os") not in {None, registry.get("os")}:
        raise ValueError(f"validation rule OS mismatch: {raw_key}")
    host_cli = data.get("host_cli_action")
    exact_fields = {
        "name": data.get("name"),
        "desc": data.get("desc"),
        "action_type": data.get("action_type"),
        "os": data.get("os"),
        "notes": data.get("notes"),
        "run_as": (data.get("old_tags") or {}).get("run_as", []),
        "required_parms": data.get("required_parms"),
        "host_cli_action": {
            "shell": host_cli.get("shell") if isinstance(host_cli, dict) else None,
            "raw_text": host_cli.get("raw_text") if isinstance(host_cli, dict) else None,
            "steps": host_cli.get("steps") if isinstance(host_cli, dict) else None,
            "delivery_failed_result": host_cli.get("delivery_failed_result") if isinstance(host_cli, dict) else None,
            "destination_exists_result": host_cli.get("destination_exists_result") if isinstance(host_cli, dict) else None,
            "monitor_connections": host_cli.get("monitor_connections") if isinstance(host_cli, dict) else None,
        },
        "is_http": data.get("is_http"),
        "is_net_host_cli": data.get("is_net_host_cli"),
        "must_sandbox": data.get("must_sandbox"),
        "is_endpoint": data.get("is_endpoint"),
    }
    return {
        "source_file": f"APT数据集/Validation_rules/{vid}.json",
        "source_locator": "$.data",
        "source_file_sha256": _sha256_file(sidecar_path),
        "validation_rule_data_sha256": _canonical_sha256(data),
        "dataset_vid": vid,
        "playbook_source_file": playbook_source_file,
        "exact_source_fields": exact_fields,
        "availability": "PRESENT_IN_IMMUTABLE_LOCAL_PROJECT_EVIDENCE",
    }


def _source_registry(project_root: Path) -> tuple[dict[str, Mapping[str, Any]], str]:
    path = project_root / "data/full_action/raw_action_registry.jsonl"
    rows = _load_jsonl(path)
    by_key = {str(row.get("raw_action_key")): row for row in rows}
    if len(rows) != EXPECTED_RAW_COUNT or len(by_key) != EXPECTED_RAW_COUNT:
        raise ValueError("verified raw registry does not contain exact1796 rows")
    return by_key, _sha256_file(path)


def _input_authentication(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    r4_exact = _load_json(root / R4_EXACT_FILE)
    r4_templates = _load_json(root / R4_TEMPLATES_FILE)
    r4_map = _load_jsonl(root / R4_MAP_FILE)
    r4_packets = _load_jsonl(root / R4_PACKETS_FILE)
    r4_audit = _load_json(root / R4_AUDIT_FILE)
    r4_outliers = _load_json(root / R4_OUTLIERS_FILE)
    r5_auth = _load_json(root / R5_AUTH_FILE)
    r5_priority = _load_json(root / R5_PRIORITY_FILE)
    r5_batches = _load_json(root / R5_BATCHES_FILE)
    r5_recovery = _load_json(root / R5_RECOVERY_FILE)
    r5_raw_specific = _load_json(root / R5_RAW_SPECIFIC_FILE)
    r1_rows = _load_jsonl(root / R1_FILE)
    r2_rows = _load_json(root / R2_FILE).get("rows", [])
    r3_rows = _load_jsonl(root / R3_FILE)
    r1_by_key = {str(row.get("raw_key")): row for row in r1_rows}
    r2_by_key = {str(row.get("raw_key")): row for row in r2_rows}
    r3_by_key = {str(row.get("raw_key")): row for row in r3_rows}
    if len(r1_by_key) != 1796 or len(r3_by_key) != 1796:
        raise ValueError("R1/R3 exact1796 sets are not authenticated")

    shared_templates = sorted(
        [template for template in r4_templates.get("templates", []) if template.get("classification") == SHARED_TEMPLATE],
        key=lambda item: str(item.get("template_id")),
    )
    shared_priority = sorted(r5_priority.get("templates", []), key=lambda item: int(item.get("priority_rank", 0)))
    if len(shared_templates) != EXPECTED_SHARED_TEMPLATE_COUNT or len(shared_priority) != EXPECTED_SHARED_TEMPLATE_COUNT:
        raise ValueError("R4/R5 exact89 shared template set is invalid")
    shared_ids = {str(item.get("template_id")) for item in shared_templates}
    if {str(item.get("template_id")) for item in shared_priority} != shared_ids:
        raise ValueError("R5 priority template IDs differ from R4 exact89")

    exact_keys = sorted(str(item) for item in r4_exact.get("raw_keys", []))
    if len(exact_keys) != EXPECTED_MANUAL_COUNT or len(set(exact_keys)) != EXPECTED_MANUAL_COUNT or r4_exact.get("manual_set_conservation") != "PASS":
        raise ValueError("R4 exact589 manual set is invalid")
    map_by_key = {str(row.get("raw_key")): row for row in r4_map}
    if len(r4_map) != EXPECTED_MANUAL_COUNT or set(map_by_key) != set(exact_keys):
        raise ValueError("R4 raw-to-template map does not match exact589")
    shared_member_keys = sorted(
        str(key) for key, row in map_by_key.items() if row.get("template_classification") == SHARED_TEMPLATE
    )
    if len(shared_member_keys) != EXPECTED_SHARED_COVERED_ROWS or len(set(shared_member_keys)) != EXPECTED_SHARED_COVERED_ROWS:
        raise ValueError("R4 shared member union is not exact494")
    blocked_keys = sorted(
        str(item.get("raw_key")) for item in r4_outliers.get("rows", []) if item.get("classification") == BLOCKED_DETAIL
    )
    raw_specific_keys = sorted(
        str(item.get("raw_key")) for item in r4_outliers.get("rows", []) if item.get("classification") == RAW_SPECIFIC
    )
    if len(blocked_keys) != EXPECTED_BLOCKED_COUNT or len(raw_specific_keys) != EXPECTED_RAW_SPECIFIC_COUNT:
        raise ValueError("R4 outlier sets are not exact31/exact64")
    if r5_recovery.get("blocked_need_more_source_detail_count") != EXPECTED_BLOCKED_COUNT or r5_raw_specific.get("raw_specific_count") != EXPECTED_RAW_SPECIFIC_COUNT:
        raise ValueError("R5 recovery or raw-specific counts drifted")
    if sorted(str(row.get("raw_key")) for row in r5_recovery.get("rows", [])) != blocked_keys:
        raise ValueError("R5 blocked recovery set differs from R4 exact31")
    if sorted(str(row.get("raw_key")) for row in r5_raw_specific.get("rows", [])) != raw_specific_keys:
        raise ValueError("R5 raw-specific set differs from R4 exact64")
    if r5_batches.get("review_batch_count") != EXPECTED_REVIEW_BATCH_COUNT:
        raise ValueError("R5 review batch count drifted")
    batch_ids = [str(template_id) for batch in r5_batches.get("batches", []) for template_id in batch.get("template_ids", [])]
    if len(batch_ids) != EXPECTED_SHARED_TEMPLATE_COUNT or len(set(batch_ids)) != EXPECTED_SHARED_TEMPLATE_COUNT or set(batch_ids) != shared_ids:
        raise ValueError("R5 batches do not conserve exact89 template IDs")
    if r5_auth.get("shared_template_count") != EXPECTED_SHARED_TEMPLATE_COUNT or r5_auth.get("shared_template_covered_rows") != EXPECTED_SHARED_COVERED_ROWS or r5_auth.get("template_member_overlap") != 0 or r5_auth.get("template_member_missing") != 0:
        raise ValueError("R5 exact89 audit is not PASS")
    if len(r4_packets) != len(r4_templates.get("templates", [])) or len({str(packet.get("template_id")) for packet in r4_packets}) != len(r4_packets):
        raise ValueError("R4 review packets do not cover the full template set")
    if any(packet.get("decision") is not None or packet.get("human_decisions_created") != 0 for packet in r4_packets):
        raise ValueError("R4 review packets contain decisions")
    if r4_audit.get("exact_manual_raw_count") != EXPECTED_MANUAL_COUNT or r4_audit.get("classification_overlap") != 0 or r4_audit.get("classification_missing") != 0:
        raise ValueError("R4 workload audit is not conserved")
    if r4_audit.get("human_decisions_created") != 0 or r5_auth.get("human_decisions_created") != 0:
        raise ValueError("prior artifact contains human decisions")

    commitments = {}
    for template in shared_priority:
        keys = sorted(str(key) for key in template.get("member_keys", []))
        if template.get("member_key_commitment", {}).get("sha256") != _sha256_keys(keys):
            raise ValueError(f"member commitment drift: {template.get('template_id')}")
        commitments[str(template["template_id"])] = {
            "member_count": len(keys),
            "member_key_sha256": template["member_key_commitment"]["sha256"],
            "member_keys": keys,
        }
    union = [key for item in commitments.values() for key in item["member_keys"]]
    overlap = len(union) - len(set(union))
    missing = len(set(shared_member_keys) - set(union)) + len(set(union) - set(shared_member_keys))
    if len(union) != EXPECTED_SHARED_COVERED_ROWS or overlap != 0 or missing != 0:
        raise ValueError("R5 member commitments do not conserve exact494")
    status_checks = []
    for key in sorted(set(union) | set(blocked_keys) | set(raw_specific_keys)):
        row = r3_by_key.get(key)
        if row is None or row.get("global_planning_status") != MANUAL_STATUS:
            raise ValueError(f"manual status drift: {key}")
        status_checks.append({"raw_key": key, "r3_global_planning_status": row.get("global_planning_status")})
    authenticated_inputs = [
        {"file": name, "sha256": _sha256_file(root / name)}
        for name in (
            R4_EXACT_FILE,
            R4_TEMPLATES_FILE,
            R4_MAP_FILE,
            R4_PACKETS_FILE,
            R4_AUDIT_FILE,
            R4_OUTLIERS_FILE,
            R5_AUTH_FILE,
            R5_PRIORITY_FILE,
            R5_BATCHES_FILE,
            R5_RECOVERY_FILE,
            R5_RAW_SPECIFIC_FILE,
            R5_SHEETS_FILE,
            R5_REPORT_FILE,
        )
    ]
    authenticated_supporting_inputs = [
        {"file": name, "sha256": _sha256_file(root / name)}
        for name in (R1_FILE, R2_FILE, R3_FILE)
    ]
    auth = {
        "schema_version": "e0c-r6-input-authentication-v1",
        "pinned_review_commit": PINNED_REVIEW_COMMIT,
        "github_review_commit": PINNED_REVIEW_COMMIT,
        "review_commit": PINNED_REVIEW_COMMIT,
        "pinned_review_commit_verification": "DECLARED_BY_R6_PROMPT; COMMIT_NOT_PRESENT_IN_LOCAL_WORKTREE",
        "authenticated_inputs": authenticated_inputs,
        "authenticated_supporting_inputs": authenticated_supporting_inputs,
        "exact_manual_raw_count": EXPECTED_MANUAL_COUNT,
        "shared_template_count": EXPECTED_SHARED_TEMPLATE_COUNT,
        "shared_template_covered_rows": EXPECTED_SHARED_COVERED_ROWS,
        "raw_specific_count": len(raw_specific_keys),
        "blocked_count": len(blocked_keys),
        "review_batch_count": r5_batches.get("review_batch_count"),
        "review_batch_template_ids": batch_ids,
        "review_batch_template_ids_commitment": {"algorithm": "sha256", "canonical_order": "template IDs in deterministic batch order joined with LF", "sha256": _sha256_bytes("\n".join(batch_ids).encode("utf-8"))},
        "template_member_overlap": overlap,
        "template_member_missing": missing,
        "shared_member_set_commitment": {"algorithm": "sha256", "canonical_order": "lexicographic raw_key joined with LF", "sha256": _sha256_keys(shared_member_keys)},
        "blocked_set_commitment": {"algorithm": "sha256", "canonical_order": "lexicographic raw_key joined with LF", "sha256": _sha256_keys(blocked_keys)},
        "raw_specific_set_commitment": {"algorithm": "sha256", "canonical_order": "lexicographic raw_key joined with LF", "sha256": _sha256_keys(raw_specific_keys)},
        "template_member_commitments": commitments,
        "member_status_checks": status_checks,
        "human_decisions_created": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "authority_mutation": "NO",
        "scoring_mutation": "NO",
        "provx_claim": "NONE; all R1/R3 PROVX status fields remain UNKNOWN or UNEXECUTED_NOT_OBSERVED",
    }
    return auth, {
        "r1_by_key": r1_by_key,
        "r2_by_key": r2_by_key,
        "r3_by_key": r3_by_key,
        "map_by_key": map_by_key,
        "shared_priority": shared_priority,
        "shared_templates": shared_templates,
        "blocked_keys": blocked_keys,
        "raw_specific_keys": raw_specific_keys,
        "r4_outliers": r4_outliers,
        "r5_raw_specific": r5_raw_specific,
    }


def _search_identity(path: str, sha256: str, role: str, locator: str | None = None) -> dict[str, Any]:
    value = {"source_identity": path, "sha256": sha256, "role": role}
    if locator is not None:
        value["locator"] = locator
    return value


def _recover_blocked(
    root: Path,
    project_root: Path,
    auth: Mapping[str, Any],
    data: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    registry, registry_sha = _source_registry(project_root)
    r1_by_key = data["r1_by_key"]
    r2_by_key = data["r2_by_key"]
    r3_by_key = data["r3_by_key"]
    outlier_by_key = {str(row.get("raw_key")): row for row in data["r4_outliers"].get("rows", [])}
    searched_common = [
        _search_identity(R1_FILE, _sha256_file(root / R1_FILE), "authenticated_R1_enrichment"),
        _search_identity(R2_FILE, _sha256_file(root / R2_FILE), "authenticated_R2_blocker_evidence"),
        _search_identity(R3_FILE, _sha256_file(root / R3_FILE), "authenticated_R3_status"),
        _search_identity(R4_OUTLIERS_FILE, _sha256_file(root / R4_OUTLIERS_FILE), "authenticated_R4_missing-detail_rationale"),
        _search_identity(R5_RECOVERY_FILE, _sha256_file(root / R5_RECOVERY_FILE), "authenticated_R5_recovery_plan"),
        _search_identity("data/full_action/raw_action_registry.jsonl", registry_sha, "verified_raw_action_registry"),
    ]
    recovered_rows: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    for raw_key in data["blocked_keys"]:
        r1 = r1_by_key[raw_key]
        r2 = r2_by_key[raw_key]
        r3 = r3_by_key[raw_key]
        outlier = outlier_by_key[raw_key]
        reg = registry.get(raw_key)
        if reg is None:
            raise ValueError(f"blocked raw missing from verified registry: {raw_key}")
        source = _source_action(project_root, r1, reg)
        source_path = project_root / str(r1["source_file"])
        source_file_sha = _sha256_file(source_path)
        source_locator = str(r1["source_locator"])
        row_searches = [
            dict(item, searched_fields={field: ("UNKNOWN" if field in r1 and _unknown(r1.get(field)) else r1.get(field)) for field in SOURCE_DETAIL_FIELDS})
            for item in searched_common
        ]
        row_searches.append(_search_identity(
            str(r1["source_file"]),
            source_file_sha,
            "authoritative_raw_playbook_corpus",
            source_locator,
        ))
        source_action = source["source_action_fields"]
        validation_rule = source["validation_rule_evidence"]
        if validation_rule.get("source_file"):
            row_searches.append(_search_identity(
                str(validation_rule["source_file"]),
                str(validation_rule.get("source_file_sha256", "")),
                "immutable_local_validation_rule_evidence",
                str(validation_rule.get("source_locator", "$.data")),
            ))
        validation_fields = validation_rule.get("exact_source_fields", {})
        validation_host_cli = validation_fields.get("host_cli_action", {}) if isinstance(validation_fields, dict) else {}
        missing_results = {
            "named_protocols_or_services": {
                "r1_value": r1.get("named_protocols_or_services"),
                "registry_field": "ABSENT",
                "source_action_field": "ABSENT",
                "validation_rule_field": "ABSENT",
                "source_text_mentions_protocol": "PRESENT_AS_UNSPECIFIED_NARRATIVE" if "protocol" in str(source["action_description"]).lower() else "ABSENT",
            },
            "service_prerequisites": {
                "r1_value": r1.get("service_prerequisites"),
                "registry_field": "ABSENT",
                "source_action_field": "ABSENT",
                "validation_rule_field": "ABSENT",
                "required_parms": source_action.get("required_parms"),
            },
        }
        exact_evidence = {
            "raw_key": raw_key,
            "source_file": source["source_file"],
            "source_locator": source_locator,
            "source_file_sha256": source_file_sha,
            "source_action_sha256": source["source_action_sha256"],
            "source_action_name": source["action_name"],
            "source_action_description": source["action_description"],
            "source_action_type": source["action_type"],
            "source_os": source["os"],
            "verified_registry_identity": {
                "raw_action_key": reg.get("raw_action_key"),
                "source_file": reg.get("source_file"),
                "source_locator": reg.get("source_locator"),
                "source_file_sha256": reg.get("source_file_sha256"),
                "dataset_uuid": reg.get("dataset_uuid"),
                "dataset_vid": reg.get("dataset_vid"),
            },
            "validation_rule_evidence": validation_rule,
        }
        evidence_hash = _canonical_sha256({"exact_source_evidence": exact_evidence, "missing_field_search": missing_results})
        source_fields = {
            "source_file": source["source_file"],
            "source_locator": source_locator,
            "source_file_sha256": source_file_sha,
            "source_action_sha256": source["source_action_sha256"],
            "action_name": source["action_name"],
            "action_description": source["action_description"],
            "action_type": source["action_type"],
            "os": source["os"],
            "validation_rule_shell": validation_host_cli.get("shell") if isinstance(validation_host_cli, dict) else None,
            "validation_rule_raw_text": validation_host_cli.get("raw_text") if isinstance(validation_host_cli, dict) else None,
            "validation_rule_steps": validation_host_cli.get("steps") if isinstance(validation_host_cli, dict) else None,
            "validation_rule_run_as": validation_fields.get("run_as", []) if isinstance(validation_fields, dict) else [],
        }
        recovery_status = "NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE"
        recovered_rows.append({
            "raw_key": raw_key,
            "original_r4_classification": outlier.get("classification"),
            "classification": BLOCKED_DETAIL,
            "r4_rationale": outlier.get("rationale"),
            "missing_fields": list(SOURCE_DETAIL_FIELDS),
            "searched_source_identities": row_searches,
            "exact_source_evidence": exact_evidence,
            "validation_rule_evidence": validation_rule,
            "recovered_source_fields": source_fields,
            "missing_field_search_results": missing_results,
            "evidence_hash": evidence_hash,
            "evidence_sha256": evidence_hash,
            "recovery_status": recovery_status,
            "resulting_classification": BLOCKED_DETAIL,
            "advisory_reclassification": "CANDIDATE_FOR_HUMAN_RECLASSIFICATION_AFTER_SOURCE_RECOVERY",
            "semantics_inferred": False,
            "r3_global_planning_status": r3.get("global_planning_status"),
            "formal_execution_authorized": False,
            "human_decision": None,
            "status_mutations": 0,
            "denominator_change": "NO",
        })
        evidence_rows.append({
            "raw_key": raw_key,
            "classification": BLOCKED_DETAIL,
            "recovery_status": recovery_status,
            "source_file": source["source_file"],
            "source_locator": source_locator,
            "source_file_sha256": source_file_sha,
            "source_action_sha256": source["source_action_sha256"],
            "validation_rule_evidence": validation_rule,
            "recovered_source_fields": source_fields,
            "missing_source_fields": list(SOURCE_DETAIL_FIELDS),
            "missing_field_search_results": missing_results,
            "evidence_hash": evidence_hash,
            "evidence_sha256": evidence_hash,
            "searched_source_identities": row_searches,
            "semantics_inferred": False,
            "original_r4_classification": BLOCKED_DETAIL,
            "resulting_classification": BLOCKED_DETAIL,
            "advisory_reclassification": "CANDIDATE_FOR_HUMAN_RECLASSIFICATION_AFTER_SOURCE_RECOVERY",
            "status_mutations": 0,
            "denominator_change": "NO",
        })
    statuses = Counter(str(row["recovery_status"]) for row in recovered_rows)
    result = {
        "schema_version": "e0c-r6-blocked31-source-recovery-results-v1",
        "exact31_conservation": "PASS" if len(recovered_rows) == EXPECTED_BLOCKED_COUNT and len({row["raw_key"] for row in recovered_rows}) == EXPECTED_BLOCKED_COUNT else "BLOCKED",
        "blocked_count": len(recovered_rows),
        "recovered_from_authenticated_existing_source": statuses.get("RECOVERED_FROM_AUTHENTICATED_EXISTING_SOURCE", 0),
        "not_present_in_authenticated_existing_source": statuses.get("NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE", 0),
        "conflicting_existing_source_detail": statuses.get("CONFLICTING_EXISTING_SOURCE_DETAIL", 0),
        "allowed_recovery_statuses": sorted(RECOVERY_STATUSES),
        "advisory_reclassification": "CANDIDATE_FOR_HUMAN_RECLASSIFICATION_AFTER_SOURCE_RECOVERY",
        "rows": recovered_rows,
        "human_decisions_created": 0,
        "status_mutations": 0,
        "denominator_change": "NO",
        "authority_mutation": "NO",
        "formal_execution_authorized": False,
        "inferred_semantics": False,
    }
    return result, evidence_rows


def _source_evidence_reference(r1: Mapping[str, Any], source: Mapping[str, Any], raw_key: str) -> dict[str, Any]:
    return {
        "raw_key": raw_key,
        "source_file": source["source_file"],
        "source_locator": source["source_locator"],
        "source_file_sha256": source["source_file_sha256"],
        "source_action_sha256": source["source_action_sha256"],
        "validation_rule_evidence_reference": source["validation_rule_evidence"],
        "exact_source_fields": {
            "action_name": source["action_name"],
            "action_description": source["action_description"],
            "action_type": source["action_type"],
            "os": source["os"],
            "r1_named_protocols_or_services": r1.get("named_protocols_or_services"),
            "r1_service_prerequisites": r1.get("service_prerequisites"),
            "r1_required_protocol": r1.get("required_protocol"),
            "r1_required_service_class": r1.get("required_service_class"),
        },
        "source_field_provenance": r1.get("planning_field_provenance", {}),
    }


def _unknown_fields(rows: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    fields = [
        "named_protocols_or_services",
        "service_prerequisites",
        "required_protocol",
        "required_service_class",
        "required_preconditions",
        "cleanup_reset_requirement",
        "defensive_equivalence_requirements",
        "provx_expected_causal_edge_classes",
        "provx_expected_entity_types",
    ]
    unknowns = []
    for field in fields:
        values = [row.get(field) for row in rows]
        if any(_unknown(value) for value in values):
            unknowns.append({"field": field, "state": "UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE"})
    return unknowns


def _environment_prerequisites(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    fields = (
        "required_os_or_host_class",
        "required_preconditions",
        "required_protocol",
        "required_service_class",
        "named_protocols_or_services",
        "service_prerequisites",
        "environment_blockers",
        "requires_external_service_emulation",
        "requires_windows_semantics",
        "requires_linux_semantics",
    )
    return {
        "per_raw_authenticated_values": [
            {"raw_key": str(row.get("raw_key")), **{field: row.get(field) for field in fields}}
            for row in rows
        ],
        "known_protocol_service_platform": {
            field: sorted({str(item) for row in rows for item in _flatten(row.get(field)) if not str(item).startswith("UNKNOWN")})
            for field in ("required_os_or_host_class", "required_protocol", "required_service_class", "service_prerequisites")
        },
        "unresolved_environment_fields": _unknown_fields(rows),
        "controlled_environment_feasibility": "NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION",
        "formal_execution_authorized": False,
    }


def _flatten(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def _enrich_templates(
    project_root: Path,
    data: Mapping[str, Any],
    recovery_rows: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    registry, _ = _source_registry(project_root)
    r1_by_key = data["r1_by_key"]
    r3_by_key = data["r3_by_key"]
    recovery_by_key = {str(row["raw_key"]): row for row in recovery_rows}
    packets: list[dict[str, Any]] = []
    for template in data["shared_priority"]:
        template_id = str(template["template_id"])
        keys = sorted(str(key) for key in template.get("member_keys", []))
        rows = [r1_by_key[key] for key in keys]
        refs = []
        for row in rows:
            source = _source_action(project_root, row, registry[row["raw_key"]])
            refs.append(_source_evidence_reference(row, source, str(row["raw_key"])))
        representatives = []
        for ref in refs[:3]:
            fields = ref["exact_source_fields"]
            representatives.append({
                "raw_key": ref["raw_key"],
                "source_file": ref["source_file"],
                "source_locator": ref["source_locator"],
                "source_file_sha256": ref["source_file_sha256"],
                "source_action_sha256": ref["source_action_sha256"],
                "exact_source_snippet": {
                    "action_name": fields["action_name"],
                    "action_description": fields["action_description"],
                    "action_type": fields["action_type"],
                    "os": fields["os"],
                },
            })
        signature = template.get("defensive_equivalence", {}).get("invariants", {})
        telemetry = template.get("telemetry_surfaces", {})
        packets.append({
            "schema_version": "e0c-r6-exact89-enriched-template-packet-v1",
            "template_id": template_id,
            "classification": SHARED_TEMPLATE,
            "template_version": "r4-template-evidence-enriched-0.1.0",
            "member_count": len(keys),
            "member_keys": keys,
            "member_key_commitment": {"algorithm": "sha256", "canonical_order": "lexicographic raw_key joined with LF", "sha256": _sha256_keys(keys)},
            "playbook_count": template.get("playbook_count"),
            "primary_execution_archetype": template.get("primary_execution_archetype"),
            "exact_source_evidence_references": refs,
            "representative_raw_source_snippets": representatives,
            "environment_prerequisites": _environment_prerequisites(rows),
            "known_protocol_service_platform": {
                "os_platform_hints": sorted({str(item) for row in rows for item in _flatten(row.get("os_platform_hints"))}),
                "named_protocols_or_services": sorted({str(item) for row in rows for item in _flatten(row.get("named_protocols_or_services"))}),
                "service_prerequisites": sorted({str(item) for row in rows for item in _flatten(row.get("service_prerequisites"))}),
            },
            "unresolved_unknown_fields": _unknown_fields(rows),
            "defensive_equivalence_invariants": signature,
            "telemetry_equivalence_invariants": {
                **telemetry,
                "provx_phase1_observable": "UNKNOWN",
                "provx_phase2_core_edge_localizable": "UNKNOWN",
                "result_status": "UNEXECUTED_NOT_OBSERVED",
            },
            "cleanup_reset_requirements": {
                "r4_cleanup_reset": template.get("cleanup_reset", []),
                "r5_reset_safety_complexity": template.get("reset_safety_complexity", {}),
            },
            "reset_safety_complexity": template.get("reset_safety_complexity", {}),
            "negative_cases": template.get("negative_cases", []),
            "raw_specific_parameters": template.get("raw_specific_parameters", []),
            "unresolved_human_questions": template.get("unresolved_human_questions", []),
            "proposed_reusable_design_contract": {
                "source_basis": "R4 template invariants plus exact source evidence references; no semantic embedding",
                "preserve": [
                    "exact member-set authority and per-raw source locator",
                    "source-visible platform/service/protocol values where explicit",
                    "R4 defensive and telemetry equivalence invariants",
                    "inert side effects only after human approval",
                ],
                "must_remain_unknown": [item["field"] for item in _unknown_fields(rows)],
                "not_an_implementation": True,
            },
            "human_decision_options": list(DECISION_OPTIONS),
            "human_decision": None,
            "r3_global_planning_status": MANUAL_STATUS if all(r3_by_key[key].get("global_planning_status") == MANUAL_STATUS for key in keys) else "STATUS_DRIFT",
            "formal_execution_authorized": False,
            "provx_phase1_observable": "UNKNOWN",
            "provx_phase2_core_edge_localizable": "UNKNOWN",
            "result_status": "UNEXECUTED_NOT_OBSERVED",
            "human_decisions_created": 0,
            "status_mutations": 0,
            "denominator_change": "NO",
            "authority_mutation": "NO",
            "recovery_context_for_member_rows": [recovery_by_key[key] for key in keys if key in recovery_by_key],
        })
    if len(packets) != EXPECTED_SHARED_TEMPLATE_COUNT:
        raise ValueError("exact89 template enrichment count failed")
    return packets


def _first_tranche(packets: list[Mapping[str, Any]]) -> dict[str, Any]:
    # R5 priority is already deterministic by coverage/reuse. R6 adds source
    # completeness and feasibility as explicit tie-break dimensions without a
    # weighted score or changing template authority.
    def rank_key(packet: Mapping[str, Any]) -> tuple[Any, ...]:
        rows = packet["exact_source_evidence_references"]
        complete = sum(
            not _unknown(ref["exact_source_fields"].get(field))
            for ref in rows
            for field in ("action_name", "action_description", "action_type", "os")
        )
        feasibility = packet["environment_prerequisites"]["controlled_environment_feasibility"]
        safety_level = str(packet.get("reset_safety_complexity", {}).get("level", "HIGH"))
        safety_order = {"LOW": 0, "MODERATE": 1, "HIGH": 2}.get(safety_level, 3)
        return (-int(packet["member_count"]), -int(packet.get("playbook_count") or 0), -complete, feasibility, safety_order, str(packet["template_id"]))

    ordered = sorted(packets, key=rank_key)
    selected = []
    for packet in ordered[:FIRST_TRANCHE_TEMPLATE_COUNT]:
        selected.append({
            "template_id": packet["template_id"],
            "member_count": packet["member_count"],
            "member_keys": packet["member_keys"],
            "member_key_commitment": packet["member_key_commitment"],
            "primary_execution_archetype": packet["primary_execution_archetype"],
            "playbook_count": packet.get("playbook_count"),
            "exact_source_evidence_references": packet["exact_source_evidence_references"],
            "representative_raw_source_snippets": packet["representative_raw_source_snippets"],
            "environment_prerequisites": packet["environment_prerequisites"],
            "known_protocol_service_platform": packet["known_protocol_service_platform"],
            "unresolved_unknown_fields": packet["unresolved_unknown_fields"],
            "defensive_equivalence_invariants": packet["defensive_equivalence_invariants"],
            "telemetry_equivalence_invariants": packet["telemetry_equivalence_invariants"],
            "cleanup_reset_requirements": packet["cleanup_reset_requirements"],
            "reset_safety_complexity": packet["reset_safety_complexity"],
            "negative_cases": packet["negative_cases"],
            "proposed_reusable_design_contract": packet["proposed_reusable_design_contract"],
            "unresolved_human_questions": packet["unresolved_human_questions"],
            "consequences_of_approval": "Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.",
            "human_decision_options": list(DECISION_OPTIONS),
            "human_decision": None,
            "r3_global_planning_status": MANUAL_STATUS,
            "formal_execution_authorized": False,
            "status_mutations": 0,
            "denominator_change": "NO",
        })
    return {
        "schema_version": "e0c-r6-first-human-review-tranche-v1",
        "selection_policy": "Deterministic lexicographic order by coverage, playbook reuse, complete exact source fields, controlled-environment feasibility, and lower reset/safety complexity; no weighted score.",
        "template_count": len(selected),
        "raw_coverage": sum(int(item["member_count"]) for item in selected),
        "template_ids": [str(item["template_id"]) for item in selected],
        "templates": selected,
        "human_decisions_created": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "authority_mutation": "NO",
    }


def _first_review_sheets(tranche: Mapping[str, Any]) -> str:
    lines = [
        "# E0C-R6 First Human Review Sheets",
        "",
        "First-tranche presentation only. No decision is prefilled; each exact member set remains R3 `MANUAL_DESIGN_REQUIRED`.",
        "",
    ]
    for item in tranche["templates"]:
        reps = ", ".join(str(ref["raw_key"]) for ref in item["representative_raw_source_snippets"])
        lines.extend([
            f"### {item['template_id']}",
            "",
            f"- Exact covered raw count: `{item['member_count']}`",
            f"- Exact member SHA256: `{item['member_key_commitment']['sha256']}`",
            f"- Representative raw keys: `{reps}`",
            f"- Archetype / known platform / protocol-service: `{item['primary_execution_archetype']}` / `{', '.join(item['known_protocol_service_platform']['os_platform_hints'])}` / `{', '.join(item['known_protocol_service_platform']['named_protocols_or_services'])}`",
            "- Source evidence:",
        ])
        for ref in item["representative_raw_source_snippets"]:
            snippet = ref["exact_source_snippet"]
            lines.append(f"  - `{ref['raw_key']}` at `{ref['source_file']}::{ref['source_locator']}` — `{snippet['action_name']}`; exact description: {snippet['action_description']}")
        lines.extend([
            f"- Proposed reusable design contract: `{item['proposed_reusable_design_contract']['source_basis']}`",
            f"- Unresolved UNKNOWN fields: `{', '.join(entry['field'] for entry in item['unresolved_unknown_fields'])}`",
            f"- Unresolved human questions: {'; '.join(item['unresolved_human_questions'])}",
            f"- Consequences of approval: {item['consequences_of_approval']}",
            "- Allowed human actions (unselected):",
            *[f"  - `{option}`" for option in DECISION_OPTIONS],
            "",
        ])
    return "\n".join(lines) + "\n"


def _raw_specific_fixture_analysis(data: Mapping[str, Any], packets: list[Mapping[str, Any]]) -> dict[str, Any]:
    shared_signatures: dict[tuple[Any, ...], list[str]] = {}
    for packet in packets:
        flags = packet["telemetry_equivalence_invariants"].get("source_telemetry_flags", {})
        # Fixture reuse deliberately ignores semantic archetype and action
        # names. It compares only host/platform, service prerequisites, and
        # telemetry/environment requirements; semantic design remains raw-
        # specific even when this relaxed signature matches.
        sig = (
            tuple(packet["known_protocol_service_platform"].get("os_platform_hints", [])),
            tuple(packet["environment_prerequisites"].get("per_raw_authenticated_values", [{}])[0].get("service_prerequisites") or ["UNKNOWN"]),
            tuple(packet["known_protocol_service_platform"].get("named_protocols_or_services", [])),
            bool(flags.get("requires_host_process_telemetry")),
            bool(flags.get("requires_file_telemetry")),
            bool(flags.get("requires_socket_telemetry")),
            bool(flags.get("requires_network_fabric")),
        )
        shared_signatures.setdefault(sig, []).append(str(packet["template_id"]))
    rows = []
    outlier_by_key = {str(item.get("raw_key")): item for item in data["r4_outliers"].get("rows", [])}
    for source_row in sorted(data["r5_raw_specific"].get("rows", []), key=lambda item: int(item.get("priority_rank", 0))):
        raw_key = str(source_row["raw_key"])
        signature_obj = source_row.get("shared_fixture_reuse", {}).get("candidate_fixture_signature", {})
        signature = (
            tuple(signature_obj.get("os_platform_hints", [])),
            tuple(signature_obj.get("service_prerequisites", [])),
            tuple(signature_obj.get("named_protocols_or_services", [])),
            bool(signature_obj.get("requires_host_process_telemetry")),
            bool(signature_obj.get("requires_file_telemetry")),
            bool(signature_obj.get("requires_socket_telemetry")),
            bool(signature_obj.get("requires_network_fabric")),
        )
        candidates = sorted(shared_signatures.get(signature, []))
        rows.append({
            "priority_rank": int(source_row["priority_rank"]),
            "raw_key": raw_key,
            "template_id": outlier_by_key.get(raw_key, {}).get("template_id"),
            "original_classification": RAW_SPECIFIC,
            "mechanical_fixture_signature": signature_obj,
            "shared_environment_fixture_reuse_candidate": {
                "candidate_shared_template_ids": candidates,
                "reuse_scope": "ENVIRONMENT_OR_FIXTURE_ONLY; SEMANTIC_DESIGN_REMAINS_RAW_SPECIFIC",
                "evidence_basis": "Exact R1 platform/service/telemetry fields and R5 mechanical environment signature; semantic archetype is intentionally excluded from reuse matching.",
                "reuse_approved": False,
            },
            "shared_template_conversion": False,
            "semantic_resolution": None,
            "human_decision": None,
            "formal_execution_authorized": False,
            "r3_global_planning_status": MANUAL_STATUS,
            "provx_phase1_observable": "UNKNOWN",
            "provx_phase2_core_edge_localizable": "UNKNOWN",
            "status_mutations": 0,
            "denominator_change": "NO",
        })
    if len(rows) != EXPECTED_RAW_SPECIFIC_COUNT:
        raise ValueError("raw-specific fixture analysis count failed")
    return {
        "schema_version": "e0c-r6-raw-specific64-fixture-reuse-analysis-v1",
        "raw_specific_count": len(rows),
        "analysis_policy": "Support-only fixture/environment matching by exact mechanical signature; no semantic template conversion or resolution.",
        "rows": rows,
        "human_decisions_created": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "authority_mutation": "NO",
    }


def _report(auth: Mapping[str, Any], recovery: Mapping[str, Any], tranche: Mapping[str, Any], packet_count: int) -> str:
    return "\n".join([
        "# E0C-R6 Source Recovery And Template Evidence Enrichment",
        "",
        "Evidence-only recovery was attempted against the authenticated corpus and verified raw registry. Exact source fields and locators were attached to all 89 shared-template packets; no row was reclassified or executed.",
        "",
        "## Terminal",
        "",
        "E0C_R6_SOURCE_RECOVERY_AND_TEMPLATE_ENRICHMENT = READY_FOR_HUMAN_REVIEW",
        f"EXACT31_CONSERVATION = {recovery['exact31_conservation']}",
        f"RECOVERED_FROM_AUTHENTICATED_EXISTING_SOURCE = {recovery['recovered_from_authenticated_existing_source']}",
        f"NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE = {recovery['not_present_in_authenticated_existing_source']}",
        f"CONFLICTING_EXISTING_SOURCE_DETAIL = {recovery['conflicting_existing_source_detail']}",
        f"EXACT89_TEMPLATE_ENRICHMENT = {'PASS' if packet_count == EXPECTED_SHARED_TEMPLATE_COUNT else 'BLOCKED'}",
        f"FIRST_HUMAN_REVIEW_TRANCHE_TEMPLATE_COUNT = {tranche['template_count']}",
        f"FIRST_HUMAN_REVIEW_TRANCHE_RAW_COVERAGE = {tranche['raw_coverage']}",
        "HUMAN_DECISIONS_CREATED = 0",
        "STATUS_MUTATIONS = 0",
        "FORMAL_EXPERIMENT_EXECUTED = NO",
        "DENOMINATOR_CHANGE = NO",
        "NEXT_ACTION =",
        "FRESH_REVIEW_OF_E0C_R6_SOURCE_RECOVERY_AND_TEMPLATE_ENRICHMENT",
        "STOP = true",
        "",
        "## Boundaries",
        "",
        "All 31 source-detail rows retain BLOCKED_NEED_MORE_SOURCE_DETAIL and receive only the advisory CANDIDATE_FOR_HUMAN_RECLASSIFICATION_AFTER_SOURCE_RECOVERY. All 89 shared templates retain exact member commitments and MANUAL_DESIGN_REQUIRED status. R5/R6 are presentation and evidence-enrichment layers only; PROVX fields remain UNKNOWN, and no binding, scoring, denominator, authority, formal outcome, or action execution changes.",
        "",
        "STOP = true",
        "",
    ])


def build_outputs(root: Path = Path(".")) -> dict[str, Any]:
    project_root = _source_root(root)
    auth, data = _input_authentication(root)
    recovery, evidence_rows = _recover_blocked(root, project_root, auth, data)
    packets = _enrich_templates(project_root, data, recovery["rows"])
    tranche = _first_tranche(packets)
    sheets = _first_review_sheets(tranche)
    fixture = _raw_specific_fixture_analysis(data, packets)
    report = _report(auth, recovery, tranche, len(packets))
    return {
        "input_authentication": auth,
        "blocked31_source_recovery_results": recovery,
        "blocked31_recovered_evidence_jsonl": evidence_rows,
        "enriched_template_packets": packets,
        "first_human_review_tranche": tranche,
        "first_human_review_sheets": sheets,
        "raw_specific64_fixture_reuse_analysis": fixture,
        "report": report,
    }


def write_outputs(root: Path, outputs: Mapping[str, Any]) -> None:
    def write_json(name: str, value: Any) -> None:
        (root / name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")

    write_json("E0C_R6_INPUT_AUTHENTICATION.json", outputs["input_authentication"])
    write_json("E0C_R6_BLOCKED31_SOURCE_RECOVERY_RESULTS.json", outputs["blocked31_source_recovery_results"])
    (root / "E0C_R6_BLOCKED31_RECOVERED_EVIDENCE.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in outputs["blocked31_recovered_evidence_jsonl"]), encoding="utf-8", newline="\n")
    (root / "E0C_R6_EXACT89_ENRICHED_TEMPLATE_PACKETS.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in outputs["enriched_template_packets"]), encoding="utf-8", newline="\n")
    write_json("E0C_R6_FIRST_HUMAN_REVIEW_TRANCHE.json", outputs["first_human_review_tranche"])
    (root / "E0C_R6_FIRST_HUMAN_REVIEW_SHEETS.md").write_text(outputs["first_human_review_sheets"], encoding="utf-8", newline="\n")
    write_json("E0C_R6_RAW_SPECIFIC64_FIXTURE_REUSE_ANALYSIS.json", outputs["raw_specific64_fixture_reuse_analysis"])
    (root / "E0C_R6_SOURCE_RECOVERY_AND_ENRICHMENT_REPORT.md").write_text(outputs["report"], encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        outputs = build_outputs(args.root)
        if outputs["blocked31_source_recovery_results"]["exact31_conservation"] != "PASS":
            raise ValueError("exact31 recovery conservation failed")
        if len(outputs["enriched_template_packets"]) != EXPECTED_SHARED_TEMPLATE_COUNT:
            raise ValueError("exact89 enrichment failed")
        write_outputs(args.root, outputs)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print("E0C_R6_SOURCE_RECOVERY_AND_TEMPLATE_ENRICHMENT = BLOCKED")
        print(f"ERROR = {error}")
        print("EXACT31_CONSERVATION = BLOCKED")
        print("HUMAN_DECISIONS_CREATED = 0")
        print("STATUS_MUTATIONS = 0")
        print("FORMAL_EXPERIMENT_EXECUTED = NO")
        print("DENOMINATOR_CHANGE = NO")
        print("NEXT_ACTION =")
        print("FRESH_REVIEW_OF_E0C_R6_SOURCE_RECOVERY_AND_TEMPLATE_ENRICHMENT")
        print("STOP = true")
        return 1
    auth = outputs["input_authentication"]
    recovery = outputs["blocked31_source_recovery_results"]
    tranche = outputs["first_human_review_tranche"]
    print("E0C_R6_SOURCE_RECOVERY_AND_TEMPLATE_ENRICHMENT = READY_FOR_HUMAN_REVIEW")
    print(f"EXACT31_CONSERVATION = {recovery['exact31_conservation']}")
    print(f"RECOVERED_FROM_AUTHENTICATED_EXISTING_SOURCE = {recovery['recovered_from_authenticated_existing_source']}")
    print(f"NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE = {recovery['not_present_in_authenticated_existing_source']}")
    print(f"CONFLICTING_EXISTING_SOURCE_DETAIL = {recovery['conflicting_existing_source_detail']}")
    print("EXACT89_TEMPLATE_ENRICHMENT = PASS")
    print(f"FIRST_HUMAN_REVIEW_TRANCHE_TEMPLATE_COUNT = {tranche['template_count']}")
    print(f"FIRST_HUMAN_REVIEW_TRANCHE_RAW_COVERAGE = {tranche['raw_coverage']}")
    print("HUMAN_DECISIONS_CREATED = 0")
    print("STATUS_MUTATIONS = 0")
    print("FORMAL_EXPERIMENT_EXECUTED = NO")
    print("DENOMINATOR_CHANGE = NO")
    print("NEXT_ACTION =")
    print("FRESH_REVIEW_OF_E0C_R6_SOURCE_RECOVERY_AND_TEMPLATE_ENRICHMENT")
    print("STOP = true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
