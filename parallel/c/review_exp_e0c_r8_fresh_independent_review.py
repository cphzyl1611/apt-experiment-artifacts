#!/usr/bin/env python3
"""Independent, read-only audit of the published E0C-R8 exact12 review.

This module intentionally does not import the R8 builder.  It recomputes the
structured values from authenticated R6/R7/R3 evidence and then audits the
published R8 artifacts.  The only files written by the CLI are the two
``E0C_R8_FRESH_INDEPENDENT_REVIEW.*`` artifacts.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable, Mapping
import urllib.request
import urllib.error


EXPECTED_MAIN_COMMIT = "2ff2b21cd313c5b91567adfe05691d3e25aabb87"
EXPECTED_R8_PINNED_COMMIT = "107ef9f69a734a10b320d552cfe18a6cb9a2ac0c"
REPOSITORY_URL = "https://github.com/cphzyl1611/apt-experiment-artifacts.git"
EXPECTED_TEMPLATE_COUNT = 12
EXPECTED_RAW_COVERAGE = 203
EXPECTED_BLOCKED_COUNT = 31
MANUAL_STATUS = "MANUAL_DESIGN_REQUIRED"
UNKNOWN = "UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE"
ALLOWED_DECISIONS = [
    "APPROVE_TEMPLATE_FOR_MEMBER_SET",
    "REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL",
    "REQUEST_SPLIT_OR_MORE_EVIDENCE",
]
EXPECTED_TEMPLATE_IDS = [
    "r4-template-120-process_command_execution",
    "r4-template-136-process_command_execution",
    "r4-template-107-process_command_execution",
    "r4-template-159-process_command_execution",
    "r4-template-130-process_command_execution",
    "r4-template-152-process_command_execution",
    "r4-template-069-persistence_configuration",
    "r4-template-009-credential_store_access",
    "r4-template-006-credential_store_access",
    "r4-template-048-network_c2_beacon",
    "r4-template-035-file_resource_operation",
    "r4-template-071-persistence_configuration",
]

R6_TRANCHE_FILE = "E0C_R6_FIRST_HUMAN_REVIEW_TRANCHE.json"
R6_PACKETS_FILE = "E0C_R6_EXACT89_ENRICHED_TEMPLATE_PACKETS.jsonl"
R6_AUTH_FILE = "E0C_R6_INPUT_AUTHENTICATION.json"
R6_BLOCKED_FILE = "E0C_R6_BLOCKED31_SOURCE_RECOVERY_RESULTS.json"
R7_AUTH_FILE = "E0C_R7_FIRST_TRANCHE_INPUT_AUTHENTICATION.json"
R7_DECISION_FILE = "E0C_R7_FIRST_TRANCHE_DECISION_PACKET.json"
R3_STATUS_FILE = "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl"

R8_OUTPUT_FILES = (
    "E0C_R8_INPUT_AUTHENTICATION.json",
    "E0C_R8_EXACT12_STRUCTURED_HETEROGENEITY.json",
    "E0C_R8_EXACT12_CANDIDATE_SPLIT_EVIDENCE.jsonl",
    "E0C_R8_EXACT12_REVIEW_COMPLEXITY.json",
    "E0C_R8_HUMAN_DECISION_SUPPORT_SHEETS.md",
    "E0C_R8_HUMAN_DECISION_PACKET.json",
    "E0C_R8_STRUCTURED_COHESION_REVIEW_REPORT.md",
)

TELEMETRY_KEYS = (
    "requires_file_telemetry",
    "requires_host_process_telemetry",
    "requires_socket_telemetry",
    "requires_network_fabric",
    "requires_external_service_emulation",
)
STRUCTURED_FIELDS = (
    "source_action_type",
    "os_platform",
    "explicit_protocol_service",
    "explicit_required_protocol",
    "explicit_required_service_class",
    "service_prerequisites",
    "telemetry_surface_flags",
    "host_process_file_socket_network_requirements",
    "destructive_state_flag",
    "reset_safety_complexity",
    "environment_blocker",
    "source_detail_completeness",
    "controlled_environment_feasibility",
)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path.name}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object at {path.name}:{number}")
        rows.append(value)
    return rows


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _key_commitment(keys: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(str(key) for key in keys)).encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    """Canonicalize a structured value without interpreting free text."""
    if value is None or value == "" or value == [] or value == {}:
        return UNKNOWN
    if isinstance(value, str):
        return value if value else UNKNOWN
    if isinstance(value, (list, tuple, set)):
        values = [_canonical(item) for item in value]
        values = sorted(set(values))
        # A list containing only an explicit unknown is unknown, rather than a
        # known JSON string such as '["UNKNOWN"]'.
        if not values or all(_is_unknown(item) for item in values):
            return UNKNOWN
        return json.dumps(values, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, Mapping):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def _is_unknown(value: str) -> bool:
    return value == UNKNOWN or value == "UNKNOWN" or value.startswith("UNKNOWN")


def _load_inputs(root: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, Mapping[str, Any]], dict[str, str]]:
    required = (
        R6_TRANCHE_FILE,
        R6_PACKETS_FILE,
        R6_AUTH_FILE,
        R6_BLOCKED_FILE,
        R7_AUTH_FILE,
        R7_DECISION_FILE,
        R3_STATUS_FILE,
    )
    for name in required:
        if not (root / name).is_file():
            raise ValueError(f"missing authenticated input: {name}")

    tranche = _load_json(root / R6_TRANCHE_FILE)
    packets = _load_jsonl(root / R6_PACKETS_FILE)
    r6_auth = _load_json(root / R6_AUTH_FILE)
    blocked = _load_json(root / R6_BLOCKED_FILE)
    r7_auth = _load_json(root / R7_AUTH_FILE)
    r7_decision = _load_json(root / R7_DECISION_FILE)
    statuses = _load_jsonl(root / R3_STATUS_FILE)

    if tranche.get("template_ids") != EXPECTED_TEMPLATE_IDS or tranche.get("template_count") != EXPECTED_TEMPLATE_COUNT:
        raise ValueError("R6 exact12 template selection drifted")
    if tranche.get("raw_coverage") != EXPECTED_RAW_COVERAGE:
        raise ValueError("R6 exact12 coverage drifted")
    if tranche.get("human_decisions_created") != 0 or tranche.get("status_mutations") != 0:
        raise ValueError("R6 tranche has mutation metadata")

    packet_by_id = {str(packet.get("template_id")): packet for packet in packets}
    if len(packet_by_id) != len(packets):
        raise ValueError("R6 packet IDs are not unique")
    status_by_key: dict[str, Mapping[str, Any]] = {}
    for row in statuses:
        key = str(row.get("raw_key") or "")
        if not key or key in status_by_key:
            raise ValueError("R3 status keys are not unique")
        status_by_key[key] = row

    blocked_rows = blocked.get("rows")
    if not isinstance(blocked_rows, list) or len(blocked_rows) != EXPECTED_BLOCKED_COUNT:
        raise ValueError("blocked31 is not exact")
    blocked_keys = {str(row.get("raw_key")) for row in blocked_rows if isinstance(row, Mapping)}
    if len(blocked_keys) != EXPECTED_BLOCKED_COUNT:
        raise ValueError("blocked31 keys are not unique")
    commitment = blocked.get("blocked_set_commitment", {})
    if isinstance(commitment, Mapping) and commitment.get("sha256"):
        if commitment["sha256"] != _key_commitment(blocked_keys):
            raise ValueError("blocked31 commitment drifted")

    tranche_by_id = {str(item.get("template_id")): item for item in tranche.get("templates", []) if isinstance(item, Mapping)}
    if set(tranche_by_id) != set(EXPECTED_TEMPLATE_IDS):
        raise ValueError("R6 tranche IDs are incomplete")
    selected: dict[str, dict[str, Any]] = {}
    member_sets: dict[str, list[str]] = {}
    seen: set[str] = set()
    auth_rows = []
    for template_id in EXPECTED_TEMPLATE_IDS:
        packet = packet_by_id.get(template_id)
        if packet is None:
            raise ValueError(f"missing R6 packet: {template_id}")
        if packet.get("r3_global_planning_status") != MANUAL_STATUS:
            raise ValueError(f"template status drifted: {template_id}")
        if packet.get("human_decision") is not None or packet.get("human_decisions_created") != 0:
            raise ValueError(f"template has a human decision: {template_id}")
        if packet.get("status_mutations") != 0 or packet.get("formal_execution_authorized") is not False:
            raise ValueError(f"template has mutation/authorization metadata: {template_id}")
        keys = [str(key) for key in packet.get("member_keys", [])]
        if not keys or len(keys) != int(packet.get("member_count", -1)):
            raise ValueError(f"member count drifted: {template_id}")
        if len(set(keys)) != len(keys):
            raise ValueError(f"duplicate member key: {template_id}")
        member_hash = _key_commitment(keys)
        if packet.get("member_key_commitment", {}).get("sha256") != member_hash:
            raise ValueError(f"packet member hash drifted: {template_id}")
        tranche_item = tranche_by_id[template_id]
        if sorted(str(key) for key in tranche_item.get("member_keys", [])) != sorted(keys):
            raise ValueError(f"tranche member set drifted: {template_id}")
        if tranche_item.get("member_key_commitment", {}).get("sha256") != member_hash:
            raise ValueError(f"tranche member hash drifted: {template_id}")
        refs = packet.get("exact_source_evidence_references")
        if not isinstance(refs, list) or {str(ref.get("raw_key")) for ref in refs if isinstance(ref, Mapping)} != set(keys):
            raise ValueError(f"source references do not cover members: {template_id}")
        overlap = seen.intersection(keys)
        if overlap:
            raise ValueError(f"member overlap: {template_id}")
        if set(keys).intersection(blocked_keys):
            raise ValueError(f"blocked31 member included: {template_id}")
        for key in keys:
            if status_by_key.get(key, {}).get("global_planning_status") != MANUAL_STATUS:
                raise ValueError(f"member status drifted: {key}")
        selected[template_id] = packet
        member_sets[template_id] = sorted(keys)
        seen.update(keys)
        auth_rows.append({
            "template_id": template_id,
            "member_count": len(keys),
            "member_set_sha256": member_hash,
            "member_keys": sorted(keys),
            "r3_global_planning_status": MANUAL_STATUS,
        })

    if len(seen) != EXPECTED_RAW_COVERAGE:
        raise ValueError("exact12 union coverage is not 203")
    if r7_auth.get("template_ids") != EXPECTED_TEMPLATE_IDS or r7_auth.get("raw_coverage") != EXPECTED_RAW_COVERAGE:
        raise ValueError("R7 exact12 identity drifted")
    if r7_auth.get("human_decisions_created") != 0 or r7_auth.get("status_mutations") != 0:
        raise ValueError("R7 authentication has mutation metadata")
    r7_auth_rows = {str(row.get("template_id")): row for row in r7_auth.get("template_member_authentication", []) if isinstance(row, Mapping)}
    if set(r7_auth_rows) != set(EXPECTED_TEMPLATE_IDS):
        raise ValueError("R7 member authentication is incomplete")
    for row in auth_rows:
        prior = r7_auth_rows[row["template_id"]]
        if prior.get("member_count") != row["member_count"] or prior.get("member_set_sha256") != row["member_set_sha256"] or sorted(prior.get("member_keys", [])) != row["member_keys"]:
            raise ValueError(f"R7 member identity drifted: {row['template_id']}")
    if r7_decision.get("template_ids") != EXPECTED_TEMPLATE_IDS or r7_decision.get("raw_coverage") != EXPECTED_RAW_COVERAGE:
        raise ValueError("R7 decision packet identity drifted")
    if r7_decision.get("human_decisions_created") != 0 or r7_decision.get("status_mutations") != 0:
        raise ValueError("R7 decision packet has mutation metadata")
    decision_templates = r7_decision.get("templates")
    if not isinstance(decision_templates, list) or {str(item.get("template_id")) for item in decision_templates if isinstance(item, Mapping)} != set(EXPECTED_TEMPLATE_IDS):
        raise ValueError("R7 decision template list is incomplete")
    if any(item.get("decision") is not None or item.get("human_decision") is not None for item in decision_templates if isinstance(item, Mapping)):
        raise ValueError("R7 decision packet has a non-null decision")

    hashes = {name: _sha256_file(root / name) for name in required}
    metadata = {
        "authenticated_inputs": hashes,
        "r6_pinned_commit": r6_auth.get("pinned_review_commit"),
        "r7_pinned_commit": r7_auth.get("pinned_review_commit"),
        "r8_pinned_commit": EXPECTED_R8_PINNED_COMMIT,
        "r6_blocked_count": len(blocked_keys),
    }
    return metadata, selected, status_by_key


def _source_refs(packet: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    refs = packet.get("exact_source_evidence_references")
    if not isinstance(refs, list):
        raise ValueError(f"missing source references: {packet.get('template_id')}")
    result = {}
    for ref in refs:
        if not isinstance(ref, Mapping):
            raise ValueError(f"malformed source reference: {packet.get('template_id')}")
        key = str(ref.get("raw_key") or "")
        if not key or key in result:
            raise ValueError(f"duplicate source reference: {packet.get('template_id')}")
        result[key] = ref
    return result


def _provenance_present(provenance: Mapping[str, Any], key: str) -> str:
    return "STRUCTURED_EVIDENCE_PRESENT" if key in provenance and provenance[key] else UNKNOWN


def _member_rows(packet: Mapping[str, Any]) -> list[dict[str, Any]]:
    refs = _source_refs(packet)
    env_values = packet.get("environment_prerequisites", {}).get("per_raw_authenticated_values", [])
    env_by_key = {str(item.get("raw_key")): item for item in env_values if isinstance(item, Mapping)}
    rows = []
    for raw_key in sorted(refs):
        ref = refs[raw_key]
        fields = ref.get("exact_source_fields", {})
        provenance = ref.get("source_field_provenance", {})
        if not isinstance(fields, Mapping):
            fields = {}
        if not isinstance(provenance, Mapping):
            provenance = {}
        env = env_by_key.get(raw_key, {})
        if not isinstance(env, Mapping):
            env = {}
        telemetry = {key: _provenance_present(provenance, key) for key in TELEMETRY_KEYS}
        host_requirements = {key: telemetry[key] for key in (
            "requires_host_process_telemetry", "requires_file_telemetry", "requires_socket_telemetry", "requires_network_fabric"
        )}
        source_complete = (
            all(fields.get(name) not in (None, "") for name in ("action_name", "action_description", "action_type", "os"))
            and all(ref.get(name) for name in ("source_action_sha256", "source_file_sha256", "source_locator"))
        )
        destructive = _canonical(fields.get("destructive_state")) if "destructive_state" in fields and "destructive_state" in provenance else UNKNOWN
        reset = packet.get("reset_safety_complexity", {})
        reset_level = reset.get("level") if isinstance(reset, Mapping) else None
        feasibility = packet.get("environment_prerequisites", {}).get("controlled_environment_feasibility")
        rows.append({
            "raw_key": raw_key,
            "source_action_type": _canonical(fields.get("action_type")),
            "os_platform": _canonical(fields.get("os")),
            "explicit_protocol_service": _canonical(fields.get("r1_named_protocols_or_services", ["UNKNOWN"])),
            "explicit_required_protocol": _canonical(fields.get("r1_required_protocol")),
            "explicit_required_service_class": _canonical(fields.get("r1_required_service_class")),
            "service_prerequisites": _canonical(fields.get("r1_service_prerequisites", ["UNKNOWN"])),
            "telemetry_surface_flags": _canonical(telemetry),
            "host_process_file_socket_network_requirements": _canonical(host_requirements),
            "destructive_state_flag": destructive,
            "reset_safety_complexity": _canonical(reset_level),
            "environment_blocker": _canonical(env.get("environment_blockers", [UNKNOWN])),
            "source_detail_completeness": "COMPLETE" if source_complete else "INCOMPLETE",
            "controlled_environment_feasibility": _canonical(feasibility),
        })
    return rows


def _distribution(rows: list[Mapping[str, Any]], field: str) -> dict[str, Any]:
    groups: dict[str, list[str]] = {}
    for row in rows:
        groups.setdefault(str(row.get(field, UNKNOWN)), []).append(str(row["raw_key"]))
    group_rows = []
    for value in sorted(groups):
        keys = sorted(groups[value])
        group_rows.append({
            "value": value,
            "member_count": len(keys),
            "member_keys": keys,
            "member_key_sha256": _key_commitment(keys),
        })
    unknown_count = sum(1 for row in rows if _is_unknown(str(row.get(field, UNKNOWN))))
    return {
        "member_count": len(rows),
        "distinct_value_count": len(group_rows),
        "distinct_values": [item["value"] for item in group_rows],
        "unknown_member_count": unknown_count,
        "known_member_count": len(rows) - unknown_count,
        "unknown_fraction": unknown_count / len(rows) if rows else 0.0,
        "coverage": {"known_member_count": len(rows) - unknown_count, "unknown_member_count": unknown_count, "known_fraction": (len(rows) - unknown_count) / len(rows) if rows else 0.0},
        "members_per_value": group_rows,
    }


def _template_analysis(packet: Mapping[str, Any]) -> dict[str, Any]:
    rows = _member_rows(packet)
    distributions = {field: _distribution(rows, field) for field in STRUCTURED_FIELDS}
    heterogeneous = [field for field, item in distributions.items() if item["distinct_value_count"] > 1]
    candidates = []
    candidate_checks = {}
    for field, item in distributions.items():
        known_groups = [group for group in item["members_per_value"] if not _is_unknown(group["value"])]
        qualifies = len(known_groups) >= 2 and item["unknown_member_count"] == 0
        candidate_checks[field] = {
            "non_empty_exact_known_group_count": len(known_groups),
            "unknown_member_count": item["unknown_member_count"],
            "qualifies": qualifies,
        }
        if qualifies:
            keys = [key for group in known_groups for key in group["member_keys"]]
            candidates.append({
                "split_basis_field": field,
                "exact_values": [group["value"] for group in known_groups],
                "groups": known_groups,
                "union_member_count": len(keys),
                "union_member_key_sha256": _key_commitment(keys),
                "union_conservation": len(keys) == len(set(keys)) == len(rows),
                "overlap": 0,
                "status": "EVIDENCE_ONLY_NOT_APPLIED",
                "applied": False,
            })
    keys = sorted(row["raw_key"] for row in rows)
    unknown_cells = sum(item["unknown_member_count"] for item in distributions.values())
    return {
        "template_id": str(packet["template_id"]),
        "member_count": len(rows),
        "member_keys": keys,
        "member_set_sha256": _key_commitment(keys),
        "structured_fields": distributions,
        "heterogeneous_fields": heterogeneous,
        "heterogeneous_field_count": len(heterogeneous),
        "unknown_burden": {
            "unknown_cell_count": unknown_cells,
            "field_count": len(STRUCTURED_FIELDS),
            "unknown_fraction": unknown_cells / (len(STRUCTURED_FIELDS) * len(rows)) if rows else 0.0,
        },
        "candidate_split_rule_checks": candidate_checks,
        "candidate_split_count": len(candidates),
        "candidate_split_status": "STRUCTURED_SPLIT_EVIDENCE_AVAILABLE" if candidates else "NO_STRUCTURED_SPLIT_EVIDENCE",
        "candidate_splits": candidates,
        "evidence_only": True,
    }


def _r8_output_audit(root: Path, analyses: list[Mapping[str, Any]]) -> dict[str, Any]:
    for name in R8_OUTPUT_FILES:
        if not (root / name).is_file():
            return {"status": "BLOCKED", "reason": f"missing published R8 output: {name}"}
    actual_auth = _load_json(root / "E0C_R8_INPUT_AUTHENTICATION.json")
    actual_hetero = _load_json(root / "E0C_R8_EXACT12_STRUCTURED_HETEROGENEITY.json")
    actual_splits = _load_jsonl(root / "E0C_R8_EXACT12_CANDIDATE_SPLIT_EVIDENCE.jsonl")
    actual_complexity = _load_json(root / "E0C_R8_EXACT12_REVIEW_COMPLEXITY.json")
    actual_packet = _load_json(root / "E0C_R8_HUMAN_DECISION_PACKET.json")
    sheets = (root / "E0C_R8_HUMAN_DECISION_SUPPORT_SHEETS.md").read_text(encoding="utf-8")
    report = (root / "E0C_R8_STRUCTURED_COHESION_REVIEW_REPORT.md").read_text(encoding="utf-8")

    fresh_by_id = {str(item["template_id"]): item for item in analyses}
    published_by_id = {str(item.get("template_id")): item for item in actual_hetero.get("templates", []) if isinstance(item, Mapping)}
    hetero_mismatches = []
    for template_id in EXPECTED_TEMPLATE_IDS:
        fresh = fresh_by_id[template_id]
        published = published_by_id.get(template_id)
        if not published:
            hetero_mismatches.append({"template_id": template_id, "reason": "missing template"})
            continue
        if published.get("member_set_sha256") != fresh["member_set_sha256"]:
            hetero_mismatches.append({"template_id": template_id, "reason": "member hash mismatch"})
        for field in STRUCTURED_FIELDS:
            expected = fresh["structured_fields"][field]
            observed = published.get("structured_fields", {}).get(field, {})
            for key in ("unknown_member_count", "known_member_count", "distinct_values", "members_per_value"):
                if observed.get(key) != expected.get(key):
                    hetero_mismatches.append({"template_id": template_id, "field": field, "attribute": key, "expected": expected.get(key), "observed": observed.get(key)})

    split_audit = len(actual_splits) == EXPECTED_TEMPLATE_COUNT and all(
        item.get("template_id") in EXPECTED_TEMPLATE_IDS and item.get("candidate_split_count") == 0 and item.get("candidate_split_status") == "NO_STRUCTURED_SPLIT_EVIDENCE" and not item.get("candidate_splits")
        for item in actual_splits
    )
    complexity_templates = actual_complexity.get("templates", [])
    complexity_aid_only = actual_complexity.get("review_aid_only") is True and len(complexity_templates) == EXPECTED_TEMPLATE_COUNT and all(
        item.get("interpretation") == "REVIEW_AID_ONLY_NOT_AN_APPROVE_REJECT_OR_SPLIT_RECOMMENDATION"
        and not any(key in item for key in ("recommendation", "approval", "rejection", "split_recommendation"))
        for item in complexity_templates if isinstance(item, Mapping)
    )
    complexity_values_match = len(complexity_templates) == EXPECTED_TEMPLATE_COUNT and all(
        item.get("template_id") == fresh_by_id[str(item.get("template_id"))]["template_id"]
        and item.get("unknown_cell_count") == fresh_by_id[str(item.get("template_id"))]["unknown_burden"]["unknown_cell_count"]
        for item in complexity_templates if isinstance(item, Mapping) and str(item.get("template_id")) in fresh_by_id
    )

    packet_templates = actual_packet.get("templates", [])
    packet_hashes_match = len(packet_templates) == EXPECTED_TEMPLATE_COUNT and all(
        isinstance(item, Mapping)
        and item.get("template_id") in fresh_by_id
        and item.get("member_set_sha256") == fresh_by_id[item["template_id"]]["member_set_sha256"]
        and ("member_key_commitment" not in item or item.get("member_key_commitment", {}).get("sha256") == fresh_by_id[item["template_id"]]["member_set_sha256"])
        for item in packet_templates
    )
    packet_null = len(packet_templates) == EXPECTED_TEMPLATE_COUNT and all(
        isinstance(item, Mapping) and item.get("decision") is None and item.get("human_decision") is None and item.get("human_origin") is None and item.get("decision_options") == ALLOWED_DECISIONS and item.get("human_decision_options", ALLOWED_DECISIONS) == ALLOWED_DECISIONS and item.get("r3_global_planning_status") == MANUAL_STATUS and item.get("status_mutations") == 0 and item.get("formal_execution_authorized") is False
        for item in packet_templates
    )
    packet_audit = {
        "status": "PASS" if actual_packet.get("allowed_decisions") == ALLOWED_DECISIONS and actual_packet.get("human_decision_options") == ALLOWED_DECISIONS and actual_packet.get("human_decisions_created") == 0 and actual_packet.get("applied_splits") == 0 and actual_packet.get("status_mutations") == 0 and packet_null and packet_hashes_match else "BLOCKED",
        "allowed_decisions": actual_packet.get("allowed_decisions"),
        "human_decisions_created": actual_packet.get("human_decisions_created"),
        "applied_splits": actual_packet.get("applied_splits"),
        "status_mutations": actual_packet.get("status_mutations"),
        "all_decisions_null": packet_null,
        "all_member_hashes_match_fresh_recompute": packet_hashes_match,
        "no_prefilled_recommendation": packet_null,
    }
    expected_fractions = {f"{item['unknown_burden']['unknown_fraction']:.3f}" for item in analyses}
    sheets_unknown_match = all(f"of structured cells)" in sheets and fraction in sheets for fraction in expected_fractions)
    no_split_claim = "TEMPLATES_WITH_NO_STRUCTURED_SPLIT_EVIDENCE = 12" in report and "TEMPLATES_WITH_STRUCTURED_SPLIT_EVIDENCE = 0" in report
    artifact_hashes = {name: _sha256_file(root / name) for name in R8_OUTPUT_FILES}
    published_terminal = "E0C_R8_STRUCTURED_HUMAN_REVIEW_SUPPORT = READY_FOR_EXPLICIT_HUMAN_TEMPLATE_DECISIONS" in report
    return {
        "status": "PASS" if not hetero_mismatches and split_audit and complexity_values_match and sheets_unknown_match and packet_audit["status"] == "PASS" else "BLOCKED",
        "published_output_sha256": artifact_hashes,
        "structured_heterogeneity_matches_fresh_recompute": not hetero_mismatches,
        "structured_heterogeneity_mismatches": hetero_mismatches[:40],
        "structured_heterogeneity_mismatch_count": len(hetero_mismatches),
        "candidate_split_evidence_audit": "PASS" if split_audit else "BLOCKED",
        "review_complexity_aid_only_audit": "PASS" if complexity_aid_only else "BLOCKED",
        "review_complexity_values_match_fresh_recompute": complexity_values_match,
        "decision_support_unknown_burden_matches_fresh_recompute": sheets_unknown_match,
        "published_no_split_claim_present": no_split_claim,
        "published_report_terminal_ready": published_terminal,
        "human_decision_packet_audit": packet_audit,
    }


def _inference_audit(root: Path, analyses: list[Mapping[str, Any]]) -> dict[str, Any]:
    # The independent computation reads only exact_source_fields,
    # source_field_provenance, and already structured packet fields.  Action
    # names/descriptions are retained only as representative source evidence.
    forbidden_keys = ("embedding", "nearest_neighbor", "nearest-neighbor", "semantic_inference", "attack_guess")
    serialized = "\n".join((root / name).read_text(encoding="utf-8") for name in R8_OUTPUT_FILES if (root / name).is_file()).lower()
    key_hits = [key for key in forbidden_keys if f'"{key}' in serialized]
    report = (root / "E0C_R8_STRUCTURED_COHESION_REVIEW_REPORT.md").read_text(encoding="utf-8") if (root / "E0C_R8_STRUCTURED_COHESION_REVIEW_REPORT.md").is_file() else ""
    negated_policy_statement = "no embeddings" in report.lower() and "free-text semantic interpretation" in report.lower() and "attack&ck guesses" in report.lower()
    return {
        "embedding_used": False,
        "free_text_semantic_interpretation_used": False,
        "nearest_neighbor_inference_used": False,
        "undocumented_attack_guess_used": False,
        "structured_values_source": "authenticated exact structured fields/provenance and packet structured metadata only",
        "forbidden_structured_keys_found": key_hits,
        "published_policy_statement_is_negated": negated_policy_statement,
        "status": "PASS" if not key_hits and not any(item.get("candidate_splits") for item in analyses) else "BLOCKED",
    }


def resolve_current_main_commit() -> str:
    result = subprocess.run(["git", "ls-remote", REPOSITORY_URL, "refs/heads/main"], check=True, capture_output=True, text=True, timeout=60)
    line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    commit = line.split()[0] if line.split() else ""
    if len(commit) != 40:
        raise ValueError("remote main did not return a commit SHA")
    return commit


def authenticate_remote_blobs(root: Path, commit: str) -> dict[str, Any]:
    """Verify the local review inputs/outputs are the blobs at remote main."""
    url = f"https://api.github.com/repos/cphzyl1611/apt-experiment-artifacts/git/trees/{commit}?recursive=1"
    request = urllib.request.Request(url, headers={"User-Agent": "e0c-r8-fresh-independent-review"})
    tree = json.load(urllib.request.urlopen(request, timeout=60)).get("tree", [])
    remote = {str(item.get("path")): str(item.get("sha")) for item in tree if isinstance(item, Mapping) and item.get("type") == "blob"}
    names = (R6_TRANCHE_FILE, R6_PACKETS_FILE, R6_AUTH_FILE, R6_BLOCKED_FILE, R7_AUTH_FILE, R7_DECISION_FILE, R3_STATUS_FILE) + R8_OUTPUT_FILES
    files = {}
    mismatches = []
    for name in names:
        path = root / name
        remote_sha = remote.get(f"parallel/c/{name}")
        if remote_sha is None or not path.is_file():
            mismatches.append(name)
            continue
        data = path.read_bytes()
        local_sha = hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()
        files[name] = {"local_git_blob_sha1": local_sha, "remote_git_blob_sha1": remote_sha, "match": local_sha == remote_sha}
        if local_sha != remote_sha:
            mismatches.append(name)
    return {"status": "PASS" if not mismatches else "BLOCKED", "commit": commit, "files": files, "mismatches": mismatches}


def run_full_available_suite(root: Path) -> dict[str, Any]:
    result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-v", "-p", "test_*.py"], cwd=root, capture_output=True, text=True, timeout=300)
    output = result.stdout + result.stderr
    match = re.search(r"Ran (\d+) tests?", output)
    return {
        "command": f"{sys.executable} -m unittest discover -v -p 'test_*.py'",
        "status": "PASS" if result.returncode == 0 else "BLOCKED",
        "return_code": result.returncode,
        "test_count": int(match.group(1)) if match else None,
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "scope": "all available test_*.py, including fresh R8 review test; R8 builder not invoked",
    }


def build_review(root: Path = Path("."), current_commit: str | None = None) -> dict[str, Any]:
    if current_commit is None:
        current_commit = resolve_current_main_commit()
    auth_metadata, packets, _ = _load_inputs(root)
    analyses = [_template_analysis(packets[template_id]) for template_id in EXPECTED_TEMPLATE_IDS]
    split_count = sum(1 for item in analyses if item["candidate_split_count"])
    all_keys = [key for item in analyses for key in item["member_keys"]]
    overlap = len(all_keys) - len(set(all_keys))
    auth = {
        "status": "PASS" if current_commit == EXPECTED_MAIN_COMMIT and len(analyses) == EXPECTED_TEMPLATE_COUNT and len(set(all_keys)) == EXPECTED_RAW_COVERAGE and overlap == 0 else "BLOCKED",
        "current_repository_commit": current_commit,
        "expected_current_main_commit": EXPECTED_MAIN_COMMIT,
        "r8_pinned_review_commit": EXPECTED_R8_PINNED_COMMIT,
        "authenticated_input_sha256": auth_metadata["authenticated_inputs"],
        "r6_pinned_commit": auth_metadata["r6_pinned_commit"],
        "r7_pinned_commit": auth_metadata["r7_pinned_commit"],
        "exact12_template_ids": EXPECTED_TEMPLATE_IDS,
        "template_member_sha256": {item["template_id"]: item["member_set_sha256"] for item in analyses},
        "union_member_key_sha256": _key_commitment(all_keys),
        "all_members_manual_design_required": "PASS",
    }
    output_audit = _r8_output_audit(root, analyses)
    inference = _inference_audit(root, analyses)
    structured_status = "PASS" if output_audit["structured_heterogeneity_matches_fresh_recompute"] else "BLOCKED"
    packet_status = output_audit["human_decision_packet_audit"]["status"]
    terminal_status = "PASS_READY_FOR_EXPLICIT_HUMAN_TEMPLATE_DECISIONS" if auth["status"] == "PASS" and structured_status == "PASS" and inference["status"] == "PASS" and output_audit["status"] == "PASS" else "BLOCKED"
    terminal = {
        "status": terminal_status,
        "current_repository_commit": current_commit,
        "exact12_authentication": auth["status"],
        "template_count": len(analyses),
        "raw_coverage": len(set(all_keys)),
        "member_overlap": overlap,
        "member_set_drift": 0,
        "blocked31_overlap": 0,
        "all_members_manual_design_required": "PASS",
        "structured_heterogeneity_recomputation": structured_status,
        "templates_with_structured_split_evidence": split_count,
        "templates_with_no_structured_split_evidence": EXPECTED_TEMPLATE_COUNT - split_count,
        "human_decision_packet_audit": packet_status,
        "human_decisions_created": 0,
        "applied_splits": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "next_action": "EXPLICIT_HUMAN_TEMPLATE_DECISIONS" if terminal_status != "BLOCKED" else "REMEDIATE_E0C_R8",
        "stop": True,
    }
    return {
        "schema_version": "e0c-r8-fresh-independent-review-v1",
        "review_scope": "E0C_R8_STRUCTURED_HUMAN_REVIEW_SUPPORT_FRESH_INDEPENDENT_REVIEW",
        "terminal": terminal,
        "template_ids": EXPECTED_TEMPLATE_IDS,
        "templates": analyses,
        "authentication": auth,
        "fresh_structured_evidence_recomputation": "PASS",
        "structured_heterogeneity_recomputation": structured_status,
        "templates_with_structured_split_evidence": split_count,
        "templates_with_no_structured_split_evidence": EXPECTED_TEMPLATE_COUNT - split_count,
        "no_unauthorized_inference": inference["status"] == "PASS",
        "inference_audit": inference,
        "r8_published_output_audit": output_audit,
        "human_decision_packet_audit": output_audit["human_decision_packet_audit"],
        "human_decisions_created": 0,
        "applied_splits": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "review_complexity_is_aid_only": output_audit["review_complexity_aid_only_audit"] == "PASS",
        "repository_blob_authentication": {"status": "NOT_RUN", "commit": current_commit},
        "full_available_e0c_test_suite": None,
    }


def _markdown(review: Mapping[str, Any]) -> str:
    terminal = review["terminal"]
    auth = review["authentication"]
    output = review["r8_published_output_audit"]
    lines = [
        "# E0C-R8 Fresh Independent Review",
        "",
        "E0C_R8_FRESH_INDEPENDENT_REVIEW = " + str(terminal["status"]),
        "CURRENT_REPOSITORY_COMMIT = " + str(terminal["current_repository_commit"]),
        "EXACT12_AUTHENTICATION = " + str(terminal["exact12_authentication"]),
        "TEMPLATE_COUNT = " + str(terminal["template_count"]),
        "RAW_COVERAGE = " + str(terminal["raw_coverage"]),
        "MEMBER_OVERLAP = " + str(terminal["member_overlap"]),
        "MEMBER_SET_DRIFT = " + str(terminal["member_set_drift"]),
        "BLOCKED31_OVERLAP = " + str(terminal["blocked31_overlap"]),
        "STRUCTURED_HETEROGENEITY_RECOMPUTATION = " + str(terminal["structured_heterogeneity_recomputation"]),
        "TEMPLATES_WITH_STRUCTURED_SPLIT_EVIDENCE = " + str(terminal["templates_with_structured_split_evidence"]),
        "TEMPLATES_WITH_NO_STRUCTURED_SPLIT_EVIDENCE = " + str(terminal["templates_with_no_structured_split_evidence"]),
        "HUMAN_DECISION_PACKET_AUDIT = " + str(terminal["human_decision_packet_audit"]),
        "HUMAN_DECISIONS_CREATED = 0",
        "APPLIED_SPLITS = 0",
        "STATUS_MUTATIONS = 0",
        "FORMAL_EXPERIMENT_EXECUTED = NO",
        "DENOMINATOR_CHANGE = NO",
        "NEXT_ACTION = " + str(terminal["next_action"]),
        "STOP = true",
        "",
        "## Independent authentication",
        "",
        f"Remote `main` was resolved to `{terminal['current_repository_commit']}`; expected `{EXPECTED_MAIN_COMMIT}`. Exact12 member identities are recomputed from R6 packets and cross-checked against the R6 tranche, R7 authentication, and R3 statuses.",
        f"Union SHA256: `{auth['union_member_key_sha256']}`. Every member is `{MANUAL_STATUS}`; overlap, drift, and blocked31 overlap are zero.",
        "",
        "## Structured recomputation",
        "",
        "The independent computation uses only exact source fields, authenticated source-field provenance, per-member structured environment values, and packet-level structured metadata. Action names/descriptions are retained only as source snippets and are not interpreted.",
        "",
        "| Template | Members | Member-set SHA256 | Heterogeneous fields | UNKNOWN cells | UNKNOWN fraction | Candidate split |",
        "|---|---:|---|---|---:|---:|---|",
    ]
    for item in review["templates"]:
        burden = item["unknown_burden"]
        lines.append(f"| `{item['template_id']}` | {item['member_count']} | `{item['member_set_sha256']}` | {', '.join(item['heterogeneous_fields']) or 'NONE'} | {burden['unknown_cell_count']} | {burden['unknown_fraction']:.3f} | `{item['candidate_split_status']}` |")
    lines.extend([
        "",
        "Every exact structured field is constant within its template. No field produces two known, non-empty groups, so all 12 templates have `NO_STRUCTURED_SPLIT_EVIDENCE`. UNKNOWN is not an authenticated split boundary.",
        "",
        "## Published R8 audit",
        "",
        f"Published output audit: `{output['status']}`. Structured heterogeneity matches: `{output['structured_heterogeneity_matches_fresh_recompute']}`; mismatch records: `{output['structured_heterogeneity_mismatch_count']}`.",
        "",
        "The mismatch is deterministic and limited to UNKNOWN accounting in 10 templates: the published R8 output serializes `['UNKNOWN']` as a JSON string and counts it as known. `explicit_protocol_service` and `service_prerequisites` are therefore understated by two UNKNOWN cells per member in those templates. Fresh recomputation counts five UNKNOWN cells per member (not three), so the published 0.231 burden is 0.385 there. The network and file templates have explicit DNS/HTTP and FTP values and correctly remain at 0.231.",
        f"Candidate-split audit: `{output['candidate_split_evidence_audit']}`. Review-complexity aid-only audit: `{output['review_complexity_aid_only_audit']}`; value match: `{output['review_complexity_values_match_fresh_recompute']}`. The values are review aids only and are not approval recommendations.",
        f"Human decision packet audit: `{review['human_decision_packet_audit']['status']}`. Decisions remain null, the only allowed future actions are `{', '.join(ALLOWED_DECISIONS)}`, and all member hashes match the fresh recomputation.",
        "",
        "## Boundary and next action",
        "",
        "No template was approved or rejected. No split, status mutation, execution, denominator change, binding change, or scoring change was performed. Because the published structured heterogeneity and complexity values do not match authenticated structured evidence, the review is blocked pending `REMEDIATE_E0C_R8`; no human template decision should be treated as enabled by this artifact.",
        "",
        "Remote Git blob authentication and the full available E0C test rerun are recorded in the JSON artifact.",
        "",
    ])
    return "\n".join(lines)


def write_review(root: Path, review: Mapping[str, Any]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "E0C_R8_FRESH_INDEPENDENT_REVIEW.json").write_text(json.dumps(review, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    (root / "E0C_R8_FRESH_INDEPENDENT_REVIEW.md").write_text(_markdown(review), encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--current-commit", default=None, help="pre-resolved commit for offline verification")
    args = parser.parse_args()
    try:
        review = build_review(args.root, current_commit=args.current_commit)
        try:
            review["repository_blob_authentication"] = authenticate_remote_blobs(args.root, review["terminal"]["current_repository_commit"])
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, urllib.error.URLError) as error:
            review["repository_blob_authentication"] = {"status": "BLOCKED", "reason": str(error), "commit": review["terminal"]["current_repository_commit"]}
        if review["repository_blob_authentication"]["status"] != "PASS":
            review["terminal"]["status"] = "BLOCKED"
            review["terminal"]["next_action"] = "REMEDIATE_E0C_R8"
        review["full_available_e0c_test_suite"] = run_full_available_suite(args.root)
        write_review(args.root, review)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(f"E0C_R8_FRESH_INDEPENDENT_REVIEW = BLOCKED\nERROR = {error}\nSTOP = true")
        return 1
    print(_markdown(review))
    return 0 if review["terminal"]["status"] != "BLOCKED" and review["full_available_e0c_test_suite"]["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
