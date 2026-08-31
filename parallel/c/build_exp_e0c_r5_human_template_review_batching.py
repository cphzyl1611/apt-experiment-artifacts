#!/usr/bin/env python3
"""Prepare non-decisional human-review batches for R4 shared templates."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


EXPECTED_MANUAL_COUNT = 589
EXPECTED_SHARED_TEMPLATE_COUNT = 89
EXPECTED_SHARED_COVERED_ROWS = 494
EXPECTED_RAW_SPECIFIC_COUNT = 64
EXPECTED_BLOCKED_COUNT = 31

R4_SHARED_TEMPLATES_FILE = "E0C_R4_SHARED_MANUAL_DESIGN_TEMPLATES.json"
R4_RAW_TO_TEMPLATE_MAP_FILE = "E0C_R4_RAW_TO_TEMPLATE_MAP.jsonl"
R4_EXACT_MANUAL_SET_FILE = "E0C_R4_EXACT589_MANUAL_SET.json"
R4_REVIEW_PACKETS_FILE = "E0C_R4_HUMAN_TEMPLATE_REVIEW_PACKETS.jsonl"
R4_WORKLOAD_AUDIT_FILE = "E0C_R4_MANUAL_WORKLOAD_AUDIT.json"
R4_OUTLIERS_FILE = "E0C_R4_MANUAL_OUTLIERS.json"
R1_FILE = "EXP_E0C_R1_1796_ENRICHED_READINESS.jsonl"
R2_BLOCKERS_FILE = "E0C_R2_MANUAL_DESIGN_BLOCKERS.json"
R3_STATUS_FILE = "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl"

SHARED_TEMPLATE = "CANDIDATE_FOR_SHARED_HUMAN_TEMPLATE"
RAW_SPECIFIC = "RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED"
BLOCKED_DETAIL = "BLOCKED_NEED_MORE_SOURCE_DETAIL"
MANUAL_STATUS = "MANUAL_DESIGN_REQUIRED"
DECISION_OPTIONS = [
    "APPROVE_TEMPLATE_FOR_MEMBER_SET",
    "REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL",
    "REQUEST_SPLIT_OR_MORE_EVIDENCE",
]

R4_AUTHENTICATED_INPUTS = (
    R4_SHARED_TEMPLATES_FILE,
    R4_RAW_TO_TEMPLATE_MAP_FILE,
    R4_EXACT_MANUAL_SET_FILE,
    R4_REVIEW_PACKETS_FILE,
    R4_WORKLOAD_AUDIT_FILE,
)

SAFETY_COMPLEXITY_ORDER = {"LOW": 0, "MODERATE": 1, "HIGH": 2}
HIGH_SAFETY_BLOCKERS = {"credential_sensitive", "destructive_state", "privileged_action"}
MODERATE_SAFETY_BLOCKERS = {
    "missing_exact_command_semantics",
    "multi_step_composite",
    "service_environment_absent",
    "windows_only_semantics",
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


def _sha256_keys(keys: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(keys)).encode("utf-8")).hexdigest()


def _as_sorted_strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return sorted(str(item) for item in value)
    if value is None:
        return ["UNKNOWN"]
    return [str(value)]


def _ordered_unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _r4_input_commitments(root: Path) -> list[dict[str, Any]]:
    return [
        {"file": name, "sha256": _sha256_file(root / name)}
        for name in R4_AUTHENTICATED_INPUTS
    ]


def _safety_complexity(blockers: list[str]) -> dict[str, Any]:
    blocker_set = set(blockers)
    if blocker_set & HIGH_SAFETY_BLOCKERS:
        level = "HIGH"
    elif blocker_set & MODERATE_SAFETY_BLOCKERS:
        level = "MODERATE"
    else:
        level = "LOW"
    return {
        "level": level,
        "source_supported_drivers": sorted(blocker_set & (HIGH_SAFETY_BLOCKERS | MODERATE_SAFETY_BLOCKERS)),
        "cleanup_reset_evidence": "R4 template cleanup/reset instructions; no reset is executed in R5.",
    }


def _environment_availability(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    blockers = sorted({str(item) for row in rows for item in row.get("environment_blockers", [])})
    if "NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION" in blockers:
        state = "NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT"
    else:
        state = "NO_POSITIVE_ENVIRONMENT_AVAILABILITY_EVIDENCE"
    return {
        "state": state,
        "source_environment_blockers": blockers,
        "formal_execution_authorized": False,
    }


def _telemetry_summary(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    surfaces = sorted({str(item) for row in rows for item in row.get("provx_candidate_observation_surface", ["UNKNOWN"])})
    flags = {
        "requires_host_process_telemetry": any(bool(row.get("requires_host_process_telemetry")) for row in rows),
        "requires_file_telemetry": any(bool(row.get("requires_file_telemetry")) for row in rows),
        "requires_socket_telemetry": any(bool(row.get("requires_socket_telemetry")) for row in rows),
        "requires_network_fabric": any(bool(row.get("requires_network_fabric")) for row in rows),
    }
    return {
        "candidate_observation_surfaces": surfaces,
        "source_telemetry_flags": flags,
        "equivalence_confidence": "SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY",
        "provx_phase1_observable": "UNKNOWN",
        "provx_phase2_core_edge_localizable": "UNKNOWN",
    }


def _defensive_summary(template: Mapping[str, Any]) -> dict[str, Any]:
    signature = template.get("common_evidence_signature", {})
    return {
        "equivalence_confidence": "R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT",
        "source_visible_dimensions": {
            "os_platform_hints": _as_sorted_strings(signature.get("os_platform_hints")),
            "named_protocols_or_services": _as_sorted_strings(signature.get("named_protocols_or_services")),
            "service_prerequisites": _as_sorted_strings(signature.get("service_prerequisites")),
            "source_action_type": str(signature.get("source_action_type", "UNKNOWN")),
        },
        "invariants": template.get("defensive_equivalence_invariants", {}),
        "unknowns_remain_unknown": True,
    }


def _dominant_blockers(rows: list[Mapping[str, Any]], template: Mapping[str, Any]) -> list[dict[str, Any]]:
    counter = Counter(
        str(item)
        for row in rows
        for item in row.get("manual_design_blockers", template.get("common_evidence_signature", {}).get("blocker_taxonomy", []))
    )
    return [
        {"blocker": blocker, "member_rows": count}
        for blocker, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    ]


def _template_record(
    template: Mapping[str, Any],
    member_rows: list[Mapping[str, Any]],
    packet: Mapping[str, Any],
) -> dict[str, Any]:
    signature = template.get("common_evidence_signature", {})
    member_keys = sorted(str(item) for item in template["member_keys"])
    blockers = [item["blocker"] for item in _dominant_blockers(member_rows, template)]
    representatives = [
        {
            "raw_key": str(row.get("raw_key")),
            "source_file": row.get("source_file"),
            "source_locator": row.get("source_locator"),
            "action_name": row.get("action_name"),
        }
        for row in packet.get("representative_source_fields", [])[:3]
    ]
    if not representatives:
        representatives = [
            {
                "raw_key": str(row["raw_key"]),
                "source_file": row.get("source_file"),
                "source_locator": row.get("source_locator"),
                "action_name": row.get("action_name"),
            }
            for row in member_rows[:3]
        ]
    return {
        "template_id": str(template["template_id"]),
        "classification": SHARED_TEMPLATE,
        "member_count": len(member_keys),
        "member_keys": member_keys,
        "member_key_commitment": {
            "algorithm": "sha256",
            "canonical_order": "lexicographic raw_key joined with LF",
            "sha256": _sha256_keys(member_keys),
        },
        "playbook_count": len({str(row.get("playbook_id")) for row in member_rows}),
        "primary_execution_archetype": str(template.get("primary_execution_archetype", "UNKNOWN")),
        "os_platform_hints": _as_sorted_strings(signature.get("os_platform_hints")),
        "named_protocols_or_services": _as_sorted_strings(signature.get("named_protocols_or_services")),
        "service_prerequisites": _as_sorted_strings(signature.get("service_prerequisites")),
        "dominant_blockers": _dominant_blockers(member_rows, template),
        "telemetry_surfaces": _telemetry_summary(member_rows),
        "environment_availability": _environment_availability(member_rows),
        "reset_safety_complexity": _safety_complexity(blockers),
        "defensive_equivalence": _defensive_summary(template),
        "representative_raws": representatives,
        "raw_specific_parameters": list(template.get("per_raw_parameters", [])),
        "unresolved_human_questions": list(packet.get("unresolved_questions", template.get("raw_specific_human_questions", []))),
        "negative_cases": list(template.get("negative_cases", [])),
        "decision_options": list(packet.get("decision_options", template.get("human_decision_options", DECISION_OPTIONS))),
        "human_decision": None,
        "formal_execution_authorized": False,
        "provx_phase1_observable": "UNKNOWN",
        "provx_phase2_core_edge_localizable": "UNKNOWN",
        "result_status": "UNEXECUTED_NOT_OBSERVED",
    }


def _priority_sort_key(record: Mapping[str, Any]) -> tuple[Any, ...]:
    # This is a lexicographic review order, not a weighted score. It first
    # exposes broad reusable coverage, then prefers lower reset complexity.
    environment = str(record["environment_availability"]["state"])
    defensive = str(record["defensive_equivalence"]["equivalence_confidence"])
    telemetry = str(record["telemetry_surfaces"]["equivalence_confidence"])
    complexity = SAFETY_COMPLEXITY_ORDER[str(record["reset_safety_complexity"]["level"])]
    return (
        -int(record["member_count"]),
        -int(record["playbook_count"]),
        defensive,
        telemetry,
        environment,
        complexity,
        str(record["template_id"]),
    )


def _presentation_sort_key(record: Mapping[str, Any]) -> tuple[Any, ...]:
    blockers = tuple(item["blocker"] for item in record["dominant_blockers"])
    return (
        str(record["primary_execution_archetype"]),
        tuple(record["os_platform_hints"]),
        tuple(record["named_protocols_or_services"]),
        tuple(record["service_prerequisites"]),
        blockers,
        str(record["environment_availability"]["state"]),
        int(record["priority_rank"]),
        str(record["template_id"]),
    )


def _batch_sizes(total: int) -> list[int]:
    if total != EXPECTED_SHARED_TEMPLATE_COUNT:
        raise ValueError(f"cannot form R5 batches for {total} templates")
    # Eight 10-template batches and one 9-template batch keep every review
    # group inside the requested 8-12 template range.
    return [10] * 8 + [9]


def _review_batches(records: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(records, key=_presentation_sort_key)
    batches: list[dict[str, Any]] = []
    offset = 0
    for number, size in enumerate(_batch_sizes(len(ordered)), 1):
        group = ordered[offset:offset + size]
        offset += size
        template_ids = [str(item["template_id"]) for item in group]
        batches.append({
            "batch_id": f"r5-review-batch-{number:02d}",
            "presentation_only": True,
            "template_count": len(group),
            "template_ids": template_ids,
            "member_row_count": sum(int(item["member_count"]) for item in group),
            "template_member_commitments": [
                {
                    "template_id": item["template_id"],
                    "member_count": item["member_count"],
                    "member_key_sha256": item["member_key_commitment"]["sha256"],
                }
                for item in group
            ],
            "mechanical_grouping_dimensions": [
                "primary_execution_archetype",
                "os_platform_hints",
                "named_protocols_or_services",
                "service_prerequisites",
                "dominant_blockers",
                "environment_availability",
            ],
            "group_summary": {
                "archetypes": dict(sorted(Counter(item["primary_execution_archetype"] for item in group).items())),
                "platforms": dict(sorted(Counter("|".join(item["os_platform_hints"]) for item in group).items())),
                "protocol_or_service_sets": dict(sorted(Counter("|".join(item["named_protocols_or_services"]) for item in group).items())),
                "environment_states": dict(sorted(Counter(item["environment_availability"]["state"] for item in group).items())),
            },
            "template_priority_ranks": [int(item["priority_rank"]) for item in group],
            "human_decisions_created": 0,
        })
    if offset != len(ordered):
        raise ValueError("review batch sizing did not consume all shared templates")
    return {
        "schema_version": "e0c-r5-review-batches-v1",
        "review_batch_count": len(batches),
        "batching_policy": "Deterministic mechanical grouping followed by fixed 10/10/10/10/10/10/10/10/9 presentation batches; template authority and member sets are not merged.",
        "batches": batches,
        "human_decisions_created": 0,
    }


def _human_review_sheets(batches: Mapping[str, Any], records_by_id: Mapping[str, Mapping[str, Any]]) -> str:
    lines = [
        "# E0C-R5 Human Template Review Sheets",
        "",
        "Presentation-only sheets for the exact R4 shared-template candidates. Each template retains its R4 member authority; all decision fields remain unselected.",
        "",
    ]
    for batch in batches["batches"]:
        lines.extend([
            f"## {batch['batch_id']}",
            "",
            f"Templates: {batch['template_count']}. Member rows represented: {batch['member_row_count']}.",
            "",
        ])
        for template_id in batch["template_ids"]:
            record = records_by_id[template_id]
            blockers = ", ".join(item["blocker"] for item in record["dominant_blockers"]) or "UNKNOWN"
            reps = ", ".join(item["raw_key"] for item in record["representative_raws"])
            lines.extend([
                f"### {template_id}",
                "",
                f"- Member count: `{record['member_count']}`",
                f"- Member-set SHA256: `{record['member_key_commitment']['sha256']}`",
                f"- Representative raw keys: `{reps}`",
                f"- Archetype / platform / service: `{record['primary_execution_archetype']}` / `{', '.join(record['os_platform_hints'])}` / `{', '.join(record['named_protocols_or_services'])}`",
                f"- Blocker summary: `{blockers}`",
                f"- Defensive-equivalence summary: `{record['defensive_equivalence']['equivalence_confidence']}`; preserve R4 source-visible invariants only.",
                f"- Telemetry-equivalence summary: `{record['telemetry_surfaces']['equivalence_confidence']}`; candidate surfaces `{', '.join(record['telemetry_surfaces']['candidate_observation_surfaces'])}`; PROVX remains UNKNOWN.",
                f"- Environment availability: `{record['environment_availability']['state']}`",
                f"- Reset/safety complexity: `{record['reset_safety_complexity']['level']}`",
                "- Raw-specific parameters:",
            ])
            lines.extend(f"  - `{item}`" for item in record["raw_specific_parameters"])
            lines.append("- Unresolved human questions:")
            lines.extend(f"  - {item}" for item in record["unresolved_human_questions"])
            lines.append("- Negative cases:")
            lines.extend(f"  - {item}" for item in record["negative_cases"])
            lines.extend([
                "- Allowed human actions (unselected):",
                *[f"  - `{item}`" for item in record["decision_options"]],
                "",
            ])
    return "\n".join(lines) + "\n"


def _blocked_recovery(
    outliers: Mapping[str, Any],
    r1_by_key: Mapping[str, Mapping[str, Any]],
    r2_by_key: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for outlier in sorted(outliers.get("rows", []), key=lambda item: str(item.get("raw_key"))):
        if outlier.get("classification") != BLOCKED_DETAIL:
            continue
        raw_key = str(outlier["raw_key"])
        r1 = r1_by_key.get(raw_key)
        r2 = r2_by_key.get(raw_key)
        if r1 is None or r2 is None:
            raise ValueError(f"blocked raw lacks R1/R2 evidence: {raw_key}")
        named = _as_sorted_strings(r1.get("named_protocols_or_services"))
        service = _as_sorted_strings(r1.get("service_prerequisites"))
        if named != ["UNKNOWN"] or service != ["UNKNOWN"]:
            raise ValueError(f"blocked raw no longer has the R4 missing protocol/service condition: {raw_key}")
        rows.append({
            "raw_key": raw_key,
            "template_id": outlier.get("template_id"),
            "r4_rationale": outlier.get("rationale"),
            "primary_execution_archetype": r1.get("primary_execution_archetype"),
            "missing_fields": ["named_protocols_or_services", "service_prerequisites"],
            "observed_authenticated_values": {
                "named_protocols_or_services": named,
                "service_prerequisites": service,
                "required_protocol": r1.get("required_protocol"),
                "required_service_class": r1.get("required_service_class"),
            },
            "source_detail_to_recover": "An explicit protocol or service identifier and any source-scoped service prerequisite needed before defining a shared review contract.",
            "r1_source_locator_and_text": {
                "source_file": r1.get("source_file"),
                "source_locator": r1.get("source_locator"),
                "action_name": r1.get("action_name"),
                "action_description": r1.get("action_description"),
            },
            "r2_blockers": list(r2.get("blockers", [])),
            "r2_blocker_evidence": r2.get("blocker_evidence", {}),
            "missing_evidence_source_key": "HUMAN_CLARIFICATION::EXPLICIT_PROTOCOL_OR_SERVICE_NOT_PRESENT_IN_AUTHENTICATED_R1_FIELDS",
            "recovery_source_kind": "HUMAN_CLARIFICATION",
            "recovery_source_reason": "R4 records missing protocol/service detail and the authenticated R1 protocol and service fields are both UNKNOWN; R2 blocker evidence supplies no replacement protocol or service semantics.",
            "human_clarification_request": "Provide source-cited explicit protocol or service prerequisite details for this exact raw, or confirm that none exist. Do not infer command, credential, target, or network semantics.",
            "inferred_semantics": False,
            "formal_execution_authorized": False,
            "r3_global_planning_status": MANUAL_STATUS,
        })
    if len(rows) != EXPECTED_BLOCKED_COUNT:
        raise ValueError(f"blocked recovery count is {len(rows)}, expected {EXPECTED_BLOCKED_COUNT}")
    group_key = "HUMAN_CLARIFICATION::EXPLICIT_PROTOCOL_OR_SERVICE_NOT_PRESENT_IN_AUTHENTICATED_R1_FIELDS"
    return {
        "schema_version": "e0c-r5-blocked31-source-detail-recovery-v1",
        "blocked_need_more_source_detail_count": len(rows),
        "grouping_policy": "Rows are grouped only by their identical mechanically observed missing-evidence source key.",
        "recovery_groups": [{
            "missing_evidence_source_key": group_key,
            "recovery_source_kind": "HUMAN_CLARIFICATION",
            "missing_fields": ["named_protocols_or_services", "service_prerequisites"],
            "raw_key_count": len(rows),
            "raw_keys": [row["raw_key"] for row in rows],
        }],
        "rows": rows,
        "inferred_semantics": False,
        "human_decisions_created": 0,
    }


def _raw_specific_priority(
    outliers: Mapping[str, Any],
    r1_by_key: Mapping[str, Mapping[str, Any]],
    r2_by_key: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    raw_specific_keys = sorted(
        str(item["raw_key"])
        for item in outliers.get("rows", [])
        if item.get("classification") == RAW_SPECIFIC
    )
    if len(raw_specific_keys) != EXPECTED_RAW_SPECIFIC_COUNT:
        raise ValueError(f"raw-specific priority count is {len(raw_specific_keys)}, expected {EXPECTED_RAW_SPECIFIC_COUNT}")
    fixture_signatures: Counter[tuple[Any, ...]] = Counter()
    preliminary: list[tuple[str, Mapping[str, Any], Mapping[str, Any], tuple[Any, ...]]] = []
    for raw_key in raw_specific_keys:
        r1 = r1_by_key.get(raw_key)
        r2 = r2_by_key.get(raw_key)
        if r1 is None or r2 is None:
            raise ValueError(f"raw-specific raw lacks R1/R2 evidence: {raw_key}")
        signature = (
            str(r1.get("primary_execution_archetype")),
            tuple(_as_sorted_strings(r1.get("os_platform_hints"))),
            tuple(_as_sorted_strings(r1.get("named_protocols_or_services"))),
            tuple(_as_sorted_strings(r1.get("service_prerequisites"))),
            bool(r1.get("requires_host_process_telemetry")),
            bool(r1.get("requires_file_telemetry")),
            bool(r1.get("requires_socket_telemetry")),
            bool(r1.get("requires_network_fabric")),
        )
        fixture_signatures[signature] += 1
        preliminary.append((raw_key, r1, r2, signature))
    for raw_key, r1, r2, signature in preliminary:
        blockers = sorted(str(item) for item in r2.get("blockers", []))
        complexity = _safety_complexity(blockers)
        environment = _environment_availability([r1])
        candidates.append({
            "raw_key": raw_key,
            "template_id": next(
                str(item["template_id"])
                for item in outliers.get("rows", [])
                if item.get("classification") == RAW_SPECIFIC and str(item["raw_key"]) == raw_key
            ),
            "playbook_id": r1.get("playbook_id"),
            "stage_index": r1.get("stage_index"),
            "primary_execution_archetype": r1.get("primary_execution_archetype"),
            "source_file": r1.get("source_file"),
            "source_locator": r1.get("source_locator"),
            "playbook_dependency_criticality": {
                "state": "UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE",
                "source_stage_index": r1.get("stage_index"),
                "note": "Stage order is preserved as evidence but is not treated as a dependency assertion.",
            },
            "environment_availability": environment,
            "shared_fixture_reuse": {
                "candidate_fixture_signature": {
                    "primary_execution_archetype": signature[0],
                    "os_platform_hints": list(signature[1]),
                    "named_protocols_or_services": list(signature[2]),
                    "service_prerequisites": list(signature[3]),
                    "requires_host_process_telemetry": signature[4],
                    "requires_file_telemetry": signature[5],
                    "requires_socket_telemetry": signature[6],
                    "requires_network_fabric": signature[7],
                },
                "raw_specific_rows_with_same_mechanical_signature": fixture_signatures[signature],
                "reuse_is_not_approved": True,
            },
            "reset_safety_complexity": complexity,
            "r2_blockers": blockers,
            "r2_blocker_evidence": r2.get("blocker_evidence", {}),
            "resolution": None,
            "human_decision": None,
            "formal_execution_authorized": False,
            "r3_global_planning_status": MANUAL_STATUS,
            "provx_phase1_observable": "UNKNOWN",
            "provx_phase2_core_edge_localizable": "UNKNOWN",
        })

    def priority_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
        # Dependency criticality and environment availability are unknown or
        # non-positive in authenticated evidence. The remaining mechanical
        # order exposes reuse candidates and higher safety complexity first.
        return (
            str(row["playbook_dependency_criticality"]["state"]),
            str(row["environment_availability"]["state"]),
            -int(row["shared_fixture_reuse"]["raw_specific_rows_with_same_mechanical_signature"]),
            -SAFETY_COMPLEXITY_ORDER[str(row["reset_safety_complexity"]["level"])],
            str(row["raw_key"]),
        )

    ranked = sorted(candidates, key=priority_key)
    for rank, row in enumerate(ranked, 1):
        row["priority_rank"] = rank
        row["ranking_basis"] = [
            "playbook_dependency_criticality from authenticated source",
            "environment_availability from authenticated source",
            "shared_fixture_reuse by same mechanical signature",
            "reset_safety_complexity from R2 blocker taxonomy",
            "raw_key deterministic tie-breaker",
        ]
    return {
        "schema_version": "e0c-r5-raw-specific64-priority-v1",
        "raw_specific_count": len(ranked),
        "ranking_policy": "Deterministic lexicographic review order with no weighted score and no resolution or approval decision.",
        "rows": ranked,
        "human_decisions_created": 0,
    }


def _report(audit: Mapping[str, Any], batches: Mapping[str, Any]) -> str:
    return "\n".join([
        "# E0C-R5 Human Template Review Batching",
        "",
        "The R4 shared-template candidates are organized as compact human-review presentation batches. Template authority, member sets, R3 manual status, formal authorization, and PROVX UNKNOWN boundaries remain unchanged.",
        "",
        "## Terminal State",
        "",
        "E0C_R5_TEMPLATE_REVIEW_BATCHING = READY_FOR_HUMAN_REVIEW",
        f"SHARED_TEMPLATE_COUNT = {audit['shared_template_count']}",
        f"SHARED_TEMPLATE_COVERED_ROWS = {audit['shared_template_covered_rows']}",
        f"TEMPLATE_MEMBER_OVERLAP = {audit['template_member_overlap']}",
        f"TEMPLATE_MEMBER_MISSING = {audit['template_member_missing']}",
        f"REVIEW_BATCH_COUNT = {batches['review_batch_count']}",
        "BLOCKED31_RECOVERY_PLAN_READY = YES",
        "RAW_SPECIFIC64_PRIORITY_READY = YES",
        "HUMAN_DECISIONS_CREATED = 0",
        "FORMAL_EXPERIMENT_EXECUTED = NO",
        "DENOMINATOR_CHANGE = NO",
        "NEXT_ACTION = FRESH_REVIEW_OF_E0C_R5_TEMPLATE_REVIEW_BATCHING",
        "STOP = true",
        "",
        "## Review Policy",
        "",
        "Template priority is a deterministic lexicographic ordering by member coverage, playbook reuse, source-supported defensive and telemetry equivalence evidence, environment evidence, and lower reset complexity. It contains no weighted score. Batches are presentation-only; no template authority or member set is merged or changed.",
        "",
        "## Recovery And Raw-Specific Work",
        "",
        "All 31 blocked rows retain their R4 classification and request human clarification only for source-cited protocol/service details that remain UNKNOWN in authenticated R1 fields. The 64 raw-specific rows are only ranked for later one-by-one review; none is resolved.",
        "",
        "STOP = true",
        "",
    ])


def build_outputs(root: Path = Path(".")) -> dict[str, Any]:
    shared_data = _load_json(root / R4_SHARED_TEMPLATES_FILE)
    raw_map = _load_jsonl(root / R4_RAW_TO_TEMPLATE_MAP_FILE)
    exact_manual = _load_json(root / R4_EXACT_MANUAL_SET_FILE)
    packets = _load_jsonl(root / R4_REVIEW_PACKETS_FILE)
    workload_audit = _load_json(root / R4_WORKLOAD_AUDIT_FILE)
    outliers = _load_json(root / R4_OUTLIERS_FILE)
    r1_rows = _load_jsonl(root / R1_FILE)
    r2_data = _load_json(root / R2_BLOCKERS_FILE)
    r3_rows = _load_jsonl(root / R3_STATUS_FILE)

    templates = shared_data.get("templates", [])
    if not isinstance(templates, list):
        raise ValueError("R4 shared template artifact has no template list")
    shared = sorted(
        (template for template in templates if template.get("classification") == SHARED_TEMPLATE),
        key=lambda template: str(template.get("template_id")),
    )
    if shared_data.get("shared_template_count") != EXPECTED_SHARED_TEMPLATE_COUNT or len(shared) != EXPECTED_SHARED_TEMPLATE_COUNT:
        raise ValueError("R4 shared template count is not exact89")
    template_by_id = {str(template.get("template_id")): template for template in shared}
    if len(template_by_id) != EXPECTED_SHARED_TEMPLATE_COUNT:
        raise ValueError("R4 shared template IDs are not unique")

    exact_keys = sorted(str(item) for item in exact_manual.get("raw_keys", []))
    if exact_manual.get("exact_manual_raw_count") != EXPECTED_MANUAL_COUNT or len(exact_keys) != EXPECTED_MANUAL_COUNT or len(set(exact_keys)) != EXPECTED_MANUAL_COUNT:
        raise ValueError("R4 exact589 manual set is invalid")
    if exact_manual.get("manual_set_conservation") != "PASS":
        raise ValueError("R4 exact589 manual conservation is not PASS")

    map_by_key = {str(row.get("raw_key")): row for row in raw_map}
    if len(raw_map) != EXPECTED_MANUAL_COUNT or len(map_by_key) != EXPECTED_MANUAL_COUNT or sorted(map_by_key) != exact_keys:
        raise ValueError("R4 raw-to-template map does not match exact589 manual set")
    mapped_shared_keys = sorted(
        raw_key for raw_key, row in map_by_key.items() if row.get("template_classification") == SHARED_TEMPLATE
    )
    if len(mapped_shared_keys) != EXPECTED_SHARED_COVERED_ROWS:
        raise ValueError("R4 map does not contain exact494 shared members")

    packets_by_template = {str(packet.get("template_id")): packet for packet in packets}
    if len(packets) != len(templates) or len(packets_by_template) != len(templates):
        raise ValueError("R4 review packet coverage is invalid")
    for template in shared:
        packet = packets_by_template.get(str(template["template_id"]))
        if packet is None:
            raise ValueError(f"R4 shared template lacks packet: {template['template_id']}")
        if packet.get("decision") is not None or packet.get("human_decisions_created") != 0:
            raise ValueError(f"R4 packet contains a human decision: {template['template_id']}")
        if list(packet.get("decision_options", [])) != DECISION_OPTIONS:
            raise ValueError(f"R4 packet decision options drift: {template['template_id']}")

    if (
        workload_audit.get("exact_manual_raw_count") != EXPECTED_MANUAL_COUNT
        or workload_audit.get("shared_template_count") != EXPECTED_SHARED_TEMPLATE_COUNT
        or workload_audit.get("shared_template_covered_rows") != EXPECTED_SHARED_COVERED_ROWS
        or workload_audit.get("raw_specific_human_design_required") != EXPECTED_RAW_SPECIFIC_COUNT
        or workload_audit.get("blocked_need_more_source_detail") != EXPECTED_BLOCKED_COUNT
        or workload_audit.get("classification_overlap") != 0
        or workload_audit.get("classification_missing") != 0
        or workload_audit.get("human_decisions_created") != 0
    ):
        raise ValueError("R4 workload audit does not preserve frozen manual workload")

    r1_by_key = {str(row.get("raw_key")): row for row in r1_rows}
    r2_by_key = {str(row.get("raw_key")): row for row in r2_data.get("rows", [])}
    r3_by_key = {str(row.get("raw_key")): row for row in r3_rows}
    if len(r1_by_key) != 1796 or len(r3_by_key) != 1796:
        raise ValueError("R1/R3 do not retain the exact1796 authority set")

    member_keys: list[str] = []
    member_status_checks: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for template in shared:
        template_id = str(template["template_id"])
        keys = sorted(str(item) for item in template.get("member_keys", []))
        if len(keys) != int(template.get("member_count", -1)) or len(set(keys)) != len(keys):
            raise ValueError(f"R4 shared template member count drift: {template_id}")
        commitment = template.get("member_key_commitment", {})
        if commitment.get("sha256") != _sha256_keys(keys):
            raise ValueError(f"R4 shared template commitment drift: {template_id}")
        if template.get("human_decision") is not None or template.get("formal_execution_authorized") is not False:
            raise ValueError(f"R4 shared template authority drift: {template_id}")
        rows_for_template: list[Mapping[str, Any]] = []
        for raw_key in keys:
            mapped = map_by_key.get(raw_key)
            r1 = r1_by_key.get(raw_key)
            r3 = r3_by_key.get(raw_key)
            if mapped is None or r1 is None or r3 is None:
                raise ValueError(f"shared member lacks source authority: {raw_key}")
            if mapped.get("template_id") != template_id or mapped.get("template_classification") != SHARED_TEMPLATE:
                raise ValueError(f"shared member map authority drift: {raw_key}")
            if mapped.get("r3_global_planning_status") != MANUAL_STATUS or mapped.get("human_decision") is not None:
                raise ValueError(f"shared member map status drift: {raw_key}")
            if r3.get("global_planning_status") != MANUAL_STATUS:
                raise ValueError(f"shared member is no longer R3 manual: {raw_key}")
            if r1.get("formal_execution_authorized") is not False or r1.get("provx_phase1_observable") != "UNKNOWN" or r1.get("provx_phase2_core_edge_localizable") != "UNKNOWN":
                raise ValueError(f"shared member R1 execution/PROVX boundary drift: {raw_key}")
            member_status_checks.append({
                "raw_key": raw_key,
                "template_id": template_id,
                "r3_global_planning_status": r3.get("global_planning_status"),
                "formal_execution_authorized": False,
                "provx_phase1_observable": "UNKNOWN",
                "provx_phase2_core_edge_localizable": "UNKNOWN",
            })
            rows_for_template.append(r1)
        member_keys.extend(keys)
        records.append(_template_record(template, rows_for_template, packets_by_template[template_id]))

    member_key_set = set(member_keys)
    overlap = len(member_keys) - len(member_key_set)
    missing = len(set(mapped_shared_keys) - member_key_set) + len(member_key_set - set(mapped_shared_keys))
    if len(member_keys) != EXPECTED_SHARED_COVERED_ROWS or len(member_key_set) != EXPECTED_SHARED_COVERED_ROWS or overlap != 0 or missing != 0:
        raise ValueError("R4 shared member union is not exact494 without overlap")

    ranked = sorted(records, key=_priority_sort_key)
    for rank, record in enumerate(ranked, 1):
        record["priority_rank"] = rank
        record["ranking_basis"] = [
            "member_coverage descending",
            "playbook_reuse descending",
            "defensive_equivalence_evidence from existing R4 source invariants",
            "telemetry_equivalence_evidence from existing R1 source fields",
            "environment_availability evidence",
            "lower_reset_safety_complexity",
            "template_id deterministic tie-breaker",
        ]
    records_by_id = {str(record["template_id"]): record for record in ranked}
    batches = _review_batches(ranked)
    audit = {
        "schema_version": "e0c-r5-exact89-template-audit-v1",
        "authenticated_inputs": _r4_input_commitments(root),
        "authenticated_supporting_authority": [
            {"file": R1_FILE, "sha256": _sha256_file(root / R1_FILE)},
            {"file": R2_BLOCKERS_FILE, "sha256": _sha256_file(root / R2_BLOCKERS_FILE)},
            {"file": R3_STATUS_FILE, "sha256": _sha256_file(root / R3_STATUS_FILE)},
        ],
        "exact_manual_raw_count": EXPECTED_MANUAL_COUNT,
        "shared_template_count": len(shared),
        "shared_template_covered_rows": len(member_key_set),
        "template_member_overlap": overlap,
        "template_member_missing": missing,
        "shared_template_ids": sorted(records_by_id),
        "shared_member_set_commitment": {
            "algorithm": "sha256",
            "canonical_order": "lexicographic raw_key joined with LF",
            "sha256": _sha256_keys(sorted(member_key_set)),
        },
        "member_status_checks": member_status_checks,
        "r3_manual_design_required_member_count": len(member_status_checks),
        "human_decisions_created": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "status_authority_mutation": "NO",
        "authority_mutation": "NO",
        "provx_detection_claim": "NONE; R5 is review preparation only and phase fields remain UNKNOWN.",
    }
    priority = {
        "schema_version": "e0c-r5-template-priority-v1",
        "shared_template_count": len(ranked),
        "ranking_policy": "Deterministic lexicographic review order with no weighted score and no human decision.",
        "templates": ranked,
        "human_decisions_created": 0,
    }
    recovery = _blocked_recovery(outliers, r1_by_key, r2_by_key)
    raw_specific = _raw_specific_priority(outliers, r1_by_key, r2_by_key)
    report = _report(audit, batches)
    return {
        "exact89_template_audit": audit,
        "template_priority": priority,
        "review_batches": batches,
        "human_review_sheets": _human_review_sheets(batches, records_by_id),
        "blocked31_source_detail_recovery": recovery,
        "raw_specific64_priority": raw_specific,
        "report": report,
    }


def write_outputs(root: Path, outputs: Mapping[str, Any]) -> None:
    def write_json(name: str, value: Any) -> None:
        (root / name).write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    write_json("E0C_R5_EXACT89_TEMPLATE_AUDIT.json", outputs["exact89_template_audit"])
    write_json("E0C_R5_TEMPLATE_PRIORITY.json", outputs["template_priority"])
    write_json("E0C_R5_REVIEW_BATCHES.json", outputs["review_batches"])
    (root / "E0C_R5_HUMAN_REVIEW_SHEETS.md").write_text(outputs["human_review_sheets"], encoding="utf-8", newline="\n")
    write_json("E0C_R5_BLOCKED31_SOURCE_DETAIL_RECOVERY.json", outputs["blocked31_source_detail_recovery"])
    write_json("E0C_R5_RAW_SPECIFIC64_PRIORITY.json", outputs["raw_specific64_priority"])
    (root / "E0C_R5_REVIEW_BATCHING_REPORT.md").write_text(outputs["report"], encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        outputs = build_outputs(args.root)
        audit = outputs["exact89_template_audit"]
        if audit["shared_template_count"] != EXPECTED_SHARED_TEMPLATE_COUNT:
            raise ValueError("exact89 audit failed")
        write_outputs(args.root, outputs)
    except (OSError, ValueError, json.JSONDecodeError, KeyError, TypeError) as error:
        print("E0C_R5_TEMPLATE_REVIEW_BATCHING = BLOCKED")
        print(f"ERROR = {error}")
        print("SHARED_TEMPLATE_COUNT = 89")
        print("SHARED_TEMPLATE_COVERED_ROWS = 494")
        print("HUMAN_DECISIONS_CREATED = 0")
        print("FORMAL_EXPERIMENT_EXECUTED = NO")
        print("DENOMINATOR_CHANGE = NO")
        print("NEXT_ACTION = FRESH_REVIEW_OF_E0C_R5_TEMPLATE_REVIEW_BATCHING")
        print("STOP = true")
        return 1
    batches = outputs["review_batches"]
    print("E0C_R5_TEMPLATE_REVIEW_BATCHING = READY_FOR_HUMAN_REVIEW")
    print(f"SHARED_TEMPLATE_COUNT = {audit['shared_template_count']}")
    print(f"SHARED_TEMPLATE_COVERED_ROWS = {audit['shared_template_covered_rows']}")
    print(f"TEMPLATE_MEMBER_OVERLAP = {audit['template_member_overlap']}")
    print(f"TEMPLATE_MEMBER_MISSING = {audit['template_member_missing']}")
    print(f"REVIEW_BATCH_COUNT = {batches['review_batch_count']}")
    print("BLOCKED31_RECOVERY_PLAN_READY = YES")
    print("RAW_SPECIFIC64_PRIORITY_READY = YES")
    print("HUMAN_DECISIONS_CREATED = 0")
    print("FORMAL_EXPERIMENT_EXECUTED = NO")
    print("DENOMINATOR_CHANGE = NO")
    print("NEXT_ACTION = FRESH_REVIEW_OF_E0C_R5_TEMPLATE_REVIEW_BATCHING")
    print("STOP = true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
