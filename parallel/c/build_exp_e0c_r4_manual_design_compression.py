#!/usr/bin/env python3
"""Compress the exact R3 manual-design set into evidence-bound review templates."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


EXPECTED_MANUAL_COUNT = 589
EXPECTED_RAW_COUNT = 1796
R3_STATUS_FILE = "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl"
R1_FILE = "EXP_E0C_R1_1796_ENRICHED_READINESS.jsonl"
R2_BLOCKERS_FILE = "E0C_R2_MANUAL_DESIGN_BLOCKERS.json"
R3_AUDIT_FILE = "E0C_R3_GLOBAL_COVERAGE_AUDIT.json"
R3_RECONCILIATION_FILE = "E0C_R3_R2_ACCOUNTING_RECONCILIATION.json"
GLOBAL_MANUAL_STATUS = "MANUAL_DESIGN_REQUIRED"
SHARED_TEMPLATE = "CANDIDATE_FOR_SHARED_HUMAN_TEMPLATE"
RAW_SPECIFIC = "RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED"
BLOCKED_DETAIL = "BLOCKED_NEED_MORE_SOURCE_DETAIL"
CLASSIFICATIONS = (SHARED_TEMPLATE, RAW_SPECIFIC, BLOCKED_DETAIL)

MANUAL_BLOCKERS = (
    "missing_exact_command_semantics",
    "privileged_action",
    "credential_sensitive",
    "destructive_state",
    "windows_only_semantics",
    "service_environment_absent",
    "ambiguous_source_wording",
    "multi_step_composite",
    "other",
)

_COMMAND_RE = re.compile(r"(?:command|command\s+line|shell|powershell|\bcmd\b|\bbash\b|execute|run|script|命令|执行|脚本)", re.I)
_PRIVILEGE_RE = re.compile(r"(?:privilege|administrator|admin|root|uac|elevation|escalat|sudo|fodhelper|cmstplua|提权|管理员|权限)", re.I)
_CREDENTIAL_RE = re.compile(r"(?:credential|password|hash|cookie|keylog|mimikatz|凭证|密码|哈希|浏览器)", re.I)
_DESTRUCTIVE_RE = re.compile(r"(?:delete|wipe|format|destructive|disable|bypass|exploit|ransomware|恶意|删除|禁用|绕过|破坏|勒索)", re.I)
_MULTI_STEP_RE = re.compile(r"(?:\band\b|\bthen\b|\bafter\b|\bbefore\b|,|;|\+|\band/or\b|以及|并|然后|之后)", re.I)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"non-object JSONL row at {path}:{line_number}")
            rows.append(value)
    return rows


def _sha256_keys(keys: list[str]) -> str:
    return hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _list_values(row: Mapping[str, Any], field: str) -> tuple[str, ...]:
    value = row.get(field, ["UNKNOWN"])
    if isinstance(value, list):
        return tuple(sorted(str(item) for item in value))
    return (str(value),)


def _text(row: Mapping[str, Any]) -> str:
    return f"{row.get('action_name', '')} {row.get('action_description', '')}"


def _source_evidence(row: Mapping[str, Any], field: str, rule_id: str) -> dict[str, Any]:
    suffix = {"name": ".name", "desc": ".desc", "action_type": ".action_type", "os": ".os"}[field]
    source_value = {
        "name": row.get("action_name"),
        "desc": row.get("action_description"),
        "action_type": row.get("action_type"),
        "os": row.get("required_os_or_host_class", row.get("os_platform_hints")),
    }[field]
    return {
        "source_field_path": f"{row.get('source_locator', '$.pipeline[*].actions[*]')}{suffix}",
        "exact_source_value": source_value,
        "derivation_rule_id": rule_id,
    }


def _auth_inputs(root: Path) -> dict[str, Any]:
    r1 = _load_jsonl(root / R1_FILE)
    r3 = _load_jsonl(root / R3_STATUS_FILE)
    r1_by_key = {str(row.get("raw_key")): row for row in r1}
    r3_by_key = {str(row.get("raw_key")): row for row in r3}
    if len(r1) != EXPECTED_RAW_COUNT or len(r1_by_key) != EXPECTED_RAW_COUNT:
        raise ValueError("R1 does not contain exactly 1796 unique raw keys")
    if len(r3) != EXPECTED_RAW_COUNT or len(r3_by_key) != EXPECTED_RAW_COUNT:
        raise ValueError("R3 does not contain exactly 1796 unique raw keys")
    if set(r1_by_key) != set(r3_by_key):
        raise ValueError("R1/R3 raw key sets differ")
    if any(row.get("formal_execution_authorized") is not False for row in r1):
        raise ValueError("R1 formal authorization boundary drift")
    if any(row.get("provx_phase1_observable") != "UNKNOWN" or row.get("provx_phase2_core_edge_localizable") != "UNKNOWN" for row in r1):
        raise ValueError("R1 PROVX boundary drift")
    manual_status_keys = {key for key, row in r3_by_key.items() if row.get("global_planning_status") == GLOBAL_MANUAL_STATUS}
    if len(manual_status_keys) != EXPECTED_MANUAL_COUNT:
        raise ValueError(f"R3 manual status count is {len(manual_status_keys)}, expected 589")
    if any(row.get("global_planning_status") not in {"CONTRACT_DESIGNED_READY_FOR_IMPLEMENTATION_PLANNING", "MANUAL_DESIGN_REQUIRED", "BLOCKED_UNRESOLVED_PREREQUISITE"} for row in r3):
        raise ValueError("R3 contains unknown global planning status")
    r3_audit = _load_json(root / R3_AUDIT_FILE)
    if r3_audit.get("global_status_sum") != EXPECTED_RAW_COUNT or r3_audit.get("global_status_overlap") != 0 or r3_audit.get("global_status_missing") != 0:
        raise ValueError("R3 global coverage audit is not PASS_1796")
    blockers = _load_json(root / R2_BLOCKERS_FILE)
    blocker_keys = {str(row.get("raw_key")) for row in blockers.get("rows", [])}
    if blocker_keys != manual_status_keys or blockers.get("manual_design_row_count") != EXPECTED_MANUAL_COUNT:
        raise ValueError("R2 manual blocker set does not match R3 manual status set")
    reconciliation = _load_json(root / R3_RECONCILIATION_FILE)
    if reconciliation.get("r1_r2_authority") != "PASS" or reconciliation.get("r2_authenticated_artifact_count") != 5:
        raise ValueError("R3 reconciliation does not authenticate prior authority")
    return {
        "r1_rows": r1,
        "r1_by_key": r1_by_key,
        "r3_by_key": r3_by_key,
        "manual_keys": sorted(manual_status_keys),
        "r1_audit_sha256": _sha256_file(root / "EXP_E0C_R1_CONSERVATION_AUDIT.json"),
        "r3_audit_sha256": _sha256_file(root / R3_AUDIT_FILE),
        "r2_blocker_sha256": _sha256_file(root / R2_BLOCKERS_FILE),
    }


def _cluster_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    blockers = tuple(sorted(str(item) for item in row.get("manual_design_blockers", [])))
    if not blockers:
        blockers = tuple(sorted(str(item) for item in row.get("blockers", [])))
    return (
        str(row.get("primary_execution_archetype")),
        _list_values(row, "os_platform_hints"),
        _list_values(row, "named_protocols_or_services"),
        bool(row.get("requires_privileged_host_action")),
        "credential_sensitive" in blockers,
        "destructive_state" in blockers,
        "windows_only_semantics" in blockers,
        "persistence" if str(row.get("primary_execution_archetype")) == "PERSISTENCE_CONFIGURATION" else "none",
        blockers,
        str(row.get("action_type")),
        _list_values(row, "explicit_tool_or_malware_names"),
        _list_values(row, "service_prerequisites"),
    )


def _template_classification(rows: list[dict[str, Any]], key: tuple[Any, ...]) -> tuple[str, str]:
    # Shared templates are offered only where at least two rows share every
    # mechanically available dimension and no source-sensitive detail must be
    # guessed. A unique row is retained as raw-specific design work.
    if len(rows) < 2:
        return RAW_SPECIFIC, "No second row shares the complete evidence signature."
    if key[2] == ("UNKNOWN",) and key[0] in {"NETWORK_C2_BEACON", "DISCOVERY_ENUMERATION"}:
        return BLOCKED_DETAIL, "Network/discovery semantics lack an explicit protocol or service detail for a shared contract."
    if key[4] or key[5] or key[6] or key[8]:
        return SHARED_TEMPLATE, "Rows share source-visible safety blockers and evidence dimensions; raw-specific parameters remain required."
    return SHARED_TEMPLATE, "Rows share the full mechanically available evidence signature; no semantic embedding or guessed command is used."


def _template_contract(template_id: str, family: str, rows: list[dict[str, Any]], classification: str, key: tuple[Any, ...]) -> dict[str, Any]:
    keys = [str(row["raw_key"]) for row in rows]
    blockers = sorted({str(item) for row in rows for item in row.get("manual_design_blockers", [])})
    if not blockers:
        blockers = sorted({str(item) for row in rows for item in row.get("blockers", [])})
    modes = sorted({str(row.get("candidate_execution_mode_for_design")) for row in rows})
    return {
        "template_id": template_id,
        "template_version": "0.1.0-design",
        "classification": classification,
        "primary_execution_archetype": family,
        "member_count": len(keys),
        "member_keys": keys,
        "member_key_commitment": {"algorithm": "sha256", "canonical_order": "lexicographic raw_key joined with LF", "sha256": _sha256_keys(keys)},
        "common_evidence_signature": {
            "os_platform_hints": list(key[1]),
            "named_protocols_or_services": list(key[2]),
            "requires_privileged_host_action": key[3],
            "credential_sensitive": key[4],
            "destructive_state_risk": key[5],
            "windows_specific_semantics": key[6],
            "persistence_dimension": key[7],
            "blocker_taxonomy": list(key[8]),
            "source_action_type": key[9],
            "explicit_tooling": list(key[10]),
            "service_prerequisites": list(key[11]),
        },
        "common_blockers_environment": blockers + (["source-defined platform/service fixture requirements"] if key[11] != ("UNKNOWN",) else ["no explicit service prerequisite is source-evidenced"]),
        "allowed_candidate_fidelity_classes": modes,
        "defensive_equivalence_invariants": {
            "process_ancestry": "Preserve host process ancestry class where applicable; never substitute a guessed parent process.",
            "file_socket_entity_classes": "Preserve source-indicated file/socket entity and operation classes; inert content may differ.",
            "network_direction_protocol": "Preserve explicit direction/protocol/service evidence; UNKNOWN remains UNKNOWN.",
            "timing_sequence": "Preserve source-visible ordering and coarse timing relationships; exact timing may differ.",
            "observable_causality": "Preserve only causality supported by the source and later telemetry; do not fabricate edges.",
            "required_side_effects": "Use only inert side effects required for the same defensive decision point.",
            "safe_differences": ["payload bytes", "credentials/secrets", "public endpoints", "exploitability", "destructive effects", "fixture identifiers with reversible mapping"],
        },
        "telemetry_equivalence_invariants": {
            "process_surface": bool(any(row.get("requires_host_process_telemetry") for row in rows)),
            "file_surface": bool(any(row.get("requires_file_telemetry") for row in rows)),
            "socket_surface": bool(any(row.get("requires_socket_telemetry") for row in rows)),
            "network_surface": bool(any(row.get("requires_network_fabric") for row in rows)),
            "provx_candidate_surface": sorted({str(item) for row in rows for item in row.get("provx_candidate_observation_surface", ["UNKNOWN"])}),
            "phase1_observable": "UNKNOWN",
            "phase2_core_edge_localizable": "UNKNOWN",
            "result_status": "UNEXECUTED_NOT_OBSERVED",
        },
        "cleanup_reset": ["Record reset plan before any future implementation.", "Remove only inert fixture artifacts created for the review design.", "Verify process/file/socket/service/topology state returns to the approved baseline."],
        "per_raw_parameters": ["raw_key", "source_locator", "source action name/description", "raw-specific OS/service/protocol values", "raw-specific blocker evidence", "approved fixture identifier", "run_id binding"],
        "raw_specific_human_questions": [
            "What exact source-visible semantics must remain equivalent for this raw?",
            "Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?",
            "Which side effects are necessary for the defensive decision point, and which must be excluded?",
        ],
        "negative_cases": [
            "Do not infer missing command syntax, credentials, target behavior, or exploitability.",
            "Do not use public endpoints, real malware, destructive effects, or uncontrolled services.",
            "Do not mark PROVX detection/localization or formal outcomes from a design packet.",
        ],
        "human_decision_options": ["APPROVE_TEMPLATE_FOR_MEMBER_SET", "REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL", "REQUEST_SPLIT_OR_MORE_EVIDENCE"],
        "human_decision": None,
        "implementation_status": "DESIGN_ONLY_NOT_IMPLEMENTED",
        "formal_execution_authorized": False,
    }


def _review_packet(template: Mapping[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    reps = []
    for row in rows[:3]:
        reps.append({
            "raw_key": row["raw_key"],
            "source_file": row.get("source_file"),
            "source_locator": row.get("source_locator"),
            "action_name": row.get("action_name"),
            "action_description": row.get("action_description"),
            "action_type": row.get("action_type"),
            "os_platform_hints": row.get("os_platform_hints"),
            "named_protocols_or_services": row.get("named_protocols_or_services"),
            "service_prerequisites": row.get("service_prerequisites"),
        })
    return {
        "review_packet_id": f"review::{template['template_id']}",
        "template_id": template["template_id"],
        "member_count": template["member_count"],
        "member_keys": template["member_keys"],
        "member_key_commitment": template["member_key_commitment"],
        "representative_source_fields": reps,
        "proposed_contract": template,
        "unresolved_questions": template["raw_specific_human_questions"],
        "decision_options": template["human_decision_options"],
        "decision": None,
        "human_decisions_created": 0,
    }


def build_outputs(root: Path = Path(".")) -> dict[str, Any]:
    inputs = _auth_inputs(root)
    r1_by_key = inputs["r1_by_key"]
    manual_rows: list[dict[str, Any]] = []
    blocker_data = _load_json(root / R2_BLOCKERS_FILE)
    blocker_by_key = {str(row["raw_key"]): row for row in blocker_data["rows"]}
    for key in inputs["manual_keys"]:
        row = dict(r1_by_key[key])
        row["manual_design_blockers"] = blocker_by_key[key].get("blockers", [])
        manual_rows.append(row)
    dimensions = {
        "schema_version": "e0c-r4-manual-clustering-dimensions-v1",
        "source": "R1 exact fields plus R2 source-supported blocker taxonomy",
        "dimensions": [
            {"field": "primary_execution_archetype", "source": "R1 primary_execution_archetype", "mechanical": True},
            {"field": "os_platform_hints", "source": "R1 os_platform_hints", "mechanical": True},
            {"field": "named_protocols_or_services", "source": "R1 named_protocols_or_services", "mechanical": True},
            {"field": "requires_privileged_host_action", "source": "R1 boolean flag", "mechanical": True},
            {"field": "credential_sensitive", "source": "R2 credential_sensitive blocker", "mechanical": True},
            {"field": "destructive_state_risk", "source": "R2 destructive_state blocker", "mechanical": True},
            {"field": "persistence", "source": "R1 primary archetype", "mechanical": True},
            {"field": "windows_specific_semantics", "source": "R2 windows_only_semantics blocker", "mechanical": True},
            {"field": "blocker_taxonomy", "source": "R2 manual blocker taxonomy", "mechanical": True},
            {"field": "source_action_type", "source": "R1 action_type", "mechanical": True},
            {"field": "explicit_tooling", "source": "R1 explicit_tool_or_malware_names", "mechanical": True},
            {"field": "service_prerequisites", "source": "R1 service_prerequisites", "mechanical": True},
        ],
        "excluded_methods": ["embeddings", "semantic similarity models", "unstated command inference", "human decisions"],
    }
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in manual_rows:
        grouped[_cluster_key(row)].append(row)
    templates: list[dict[str, Any]] = []
    row_map: list[dict[str, Any]] = []
    outlier_rows: list[dict[str, Any]] = []
    for index, key in enumerate(sorted(grouped, key=str), 1):
        rows = sorted(grouped[key], key=lambda row: str(row["raw_key"]))
        family = str(key[0])
        classification, rationale = _template_classification(rows, key)
        template_id = f"r4-template-{index:03d}-{family.lower()}"
        template = _template_contract(template_id, family, rows, classification, key)
        template["classification_rationale"] = rationale
        templates.append(template)
        if classification != SHARED_TEMPLATE:
            outlier_rows.extend({
                "raw_key": row["raw_key"],
                "template_id": template_id,
                "classification": classification,
                "rationale": rationale,
                "source_locator": row.get("source_locator"),
            } for row in rows)
        for row in rows:
            row_map.append({
                "raw_key": row["raw_key"],
                "template_id": template_id,
                "template_classification": classification,
                "primary_execution_archetype": row["primary_execution_archetype"],
                "manual_design_blockers": row["manual_design_blockers"],
                "r1_candidate_execution_mode": row["candidate_execution_mode_for_design"],
                "r3_global_planning_status": GLOBAL_MANUAL_STATUS,
                "formal_execution_authorized": False,
                "provx_phase1_observable": "UNKNOWN",
                "provx_phase2_core_edge_localizable": "UNKNOWN",
                "result_status": "UNEXECUTED_NOT_OBSERVED",
                "source_locator": row.get("source_locator"),
                "human_decision_required": True,
                "human_decision": None,
            })
    # A shared template is a candidate only; each member is still manually
    # reviewed and no row is automatically resolved.
    shared_rows = sum(t["member_count"] for t in templates if t["classification"] == SHARED_TEMPLATE)
    specific_rows = sum(t["member_count"] for t in templates if t["classification"] == RAW_SPECIFIC)
    blocked_rows = sum(t["member_count"] for t in templates if t["classification"] == BLOCKED_DETAIL)
    review_packets = [_review_packet(template, sorted(grouped[_cluster_key(next(row for row in manual_rows if row["raw_key"] == template["member_keys"][0]))], key=lambda row: str(row["raw_key"]))) for template in templates]
    audit = {
        "schema_version": "e0c-r4-manual-workload-audit-v1",
        "exact_manual_raw_count": EXPECTED_MANUAL_COUNT,
        "manual_set_conservation": "PASS" if len(manual_rows) == EXPECTED_MANUAL_COUNT and len({row["raw_key"] for row in manual_rows}) == EXPECTED_MANUAL_COUNT else "BLOCKED",
        "shared_template_count": sum(template["classification"] == SHARED_TEMPLATE for template in templates),
        "shared_template_covered_rows": shared_rows,
        "raw_specific_human_design_required": specific_rows,
        "blocked_need_more_source_detail": blocked_rows,
        "classification_counts": {SHARED_TEMPLATE: shared_rows, RAW_SPECIFIC: specific_rows, BLOCKED_DETAIL: blocked_rows},
        "classification_sum": shared_rows + specific_rows + blocked_rows,
        "classification_overlap": 0,
        "classification_missing": EXPECTED_MANUAL_COUNT - (shared_rows + specific_rows + blocked_rows),
        "human_decisions_created": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "binding_authority_mutation": "NO",
        "scoring_authority_mutation": "NO",
        "status_authority_mutation": "NO",
        "provx_observability_claim": "NONE; design-only packet, all PROVX phase fields remain UNKNOWN",
        "r1_audit_sha256": inputs["r1_audit_sha256"],
        "r3_audit_sha256": inputs["r3_audit_sha256"],
        "r2_blocker_sha256": inputs["r2_blocker_sha256"],
        "next_action": "FRESH_REVIEW_OF_E0C_R4_MANUAL_DESIGN_COMPRESSION",
        "stop": True,
    }
    report_lines = [
        "# EXP-E0C-R4 Manual-Design Workload Compression", "", "Evidence-bound compression of the exact R3 manual-design set into human-reviewable template candidates. No row is automatically resolved and no action is executed.", "",
        "## Terminal State", "",
        f"- `E0C_R4_MANUAL_DESIGN_COMPRESSION = {'READY_FOR_HUMAN_TEMPLATE_REVIEW' if audit['manual_set_conservation'] == 'PASS' else 'BLOCKED'}`",
        f"- `EXACT_MANUAL_RAW_COUNT = {audit['exact_manual_raw_count']}`", f"- `MANUAL_SET_CONSERVATION = {audit['manual_set_conservation']}`", f"- `SHARED_TEMPLATE_COUNT = {audit['shared_template_count']}`", f"- `SHARED_TEMPLATE_COVERED_ROWS = {audit['shared_template_covered_rows']}`", f"- `RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED = {audit['raw_specific_human_design_required']}`", f"- `BLOCKED_NEED_MORE_SOURCE_DETAIL = {audit['blocked_need_more_source_detail']}`", "- `HUMAN_DECISIONS_CREATED = 0`", "- `FORMAL_EXPERIMENT_EXECUTED = NO`", "- `DENOMINATOR_CHANGE = NO`", "- `NEXT_ACTION = FRESH_REVIEW_OF_E0C_R4_MANUAL_DESIGN_COMPRESSION`", "- `STOP = true`", "",
        "## Compression Policy", "", "Clustering uses only exact R1 fields and R2 blocker labels. Embeddings, semantic guesses, guessed command syntax, credentials, target behavior, destructive effects, and human decisions are excluded. Shared templates remain review candidates; no member changes its R3 global status.", "",
        "## Classification", "", f"The 589 manual rows are classified into {audit['shared_template_covered_rows']} candidate shared-template rows, {audit['raw_specific_human_design_required']} raw-specific rows, and {audit['blocked_need_more_source_detail']} rows blocked on missing source detail. The counts sum to {audit['classification_sum']} with overlap {audit['classification_overlap']} and missing {audit['classification_missing']}.", "",
        "| Classification | Rows |", "|---|---:|", f"| `{SHARED_TEMPLATE}` | {shared_rows} |", f"| `{RAW_SPECIFIC}` | {specific_rows} |", f"| `{BLOCKED_DETAIL}` | {blocked_rows} |", "",
        "## Review Decisions", "", "Each JSONL review packet exposes only `APPROVE_TEMPLATE_FOR_MEMBER_SET`, `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`, or `REQUEST_SPLIT_OR_MORE_EVIDENCE`. The decision field is null and `HUMAN_DECISIONS_CREATED = 0`.", "",
        "## Boundaries", "", "R1 candidate fidelity and R3 global statuses are preserved. PROVX observability/localization remains UNKNOWN and all result state remains UNEXECUTED_NOT_OBSERVED. No authority, denominator, or formal experiment state changed.", "", "STOP = true", "",
    ]
    return {
        "exact_manual_set": {"schema_version": "e0c-r4-exact589-manual-set-v1", "raw_denominator": EXPECTED_RAW_COUNT, "exact_manual_raw_count": EXPECTED_MANUAL_COUNT, "manual_set_conservation": audit["manual_set_conservation"], "raw_keys": inputs["manual_keys"], "raw_key_set_commitment": {"algorithm": "sha256", "canonical_order": "lexicographic raw_key joined with LF", "sha256": _sha256_keys(inputs["manual_keys"])}, "source_status": GLOBAL_MANUAL_STATUS, "human_decisions_created": 0},
        "clustering_dimensions": dimensions,
        "shared_templates": {"schema_version": "e0c-r4-shared-manual-design-templates-v1", "exact_manual_raw_count": EXPECTED_MANUAL_COUNT, "template_count": len(templates), "shared_template_count": audit["shared_template_count"], "templates": templates},
        "raw_to_template_rows": row_map,
        "outliers": {"schema_version": "e0c-r4-manual-outliers-v1", "raw_specific_count": specific_rows, "blocked_need_more_source_detail_count": blocked_rows, "rows": sorted(outlier_rows, key=lambda item: str(item["raw_key"]))},
        "review_packets": review_packets,
        "audit": audit,
        "report": "\n".join(report_lines),
    }


def write_outputs(root: Path, outputs: Mapping[str, Any]) -> None:
    def write_json(name: str, value: Any) -> None:
        (root / name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    write_json("E0C_R4_EXACT589_MANUAL_SET.json", outputs["exact_manual_set"])
    write_json("E0C_R4_MANUAL_CLUSTERING_DIMENSIONS.json", outputs["clustering_dimensions"])
    write_json("E0C_R4_SHARED_MANUAL_DESIGN_TEMPLATES.json", outputs["shared_templates"])
    (root / "E0C_R4_RAW_TO_TEMPLATE_MAP.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in outputs["raw_to_template_rows"]), encoding="utf-8", newline="\n")
    write_json("E0C_R4_MANUAL_OUTLIERS.json", outputs["outliers"])
    (root / "E0C_R4_HUMAN_TEMPLATE_REVIEW_PACKETS.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in outputs["review_packets"]), encoding="utf-8", newline="\n")
    write_json("E0C_R4_MANUAL_WORKLOAD_AUDIT.json", outputs["audit"])
    (root / "E0C_R4_MANUAL_DESIGN_COMPRESSION_REPORT.md").write_text(outputs["report"], encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        outputs = build_outputs(args.root)
        if outputs["audit"]["manual_set_conservation"] != "PASS":
            raise ValueError("manual set conservation failed")
        write_outputs(args.root, outputs)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("E0C_R4_MANUAL_DESIGN_COMPRESSION = BLOCKED")
        print(f"ERROR = {error}")
        print("EXACT_MANUAL_RAW_COUNT = 589")
        print("NEXT_ACTION = FIX_R4_MANUAL_SET_AUTHORITY_DEFECT")
        print("STOP = true")
        return 1
    audit = outputs["audit"]
    print("E0C_R4_MANUAL_DESIGN_COMPRESSION = READY_FOR_HUMAN_TEMPLATE_REVIEW")
    print(f"EXACT_MANUAL_RAW_COUNT = {audit['exact_manual_raw_count']}")
    print(f"MANUAL_SET_CONSERVATION = {audit['manual_set_conservation']}")
    print(f"SHARED_TEMPLATE_COUNT = {audit['shared_template_count']}")
    print(f"SHARED_TEMPLATE_COVERED_ROWS = {audit['shared_template_covered_rows']}")
    print(f"RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED = {audit['raw_specific_human_design_required']}")
    print(f"BLOCKED_NEED_MORE_SOURCE_DETAIL = {audit['blocked_need_more_source_detail']}")
    print("HUMAN_DECISIONS_CREATED = 0")
    print("FORMAL_EXPERIMENT_EXECUTED = NO")
    print("DENOMINATOR_CHANGE = NO")
    print("NEXT_ACTION = FRESH_REVIEW_OF_E0C_R4_MANUAL_DESIGN_COMPRESSION")
    print("STOP = true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
