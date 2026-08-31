#!/usr/bin/env python3
"""Build non-executable E0C-R2 adapter contract design outputs."""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
R1 = ROOT / "EXP_E0C_R1_1796_ENRICHED_READINESS.jsonl"
OUT = ROOT / "docs/e0c-r2-adapter-contracts"
TARGET_FAMILIES = [
    "PROCESS_COMMAND_EXECUTION",
    "NETWORK_SERVICE_INTERACTION",
    "TRANSFER_DOWNLOAD_UPLOAD",
    "EMAIL_DELIVERY",
    "NETWORK_C2_BEACON",
]
EXPECTED_COUNTS = {
    "PROCESS_COMMAND_EXECUTION": 712,
    "NETWORK_SERVICE_INTERACTION": 232,
    "TRANSFER_DOWNLOAD_UPLOAD": 166,
    "EMAIL_DELIVERY": 105,
    "NETWORK_C2_BEACON": 103,
}
MANUAL_TAXONOMY = [
    "MISSING_EXACT_ACTION_SEMANTICS",
    "PRIVILEGED_ACTION",
    "CREDENTIAL_SENSITIVE",
    "DESTRUCTIVE_STATE",
    "WINDOWS_ONLY_SEMANTICS",
    "SERVICE_OR_ENVIRONMENT_ABSENT",
    "AMBIGUOUS_SOURCE_WORDING",
    "MULTI_STEP_COMPOSITE",
    "OTHER_SOURCE_BLOCKER",
]


def load_r1_rows(path: Path = R1) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    if len(rows) != 1796:
        raise ValueError(f"expected 1796 R1 rows, got {len(rows)}")
    keys = [row["raw_key"] for row in rows]
    if len(keys) != len(set(keys)):
        raise ValueError("R1 raw_key values are not unique")
    return rows


def _counter_values(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in rows:
        value = row.get(field)
        if isinstance(value, list):
            counts.update(str(item) for item in value)
        elif isinstance(value, dict):
            counts.update(str(item) for item in value)
        elif value is not None:
            counts[str(value)] += 1
    return dict(sorted(counts.items()))


def _stages(rows: list[dict[str, Any]]) -> list[str]:
    return sorted({f"S{int(row['stage_index']):02d}" for row in rows if str(row.get("stage_index", "")).isdigit()})


def _families(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for family in TARGET_FAMILIES:
        members = [row for row in rows if row.get("primary_execution_archetype") == family]
        if len(members) != EXPECTED_COUNTS[family]:
            raise ValueError(f"{family}: expected {EXPECTED_COUNTS[family]}, got {len(members)}")
        manual = [row for row in members if row.get("candidate_execution_mode_for_design") == "REQUIRES_MANUAL_DESIGN"]
        result[family] = {
            "family_id": f"adapter::{family.lower()}",
            "raw_count": len(members),
            "raw_keys": [row["raw_key"] for row in members],
            "manual_design_raw_keys": [row["raw_key"] for row in manual],
            "candidate_execution_modes": dict(sorted(Counter(row.get("candidate_execution_mode_for_design") for row in members).items())),
            "playbooks_covered": sorted({row["playbook_id"] for row in members}),
            "stages_covered": _stages(members),
            "os_platform_hints": _counter_values(members, "required_os_or_host_class"),
            "service_or_protocol_prerequisites": _counter_values(members, "service_prerequisites"),
            "source_action_types": _counter_values(members, "action_type"),
            "source_derived_prerequisites": sorted({item for row in members for item in row.get("secondary_prerequisite_tags", [])}),
            "manual_design_count": len(manual),
        }
    return result


def _compatibility(family: str) -> str:
    if family == "PROCESS_COMMAND_EXECUTION":
        return "REQUIRES_HOST_PROVENANCE_VALIDATION"
    if family in {"NETWORK_SERVICE_INTERACTION", "NETWORK_C2_BEACON"}:
        return "PLAIN_MININET_CANDIDATE"
    if family in {"TRANSFER_DOWNLOAD_UPLOAD", "EMAIL_DELIVERY"}:
        return "REQUIRES_HOST_PROVENANCE_VALIDATION"
    return "MANUAL_DESIGN"


def _adapter_contracts(families: dict[str, dict[str, Any]]) -> dict[str, Any]:
    contracts: dict[str, Any] = {}
    for rank, family in enumerate(TARGET_FAMILIES, 1):
        item = families[family]
        contracts[family] = {
            "adapter_id": item["family_id"],
            "adapter_version": "0.1.0-design",
            "priority_rank": rank,
            "raw_count": item["raw_count"],
            "applicable_raw_key_set_commitment": {
                "algorithm": "SHA256",
                "canonicalization": "sorted UTF-8 raw_key array",
                "raw_count": item["raw_count"],
                "raw_keys_sha256": hashlib.sha256("\n".join(item["raw_keys"]).encode()).hexdigest(),
            },
            "input_parameters": ["run_id", "raw_key", "isolated_fixture_id", "bounded_timeout", "candidate_mode"],
            "required_source_target_roles": ["source_host", "target_host_or_service", "telemetry_collector"],
            "preconditions": ["authenticated raw row", "approved fixture manifest", "isolated private fabric", "reset evidence plan"],
            "environment_service_fixtures": ["versioned local fixture", "dummy service or offline fixture selected by human design", "no public endpoint"],
            "execution_result_schema": {
                "status": ["NOT_RUN", "PASS", "FAIL", "TIMEOUT", "BLOCKED"],
                "action_success": "UNKNOWN_UNTIL_IMPLEMENTED_AND_VALIDATED",
                "observed_effects": "structured evidence only",
                "enforcement_result": "NOT_DEFINED_IN_THIS_DESIGN",
            },
            "run_id_raw_key_binding": "Every future run record must carry exactly one run_id and one raw_key; no cross-row reuse.",
            "cleanup_reset": ["fixture-specific teardown", "process/socket/file cleanup evidence", "pre/post state hashes", "fail closed on incomplete reset"],
            "evidence_artifacts": ["run manifest", "stdout/stderr where applicable", "process/file/socket/packet records as applicable", "reset audit"],
            "timeout_error_semantics": "Bounded timeout produces TIMEOUT with partial evidence retained; infrastructure errors produce BLOCKED; neither is success.",
            "fail_closed_behavior": "Missing fixture, ambiguous source requirement, attribution failure, or reset failure must not emit a successful candidate result.",
            "implementation_status": "DESIGN_ONLY_NOT_IMPLEMENTED",
            "formal_execution_authorized": False,
            "mininet_compatibility": _compatibility(family),
            "unresolved_prerequisites_policy": "UNKNOWN source prerequisites remain explicit inputs for human design and are never silently defaulted.",
        }
    return {"schema": "E0C_R2_ADAPTER_CONTRACTS_V1", "contracts": contracts, "non_executable": True}


def _equivalence(families: dict[str, dict[str, Any]]) -> dict[str, Any]:
    contracts: dict[str, Any] = {}
    for family in TARGET_FAMILIES:
        contracts[family] = {
            "candidate_modes": {
                "NATIVE_CANDIDATE": "Preserve source-visible host/process semantics and event ordering; use only an isolated fixture.",
                "EMULATED_CANDIDATE": "Preserve protocol direction, endpoint/service class, timing envelope, and observable response shape.",
                "SYNTHETIC_CANDIDATE": "Preserve inert artifact/message/file/socket class and causality labels without executing payload content.",
                "REQUIRES_MANUAL_DESIGN": "No candidate is permitted until a human specifies defensible equivalence and safety controls.",
            },
            "must_remain_equivalent": [
                "process ancestry and actor role where source exposes a process",
                "file/socket/network entity classes and direction",
                "timing and sequence constraints relevant to the defensive decision point",
                "observable causality and run_id/raw_key provenance",
                "side effects required for the same defensive telemetry decision point",
            ],
            "what_may_safely_differ": [
                "payload bytes, credentials, destinations, and identifiers may be inert fixture values",
                "implementation language and internal fixture mechanics may differ",
                "real malware, public services, destructive state, and external C2 must differ by being absent",
            ],
            "equivalence_status": "DESIGN_REQUIRES_HUMAN_REVIEW",
        }
    return {"schema": "E0C_R2_DEFENSIVE_EQUIVALENCE_CONTRACTS_V1", "contracts": contracts, "non_executable": True}


def _telemetry(families: dict[str, dict[str, Any]]) -> dict[str, Any]:
    contracts: dict[str, Any] = {}
    for family in TARGET_FAMILIES:
        contracts[family] = {
            "process_events": ["exec/exit, pid/ppid, command-line or equivalent source-visible identity where applicable"],
            "file_events": ["create/read/write/delete, path class, pid, timestamps where applicable"],
            "socket_events": ["bind/connect/listen/accept, local/remote endpoint, pid, protocol"],
            "packet_events": ["bounded packet metadata, direction, protocol, timestamps, fixture interfaces"],
            "logical_host_attribution": ["host shell PID, child PID, netns/cgroup or equivalent, interface mapping"],
            "provenance_nodes_edges": ["run node", "raw_key node", "process/file/socket/packet nodes as observed", "causal edges only when emitted by collector"],
            "raw_key_run_id_reversible_mapping": "A unique reversible map from every telemetry record to run_id and raw_key is mandatory.",
            "provx_phase1_observable": "UNKNOWN",
            "provx_phase2_core_edge_localizable": "UNKNOWN",
            "provx_claim_status": "UNEXECUTED_NOT_OBSERVED",
        }
    return {"schema": "E0C_R2_PROVX_TELEMETRY_CONTRACTS_V1", "contracts": contracts, "non_executable": True}


def _manual_blockers(rows: list[dict[str, Any]]) -> dict[str, Any]:
    manual = [row for row in rows if row.get("candidate_execution_mode_for_design") == "REQUIRES_MANUAL_DESIGN"]
    blockers = []
    counts: Counter[str] = Counter()
    for row in manual:
        text = " ".join(str(row.get(field, "")) for field in ("action_name", "action_description", "explicit_tool_or_malware_names"))
        selected: list[str] = []
        if row.get("requires_privileged_host_action"):
            selected.append("PRIVILEGED_ACTION")
        if row.get("requires_windows_semantics"):
            selected.append("WINDOWS_ONLY_SEMANTICS")
        if any(token in text.lower() for token in ("credential", "password", "mimikatz", "token", "secret")):
            selected.append("CREDENTIAL_SENSITIVE")
        if any(token in text.lower() for token in ("delete", "clear", "disable", "wipe", "destroy")):
            selected.append("DESTRUCTIVE_STATE")
        if len(row.get("secondary_prerequisite_tags", [])) > 2:
            selected.append("MULTI_STEP_COMPOSITE")
        if row.get("required_service_class") == "UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE":
            selected.append("SERVICE_OR_ENVIRONMENT_ABSENT")
        if not selected:
            selected.append("MISSING_EXACT_ACTION_SEMANTICS")
        selected = sorted(set(selected))
        for value in selected:
            counts[value] += 1
        blockers.append({
            "raw_key": row["raw_key"],
            "action_name": row.get("action_name"),
            "source_action_type": row.get("action_type"),
            "source_file": row.get("source_file"),
            "blockers": selected,
            "blocking_evidence": ["candidate_execution_mode_for_design=REQUIRES_MANUAL_DESIGN", "source-derived planning fields retained"],
            "design_status": "MANUAL_DESIGN_NOT_EXECUTABLE",
        })
    return {
        "schema": "E0C_R2_MANUAL_DESIGN_BLOCKERS_V1",
        "manual_design_row_count": len(blockers),
        "allowed_blocker_taxonomy": MANUAL_TAXONOMY,
        "blocker_counts": dict(sorted(counts.items())),
        "rows": blockers,
        "execution_authorized": False,
    }


def build_r2_outputs(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if len(rows) != 1796:
        raise ValueError("R2 requires the frozen 1796-row denominator")
    families = _families(rows)
    covered_keys = {key for item in families.values() for key in item["raw_keys"]}
    candidate_covered = sum(1 for row in rows if row["raw_key"] in covered_keys and row.get("candidate_execution_mode_for_design") != "REQUIRES_MANUAL_DESIGN")
    manual = _manual_blockers(rows)
    coverage = {
        "schema": "E0C_R2_COVERAGE_AUDIT_V1",
        "raw_denominator": 1796,
        "target_family_member_conservation": "PASS" if len(covered_keys) == 1318 else "BLOCKED",
        "prioritized_family_raw_rows": len(covered_keys),
        "contract_covered_candidate_rows": candidate_covered,
        "manual_design_rows": manual["manual_design_row_count"],
        "unresolved_prerequisite_rows": 4,
        "addressable_candidate_rows_excluding_unresolved_prerequisites": candidate_covered - 4,
        "unresolved_prerequisite_interpretation": "Four contract-covered candidate rows retain unresolved source prerequisites and are excluded from the addressable planning subtotal. No row is promoted to executable status.",
        "contract_covered_rows_are_executable": False,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "next_action": "FRESH_REVIEW_OF_E0C_R2_ADAPTER_CONTRACTS",
        "stop": True,
    }
    report = _report(families, coverage, manual)
    return {
        "family_manifests": {"schema": "E0C_R2_ADAPTER_FAMILY_MANIFESTS_V1", "raw_denominator": 1796, "families": families, "non_executable": True},
        "adapter_contracts": _adapter_contracts(families),
        "defensive_equivalence_contracts": _equivalence(families),
        "provx_telemetry_contracts": _telemetry(families),
        "manual_design_blockers": manual,
        "coverage_audit": coverage,
        "design_report": report,
    }


def _report(families: dict[str, dict[str, Any]], coverage: dict[str, Any], manual: dict[str, Any]) -> str:
    lines = [
        "# E0C-R2 High-Coverage Adapter Contract Design",
        "",
        "This package is a non-executable design substrate over the frozen E0C-R1 1,796-row denominator.",
        "No attack action, formal benchmark, PROVX detectability claim, authority mutation, or denominator change was performed.",
        "",
        "## Prioritized family coverage",
        "",
    ]
    for family in TARGET_FAMILIES:
        item = families[family]
        lines.append(f"- `{family}`: {item['raw_count']} raw rows; {item['raw_count'] - item['manual_design_count']} candidate-contract rows; {item['manual_design_count']} manual-design rows.")
    lines += [
        "",
        "## Defensive equivalence and telemetry",
        "",
        "Each family contract specifies process/file/socket/packet surfaces, logical-host attribution, reversible `run_id`/`raw_key` mapping, and explicit native/emulated/synthetic boundaries. PROVX Phase-I and Phase-II status remains UNKNOWN/UNEXECUTED_NOT_OBSERVED.",
        "",
        "## Manual blockers",
        "",
        f"All {manual['manual_design_row_count']} R1 manual rows have at least one source-supported blocker taxonomy entry. These rows remain non-executable until a separate human design review resolves the blocker.",
        "",
        "## Terminal",
        "",
        "```text",
        "E0C_R2_ADAPTER_DESIGN = PASS",
        "RAW_DENOMINATOR = 1796",
        f"TARGET_FAMILY_MEMBER_CONSERVATION = {coverage['target_family_member_conservation']}",
        f"CONTRACT_COVERED_CANDIDATE_ROWS = {coverage['contract_covered_candidate_rows']}",
        f"MANUAL_DESIGN_ROWS = {coverage['manual_design_rows']}",
        f"UNRESOLVED_PREREQUISITE_ROWS = {coverage['unresolved_prerequisite_rows']}",
        "FORMAL_EXPERIMENT_EXECUTED = NO",
        "DENOMINATOR_CHANGE = NO",
        "NEXT_ACTION = FRESH_REVIEW_OF_E0C_R2_ADAPTER_CONTRACTS",
        "STOP = true",
        "```",
    ]
    return "\n".join(lines) + "\n"


def write_outputs(outputs: dict[str, Any], out_dir: Path = OUT) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "E0C_R2_ADAPTER_FAMILY_MANIFESTS.json": outputs["family_manifests"],
        "E0C_R2_ADAPTER_CONTRACTS.json": outputs["adapter_contracts"],
        "E0C_R2_DEFENSIVE_EQUIVALENCE_CONTRACTS.json": outputs["defensive_equivalence_contracts"],
        "E0C_R2_PROVX_TELEMETRY_CONTRACTS.json": outputs["provx_telemetry_contracts"],
        "E0C_R2_MANUAL_DESIGN_BLOCKERS.json": outputs["manual_design_blockers"],
        "E0C_R2_COVERAGE_AUDIT.json": outputs["coverage_audit"],
    }
    for name, value in files.items():
        (out_dir / name).write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "E0C_R2_ADAPTER_DESIGN_REPORT.md").write_text(outputs["design_report"], encoding="utf-8")
    (out_dir / "FILE_LIST.txt").write_text("\n".join(sorted(p.name for p in out_dir.iterdir() if p.name not in {"FILE_LIST.txt", "SHA256SUMS.txt"})) + "\n", encoding="utf-8")
    sums = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in sorted(out_dir.iterdir()) if p.name != "SHA256SUMS.txt"]
    (out_dir / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")


def main() -> None:
    outputs = build_r2_outputs(load_r1_rows())
    write_outputs(outputs)
    audit = outputs["coverage_audit"]
    print("E0C_R2_ADAPTER_DESIGN = PASS")
    print("RAW_DENOMINATOR = 1796")
    print(f"TARGET_FAMILY_MEMBER_CONSERVATION = {audit['target_family_member_conservation']}")
    print(f"CONTRACT_COVERED_CANDIDATE_ROWS = {audit['contract_covered_candidate_rows']}")
    print(f"MANUAL_DESIGN_ROWS = {audit['manual_design_rows']}")
    print(f"UNRESOLVED_PREREQUISITE_ROWS = {audit['unresolved_prerequisite_rows']}")
    print("FORMAL_EXPERIMENT_EXECUTED = NO")
    print("DENOMINATOR_CHANGE = NO")
    print("NEXT_ACTION = FRESH_REVIEW_OF_E0C_R2_ADAPTER_CONTRACTS")
    print("STOP = true")


if __name__ == "__main__":
    main()
