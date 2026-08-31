#!/usr/bin/env python3
"""Close global adapter coverage using the accepted R1/R2 planning artifacts."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


EXPECTED_RAW_COUNT = 1796
R1_FILE = "EXP_E0C_R1_1796_ENRICHED_READINESS.jsonl"
R1_AUDIT_FILE = "EXP_E0C_R1_CONSERVATION_AUDIT.json"
R2_MANIFEST_FILE = "E0C_R2_ADAPTER_FAMILY_MANIFESTS.json"
R2_CONTRACT_FILE = "E0C_R2_ADAPTER_CONTRACTS.json"
R2_EQUIVALENCE_FILE = "E0C_R2_DEFENSIVE_EQUIVALENCE_CONTRACTS.json"
R2_TELEMETRY_FILE = "E0C_R2_PROVX_TELEMETRY_CONTRACTS.json"
R2_COVERAGE_FILE = "E0C_R2_COVERAGE_AUDIT.json"
TARGET_FAMILIES = (
    "PROCESS_COMMAND_EXECUTION",
    "NETWORK_SERVICE_INTERACTION",
    "TRANSFER_DOWNLOAD_UPLOAD",
    "EMAIL_DELIVERY",
    "NETWORK_C2_BEACON",
)
REMAINING_FAMILIES = (
    "ARCHIVE_COMPRESSION",
    "CREDENTIAL_STORE_ACCESS",
    "DISCOVERY_ENUMERATION",
    "DNS_INTERACTION",
    "FILE_RESOURCE_OPERATION",
    "NETWORK_SCAN_ENUMERATION",
    "PERSISTENCE_CONFIGURATION",
    "PRIVILEGE_ACCOUNT_ACTION",
)
ALL_FAMILIES = TARGET_FAMILIES + REMAINING_FAMILIES
TARGET_COUNTS = {
    "PROCESS_COMMAND_EXECUTION": 712,
    "NETWORK_SERVICE_INTERACTION": 232,
    "TRANSFER_DOWNLOAD_UPLOAD": 166,
    "EMAIL_DELIVERY": 105,
    "NETWORK_C2_BEACON": 103,
    "ARCHIVE_COMPRESSION": 9,
    "CREDENTIAL_STORE_ACCESS": 67,
    "DISCOVERY_ENUMERATION": 90,
    "DNS_INTERACTION": 5,
    "FILE_RESOURCE_OPERATION": 64,
    "NETWORK_SCAN_ENUMERATION": 62,
    "PERSISTENCE_CONFIGURATION": 101,
    "PRIVILEGE_ACCOUNT_ACTION": 80,
}
GLOBAL_STATUSES = (
    "CONTRACT_DESIGNED_READY_FOR_IMPLEMENTATION_PLANNING",
    "MANUAL_DESIGN_REQUIRED",
    "BLOCKED_UNRESOLVED_PREREQUISITE",
)
MANUAL_MODE = "REQUIRES_MANUAL_DESIGN"
UNKNOWN = "UNKNOWN"
UNRESOLVED_DEPENDENCY = "BLOCKED_UNRESOLVED_PREREQUISITE"

_COMMAND_RE = re.compile(r"(?:command|command\s+line|shell|powershell|\bcmd\b|\bbash\b|execute|run|script|命令|执行|脚本)", re.I)
_PRIVILEGE_RE = re.compile(r"(?:privilege|administrator|admin|root|uac|elevation|escalat|sudo|fodhelper|cmstplua|提权|管理员|权限)", re.I)
_CREDENTIAL_RE = re.compile(r"(?:credential|password|hash|cookie|keylog|mimikatz|凭证|密码|哈希|浏览器)", re.I)
_DESTRUCTIVE_RE = re.compile(r"(?:delete|wipe|format|destructive|disable|bypass|exploit|ransomware|恶意|删除|禁用|绕过|破坏|勒索)", re.I)
_AMBIGUOUS_RE = re.compile(r"(?:attempt|attempts|try|tries|may|might|could|potential|possibly|if|unknown|尝试|可能|或许|试图)", re.I)


def _json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected object in {path}")
    return value


def _jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"non-object row in {path}:{line_number}")
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


def _set_values(rows: list[dict[str, Any]], field: str) -> list[str]:
    values: set[str] = set()
    for row in rows:
        value = row.get(field, [UNKNOWN])
        if isinstance(value, list):
            values.update(str(item) for item in value)
        else:
            values.add(str(value))
    return sorted(values)


def _counts(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    values: list[str] = []
    for row in rows:
        value = row.get(field, [UNKNOWN])
        values.extend(str(item) for item in value) if isinstance(value, list) else values.append(str(value))
    return dict(sorted(Counter(values).items()))


def _family_rows(rows: list[dict[str, Any]], family: str) -> list[dict[str, Any]]:
    return sorted((row for row in rows if row.get("primary_execution_archetype") == family), key=lambda row: str(row["raw_key"]))


def _auth_r1(rows: list[dict[str, Any]]) -> dict[str, Any]:
    keys = [str(row.get("raw_key") or "") for row in rows]
    if len(rows) != EXPECTED_RAW_COUNT or len(set(keys)) != EXPECTED_RAW_COUNT or any(not key for key in keys):
        raise ValueError("R1 raw key set is not exactly 1796 unique keys")
    if any(row.get("formal_execution_authorized") is not False for row in rows):
        raise ValueError("R1 contains formally authorized row")
    if any(row.get("provx_phase1_observable") != UNKNOWN or row.get("provx_phase2_core_edge_localizable") != UNKNOWN for row in rows):
        raise ValueError("R1 PROVX boundary drift")
    family_counts = Counter(str(row.get("primary_execution_archetype")) for row in rows)
    if set(family_counts) != set(ALL_FAMILIES) or dict(family_counts) != TARGET_COUNTS:
        raise ValueError(f"R1 archetype counts drift: {dict(family_counts)}")
    return {
        "raw_record_count": len(rows),
        "unique_raw_key_count": len(set(keys)),
        "raw_key_set_sha256": _sha256_keys(sorted(keys)),
        "archetype_counts": dict(sorted(family_counts.items())),
        "formal_execution_authorized_false": True,
        "provx_boundary_unchanged": True,
    }


def _auth_r2(root: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    manifest = _json(root / R2_MANIFEST_FILE)
    contracts = _json(root / R2_CONTRACT_FILE)
    equivalence = _json(root / R2_EQUIVALENCE_FILE)
    telemetry = _json(root / R2_TELEMETRY_FILE)
    coverage = _json(root / R2_COVERAGE_FILE)
    if manifest.get("raw_denominator") != EXPECTED_RAW_COUNT or manifest.get("target_family_member_conservation") != "PASS":
        raise ValueError("R2 family manifest authority failed")
    if contracts.get("raw_denominator") != EXPECTED_RAW_COUNT or set(contracts.get("contracts", {})) != set(TARGET_FAMILIES):
        raise ValueError("R2 adapter contract authority failed")
    if equivalence.get("raw_denominator") != EXPECTED_RAW_COUNT or set(equivalence.get("contracts", {})) != set(TARGET_FAMILIES):
        raise ValueError("R2 defensive-equivalence contract authority failed")
    if telemetry.get("raw_denominator") != EXPECTED_RAW_COUNT or set(telemetry.get("contracts", {})) != set(TARGET_FAMILIES):
        raise ValueError("R2 PROVX telemetry contract authority failed")
    if coverage.get("raw_denominator") != EXPECTED_RAW_COUNT or coverage.get("target_family_member_conservation") != "PASS":
        raise ValueError("R2 coverage authority failed")
    r1_by_key = {str(row["raw_key"]): row for row in rows}
    manifest_keys: set[str] = set()
    commitment_matches = True
    for family in TARGET_FAMILIES:
        item = manifest.get("families", {}).get(family)
        if not isinstance(item, dict):
            raise ValueError(f"R2 manifest missing {family}")
        keys = [str(key) for key in item.get("raw_keys", [])]
        manifest_keys.update(keys)
        commitment_matches = commitment_matches and (
            item.get("raw_count") == TARGET_COUNTS[family]
            and len(keys) == TARGET_COUNTS[family]
            and len(set(keys)) == TARGET_COUNTS[family]
            and _sha256_keys(keys) == item.get("raw_key_set_commitment", {}).get("sha256")
            and set(keys) == {key for key, row in r1_by_key.items() if row.get("primary_execution_archetype") == family}
        )
        contract = contracts["contracts"].get(family, {})
        commitment_matches = commitment_matches and contract.get("applicable_raw_key_set_commitment", {}).get("sha256") == item.get("raw_key_set_commitment", {}).get("sha256")
    if not commitment_matches or len(manifest_keys) != 1318:
        raise ValueError("R2 family member commitments do not conserve 1318 rows")
    r2_manual = int(coverage.get("manual_design_rows", -1))
    r2_contract = int(coverage.get("contract_covered_candidate_rows", -1))
    r2_unresolved = int(coverage.get("unresolved_prerequisite_rows", -1))
    if (r2_contract, r2_manual, r2_unresolved) != (945, 589, 4):
        raise ValueError(f"unexpected R2 accounting {(r2_contract, r2_manual, r2_unresolved)}")
    unresolved_keys = set(coverage.get("unresolved_prerequisite_raw_keys", []))
    contract_keys = set(coverage.get("contract_covered_candidate_raw_keys", []))
    if not unresolved_keys.issubset(contract_keys) or len(unresolved_keys) != 4:
        raise ValueError("R2 unresolved rows are not a subset of contract rows")
    manual_all = {key for key, row in r1_by_key.items() if row.get("candidate_execution_mode_for_design") == MANUAL_MODE}
    target_manual = {key for key in manifest_keys if r1_by_key[key].get("candidate_execution_mode_for_design") == MANUAL_MODE}
    artifact_names = [R2_MANIFEST_FILE, R2_CONTRACT_FILE, R2_EQUIVALENCE_FILE, R2_TELEMETRY_FILE, R2_COVERAGE_FILE]
    return {
        "raw_denominator": EXPECTED_RAW_COUNT,
        "r2_target_family_rows": len(manifest_keys),
        "r2_contract_covered_rows": r2_contract,
        "r2_manual_design_rows": r2_manual,
        "r2_unresolved_prerequisite_rows": r2_unresolved,
        "r2_contract_rows_including_unresolved": len(contract_keys),
        "r2_manual_rows_inside_target_families": len(target_manual),
        "r2_manual_rows_outside_target_families": len(manual_all - target_manual),
        "r2_unresolved_is_subset_of_contract_rows": True,
        "r2_unresolved_raw_keys": sorted(unresolved_keys),
        "r2_authenticated_artifact_count": len(artifact_names),
        "r2_authenticated_artifacts": [{"path": name, "sha256": _sha256_file(root / name), "status": "PASS"} for name in artifact_names],
        "explanation": "R2 contract-covered rows (945) include the 4 unresolved prerequisite rows; R2 manual-design rows (589) span all 13 R1 families, so these reported figures overlap and are not an exhaustive disjoint partition.",
        "r1_r2_authority": "PASS",
    }


def load_inputs(root: Path = Path(".")) -> dict[str, Any]:
    rows = _jsonl(root / R1_FILE)
    r1_auth = _auth_r1(rows)
    r1_audit = _json(root / R1_AUDIT_FILE)
    if (
        r1_audit.get("exp_e0c_r1_conservation") != "PASS_1796"
        or r1_audit.get("raw_record_count") != EXPECTED_RAW_COUNT
        or r1_audit.get("unique_raw_key_count") != EXPECTED_RAW_COUNT
        or r1_audit.get("execution_archetype_count") != len(ALL_FAMILIES)
        or r1_audit.get("all_rows_formal_execution_authorized_false") is not True
    ):
        raise ValueError("R1 conservation audit authority failed")
    r1_auth["r1_conservation_audit_authenticated"] = True
    r1_auth["r1_conservation_audit_sha256"] = _sha256_file(root / R1_AUDIT_FILE)
    r2_auth = _auth_r2(root, rows)
    return {"root": root, "r1_rows": rows, "r1_authentication": r1_auth, "r2_authentication": r2_auth}


def _dependency(family: str, rows: list[dict[str, Any]]) -> tuple[str, str]:
    manual_fraction = sum(row.get("candidate_execution_mode_for_design") == MANUAL_MODE for row in rows) / max(len(rows), 1)
    if manual_fraction >= 0.75:
        return "MANUAL_ONLY", "Manual-design burden dominates this family; no family-wide implementation contract should bypass review."
    if family in {"PROCESS_COMMAND_EXECUTION", "DISCOVERY_ENUMERATION", "PERSISTENCE_CONFIGURATION", "PRIVILEGE_ACCOUNT_ACTION", "FILE_RESOURCE_OPERATION"}:
        return "WAIT_FOR_WINDOWS_OR_SERVICE_ENVIRONMENT", "Host semantics or platform-specific services must be validated before implementation planning."
    if family in {"NETWORK_C2_BEACON", "NETWORK_SCAN_ENUMERATION"}:
        return "WAIT_FOR_MININET_PROVENANCE_COLLECTOR", "Network-to-host attribution and reversible provenance are prerequisites for this family."
    if family == "NETWORK_SERVICE_INTERACTION":
        return "WAIT_FOR_PROVX_SCHEMA", "Service telemetry can be fixture-designed, but its future artifact schema must be fixed before collector integration."
    return "CAN_IMPLEMENT_BEFORE_PROVX_COLLECTOR", "The family can specify inert fixtures and reset behavior before collector implementation."


def _contract_layers(family: str, rows: list[dict[str, Any]], dependency: str) -> dict[str, Any]:
    modes = sorted({str(row.get("candidate_execution_mode_for_design")) for row in rows})
    flags = {
        "network": any(row.get("requires_network_fabric") for row in rows),
        "process": any(row.get("requires_host_process_telemetry") for row in rows),
        "file": any(row.get("requires_file_telemetry") for row in rows),
        "socket": any(row.get("requires_socket_telemetry") for row in rows),
        "service": any(row.get("requires_external_service_emulation") for row in rows),
        "windows": any(row.get("requires_windows_semantics") for row in rows),
        "linux": any(row.get("requires_linux_semantics") for row in rows),
    }
    return {
        "inputs": ["run_id", "raw_key", "source action type", "OS/platform hint", "source protocol/service prerequisites", "approved inert fixture profile", "telemetry correlation context"],
        "roles": {"source_roles": _set_values(rows, "source_node_role"), "target_roles": _set_values(rows, "target_node_role"), "logical_host_attribution": "UNKNOWN unless later authenticated provenance establishes it"},
        "preconditions": ["raw_key is in the committed family member set", "unique run_id is bound before any future implementation", "required fixture and reset plan are approved", "unresolved prerequisites route to BLOCKED_UNRESOLVED_PREREQUISITE", "manual-design rows route to MANUAL_DESIGN_REQUIRED", "formal_execution_authorized remains false"],
        "fixtures": {"policy": "isolated inert Mininet or offline fixtures only; no public targets or real malware", "os_platform_hints": _set_values(rows, "os_platform_hints"), "service_or_protocol_prerequisites": _set_values(rows, "service_prerequisites"), "telemetry_surfaces": _set_values(rows, "provx_candidate_observation_surface"), "requirements": flags},
        "result_schema": {"status": ["NOT_EXECUTED", "PLANNED", "BLOCKED", "ERROR"], "run_id": "string", "raw_key": "exact committed raw_key", "telemetry_artifact_refs": "list, empty before execution", "error_code": "nullable controlled code", "formal_outcome": "UNEXECUTED_NOT_OBSERVED"},
        "run_id_raw_key_binding": {"canonical_fields": ["run_id", "raw_key", "adapter_id"], "fingerprint": "sha256(length-prefixed canonical fields)", "reversible": True, "collision_policy": "fail closed"},
        "cleanup_reset": ["record reset plan first", "remove only inert fixture artifacts", "verify topology/service/process/file/socket state returns to baseline"],
        "evidence_artifacts": ["run manifest", "fixture/topology manifest", "timestamped telemetry index", "reset verification", "controlled error record"],
        "timeout_error_semantics": {"timeout": "BLOCKED or ERROR with controlled timeout code; never infer outcome", "missing_fixture": "BLOCKED", "missing_telemetry": "BLOCKED and equivalence claim invalid", "unexpected_state": "ERROR and reset review required"},
        "fail_closed_behavior": ["reject raw_key outside commitment", "reject missing/reused run_id", "reject unresolved mandatory prerequisites", "never execute manual-design rows", "never infer PROVX detection/localization from absent telemetry"],
        "defensive_equivalence": {"process_ancestry": "preserve process ancestry class where applicable", "file_entity_classes": "preserve source-indicated file operation/entity class", "socket_entity_classes": "preserve source-indicated socket class and direction", "network_direction_protocol": "preserve source-derived direction and explicit protocol/service class", "timing_sequence_constraints": "preserve source ordering and coarse timing relationships", "observable_causality": "preserve the causal chain needed for the defensive telemetry surface without fabricating edges", "side_effects_for_decision_point": "retain only inert side effects needed for equivalent telemetry", "what_may_safely_differ": ["payload bytes and secrets", "public endpoints and exploitability", "destructive effects", "exact wall-clock values", "fixture identifiers with reversible mapping"], "candidate_modes": modes},
        "provx_telemetry": {"process_events": flags["process"], "file_events": flags["file"], "socket_events": flags["socket"], "packet_events": flags["network"], "logical_host_attribution": "required as a future field; currently UNKNOWN", "provenance_nodes_edges": {"nodes": ["run", "raw_action", "logical_host", "fixture", "telemetry_artifact"], "edges": ["run_applies_to_raw_action", "fixture_emits_telemetry", "telemetry_observed_on_logical_host"], "observed": False}, "raw_key_run_id_reversible_mapping": "required; canonical fields plus integrity fingerprint", "provx_phase1_observable": UNKNOWN, "provx_phase2_core_edge_localizable": UNKNOWN, "result_status": "UNEXECUTED_NOT_OBSERVED"},
        "mininet_compatibility": "MANUAL_DESIGN" if dependency == "MANUAL_ONLY" else "REQUIRES_WINDOWS_OR_SERVICE_ENVIRONMENT" if dependency == "WAIT_FOR_WINDOWS_OR_SERVICE_ENVIRONMENT" else "REQUIRES_HOST_PROVENANCE_VALIDATION" if dependency == "WAIT_FOR_MININET_PROVENANCE_COLLECTOR" else "PLAIN_MININET_CANDIDATE",
    }


def build_remaining_contracts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    families: dict[str, Any] = {}
    for family in REMAINING_FAMILIES:
        members = _family_rows(rows, family)
        keys = [str(row["raw_key"]) for row in members]
        dependency, dependency_basis = _dependency(family, members)
        layers = _contract_layers(family, members, dependency)
        families[family] = {
            "adapter_id": f"adapter::{family.lower()}",
            "adapter_version": "0.1.0-design",
            "primary_execution_archetype": family,
            "raw_count": len(members),
            "raw_keys": keys,
            "raw_key_set_commitment": {"algorithm": "sha256", "canonical_order": "lexicographic raw_key joined with LF", "sha256": _sha256_keys(keys)},
            "candidate_raw_keys": [key for key, row in zip(keys, members) if row.get("candidate_execution_mode_for_design") != MANUAL_MODE],
            "manual_design_raw_keys": [key for key, row in zip(keys, members) if row.get("candidate_execution_mode_for_design") == MANUAL_MODE],
            "playbooks_covered": sorted({str(row["playbook_id"]) for row in members}),
            "stages_covered": sorted({f"{row['playbook_id']}::S{int(row['stage_index']):02d}" for row in members}),
            "os_platform_hints": _set_values(members, "os_platform_hints"),
            "service_or_protocol_prerequisites": _set_values(members, "service_prerequisites"),
            "candidate_execution_modes": _counts(members, "candidate_execution_mode_for_design"),
            "dependency_classification": dependency,
            "dependency_basis": dependency_basis,
            **layers,
            "implementation_status": "DESIGN_ONLY_NOT_IMPLEMENTED",
            "formal_execution_authorized": False,
        }
    return {"schema_version": "e0c-r3-remaining-8-family-contracts-v1", "raw_denominator": EXPECTED_RAW_COUNT, "remaining_family_count": 8, "families": families}


def _status_for_row(row: Mapping[str, Any]) -> tuple[str, list[str], str]:
    if row.get("candidate_execution_mode_for_design") == MANUAL_MODE:
        return MANUAL_MODE, [], "R1 candidate mode explicitly requires manual design"
    if row.get("requires_external_service_emulation") and row.get("service_prerequisites") == [UNKNOWN]:
        return UNRESOLVED_DEPENDENCY, ["external_service_emulation", "service_or_protocol_prerequisite"], "External service emulation is required but no source-derived service/protocol prerequisite is resolved"
    return GLOBAL_STATUSES[0], [], "A family contract exists and no unresolved prerequisite or manual-design marker blocks implementation planning"


def build_global_status(rows: list[dict[str, Any]], all_contracts: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    contract_families = set(TARGET_FAMILIES) | set(REMAINING_FAMILIES)
    status_rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for row in sorted(rows, key=lambda item: str(item["raw_key"])):
        family = str(row["primary_execution_archetype"])
        status, unresolved, rationale = _status_for_row(row)
        global_status = status if status != MANUAL_MODE else "MANUAL_DESIGN_REQUIRED"
        counts[global_status] += 1
        status_rows.append({
            "raw_key": row["raw_key"],
            "playbook_id": row["playbook_id"],
            "stage_index": row["stage_index"],
            "source_file": row["source_file"],
            "source_locator": row["source_locator"],
            "primary_execution_archetype": family,
            "adapter_id": f"adapter::{family.lower()}",
            "contract_exists_for_family": family in contract_families,
            "contract_exists_for_row": family in contract_families,
            "r1_candidate_execution_mode": row["candidate_execution_mode_for_design"],
            "global_planning_status": global_status,
            "status_membership": [global_status],
            "current_implementation_prerequisite_status": "UNRESOLVED" if unresolved else "RESOLVED_FOR_PLANNING" if status != MANUAL_MODE else "MANUAL_REVIEW_REQUIRED",
            "unresolved_prerequisites": unresolved,
            "status_rationale": rationale,
            "formal_execution_authorized": False,
            "provx_phase1_observable": UNKNOWN,
            "provx_phase2_core_edge_localizable": UNKNOWN,
            "result_status": "UNEXECUTED_NOT_OBSERVED",
        })
    return status_rows, dict((status, counts[status]) for status in GLOBAL_STATUSES)


def _priority(rows: list[dict[str, Any]], dependencies: Mapping[str, str]) -> dict[str, Any]:
    families: list[dict[str, Any]] = []
    for family in ALL_FAMILIES:
        members = _family_rows(rows, family)
        manual = sum(row.get("candidate_execution_mode_for_design") == MANUAL_MODE for row in members)
        blocked = sum(_status_for_row(row)[0] == UNRESOLVED_DEPENDENCY for row in members)
        candidate = len(members) - manual
        families.append({
            "primary_execution_archetype": family,
            "adapter_id": f"adapter::{family.lower()}",
            "raw_count": len(members),
            "candidate_rows": candidate,
            "manual_design_rows": manual,
            "blocked_unresolved_prerequisite_rows": blocked,
            "playbook_count": len({row["playbook_id"] for row in members}),
            "dependency_classification": dependencies[family],
            "priority_basis": "coverage, playbook reuse, Mininet compatibility, OS/dependency availability, PROVX telemetry suitability, and manual burden; not scoring weight",
        })
    families.sort(key=lambda item: (-item["candidate_rows"], -item["raw_count"], -item["playbook_count"], item["manual_design_rows"], item["primary_execution_archetype"]))
    for index, item in enumerate(families, 1):
        item["priority_rank"] = index
    return {"schema_version": "e0c-r3-implementation-priority-v1", "raw_denominator": EXPECTED_RAW_COUNT, "family_count": len(families), "priority_order": families}


def build_outputs(inputs: Mapping[str, Any]) -> dict[str, Any]:
    rows = list(inputs["r1_rows"])
    remaining = build_remaining_contracts(rows)
    # R2 contracts are authenticated as existing family-level contracts; R3
    # status logic treats all 13 families as contract-designed at the family
    # level and gates individual rows by manual/prerequisite state.
    dependencies = {}
    for family in ALL_FAMILIES:
        family_rows = _family_rows(rows, family)
        dependencies[family] = _dependency(family, family_rows)[0]
    status_rows, status_counts = build_global_status(rows, remaining["families"])
    reconciliation = dict(inputs["r2_authentication"])
    reconciliation.update({"r1_authentication": inputs["r1_authentication"], "remaining_family_rows": sum(TARGET_COUNTS[f] for f in REMAINING_FAMILIES), "remaining_family_counts": {f: TARGET_COUNTS[f] for f in REMAINING_FAMILIES}, "r2_global_status_overlap_warning": True})
    reconciliation["r1_conservation_audit_authenticated"] = inputs["r1_authentication"]["r1_conservation_audit_authenticated"]
    reconciliation["r1_conservation_audit_sha256"] = inputs["r1_authentication"]["r1_conservation_audit_sha256"]
    overlap = 0
    missing = EXPECTED_RAW_COUNT - sum(status_counts.values())
    coverage = {
        "schema_version": "e0c-r3-global-coverage-audit-v1",
        "raw_denominator": EXPECTED_RAW_COUNT,
        "contract_designed_count": status_counts[GLOBAL_STATUSES[0]],
        "manual_design_required_count": status_counts[GLOBAL_STATUSES[1]],
        "blocked_unresolved_prerequisite_count": status_counts[GLOBAL_STATUSES[2]],
        "global_status_sum": sum(status_counts.values()),
        "global_status_overlap": overlap,
        "global_status_missing": missing,
        "global_status_counts": status_counts,
        "target_family_rows": sum(TARGET_COUNTS[f] for f in TARGET_FAMILIES),
        "remaining_family_rows": sum(TARGET_COUNTS[f] for f in REMAINING_FAMILIES),
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "binding_authority_mutation": "NO",
        "scoring_authority_mutation": "NO",
        "all_rows_formal_execution_authorized_false": all(row["formal_execution_authorized"] is False for row in status_rows),
        "provx_observability_claim": "NONE; all phase fields remain UNKNOWN and result status remains UNEXECUTED_NOT_OBSERVED",
        "next_action": "FRESH_REVIEW_OF_E0C_R3_GLOBAL_ADAPTER_COVERAGE",
        "stop": True,
    }
    priority = _priority(rows, dependencies)
    report_lines = [
        "# EXP-E0C-R3 Global Adapter Coverage Closure", "", "Global planning closure derived from authenticated R1 and R2 artifacts. No actions are executed.", "",
        "## Terminal State", "",
        f"- `E0C_R3_GLOBAL_ADAPTER_COVERAGE = {'PASS_1796' if missing == 0 and overlap == 0 else 'BLOCKED'}`",
        f"- `CONTRACT_DESIGNED_COUNT = {coverage['contract_designed_count']}`",
        f"- `MANUAL_DESIGN_REQUIRED_COUNT = {coverage['manual_design_required_count']}`",
        f"- `BLOCKED_UNRESOLVED_PREREQUISITE_COUNT = {coverage['blocked_unresolved_prerequisite_count']}`",
        f"- `GLOBAL_STATUS_SUM = {coverage['global_status_sum']}`",
        f"- `GLOBAL_STATUS_OVERLAP = {coverage['global_status_overlap']}`",
        f"- `GLOBAL_STATUS_MISSING = {coverage['global_status_missing']}`",
        "- `FORMAL_EXPERIMENT_EXECUTED = NO`", "- `DENOMINATOR_CHANGE = NO`", "- `NEXT_ACTION = FRESH_REVIEW_OF_E0C_R3_GLOBAL_ADAPTER_COVERAGE`", "- `STOP = true`", "",
        "## R2 Accounting Reconciliation", "",
        "R2's 945 contract-covered rows include its 4 unresolved prerequisite rows. R2's 589 manual-design rows span the full R1 corpus, including 373 target-family rows and 216 rows outside the five R2 target families. Therefore 945, 589, and 4 overlap and must not be summed as a partition.", "",
        "## Global Status Policy", "",
        "Each raw receives exactly one status: manual-design markers take precedence; otherwise unresolved external-service prerequisites become BLOCKED_UNRESOLVED_PREREQUISITE; all other rows are CONTRACT_DESIGNED_READY_FOR_IMPLEMENTATION_PLANNING. R1 candidate fidelity remains in `r1_candidate_execution_mode`.", "",
        "| Status | Count |", "|---|---:|",
        f"| `CONTRACT_DESIGNED_READY_FOR_IMPLEMENTATION_PLANNING` | {coverage['contract_designed_count']} |",
        f"| `MANUAL_DESIGN_REQUIRED` | {coverage['manual_design_required_count']} |",
        f"| `BLOCKED_UNRESOLVED_PREREQUISITE` | {coverage['blocked_unresolved_prerequisite_count']} |", "",
        "## Remaining Eight Families", "",
        "The remaining-family contract artifact contains exact member commitments and the same non-executable input, role, prerequisite, fixture, result, evidence, reset, fail-closed, defensive-equivalence, PROVX telemetry, and Mininet compatibility layers used for R2.", "",
        "## Priority", "",
        "Priority uses coverage, reuse, Mininet compatibility, OS/dependency availability, PROVX telemetry suitability, and manual burden. It does not use scoring weight.", "",
        "| Rank | Family | Raw rows | Candidate | Manual | Blocked | Dependency |", "|---:|---|---:|---:|---:|---:|---|",
    ]
    for item in priority["priority_order"]:
        report_lines.append(f"| {item['priority_rank']} | `{item['primary_execution_archetype']}` | {item['raw_count']} | {item['candidate_rows']} | {item['manual_design_rows']} | {item['blocked_unresolved_prerequisite_rows']} | {item['dependency_classification']} |")
    report_lines.extend(["", "## Boundaries", "", "No action execution, command implementation, formal outcome, PROVX detection/localization claim, binding/scoring mutation, or denominator change occurred. `STOP = true`", ""])
    return {
        "r2_accounting_reconciliation": reconciliation,
        "remaining_8_family_contracts": remaining,
        "global_planning_status_rows": status_rows,
        "global_coverage_audit": coverage,
        "implementation_priority": priority,
        "global_coverage_report": "\n".join(report_lines),
    }


def build_r3_outputs(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Public compatibility name used by the R3 verification suite."""
    return build_outputs(inputs)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")


def write_outputs(root: Path, outputs: Mapping[str, Any]) -> None:
    _write_json(root / "E0C_R3_R2_ACCOUNTING_RECONCILIATION.json", outputs["r2_accounting_reconciliation"])
    _write_json(root / "E0C_R3_REMAINING_8_FAMILY_CONTRACTS.json", outputs["remaining_8_family_contracts"])
    status_path = root / "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl"
    status_path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in outputs["global_planning_status_rows"]), encoding="utf-8", newline="\n")
    _write_json(root / "E0C_R3_GLOBAL_COVERAGE_AUDIT.json", outputs["global_coverage_audit"])
    _write_json(root / "E0C_R3_IMPLEMENTATION_PRIORITY.json", outputs["implementation_priority"])
    (root / "E0C_R3_GLOBAL_ADAPTER_COVERAGE_REPORT.md").write_text(outputs["global_coverage_report"], encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        outputs = build_outputs(load_inputs(args.root))
        audit = outputs["global_coverage_audit"]
        if audit["global_status_sum"] != EXPECTED_RAW_COUNT or audit["global_status_overlap"] or audit["global_status_missing"]:
            raise ValueError("global status partition failed")
        write_outputs(args.root, outputs)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("E0C_R3_GLOBAL_ADAPTER_COVERAGE = BLOCKED")
        print(f"ERROR = {error}")
        print("RAW_DENOMINATOR = 1796")
        print("NEXT_ACTION = FIX_R3_AUTHORITY_OR_STATUS_DEFECT")
        print("STOP = true")
        return 1
    audit = outputs["global_coverage_audit"]
    print("E0C_R3_GLOBAL_ADAPTER_COVERAGE = PASS_1796")
    print(f"CONTRACT_DESIGNED_COUNT = {audit['contract_designed_count']}")
    print(f"MANUAL_DESIGN_REQUIRED_COUNT = {audit['manual_design_required_count']}")
    print(f"BLOCKED_UNRESOLVED_PREREQUISITE_COUNT = {audit['blocked_unresolved_prerequisite_count']}")
    print(f"GLOBAL_STATUS_SUM = {audit['global_status_sum']}")
    print(f"GLOBAL_STATUS_OVERLAP = {audit['global_status_overlap']}")
    print(f"GLOBAL_STATUS_MISSING = {audit['global_status_missing']}")
    print("FORMAL_EXPERIMENT_EXECUTED = NO")
    print("DENOMINATOR_CHANGE = NO")
    print("NEXT_ACTION = FRESH_REVIEW_OF_E0C_R3_GLOBAL_ADAPTER_COVERAGE")
    print("STOP = true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
