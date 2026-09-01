#!/usr/bin/env python3
"""Build the evidence-only E0C-R8 exact12 structured review packet.

R8 consumes the authenticated R6/R7 artifacts and never infers semantics from
free text.  It produces deterministic value distributions and candidate split
evidence, but it cannot create a human decision, apply a split, or authorize
execution.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


EXPECTED_TEMPLATE_COUNT = 12
EXPECTED_RAW_COVERAGE = 203
EXPECTED_BLOCKED_COUNT = 31
PINNED_REVIEW_COMMIT = "107ef9f69a734a10b320d552cfe18a6cb9a2ac0c"
MANUAL_STATUS = "MANUAL_DESIGN_REQUIRED"
CLASSIFICATION = "CANDIDATE_FOR_SHARED_HUMAN_TEMPLATE"
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
UNKNOWN = "UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE"

_TELEMETRY_KEYS = (
    "requires_file_telemetry",
    "requires_host_process_telemetry",
    "requires_socket_telemetry",
    "requires_network_fabric",
    "requires_external_service_emulation",
)


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
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _key_commitment(keys: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(str(key) for key in keys)).encode("utf-8")).hexdigest()


def _json_value(value: Any) -> str:
    """Canonical grouping value; empty/unknown values remain explicitly UNKNOWN."""
    if value is None or value == "" or value == [] or value == {}:
        return UNKNOWN
    if isinstance(value, str):
        return value or UNKNOWN
    if isinstance(value, (list, tuple, set)):
        values = [_json_value(item) for item in value]
        values = sorted(set(values))
        # A collection made entirely from unresolved source values carries no
        # authenticated grouping value.  Keep it as the scalar sentinel rather
        # than serializing it (for example, ["UNKNOWN"]), which would later be
        # mistaken for a known value.  Mixed collections retain their exact
        # canonical JSON so any known source evidence remains visible; their
        # UNKNOWN evidence is counted conservatively by _is_unknown().
        return UNKNOWN if not values or all(_is_unknown(item) for item in values) else json.dumps(values, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, Mapping):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def _is_unknown(value: Any) -> bool:
    """Return whether a canonical value contains unresolved source evidence.

    Canonical mixed collections are JSON strings.  Parse only JSON arrays so a
    mixed collection such as ["HTTP", "UNKNOWN"] preserves its known value
    while remaining UNKNOWN-bearing for coverage and split eligibility.
    """
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    if value == UNKNOWN or value == "UNKNOWN" or value.startswith("UNKNOWN"):
        return True
    if value.startswith("[") and value.endswith("]"):
        try:
            members = json.loads(value)
        except json.JSONDecodeError:
            return False
        if not isinstance(members, list):
            return False
        return not members or any(_is_unknown(member) for member in members)
    return False


def _provenance_flag(ref: Mapping[str, Any], key: str) -> str:
    # Presence of a R1 provenance entry is the only authenticated positive
    # evidence.  Absence is not treated as FALSE: it is UNKNOWN.
    provenance = ref.get("source_field_provenance")
    if not isinstance(provenance, Mapping) or key not in provenance:
        return UNKNOWN
    return "STRUCTURED_EVIDENCE_PRESENT"


def _exact_ref_map(packet: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    refs = packet.get("exact_source_evidence_references")
    if not isinstance(refs, list):
        raise ValueError(f"missing exact source references: {packet.get('template_id')}")
    result: dict[str, Mapping[str, Any]] = {}
    for ref in refs:
        if not isinstance(ref, Mapping):
            raise ValueError(f"malformed source reference: {packet.get('template_id')}")
        raw_key = str(ref.get("raw_key") or "")
        if not raw_key or raw_key in result:
            raise ValueError(f"duplicate/missing source reference key: {packet.get('template_id')}")
        result[raw_key] = ref
    return result


def _authenticate_inputs(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Mapping[str, Any]]]:
    tranche_path = root / R6_TRANCHE_FILE
    packets_path = root / R6_PACKETS_FILE
    r6_auth_path = root / R6_AUTH_FILE
    blocked_path = root / R6_BLOCKED_FILE
    r7_auth_path = root / R7_AUTH_FILE
    r7_decision_path = root / R7_DECISION_FILE
    status_path = root / R3_STATUS_FILE
    paths = [tranche_path, packets_path, r6_auth_path, blocked_path, r7_auth_path, r7_decision_path, status_path]
    for path in paths:
        if not path.is_file():
            raise ValueError(f"missing authenticated input: {path.name}")

    tranche = _load_json(tranche_path)
    packets = _load_jsonl(packets_path)
    r6_auth = _load_json(r6_auth_path)
    blocked = _load_json(blocked_path)
    r7_auth = _load_json(r7_auth_path)
    decision = _load_json(r7_decision_path)
    statuses = _load_jsonl(status_path)

    if tranche.get("template_ids") != EXPECTED_TEMPLATE_IDS or tranche.get("template_count") != EXPECTED_TEMPLATE_COUNT:
        raise ValueError("R6 exact12 template selection drifted")
    if tranche.get("raw_coverage") != EXPECTED_RAW_COVERAGE:
        raise ValueError("R6 exact12 raw coverage drifted")
    if tranche.get("human_decisions_created") != 0 or tranche.get("status_mutations") != 0:
        raise ValueError("R6 tranche contains mutation metadata")

    packet_by_id = {str(packet.get("template_id")): packet for packet in packets}
    if len(packet_by_id) != len(packets):
        raise ValueError("duplicate R6 packet IDs")
    status_by_key: dict[str, Mapping[str, Any]] = {}
    for row in statuses:
        key = str(row.get("raw_key") or "")
        if not key or key in status_by_key:
            raise ValueError("duplicate/missing R3 status key")
        status_by_key[key] = row

    blocked_rows = blocked.get("rows")
    if not isinstance(blocked_rows, list) or len(blocked_rows) != EXPECTED_BLOCKED_COUNT:
        raise ValueError("blocked31 input is not exact")
    blocked_keys = {str(row.get("raw_key")) for row in blocked_rows if isinstance(row, Mapping)}
    if len(blocked_keys) != EXPECTED_BLOCKED_COUNT:
        raise ValueError("blocked31 keys are not unique")
    blocked_commitment = blocked.get("blocked_set_commitment", {})
    if isinstance(blocked_commitment, Mapping) and blocked_commitment.get("sha256"):
        if blocked_commitment.get("sha256") != _key_commitment(blocked_keys):
            raise ValueError("blocked31 member commitment drifted")
    if r6_auth.get("human_decisions_created") != 0 or r6_auth.get("status_mutations") != 0 or r6_auth.get("denominator_change") != "NO":
        raise ValueError("R6 authentication contains mutation metadata")
    if r6_auth.get("blocked_count") not in (None, EXPECTED_BLOCKED_COUNT):
        raise ValueError("R6 blocked count drifted")
    if r6_auth.get("review_batch_template_ids"):
        review_batch_ids = [str(item) for item in r6_auth["review_batch_template_ids"]]
        if not set(EXPECTED_TEMPLATE_IDS).issubset(review_batch_ids):
            raise ValueError("R6 review batch template IDs do not contain exact12")

    selected: list[dict[str, Any]] = []
    all_keys: list[str] = []
    seen: set[str] = set()
    member_auth: list[dict[str, Any]] = []
    tranche_templates = tranche.get("templates")
    if not isinstance(tranche_templates, list) or len(tranche_templates) != EXPECTED_TEMPLATE_COUNT:
        raise ValueError("R6 exact12 tranche templates are incomplete")
    tranche_by_id = {str(item.get("template_id")): item for item in tranche_templates if isinstance(item, Mapping)}
    if set(tranche_by_id) != set(EXPECTED_TEMPLATE_IDS):
        raise ValueError("R6 exact12 tranche template IDs drifted")
    for template_id in EXPECTED_TEMPLATE_IDS:
        packet = packet_by_id.get(template_id)
        if packet is None:
            raise ValueError(f"missing selected R6 packet: {template_id}")
        if packet.get("classification") != CLASSIFICATION or packet.get("r3_global_planning_status") != MANUAL_STATUS:
            raise ValueError(f"selected packet classification/status drifted: {template_id}")
        if packet.get("human_decision") is not None or packet.get("human_decisions_created") != 0:
            raise ValueError(f"selected packet contains a human decision: {template_id}")
        if packet.get("status_mutations") != 0 or packet.get("formal_execution_authorized") is not False:
            raise ValueError(f"selected packet contains mutation/authorization: {template_id}")
        keys = [str(key) for key in packet.get("member_keys", [])]
        if not keys or len(keys) != int(packet.get("member_count", -1)):
            raise ValueError(f"member count drifted: {template_id}")
        sha = _key_commitment(keys)
        tranche_item = tranche_by_id[template_id]
        tranche_keys = [str(key) for key in tranche_item.get("member_keys", [])]
        if sorted(tranche_keys) != sorted(keys):
            raise ValueError(f"R6 tranche/packet member set drifted: {template_id}")
        tranche_commitment = tranche_item.get("member_key_commitment", {})
        if not isinstance(tranche_commitment, Mapping) or tranche_commitment.get("sha256") != sha:
            raise ValueError(f"R6 tranche member commitment drifted: {template_id}")
        if tranche_item.get("r3_global_planning_status") != MANUAL_STATUS:
            raise ValueError(f"R6 tranche member status drifted: {template_id}")
        commitment = packet.get("member_key_commitment", {})
        if not isinstance(commitment, Mapping) or commitment.get("sha256") != sha:
            raise ValueError(f"member commitment drifted: {template_id}")
        refs = _exact_ref_map(packet)
        if sorted(refs) != sorted(keys):
            raise ValueError(f"exact source references do not cover members: {template_id}")
        overlap = seen.intersection(keys)
        if overlap:
            raise ValueError(f"selected template member overlap: {template_id}")
        if set(keys).intersection(blocked_keys):
            raise ValueError(f"blocked31 member included: {template_id}")
        for key in keys:
            row = status_by_key.get(key)
            if row is None or row.get("global_planning_status") != MANUAL_STATUS:
                raise ValueError(f"member status drifted: {key}")
        selected.append(dict(packet))
        all_keys.extend(keys)
        seen.update(keys)
        member_auth.append({
            "template_id": template_id,
            "member_count": len(keys),
            "member_set_sha256": sha,
            "member_keys": sorted(keys),
            "r3_global_planning_status": MANUAL_STATUS,
            "exact_source_reference_count": len(refs),
            "exact_source_reference_coverage": "PASS",
            "status_mutations": 0,
        })

    if len(all_keys) != EXPECTED_RAW_COVERAGE or len(seen) != EXPECTED_RAW_COVERAGE:
        raise ValueError("exact12 union is not 203 unique raw actions")
    if r7_auth.get("template_ids") != EXPECTED_TEMPLATE_IDS or r7_auth.get("raw_coverage") != EXPECTED_RAW_COVERAGE:
        raise ValueError("R7 authentication does not pin exact12")
    if r7_auth.get("human_decisions_created") != 0 or r7_auth.get("status_mutations") != 0:
        raise ValueError("R7 authentication contains mutation metadata")
    if decision.get("template_ids") != EXPECTED_TEMPLATE_IDS or decision.get("raw_coverage") != EXPECTED_RAW_COVERAGE:
        raise ValueError("R7 decision packet selection drifted")
    if decision.get("human_decisions_created") != 0 or decision.get("status_mutations") != 0:
        raise ValueError("R7 decision packet contains mutation metadata")
    decision_templates = decision.get("templates")
    if not isinstance(decision_templates, list) or len(decision_templates) != EXPECTED_TEMPLATE_COUNT:
        raise ValueError("R7 decision packet template list is incomplete")
    if {str(item.get("template_id")) for item in decision_templates if isinstance(item, Mapping)} != set(EXPECTED_TEMPLATE_IDS):
        raise ValueError("R7 decision packet template IDs drifted")
    for item in decision_templates:
        if item.get("decision") is not None or item.get("human_decision") is not None:
            raise ValueError("R7 decision packet contains a non-null decision")
    r7_member_auth = {str(item.get("template_id")): item for item in r7_auth.get("template_member_authentication", []) if isinstance(item, Mapping)}
    if set(r7_member_auth) != set(EXPECTED_TEMPLATE_IDS):
        raise ValueError("R7 member authentication is incomplete")
    for item in member_auth:
        prior = r7_member_auth[item["template_id"]]
        if prior.get("member_count") != item["member_count"] or prior.get("member_set_sha256") != item["member_set_sha256"] or sorted(prior.get("member_keys", [])) != item["member_keys"]:
            raise ValueError(f"R7 member authentication drifted: {item['template_id']}")

    # R7's recorded authenticated input hashes bind the R6 files used here.
    r7_hashes = {str(item.get("file")): str(item.get("sha256")) for item in r7_auth.get("authenticated_inputs", []) if isinstance(item, Mapping)}
    for path in (tranche_path, packets_path):
        expected_hash = r7_hashes.get(path.name)
        if expected_hash and expected_hash != _sha256_file(path):
            raise ValueError(f"R7 authenticated hash mismatch: {path.name}")

    auth = {
        "schema_version": "e0c-r8-input-authentication-v1",
        "pinned_review_commit": PINNED_REVIEW_COMMIT,
        "pinned_review_commit_verification": "DECLARED_BY_R8_PROMPT; COMMIT_NOT_PRESENT_IN_LOCAL_WORKTREE",
        "authenticated_inputs": [
            {"file": R6_TRANCHE_FILE, "sha256": _sha256_file(tranche_path), "role": "exact12_tranche"},
            {"file": R6_PACKETS_FILE, "sha256": _sha256_file(packets_path), "role": "exact89_enriched_packets"},
            {"file": R7_AUTH_FILE, "sha256": _sha256_file(r7_auth_path), "role": "R7_exact12_authentication"},
            {"file": R7_DECISION_FILE, "sha256": _sha256_file(r7_decision_path), "role": "R7_null_decision_packet"},
        ],
        "authenticated_supporting_inputs": [
            {"file": R6_AUTH_FILE, "sha256": _sha256_file(r6_auth_path), "role": "R6_pinned_state"},
            {"file": R6_BLOCKED_FILE, "sha256": _sha256_file(blocked_path), "role": "blocked31_exclusion"},
            {"file": R3_STATUS_FILE, "sha256": _sha256_file(status_path), "role": "per_member_manual_status"},
        ],
        "template_ids": EXPECTED_TEMPLATE_IDS,
        "template_count": EXPECTED_TEMPLATE_COUNT,
        "raw_coverage": EXPECTED_RAW_COVERAGE,
        "union_raw_key_count": len(seen),
        "union_member_key_sha256": _key_commitment(all_keys),
        "template_member_overlap": 0,
        "member_set_drift": 0,
        "blocked_member_overlap": 0,
        "template_member_authentication": member_auth,
        "exact_12_template_authentication": "PASS",
        "exact_union_coverage": "PASS",
        "all_members_manual_design_required": "PASS",
        "human_decisions_created": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "authority_mutation": "NO",
    }
    return auth, selected, status_by_key


# Public aliases make the authentication and analysis stages convenient for
# tests and downstream evidence tooling while retaining the private helpers.
authenticate_inputs = _authenticate_inputs


def _member_structured_values(packet: Mapping[str, Any]) -> list[dict[str, Any]]:
    refs = _exact_ref_map(packet)
    env_values = packet.get("environment_prerequisites", {}).get("per_raw_authenticated_values", [])
    env_by_key = {str(value.get("raw_key")): value for value in env_values if isinstance(value, Mapping)}
    rows: list[dict[str, Any]] = []
    for raw_key in sorted(refs):
        ref = refs[raw_key]
        fields = ref.get("exact_source_fields", {})
        if not isinstance(fields, Mapping):
            fields = {}
        provenance = ref.get("source_field_provenance", {})
        if not isinstance(provenance, Mapping):
            provenance = {}
        env = env_by_key.get(raw_key, {})
        if not isinstance(env, Mapping):
            env = {}
        named = fields.get("r1_named_protocols_or_services", [UNKNOWN])
        required_protocol = fields.get("r1_required_protocol", UNKNOWN)
        required_service = fields.get("r1_required_service_class", UNKNOWN)
        prerequisites = fields.get("r1_service_prerequisites", [UNKNOWN])
        source_required = ("action_name", "action_description", "action_type", "os")
        source_complete = all(fields.get(name) not in (None, "") for name in source_required) and bool(ref.get("source_action_sha256")) and bool(ref.get("source_file_sha256")) and bool(ref.get("source_locator"))
        telemetry = {key: _provenance_flag(ref, key) for key in _TELEMETRY_KEYS}
        host_reqs = {
            key: telemetry[key]
            for key in ("requires_host_process_telemetry", "requires_file_telemetry", "requires_socket_telemetry", "requires_network_fabric")
        }
        destructive = _provenance_flag(ref, "destructive_state") if "destructive_state" in provenance else UNKNOWN
        reset = packet.get("reset_safety_complexity", {}).get("level", UNKNOWN)
        rows.append({
            "raw_key": raw_key,
            "source_action_type": _json_value(fields.get("action_type")),
            "os_platform": _json_value(fields.get("os")),
            "explicit_protocol_service": _json_value(named),
            "explicit_required_protocol": _json_value(required_protocol),
            "explicit_required_service_class": _json_value(required_service),
            "service_prerequisites": _json_value(prerequisites),
            "telemetry_surface_flags": _json_value(telemetry),
            "host_process_file_socket_network_requirements": _json_value(host_reqs),
            "destructive_state_flag": destructive,
            "reset_safety_complexity": _json_value(reset),
            "environment_blocker": _json_value(env.get("environment_blockers", [UNKNOWN])),
            "source_detail_completeness": "COMPLETE" if source_complete else "INCOMPLETE",
            "controlled_environment_feasibility": _json_value(packet.get("environment_prerequisites", {}).get("controlled_environment_feasibility", UNKNOWN)),
        })
    return rows


def _field_distribution(rows: list[Mapping[str, Any]], field: str) -> dict[str, Any]:
    groups: dict[str, list[str]] = {}
    for row in rows:
        value = str(row.get(field, UNKNOWN))
        groups.setdefault(value, []).append(str(row["raw_key"]))
    members_per_value = []
    for value in sorted(groups):
        keys = sorted(groups[value])
        members_per_value.append({
            "value": value,
            "member_count": len(keys),
            "member_keys": keys,
            "member_key_sha256": _key_commitment(keys),
        })
    unknown_count = sum(1 for row in rows if _is_unknown(str(row.get(field, UNKNOWN))))
    groups_list = members_per_value
    return {
        "member_count": len(rows),
        "distinct_value_count": len(groups),
        "distinct_values": [group["value"] for group in groups_list],
        "unknown_member_count": unknown_count,
        "known_member_count": len(rows) - unknown_count,
        "unknown_fraction": unknown_count / len(rows) if rows else 0.0,
        "coverage": {
            "known_member_count": len(rows) - unknown_count,
            "unknown_member_count": unknown_count,
            "known_fraction": (len(rows) - unknown_count) / len(rows) if rows else 0.0,
        },
        "members_per_value": groups_list,
        "members_by_value": groups_list,
    }


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


def _candidate_splits(template_id: str, member_rows: list[Mapping[str, Any]], distributions: Mapping[str, Any]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for field in STRUCTURED_FIELDS:
        distribution = distributions[field]
        known_groups = [group for group in distribution["members_per_value"] if not _is_unknown(group["value"])]
        # UNKNOWN is not an authenticated split boundary.  A candidate is
        # emitted only when the exact field partitions every member into at
        # least two known, non-empty groups, so union conservation is true.
        if len(known_groups) < 2 or distribution["unknown_member_count"]:
            continue
        union_keys = [key for group in known_groups for key in group["member_keys"]]
        candidates.append({
            "template_id": template_id,
            "split_basis_field": field,
            "exact_values": [group["value"] for group in known_groups],
            "groups": known_groups,
            "exact_member_groups": known_groups,
            "union_member_count": len(union_keys),
            "union_member_key_sha256": _key_commitment(union_keys),
            "union_conservation": len(union_keys) == len(set(union_keys)) == len(member_rows),
            "overlap": 0,
            "status": "EVIDENCE_ONLY_NOT_APPLIED",
            "applied": False,
        })
    return {
        "template_id": template_id,
        "candidate_split_status": "STRUCTURED_SPLIT_EVIDENCE_AVAILABLE" if candidates else "NO_STRUCTURED_SPLIT_EVIDENCE",
        "candidate_splits": candidates,
        "candidate_split_count": len(candidates),
    }


def _build_template_analysis(packet: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    member_rows = _member_structured_values(packet)
    distributions = {field: _field_distribution(member_rows, field) for field in STRUCTURED_FIELDS}
    split = _candidate_splits(str(packet["template_id"]), member_rows, distributions)
    unknown_total = sum(item["unknown_member_count"] for item in distributions.values())
    heterogeneous_fields = [field for field, item in distributions.items() if item["distinct_value_count"] > 1]
    analysis = {
        "template_id": str(packet["template_id"]),
        "member_count": len(member_rows),
        "member_keys": sorted(row["raw_key"] for row in member_rows),
        "member_set_sha256": _key_commitment(row["raw_key"] for row in member_rows),
        "structured_fields": distributions,
        "field_distributions": distributions,
        "unknown_burden": {
            "unknown_cell_count": unknown_total,
            "field_count": len(STRUCTURED_FIELDS),
            "unknown_fraction": unknown_total / (len(STRUCTURED_FIELDS) * len(member_rows)) if member_rows else 0.0,
        },
        "heterogeneous_field_count": len(heterogeneous_fields),
        "heterogeneous_fields": heterogeneous_fields,
        "candidate_split_count": split["candidate_split_count"],
        "candidate_split_status": split["candidate_split_status"],
        "evidence_only": True,
    }
    return analysis, split


def build_structured_heterogeneity(packets: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Public pure helper for deterministic structured heterogeneity output."""
    analyses = []
    for packet in packets:
        analysis, _ = _build_template_analysis(packet)
        analyses.append(analysis)
    return {
        "schema_version": "e0c-r8-exact12-structured-heterogeneity-v1",
        "template_count": len(analyses),
        "raw_coverage": sum(item["member_count"] for item in analyses),
        "templates": analyses,
        "evidence_only": True,
        "applied_splits": 0,
    }


def build_candidate_split_evidence(packets: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Public pure helper returning one evidence record per template."""
    result = []
    for packet in packets:
        analysis, split = _build_template_analysis(packet)
        # Keep a commitment in the line even when the caller supplies a
        # packet outside the pinned exact12 set; this is useful for fixtures.
        split["member_set_sha256"] = analysis["member_set_sha256"]
        result.append(split)
    return result


def _review_complexity(analysis: Mapping[str, Any]) -> dict[str, Any]:
    unknown_fraction = float(analysis["unknown_burden"]["unknown_fraction"])
    hetero = int(analysis["heterogeneous_field_count"])
    split_count = int(analysis["candidate_split_count"])
    # A deterministic aid only; it is deliberately not a recommendation.
    if unknown_fraction >= 0.5 or hetero >= 5:
        level = "HIGH"
    elif unknown_fraction > 0 or hetero > 1:
        level = "MEDIUM"
    else:
        level = "LOW"
    return {
        "template_id": analysis["template_id"],
        "member_count": analysis["member_count"],
        "heterogeneous_field_count": hetero,
        "unknown_cell_count": analysis["unknown_burden"]["unknown_cell_count"],
        "unknown_fraction": unknown_fraction,
        "candidate_split_count": split_count,
        "deterministic_review_complexity_level": level,
        "interpretation": "REVIEW_AID_ONLY_NOT_AN_APPROVE_REJECT_OR_SPLIT_RECOMMENDATION",
    }


def _value_label(value: str) -> str:
    return value if len(value) <= 180 else value[:177] + "..."


def _sheets(analyses: list[Mapping[str, Any]], packets: Mapping[str, Mapping[str, Any]]) -> str:
    lines = [
        "# E0C-R8 Structured Cohesion Review Sheets",
        "",
        "Evidence-only support for exactly 12 authenticated templates covering exactly 203 raw actions. No decision or split is selected.",
        "",
        "Allowed human actions: `" + "`, `".join(ALLOWED_DECISIONS) + "`. The decision remains null.",
        "",
    ]
    for analysis in analyses:
        tid = str(analysis["template_id"])
        packet = packets[tid]
        lines.extend([f"## {tid}", "", f"- Members: `{analysis['member_count']}`; member-set SHA256: `{analysis['member_set_sha256']}`", f"- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.", f"- Strongest structured heterogeneity evidence: `{analysis['heterogeneous_fields'] or 'NONE'}`", f"- UNKNOWN burden: `{analysis['unknown_burden']['unknown_cell_count']}` cells (`{analysis['unknown_burden']['unknown_fraction']:.3f}` of structured cells)", f"- Candidate split evidence: `{analysis['candidate_split_status']}` (`{analysis['candidate_split_count']}` candidates)", f"- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `{MANUAL_STATUS}`.", "- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8."])
        reps = packet.get("representative_raw_source_snippets", [])
        lines.append("- Representative authenticated source evidence:")
        for item in reps[:3]:
            snippet = item.get("exact_source_snippet", {}) if isinstance(item, Mapping) else {}
            lines.append(f"  - `{item.get('raw_key')}`: action name `{_value_label(str(snippet.get('action_name', 'UNKNOWN')))}`, type `{snippet.get('action_type', 'UNKNOWN')}`, OS `{snippet.get('os', 'UNKNOWN')}`; source `{item.get('source_file')}#{item.get('source_locator')}`")
        lines.append("- Structured field distributions:")
        for field, dist in analysis["structured_fields"].items():
            compact = "; ".join(f"{_value_label(str(g['value']))}={g['member_count']}" for g in dist["members_per_value"])
            lines.append(f"  - `{field}`: {compact}")
        lines.extend(["", "Decision: `null` (awaiting explicit human action).", ""])
    lines.extend(["R8_BOUNDARY = EVIDENCE_ONLY_NOT_APPLIED", "HUMAN_DECISIONS_CREATED = 0", "APPLIED_SPLITS = 0", "STATUS_MUTATIONS = 0", "STOP = true", ""])
    return "\n".join(lines)


def _decision_packet(auth: Mapping[str, Any], analyses: list[Mapping[str, Any]], splits: list[Mapping[str, Any]], packets: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    by_id = {str(item["template_id"]): item for item in splits}
    templates = []
    for analysis in analyses:
        tid = str(analysis["template_id"])
        templates.append({
            "template_id": tid,
            "member_keys": list(analysis["member_keys"]),
            "member_count": analysis["member_count"],
            "member_set_sha256": analysis["member_set_sha256"],
            "structured_evidence_reference": f"E0C_R8_EXACT12_STRUCTURED_HETEROGENEITY.json#{tid}",
            "candidate_split_evidence_reference": f"E0C_R8_EXACT12_CANDIDATE_SPLIT_EVIDENCE.jsonl#{tid}",
            "candidate_split_status": by_id[tid]["candidate_split_status"],
            "decision": None,
            "human_decision": None,
            "human_origin": None,
            "decision_options": list(ALLOWED_DECISIONS),
            "r3_global_planning_status": MANUAL_STATUS,
            "formal_execution_authorized": False,
            "status_mutations": 0,
            "denominator_change": "NO",
            "member_expansion": False,
            "member_expansion_authorized": False,
        })
    return {
        "schema_version": "e0c-r8-human-decision-packet-v1",
        "authority_mutation": "NO",
        "pinned_review_commit": PINNED_REVIEW_COMMIT,
        "template_ids": list(auth["template_ids"]),
        "template_count": EXPECTED_TEMPLATE_COUNT,
        "raw_coverage": EXPECTED_RAW_COVERAGE,
        "allowed_decisions": list(ALLOWED_DECISIONS),
        "human_decision_options": list(ALLOWED_DECISIONS),
        "templates": templates,
        "human_decisions_created": 0,
        "applied_splits": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "review_gate": "AWAITING_EXPLICIT_HUMAN_TEMPLATE_DECISIONS | BLOCKED",
        "next_action": "FRESH_REVIEW_OF_E0C_R8_STRUCTURED_HUMAN_REVIEW_SUPPORT",
        "stop": True,
    }


def build_outputs(root: Path = Path(".")) -> dict[str, Any]:
    auth, packets_list, _ = _authenticate_inputs(root)
    packets = {str(packet["template_id"]): packet for packet in packets_list}
    analyses: list[dict[str, Any]] = []
    splits: list[dict[str, Any]] = []
    complexity: list[dict[str, Any]] = []
    for template_id in EXPECTED_TEMPLATE_IDS:
        analysis, split = _build_template_analysis(packets[template_id])
        analyses.append(analysis)
        splits.append(split)
        complexity.append(_review_complexity(analysis))
    decision_packet = _decision_packet(auth, analyses, splits, packets)
    return {
        "input_authentication": auth,
        "structured_heterogeneity": {
            "schema_version": "e0c-r8-exact12-structured-heterogeneity-v1",
            "template_count": EXPECTED_TEMPLATE_COUNT,
            "raw_coverage": EXPECTED_RAW_COVERAGE,
            "templates": analyses,
            "evidence_only": True,
            "applied_splits": 0,
        },
        "candidate_split_evidence": splits,
        "review_complexity": {
            "schema_version": "e0c-r8-exact12-review-complexity-v1",
            "template_count": EXPECTED_TEMPLATE_COUNT,
            "raw_coverage": EXPECTED_RAW_COVERAGE,
            "templates": complexity,
            "review_aid_only": True,
        },
        "decision_support_sheets": _sheets(analyses, packets),
        "decision_packet": decision_packet,
    }


def write_outputs(root: Path, outputs: Mapping[str, Any]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "E0C_R8_INPUT_AUTHENTICATION.json").write_text(json.dumps(outputs["input_authentication"], ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    (root / "E0C_R8_EXACT12_STRUCTURED_HETEROGENEITY.json").write_text(json.dumps(outputs["structured_heterogeneity"], ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    with (root / "E0C_R8_EXACT12_CANDIDATE_SPLIT_EVIDENCE.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in outputs["candidate_split_evidence"]:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    (root / "E0C_R8_EXACT12_REVIEW_COMPLEXITY.json").write_text(json.dumps(outputs["review_complexity"], ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    (root / "E0C_R8_HUMAN_DECISION_SUPPORT_SHEETS.md").write_text(str(outputs["decision_support_sheets"]), encoding="utf-8", newline="\n")
    (root / "E0C_R8_HUMAN_DECISION_PACKET.json").write_text(json.dumps(outputs["decision_packet"], ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    (root / "E0C_R8_STRUCTURED_COHESION_REVIEW_REPORT.md").write_text(_report(outputs), encoding="utf-8", newline="\n")


def _report(outputs: Mapping[str, Any]) -> str:
    auth = outputs["input_authentication"]
    splits = outputs["candidate_split_evidence"]
    with_evidence = sum(1 for item in splits if item["candidate_split_count"])
    lines = [
        "# E0C-R8 Structured Cohesion Review Support",
        "",
        "E0C_R8_STRUCTURED_HUMAN_REVIEW_SUPPORT = READY_FOR_EXPLICIT_HUMAN_TEMPLATE_DECISIONS",
        f"EXACT12_AUTHENTICATION = {auth['exact_12_template_authentication']}",
        f"TEMPLATE_COUNT = {auth['template_count']}",
        f"RAW_COVERAGE = {auth['raw_coverage']}",
        f"TEMPLATES_WITH_STRUCTURED_SPLIT_EVIDENCE = {with_evidence}",
        f"TEMPLATES_WITH_NO_STRUCTURED_SPLIT_EVIDENCE = {EXPECTED_TEMPLATE_COUNT - with_evidence}",
        "HUMAN_DECISIONS_CREATED = 0",
        "APPLIED_SPLITS = 0",
        "STATUS_MUTATIONS = 0",
        "FORMAL_EXPERIMENT_EXECUTED = NO",
        "DENOMINATOR_CHANGE = NO",
        "NEXT_ACTION =",
        "FRESH_REVIEW_OF_E0C_R8_STRUCTURED_HUMAN_REVIEW_SUPPORT",
        "STOP = true",
        "",
        "All structured fields are sourced from authenticated R4/R5/R6/R7 evidence; no embeddings, free-text semantic interpretation, or ATT&CK guesses were used.",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        outputs = build_outputs(args.root)
        write_outputs(args.root, outputs)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print("E0C_R8_STRUCTURED_HUMAN_REVIEW_SUPPORT = BLOCKED")
        print(f"ERROR = {error}")
        print("EXACT12_AUTHENTICATION = BLOCKED")
        print("TEMPLATE_COUNT = 12")
        print("RAW_COVERAGE = 203")
        print("HUMAN_DECISIONS_CREATED = 0")
        print("APPLIED_SPLITS = 0")
        print("STATUS_MUTATIONS = 0")
        print("FORMAL_EXPERIMENT_EXECUTED = NO")
        print("DENOMINATOR_CHANGE = NO")
        print("NEXT_ACTION = FRESH_REVIEW_OF_E0C_R8_STRUCTURED_HUMAN_REVIEW_SUPPORT")
        print("STOP = true")
        return 1
    report = _report(outputs)
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
