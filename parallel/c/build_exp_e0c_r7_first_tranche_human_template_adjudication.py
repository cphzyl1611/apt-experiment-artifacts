#!/usr/bin/env python3
"""Authenticate and present the E0C-R7 first human template-review tranche.

R7 is deliberately a pre-decision gate.  It reads the frozen R6 tranche and
enriched packet set, verifies their exact member authority, and emits only
decision-neutral review artifacts.  No human choice is inferred or created.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


EXPECTED_TEMPLATE_COUNT = 12
EXPECTED_RAW_COVERAGE = 203
EXPECTED_R6_PACKET_COUNT = 89
EXPECTED_BLOCKED_COUNT = 31
EXPECTED_MANUAL_RAW_COUNT = 589
EXPECTED_SHARED_COVERED_ROWS = 494
EXPECTED_RAW_SPECIFIC_COUNT = 64
PINNED_REVIEW_COMMIT = "ef9cc3cf7566cbe2280c29fcc1dde958cebf12d9"

R6_TRANCHE_FILE = "E0C_R6_FIRST_HUMAN_REVIEW_TRANCHE.json"
R6_PACKETS_FILE = "E0C_R6_EXACT89_ENRICHED_TEMPLATE_PACKETS.jsonl"
R6_AUTH_FILE = "E0C_R6_INPUT_AUTHENTICATION.json"
R6_BLOCKED_FILE = "E0C_R6_BLOCKED31_SOURCE_RECOVERY_RESULTS.json"
R3_STATUS_FILE = "E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl"

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


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path.name}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"expected JSON object at {path.name}:{line_number}")
            rows.append(value)
    return rows


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _key_commitment(keys: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(keys)).encode("utf-8")).hexdigest()


def _json_cell(value: Any, *, limit: int | None = None) -> str:
    """Render structured evidence compactly and safely inside a Markdown cell."""
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if limit is not None and len(text) > limit:
        text = text[: limit - 3] + "..."
    return text.replace("|", "\\|").replace("\n", "<br>")


def _source_evidence_summary(packet: Mapping[str, Any]) -> str:
    references = list(packet.get("exact_source_evidence_references", []))
    representatives = list(packet.get("representative_raw_source_snippets", []))
    parts = [f"{len(references)} authenticated exact member source references"]
    for item in representatives[:3]:
        snippet = item.get("exact_source_snippet", {}) if isinstance(item, Mapping) else {}
        name = snippet.get("action_name", "UNKNOWN")
        action_type = snippet.get("action_type", "UNKNOWN")
        platform = snippet.get("os", "UNKNOWN")
        parts.append(
            "raw={raw}; source={source}#{locator}; action={name}; type={kind}; os={os}; "
            "description={description}; source_action_sha256={action_sha}; source_file_sha256={file_sha}".format(
                raw=item.get("raw_key", "UNKNOWN"),
                source=item.get("source_file", "UNKNOWN"),
                locator=item.get("source_locator", "UNKNOWN"),
                name=name,
                kind=action_type,
                os=platform,
                description=str(snippet.get("action_description", "UNKNOWN")).replace("|", "\\|").replace("\n", " "),
                action_sha=item.get("source_action_sha256", "UNKNOWN"),
                file_sha=item.get("source_file_sha256", "UNKNOWN"),
            )
        )
    return "<br>".join(part.replace("|", "\\|") for part in parts)


def _environment_summary(packet: Mapping[str, Any]) -> dict[str, Any]:
    """Keep the table reviewable while retaining exact per-raw evidence in R6."""
    environment = packet.get("environment_prerequisites", {})
    known = environment.get("known_protocol_service_platform", {})
    per_raw = environment.get("per_raw_authenticated_values", [])
    blockers = sorted(
        {
            str(blocker)
            for item in per_raw
            if isinstance(item, Mapping)
            for blocker in item.get("environment_blockers", [])
        }
    )
    return {
        "controlled_environment_feasibility": environment.get("controlled_environment_feasibility", "UNKNOWN"),
        "formal_execution_authorized": environment.get("formal_execution_authorized", False),
        "required_os_or_host_class": known.get("required_os_or_host_class", []),
        "required_protocol": known.get("required_protocol", []),
        "required_service_class": known.get("required_service_class", []),
        "service_prerequisites": known.get("service_prerequisites", []),
        "environment_blockers": blockers,
        "unresolved_environment_fields": environment.get("unresolved_environment_fields", []),
        "per_raw_authenticated_values_count": len(per_raw),
    }


def _authenticate_inputs(root: Path) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], set[str]]:
    tranche_path = root / R6_TRANCHE_FILE
    packets_path = root / R6_PACKETS_FILE
    r6_auth_path = root / R6_AUTH_FILE
    blocked_path = root / R6_BLOCKED_FILE
    status_path = root / R3_STATUS_FILE

    tranche = _load_json(tranche_path)
    packets = _load_jsonl(packets_path)
    r6_auth = _load_json(r6_auth_path)
    blocked = _load_json(blocked_path)
    status_rows = _load_jsonl(status_path)

    pinned_r6_state = {
        "exact_manual_raw_count": EXPECTED_MANUAL_RAW_COUNT,
        "shared_template_count": EXPECTED_R6_PACKET_COUNT,
        "shared_template_covered_rows": EXPECTED_SHARED_COVERED_ROWS,
        "raw_specific_count": EXPECTED_RAW_SPECIFIC_COUNT,
        "blocked_count": EXPECTED_BLOCKED_COUNT,
        "human_decisions_created": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
    }
    for key, expected in pinned_r6_state.items():
        if r6_auth.get(key) != expected:
            raise ValueError(f"R6 pinned state drifted: {key}")
    if r6_auth.get("authority_mutation") != "NO":
        raise ValueError("R6 authority mutation boundary drifted")

    if tranche.get("template_count") != EXPECTED_TEMPLATE_COUNT:
        raise ValueError("R6 tranche template count is not exact12")
    if tranche.get("raw_coverage") != EXPECTED_RAW_COVERAGE:
        raise ValueError("R6 tranche raw coverage is not exact203")
    if tranche.get("human_decisions_created") != 0:
        raise ValueError("R6 tranche already contains a human decision")
    if tranche.get("status_mutations") != 0:
        raise ValueError("R6 tranche contains a status mutation")
    if tranche.get("formal_experiment_executed") != "NO":
        raise ValueError("R6 tranche formal-experiment boundary drifted")
    if tranche.get("denominator_change") != "NO":
        raise ValueError("R6 tranche denominator boundary drifted")
    template_ids = [str(item) for item in tranche.get("template_ids", [])]
    if len(template_ids) != EXPECTED_TEMPLATE_COUNT or len(set(template_ids)) != EXPECTED_TEMPLATE_COUNT:
        raise ValueError("R6 tranche template IDs are not exact and unique")
    if template_ids != EXPECTED_TEMPLATE_IDS:
        raise ValueError("R6 tranche template IDs differ from the pinned R7 first tranche")
    tranche_templates = tranche.get("templates", [])
    if not isinstance(tranche_templates, list) or len(tranche_templates) != EXPECTED_TEMPLATE_COUNT:
        raise ValueError("R6 tranche template records are not exact12")
    if [str(item.get("template_id")) for item in tranche_templates] != template_ids:
        raise ValueError("R6 tranche template order or IDs drifted")
    if len(packets) != EXPECTED_R6_PACKET_COUNT:
        raise ValueError("R6 enriched packet count is not exact89")
    packet_by_id: dict[str, Mapping[str, Any]] = {}
    for packet in packets:
        template_id = str(packet.get("template_id"))
        if template_id in packet_by_id:
            raise ValueError(f"duplicate R6 packet template ID: {template_id}")
        packet_by_id[template_id] = packet

    status_by_key = {str(row.get("raw_key")): row for row in status_rows}
    if len(status_by_key) != len(status_rows):
        raise ValueError("R3 status rows contain duplicate raw keys")
    blocked_rows = blocked.get("rows", [])
    if (
        blocked.get("exact31_conservation") != "PASS"
        or blocked.get("recovered_from_authenticated_existing_source") != 0
        or blocked.get("not_present_in_authenticated_existing_source") != EXPECTED_BLOCKED_COUNT
        or blocked.get("conflicting_existing_source_detail") != 0
        or blocked.get("blocked_count") != EXPECTED_BLOCKED_COUNT
        or len(blocked_rows) != EXPECTED_BLOCKED_COUNT
    ):
        raise ValueError("R6 blocked set is not exact31")
    blocked_keys = {str(row.get("raw_key")) for row in blocked_rows}
    if len(blocked_keys) != EXPECTED_BLOCKED_COUNT:
        raise ValueError("R6 blocked set has duplicate or missing raw keys")

    template_auth: list[dict[str, Any]] = []
    all_keys: list[str] = []
    overlap = 0
    drift = 0
    blocked_overlap = 0
    seen: set[str] = set()
    for tranche_template in tranche_templates:
        template_id = str(tranche_template.get("template_id"))
        packet = packet_by_id.get(template_id)
        if packet is None:
            raise ValueError(f"R6 enriched packet missing selected template: {template_id}")
        if packet.get("classification") != CLASSIFICATION:
            raise ValueError(f"selected packet classification drifted: {template_id}")
        tranche_keys = [str(key) for key in tranche_template.get("member_keys", [])]
        packet_keys = [str(key) for key in packet.get("member_keys", [])]
        if sorted(tranche_keys) != sorted(packet_keys):
            drift += 1
            raise ValueError(f"R6 tranche/packet member-set drift: {template_id}")
        commitment = packet.get("member_key_commitment", {})
        packet_sha = str(commitment.get("sha256", ""))
        expected_sha = _key_commitment(packet_keys)
        if packet_sha != expected_sha:
            raise ValueError(f"R6 member-set SHA256 mismatch: {template_id}")
        tranche_commitment = tranche_template.get("member_key_commitment", {}).get("sha256")
        if tranche_commitment != expected_sha:
            raise ValueError(f"R6 tranche member-set SHA256 mismatch: {template_id}")
        if packet.get("member_count") != len(packet_keys) or tranche_template.get("member_count") != len(packet_keys):
            raise ValueError(f"member count mismatch: {template_id}")
        if packet.get("r3_global_planning_status") != MANUAL_STATUS or tranche_template.get("r3_global_planning_status") != MANUAL_STATUS:
            raise ValueError(f"template status is not MANUAL_DESIGN_REQUIRED: {template_id}")
        if packet.get("human_decision") is not None or tranche_template.get("human_decision") is not None:
            raise ValueError(f"pre-decision input already contains a human decision: {template_id}")
        if list(packet.get("human_decision_options", [])) != ALLOWED_DECISIONS:
            raise ValueError(f"decision options drifted: {template_id}")
        if packet.get("human_decisions_created") != 0:
            raise ValueError(f"packet already contains a human decision: {template_id}")
        if packet.get("status_mutations") != 0 or tranche_template.get("status_mutations") != 0:
            raise ValueError(f"status mutation present: {template_id}")
        if packet.get("formal_execution_authorized") is not False or tranche_template.get("formal_execution_authorized") is not False:
            raise ValueError(f"formal execution authorization present: {template_id}")
        if packet.get("denominator_change") != "NO" or tranche_template.get("denominator_change") != "NO":
            raise ValueError(f"denominator change present: {template_id}")
        references = packet.get("exact_source_evidence_references")
        if not isinstance(references, list) or len(references) != len(packet_keys):
            raise ValueError(f"exact source evidence reference count drifted: {template_id}")
        reference_keys = [str(reference.get("raw_key")) for reference in references if isinstance(reference, Mapping)]
        if sorted(reference_keys) != sorted(packet_keys) or len(set(reference_keys)) != len(packet_keys):
            raise ValueError(f"exact source evidence references do not cover the member set: {template_id}")

        member_statuses: list[dict[str, Any]] = []
        for raw_key in packet_keys:
            status = status_by_key.get(raw_key)
            if status is None:
                raise ValueError(f"R3 status missing selected raw: {raw_key}")
            if status.get("global_planning_status") != MANUAL_STATUS:
                raise ValueError(f"selected member status drifted: {raw_key}")
            member_statuses.append({"raw_key": raw_key, "global_planning_status": MANUAL_STATUS})
        duplicate_keys = seen.intersection(packet_keys)
        overlap += len(duplicate_keys)
        blocked_overlap += len(set(packet_keys).intersection(blocked_keys))
        if duplicate_keys:
            raise ValueError(f"selected template member overlap: {template_id}")
        seen.update(packet_keys)
        all_keys.extend(packet_keys)
        template_auth.append(
            {
                "template_id": template_id,
                "member_count": len(packet_keys),
                "member_keys": sorted(packet_keys),
                "member_key_sha256": expected_sha,
                "member_set_sha256": expected_sha,
                "member_key_commitment": {
                    "algorithm": "sha256",
                    "canonical_order": "lexicographic raw_key joined with LF",
                    "sha256": expected_sha,
                },
                "r3_global_planning_status": MANUAL_STATUS,
                "member_status_checks": member_statuses,
                "status_mutations": 0,
                "formal_execution_authorized": False,
                "denominator_change": "NO",
                "exact_source_reference_count": len(references),
                "exact_source_reference_coverage": "PASS",
                "evidence_packet_hash": _canonical_sha256(packet),
            }
        )

    if len(all_keys) != EXPECTED_RAW_COVERAGE or len(seen) != EXPECTED_RAW_COVERAGE:
        raise ValueError("selected template union is not exact203 and unique")
    if blocked_overlap:
        raise ValueError("blocked31 rows were included in the selected tranche")

    auth = {
        "schema_version": "e0c-r7-first-tranche-input-authentication-v1",
        "authority_mutation": "NO",
        "pinned_review_commit": PINNED_REVIEW_COMMIT,
        "github_review_commit": PINNED_REVIEW_COMMIT,
        "pinned_review_commit_verification": "DECLARED_BY_R7_PROMPT; COMMIT_NOT_PRESENT_IN_LOCAL_WORKTREE",
        "authenticated_inputs": [
            {"file": R6_TRANCHE_FILE, "sha256": _sha256_file(tranche_path), "role": "authoritative_exact12_tranche"},
            {"file": R6_PACKETS_FILE, "sha256": _sha256_file(packets_path), "role": "authoritative_exact89_enriched_packets"},
        ],
        "authenticated_supporting_inputs": [
            {"file": R6_AUTH_FILE, "sha256": _sha256_file(r6_auth_path), "role": "R6_pinned_state"},
            {"file": R6_BLOCKED_FILE, "sha256": _sha256_file(blocked_path), "role": "blocked31_exclusion_check"},
            {"file": R3_STATUS_FILE, "sha256": _sha256_file(status_path), "role": "per_member_manual_status_check"},
        ],
        "r6_packet_count": len(packets),
        "exact_manual_raw_count": EXPECTED_MANUAL_RAW_COUNT,
        "shared_template_count": EXPECTED_R6_PACKET_COUNT,
        "shared_template_covered_rows": EXPECTED_SHARED_COVERED_ROWS,
        "raw_specific_count": EXPECTED_RAW_SPECIFIC_COUNT,
        "blocked_count": EXPECTED_BLOCKED_COUNT,
        "template_ids": template_ids,
        "template_count": EXPECTED_TEMPLATE_COUNT,
        "raw_coverage": EXPECTED_RAW_COVERAGE,
        "union_raw_key_count": len(seen),
        "union_raw_count": len(seen),
        "exact_union_raw_count": len(seen),
        "union_member_key_sha256": _key_commitment(all_keys),
        "template_member_overlap": overlap,
        "no_member_overlap": overlap == 0,
        "member_set_drift": drift,
        "no_member_set_drift": drift == 0,
        "member_set_drift_count": drift,
        "template_member_drift": drift,
        "blocked_member_overlap": blocked_overlap,
        "blocked_rows_included": blocked_overlap,
        "exact_12_template_authentication": "PASS",
        "exact_union_coverage": "PASS",
        "all_members_manual_design_required": "PASS",
        "template_member_authentication": template_auth,
        "human_decisions_created": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
    }
    return auth, tranche, [dict(packet) for packet in packets], blocked_keys


def _review_row(packet: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "template_id": str(packet["template_id"]),
        "member_count": packet["member_count"],
        "playbook_count": packet["playbook_count"],
        "representative_raw_keys": [str(item.get("raw_key")) for item in packet.get("representative_raw_source_snippets", [])],
        "archetype_platform": {
            "archetype": packet.get("primary_execution_archetype"),
            "platform": packet.get("known_protocol_service_platform", {}).get("os_platform_hints", []),
            "protocols_or_services": packet.get("known_protocol_service_platform", {}).get("named_protocols_or_services", []),
        },
        "exact_source_evidence_summary": _source_evidence_summary(packet),
        "proposed_reusable_design_contract": packet.get("proposed_reusable_design_contract", {}),
        "defensive_equivalence_requirements": packet.get("defensive_equivalence_invariants", {}),
        "telemetry_equivalence_requirements": packet.get("telemetry_equivalence_invariants", {}),
        "environment_prerequisites": _environment_summary(packet),
        "unresolved_unknown_fields": packet.get("unresolved_unknown_fields", []),
        "cleanup_reset_obligations": {
            "cleanup_reset_requirements": packet.get("cleanup_reset_requirements", {}),
            "reset_safety_complexity": packet.get("reset_safety_complexity", {}),
        },
        "negative_cases": packet.get("negative_cases", []),
        "member_set_sha256": packet.get("member_key_commitment", {}).get("sha256"),
        "exact_source_reference_count": len(packet.get("exact_source_evidence_references", [])),
        "exact_source_reference_coverage": "PASS",
        "member_keys": sorted(str(key) for key in packet.get("member_keys", [])),
    }


def _review_table(rows: list[Mapping[str, Any]]) -> str:
    lines = [
        "# E0C-R7 First-Tranche Human Template Review Table",
        "",
        "Review-gate presentation for exactly 12 R6-selected shared templates covering exactly 203 raw rows. No human decision is selected; every member remains `MANUAL_DESIGN_REQUIRED`.",
        "",
        "Allowed human actions per template (choose explicitly; the builder creates none): "
        + ", ".join(f"`{item}`" for item in ALLOWED_DECISIONS)
        + ".",
        "",
        "| Template ID | Member count | Playbook count | Representative raw keys | Archetype / platform | Exact source evidence summary | Proposed reusable design contract | Defensive-equivalence requirements | Telemetry-equivalence requirements | Environment prerequisites | Unresolved UNKNOWN fields | Cleanup/reset obligations | Negative cases | Member-set SHA256 |",
        "|---|---:|---:|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            "| {template_id} | {member_count} | {playbook_count} | {representative_raw_keys} | {archetype_platform} | {evidence} | {contract} | {defensive} | {telemetry} | {environment} | {unknowns} | {cleanup} | {negative} | `{sha}` |".format(
                template_id=row["template_id"],
                member_count=row["member_count"],
                playbook_count=row["playbook_count"],
                representative_raw_keys=_json_cell(row["representative_raw_keys"]),
                archetype_platform=_json_cell(row["archetype_platform"]),
                evidence=row["exact_source_evidence_summary"],
                contract=_json_cell(row["proposed_reusable_design_contract"]),
                defensive=_json_cell(row["defensive_equivalence_requirements"]),
                telemetry=_json_cell(row["telemetry_equivalence_requirements"]),
                environment=_json_cell(row["environment_prerequisites"]),
                unknowns=_json_cell(row["unresolved_unknown_fields"]),
                cleanup=_json_cell(row["cleanup_reset_obligations"]),
                negative=_json_cell(row["negative_cases"]),
                sha=row["member_set_sha256"],
            )
        )
    lines.extend(
        [
            "",
            "Approval scope: accepting a template approves only the shared manual-design contract for its exact authenticated member set. It does not authorize action execution, PROVX outcome claims, formal experiment execution, denominator change, or status mutation.",
            "",
            "Rejected or split/more-evidence templates keep all members manual. The 31 R6 blocked source-detail rows are excluded from this tranche.",
            "",
            "REVIEW_GATE = AWAITING_EXPLICIT_HUMAN_TEMPLATE_DECISIONS | BLOCKED",
            "STOP = true",
            "",
        ]
    )
    return "\n".join(lines)


def _decision_packet(auth: Mapping[str, Any], rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    templates: list[dict[str, Any]] = []
    for row in rows:
        template = {
            "template_id": row["template_id"],
            "member_keys": row["member_keys"],
            "member_count": row["member_count"],
            "playbook_count": row["playbook_count"],
            "member_set_sha256": row["member_set_sha256"],
            "member_key_commitment": {
                "algorithm": "sha256",
                "canonical_order": "lexicographic raw_key joined with LF",
                "sha256": row["member_set_sha256"],
            },
            "evidence_packet_hash": auth["template_member_authentication"][len(templates)]["evidence_packet_hash"],
            "evidence_packet_hash_algorithm": "sha256(canonical R6 enriched template packet JSON)",
                "evidence_packet_source": R6_PACKETS_FILE,
                "decision": None,
                "human_decision": None,
                "human_origin": None,
                "decision_origin": None,
            "human_origin_required": True,
            "member_expansion": False,
                "member_expansion_authorized": False,
                "decision_options": list(ALLOWED_DECISIONS),
                "human_decision_options": list(ALLOWED_DECISIONS),
            "r3_global_planning_status": MANUAL_STATUS,
            "formal_execution_authorized": False,
            "status_mutations": 0,
            "denominator_change": "NO",
            "review_record": dict(row),
            "decision_effects": {
                    "APPROVE_TEMPLATE_FOR_MEMBER_SET": {
                        "scope": "exact_member_set_only",
                        "member_expansion": False,
                    "status_mutation": False,
                    "action_execution_authorized": False,
                    "formal_experiment_authorized": False,
                },
                "REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL": {
                    "resulting_status": MANUAL_STATUS,
                    "member_expansion": False,
                },
                "REQUEST_SPLIT_OR_MORE_EVIDENCE": {
                    "resulting_status": MANUAL_STATUS,
                    "member_expansion": False,
                    "bounded_follow_up_request": "Human reviewer must identify the split boundary or exact missing evidence for this member set; no execution occurs.",
                },
            }
        }
        templates.append(template)
    return {
        "schema_version": "e0c-r7-first-tranche-decision-packet-v1",
        "authority_mutation": "NO",
        "pinned_review_commit": PINNED_REVIEW_COMMIT,
        "exact_manual_raw_count": EXPECTED_MANUAL_RAW_COUNT,
        "shared_template_count": EXPECTED_R6_PACKET_COUNT,
        "shared_template_covered_rows": EXPECTED_SHARED_COVERED_ROWS,
        "raw_specific_count": EXPECTED_RAW_SPECIFIC_COUNT,
        "blocked_count": EXPECTED_BLOCKED_COUNT,
        "template_count": EXPECTED_TEMPLATE_COUNT,
        "raw_coverage": EXPECTED_RAW_COVERAGE,
        "template_ids": list(auth["template_ids"]),
        "allowed_decisions": list(ALLOWED_DECISIONS),
        "human_decision_options": list(ALLOWED_DECISIONS),
        "templates": templates,
        "human_decisions_created": 0,
        "status_mutations": 0,
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "review_gate": "AWAITING_EXPLICIT_HUMAN_TEMPLATE_DECISIONS | BLOCKED",
        "next_action": "HUMAN_REVIEW_OF_EXACT12_TEMPLATE_PACKETS",
        "stop": True,
        "blocked31_included": False,
        "no_member_expansion": True,
    }


def build_outputs(root: Path = Path(".")) -> dict[str, Any]:
    auth, tranche, packets, blocked_keys = _authenticate_inputs(root)
    packet_by_id = {str(packet["template_id"]): packet for packet in packets}
    selected_packets = [packet_by_id[template_id] for template_id in auth["template_ids"]]
    rows = [_review_row(packet) for packet in selected_packets]
    # Verify the blocked exclusion against the actual review rows as well as
    # during authentication, so later formatting changes cannot broaden scope.
    review_keys = {key for row in rows for key in row["member_keys"]}
    if review_keys.intersection(blocked_keys):
        raise ValueError("review table includes a blocked31 raw row")
    if len(auth["template_ids"]) != EXPECTED_TEMPLATE_COUNT or len(review_keys) != EXPECTED_RAW_COVERAGE:
        raise ValueError("review selection changed after authentication")
    packet = _decision_packet(auth, rows)
    return {
        "input_authentication": auth,
        "review_rows": rows,
        "review_table": _review_table(rows),
        "decision_packet": packet,
        "r6_tranche": tranche,
        "review_table_markdown": _review_table(rows),
    }


def write_outputs(root: Path, outputs: Mapping[str, Any]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "E0C_R7_FIRST_TRANCHE_INPUT_AUTHENTICATION.json").write_text(
        json.dumps(outputs["input_authentication"], ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (root / "E0C_R7_FIRST_TRANCHE_REVIEW_TABLE.md").write_text(
        str(outputs["review_table"]), encoding="utf-8", newline="\n"
    )
    (root / "E0C_R7_FIRST_TRANCHE_DECISION_PACKET.json").write_text(
        json.dumps(outputs["decision_packet"], ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        outputs = build_outputs(args.root)
        write_outputs(args.root, outputs)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print("E0C_R7_FIRST_TRANCHE_HUMAN_REVIEW = BLOCKED")
        print(f"ERROR = {error}")
        print("TEMPLATE_COUNT = 0")
        print("RAW_COVERAGE = 0")
        print("HUMAN_DECISIONS_CREATED = 0")
        print("STATUS_MUTATIONS = 0")
        print("FORMAL_EXPERIMENT_EXECUTED = NO")
        print("DENOMINATOR_CHANGE = NO")
        print("NEXT_ACTION = HUMAN_REVIEW_OF_EXACT12_TEMPLATE_PACKETS")
        print("STOP = true")
        return 1
    print("E0C_R7_FIRST_TRANCHE_HUMAN_REVIEW =")
    print("AWAITING_EXPLICIT_HUMAN_TEMPLATE_DECISIONS | BLOCKED")
    print(f"TEMPLATE_COUNT = {outputs['input_authentication']['template_count']}")
    print(f"RAW_COVERAGE = {outputs['input_authentication']['raw_coverage']}")
    print("HUMAN_DECISIONS_CREATED = 0")
    print("STATUS_MUTATIONS = 0")
    print("FORMAL_EXPERIMENT_EXECUTED = NO")
    print("DENOMINATOR_CHANGE = NO")
    print("NEXT_ACTION = HUMAN_REVIEW_OF_EXACT12_TEMPLATE_PACKETS")
    print("STOP = true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
