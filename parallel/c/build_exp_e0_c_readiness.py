#!/usr/bin/env python3
"""Authenticate the 1796 raw corpus and render conservative E0-C readiness records.

This program reads playbook JSON and the derived raw registry only.  It never
executes a raw action, replays a stimulus, or writes to either authority source.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


EXPECTED_PLAYBOOK_COUNT = 53
EXPECTED_RAW_COUNT = 1796
EXPECTED_HISTORICAL_MANIFEST_SHA256 = (
    "d52db285fc38deb0430ee32fad24b37e54e2f2b95f6f0ac35b96a42754725efa"
)
HISTORICAL_PROTOCOL_ID = "FULL_ACTION_PROTOCOL_V2"
SOURCE_FILE_PREFIX = "APT数据集/playbooks"
RAW_KEY_PATTERN = re.compile(r"^[^:]+::S\d{2,}::A\d{3,}$")
ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
UNKNOWN = "UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE"
UNEXECUTED = "UNEXECUTED_NOT_OBSERVED"


class AuthorityError(ValueError):
    """A malformed source object prevents raw-side authentication."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json_hash(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def source_text(value: Any) -> str:
    return "" if value is None else str(value)


def extract_attack_ids(action: Mapping[str, Any]) -> list[str]:
    """Use only explicit tag metadata, never prose, for ATT&CK identifiers."""

    fragments: list[str] = []
    tags = action.get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, Mapping):
                for field in ("tag", "tag_en"):
                    if isinstance(tag.get(field), str):
                        fragments.append(tag[field])
            elif isinstance(tag, str):
                fragments.append(tag)
    old_tags = action.get("old_tags")
    if isinstance(old_tags, Mapping):
        techniques = old_tags.get("mitre_techniques")
        if isinstance(techniques, list):
            fragments.extend(str(item) for item in techniques)
    return sorted(
        {
            match.group(0).upper()
            for fragment in fragments
            for match in ATTACK_ID_PATTERN.finditer(fragment)
        }
    )


def derive_source_rows(playbooks_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Independently traverse the raw corpus in source-file/list order."""

    if not playbooks_root.is_dir():
        raise AuthorityError(f"playbooks root is not a directory: {playbooks_root}")

    rows: list[dict[str, Any]] = []
    per_playbook: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    files = sorted(playbooks_root.glob("*.json"), key=lambda item: item.name)
    for path in files:
        try:
            with path.open("r", encoding="utf-8-sig") as handle:
                playbook = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuthorityError(f"{path}: cannot parse playbook JSON: {error}") from error
        if not isinstance(playbook, dict):
            raise AuthorityError(f"{path}: top-level playbook must be an object")

        playbook_id_value = playbook.get("vid")
        if playbook_id_value is None or not str(playbook_id_value).strip():
            raise AuthorityError(f"{path}: missing nonempty top-level vid")
        playbook_id = str(playbook_id_value)
        pipeline = playbook.get("pipeline")
        if not isinstance(pipeline, list):
            raise AuthorityError(f"{path}: pipeline must be a list")

        source_file = f"{SOURCE_FILE_PREFIX}/{path.name}"
        source_sha = sha256_file(path)
        action_total = 0
        for stage_index, stage in enumerate(pipeline, start=1):
            if not isinstance(stage, Mapping):
                raise AuthorityError(f"{path}: pipeline[{stage_index - 1}] must be an object")
            actions = stage.get("actions")
            if not isinstance(actions, list):
                raise AuthorityError(
                    f"{path}: pipeline[{stage_index - 1}].actions must be a list"
                )
            for action_index, action in enumerate(actions, start=1):
                if not isinstance(action, Mapping):
                    raise AuthorityError(
                        f"{path}: pipeline[{stage_index - 1}].actions[{action_index - 1}] "
                        "must be an object"
                    )
                raw_key = f"{playbook_id}::S{stage_index:02d}::A{action_index:03d}"
                if raw_key in seen_keys:
                    raise AuthorityError(f"duplicate positional raw key: {raw_key}")
                seen_keys.add(raw_key)
                rows.append(
                    {
                        "raw_action_key": raw_key,
                        "playbook_id": playbook_id,
                        "playbook_name": source_text(playbook.get("name")),
                        "stage_index": stage_index,
                        "stage_identifier": f"S{stage_index:02d}",
                        "stage_source_step": stage.get("step"),
                        "stage_name": source_text(stage.get("name")),
                        "action_index": action_index,
                        "action_name": source_text(action.get("name")),
                        "action_description": source_text(action.get("desc")),
                        "action_type": source_text(action.get("action_type")),
                        "os": source_text(action.get("os")),
                        "attack_ids": extract_attack_ids(action),
                        "dataset_vid": source_text(action.get("vid")),
                        "dataset_uuid": source_text(action.get("uuid")),
                        "source_file": source_file,
                        "source_file_sha256": source_sha,
                        "source_locator": (
                            f"$.pipeline[{stage_index - 1}].actions[{action_index - 1}]"
                        ),
                    }
                )
                action_total += 1
        per_playbook.append(
            {
                "playbook_id": playbook_id,
                "source_file": source_file,
                "stage_count": len(pipeline),
                "raw_action_count": action_total,
            }
        )
    return rows, per_playbook


def read_jsonl_strict(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    errors.append(f"{path}:{line_number}: invalid JSON: {error.msg}")
                    continue
                if not isinstance(value, dict):
                    errors.append(f"{path}:{line_number}: expected object")
                    continue
                rows.append(value)
    except (OSError, UnicodeDecodeError) as error:
        errors.append(f"{path}: cannot read registry: {error}")
    return rows, errors


def manifest_from_source_rows(source_rows: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    by_path: dict[str, str] = {}
    for row in source_rows:
        source_file = str(row["source_file"])
        source_sha = str(row["source_file_sha256"])
        previous = by_path.setdefault(source_file, source_sha)
        if previous != source_sha:
            raise AuthorityError(f"source derivation disagrees on SHA-256 for {source_file}")
    return [
        {"source_file": source_file, "sha256": by_path[source_file]}
        for source_file in sorted(by_path)
    ]


def audit_raw_authority(playbooks_root: Path, registry_path: Path) -> dict[str, Any]:
    """Validate C1-C3 without calling the historical registry builder."""

    try:
        source_rows, per_playbook = derive_source_rows(playbooks_root)
    except AuthorityError as error:
        return {
            "passed": False,
            "failure_reasons": [str(error)],
            "source_rows": [],
            "per_playbook": [],
            "source_playbook_count": 0,
            "source_stage_count": 0,
            "source_derived_raw_count": 0,
            "registry_row_count": 0,
            "source_derived_unique_raw_keys": 0,
            "registry_unique_raw_keys": 0,
            "missing_in_registry": [],
            "extra_in_registry": [],
            "raw_key_mismatch_count": 0,
            "source_file_sha_mismatch_count": 0,
            "source_locator_mismatch_count": 0,
            "historical_manifest_recomputed_sha256": None,
        }

    registry_rows, registry_parse_errors = read_jsonl_strict(registry_path)
    source_by_key = {row["raw_action_key"]: row for row in source_rows}
    registry_key_counts = Counter(str(row.get("raw_action_key") or "") for row in registry_rows)
    registry_duplicate_keys = sorted(
        key for key, count in registry_key_counts.items() if key and count > 1
    )
    invalid_registry_keys = sorted(
        key for key in registry_key_counts if not RAW_KEY_PATTERN.fullmatch(key)
    )
    registry_by_key = {
        key: row
        for row in registry_rows
        for key in [str(row.get("raw_action_key") or "")]
        if key and registry_key_counts[key] == 1
    }
    source_keys = set(source_by_key)
    registry_keys = set(registry_by_key)
    missing_in_registry = sorted(source_keys - registry_keys)
    extra_in_registry = sorted(registry_keys - source_keys)

    row_field_names = (
        "playbook_id",
        "playbook_name",
        "stage_index",
        "stage_identifier",
        "stage_source_step",
        "stage_name",
        "action_index",
        "action_name",
        "action_description",
        "action_type",
        "os",
        "attack_ids",
        "dataset_vid",
        "dataset_uuid",
        "source_file",
        "source_file_sha256",
        "source_locator",
    )
    field_mismatches: Counter[str] = Counter()
    raw_key_mismatch_count = 0
    source_file_sha_mismatch_count = 0
    source_locator_mismatch_count = 0
    for raw_key in sorted(source_keys & registry_keys):
        expected = source_by_key[raw_key]
        actual = registry_by_key[raw_key]
        for field in row_field_names:
            if actual.get(field) != expected[field]:
                field_mismatches[field] += 1
        if actual.get("source_file_sha256") != expected["source_file_sha256"]:
            source_file_sha_mismatch_count += 1
        if actual.get("source_locator") != expected["source_locator"]:
            source_locator_mismatch_count += 1

    source_by_locator = {
        (row["source_file"], row["source_locator"]): row for row in source_rows
    }
    for row in registry_rows:
        locator = (str(row.get("source_file") or ""), str(row.get("source_locator") or ""))
        expected = source_by_locator.get(locator)
        if expected is not None and row.get("raw_action_key") != expected["raw_action_key"]:
            raw_key_mismatch_count += 1
        elif expected is None and str(row.get("raw_action_key") or "") in source_by_key:
            source_locator_mismatch_count += 1

    source_hashes = {
        row["source_file"]: row["source_file_sha256"] for row in source_rows
    }
    registry_hashes_by_file: dict[str, set[str]] = defaultdict(set)
    for row in registry_rows:
        source_file = str(row.get("source_file") or "")
        registry_hashes_by_file[source_file].add(str(row.get("source_file_sha256") or ""))
    inconsistent_registry_source_hash_files = sorted(
        source_file
        for source_file, hashes in registry_hashes_by_file.items()
        if len(hashes) != 1 or hashes != {source_hashes.get(source_file)}
    )
    if inconsistent_registry_source_hash_files:
        source_file_sha_mismatch_count += sum(
            1 for row in registry_rows if row.get("source_file") in inconsistent_registry_source_hash_files
        )

    manifest = manifest_from_source_rows(source_rows)
    manifest_sha256 = canonical_json_hash(manifest)
    source_stage_count = sum(item["stage_count"] for item in per_playbook)
    failures: list[str] = []
    if registry_parse_errors:
        failures.append("REGISTRY_PARSE_ERRORS")
    if len(per_playbook) != EXPECTED_PLAYBOOK_COUNT:
        failures.append("PLAYBOOK_COUNT_NOT_53")
    if len(source_rows) != EXPECTED_RAW_COUNT:
        failures.append("SOURCE_DERIVED_RAW_COUNT_NOT_1796")
    if len(source_by_key) != EXPECTED_RAW_COUNT:
        failures.append("SOURCE_DERIVED_UNIQUE_RAW_KEYS_NOT_1796")
    if len(registry_rows) != EXPECTED_RAW_COUNT:
        failures.append("REGISTRY_ROW_COUNT_NOT_1796")
    if len(registry_keys) != EXPECTED_RAW_COUNT:
        failures.append("REGISTRY_UNIQUE_RAW_KEYS_NOT_1796")
    if registry_duplicate_keys:
        failures.append("REGISTRY_DUPLICATE_RAW_KEYS")
    if invalid_registry_keys:
        failures.append("REGISTRY_INVALID_RAW_KEYS")
    if missing_in_registry:
        failures.append("MISSING_IN_REGISTRY")
    if extra_in_registry:
        failures.append("EXTRA_IN_REGISTRY")
    if raw_key_mismatch_count:
        failures.append("RAW_KEY_MISMATCH")
    if source_file_sha_mismatch_count:
        failures.append("SOURCE_FILE_SHA_MISMATCH")
    if source_locator_mismatch_count:
        failures.append("SOURCE_LOCATOR_MISMATCH")
    if field_mismatches:
        failures.append("SOURCE_DERIVED_FIELD_MISMATCH")
    if manifest_sha256 != EXPECTED_HISTORICAL_MANIFEST_SHA256:
        failures.append("HISTORICAL_RAW_MANIFEST_MISMATCH")

    return {
        "passed": not failures,
        "failure_reasons": failures + registry_parse_errors,
        "source_rows": source_rows,
        "per_playbook": per_playbook,
        "source_playbook_count": len(per_playbook),
        "source_stage_count": source_stage_count,
        "source_derived_raw_count": len(source_rows),
        "registry_row_count": len(registry_rows),
        "source_derived_unique_raw_keys": len(source_by_key),
        "registry_unique_raw_keys": len(registry_keys),
        "registry_duplicate_raw_keys": registry_duplicate_keys,
        "registry_invalid_raw_keys": invalid_registry_keys,
        "missing_in_registry": missing_in_registry,
        "extra_in_registry": extra_in_registry,
        "raw_key_mismatch_count": raw_key_mismatch_count,
        "source_file_sha_mismatch_count": source_file_sha_mismatch_count,
        "source_locator_mismatch_count": source_locator_mismatch_count,
        "source_row_field_mismatch_counts": dict(sorted(field_mismatches.items())),
        "inconsistent_registry_source_hash_files": inconsistent_registry_source_hash_files,
        "historical_manifest_rule": (
            "SHA256(canonical UTF-8 JSON of sorted unique source_file/sha256 pairs)"
        ),
        "historical_manifest_recomputed_sha256": manifest_sha256,
        "historical_manifest_expected_sha256": EXPECTED_HISTORICAL_MANIFEST_SHA256,
        "historical_manifest_match": manifest_sha256 == EXPECTED_HISTORICAL_MANIFEST_SHA256,
        "source_file_manifest": manifest,
    }


def build_readiness_rows(source_rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Produce preparation-only records without inferring replay or PROVX facts."""

    evidence_requirements = [
        "run_manifest",
        "stdout_stderr_if_applicable",
        "process_event_logs_if_applicable",
        "file_audit_records_if_applicable",
        "socket_connect_records_if_applicable",
        "pcap_if_applicable",
        "provenance_graph_fragment",
        "provx_phase1_alert_output",
        "provx_phase2_core_edge_output",
        "model_level_intervention_result_if_executed",
        "enforcement_result_if_separately_implemented",
        "reset_evidence",
    ]
    records: list[dict[str, Any]] = []
    for source in source_rows:
        action_type = str(source["action_type"])
        source_os = str(source["os"])
        records.append(
            {
                "raw_key": source["raw_action_key"],
                "playbook_id": source["playbook_id"],
                "stage_index": source["stage_index"],
                "action_index": source["action_index"],
                "action_name": source["action_name"],
                "action_description": source["action_description"],
                "action_type": action_type,
                "attack_ids": source["attack_ids"],
                "source_file": source["source_file"],
                "source_file_sha256": source["source_file_sha256"],
                "source_locator": source["source_locator"],
                "source_node_role": UNKNOWN,
                "target_node_role": UNKNOWN,
                "required_os_or_host_class": source_os or UNKNOWN,
                "required_service_class": UNKNOWN,
                "required_protocol": UNKNOWN,
                "required_preconditions": UNKNOWN,
                "stimulus_class": (
                    f"SOURCE_ACTION_TYPE:{action_type}" if action_type else UNKNOWN
                ),
                "candidate_fidelity": "NOT_YET_EXECUTABLE",
                "why_this_fidelity": (
                    "No authenticated controlled replay implementation or environment "
                    "validation is available in E0-C preparation evidence."
                ),
                "defensive_equivalence_requirements": UNKNOWN,
                "telemetry_equivalence_requirements": UNKNOWN,
                "action_success_criterion": UNKNOWN,
                "cleanup_reset_requirement": UNKNOWN,
                "repeatability_requirement": UNKNOWN,
                "environment_blockers": [
                    "NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"
                ],
                "provx_expected_entity_types": ["UNKNOWN"],
                "provx_expected_causal_edge_classes": ["UNKNOWN"],
                "provx_required_host_audit_events": ["UNKNOWN"],
                "provx_expected_network_to_host_correlation": "UNKNOWN",
                "provx_alert_subgraph_acquisition_requirement": "UNKNOWN",
                "provx_phase1_observable": "UNKNOWN",
                "provx_phase2_core_edge_localizable": "UNKNOWN",
                "provx_real_enforcement_mapping_available": "UNKNOWN",
                "provx_observation_blocker": (
                    "NO_AUTHENTICATED_PROVX_OBSERVATION_CONTRACT_OR_TELEMETRY_EVIDENCE"
                ),
                "attack_action_success": UNEXECUTED,
                "provx_phase1_detection": UNEXECUTED,
                "provx_phase2_core_edge_localization_or_model_flip": UNEXECUTED,
                "real_enforcement_prevention": UNEXECUTED,
                "required_evidence": evidence_requirements,
                "raw_authority_status": "AUTHENTICATED",
                "current_binding_scoring_reference": "UNKNOWN_NOT_RESOLVED_IN_E0_C",
                "formal_execution_authorized": False,
            }
        )
    return records


def counter_by(records: Iterable[Mapping[str, Any]], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(record[field]) for record in records).items()))


def list_counter_by(records: Iterable[Mapping[str, Any]], field: str) -> dict[str, int]:
    return dict(
        sorted(Counter(item for record in records for item in record[field]).items())
    )


def conservation_audit(audit: Mapping[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    raw_keys = [record["raw_key"] for record in records]
    counts = Counter(raw_keys)
    return {
        "schema_version": "exp-e0-c-conservation-audit-v1",
        "exp_e0_c_raw_authority": (
            "AUTHENTICATED_SOURCE_CORPUS_PLUS_VERIFIED_DERIVED_REGISTRY"
            if audit["passed"] else "BLOCKED"
        ),
        "exp_e0_c_conservation": "PASS_1796" if audit["passed"] else "BLOCKED",
        "historical_protocol": {
            "protocol_id": HISTORICAL_PROTOCOL_ID,
            "raw_corpus_manifest_expected_sha256": EXPECTED_HISTORICAL_MANIFEST_SHA256,
            "raw_corpus_manifest_recomputed_sha256": audit[
                "historical_manifest_recomputed_sha256"
            ],
            "raw_corpus_manifest_recomputation": (
                "REPRODUCED_MATCH" if audit["historical_manifest_match"] else "MISMATCH"
            ),
            "scoring_metadata": "NOT_CURRENT_AUTHORITY",
        },
        "source_corpus": {
            "playbook_count": audit["source_playbook_count"],
            "stage_count": audit["source_stage_count"],
            "raw_action_count": audit["source_derived_raw_count"],
            "per_playbook": audit["per_playbook"],
            "source_file_manifest": audit["source_file_manifest"],
        },
        "registry_verification": {
            "registry_row_count": audit["registry_row_count"],
            "registry_unique_raw_keys": audit["registry_unique_raw_keys"],
            "registry_duplicate_raw_keys": audit["registry_duplicate_raw_keys"],
            "registry_invalid_raw_keys": audit["registry_invalid_raw_keys"],
            "missing_in_registry": audit["missing_in_registry"],
            "extra_in_registry": audit["extra_in_registry"],
            "raw_key_mismatch_count": audit["raw_key_mismatch_count"],
            "source_file_sha_mismatch_count": audit["source_file_sha_mismatch_count"],
            "source_locator_mismatch_count": audit["source_locator_mismatch_count"],
            "source_row_field_mismatch_counts": audit["source_row_field_mismatch_counts"],
            "inconsistent_registry_source_hash_files": audit[
                "inconsistent_registry_source_hash_files"
            ],
        },
        "conservation": {
            "raw_record_count": len(records),
            "unique_raw_key_count": len(counts),
            "missing_raw_count": len(set(audit["source_rows"]) - set(raw_keys))
            if False
            else len(set(row["raw_action_key"] for row in audit["source_rows"]) - set(raw_keys)),
            "extra_raw_count": len(set(raw_keys) - set(row["raw_action_key"] for row in audit["source_rows"])),
            "duplicate_raw_key_count": sum(count - 1 for count in counts.values() if count > 1),
        },
        "formal_experiment_executed": "NO",
        "binding_authority_mutation": "NO",
        "scoring_authority_mutation": "NO",
        "denominator_change": "NO",
        "failure_reasons": audit["failure_reasons"],
    }


def observability_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "exp-e0-c-provx-observability-summary-v1",
        "raw_record_count": len(records),
        "by_playbook": counter_by(records, "playbook_id"),
        "by_stage": dict(
            sorted(
                Counter(
                    f"{record['playbook_id']}::S{int(record['stage_index']):02d}"
                    for record in records
                ).items()
            )
        ),
        "candidate_fidelity": counter_by(records, "candidate_fidelity"),
        "required_os_or_host_class": counter_by(records, "required_os_or_host_class"),
        "provx_expected_entity_types": list_counter_by(
            records, "provx_expected_entity_types"
        ),
        "provx_phase1_observable": counter_by(records, "provx_phase1_observable"),
        "provx_phase2_core_edge_localizable": counter_by(
            records, "provx_phase2_core_edge_localizable"
        ),
        "provx_real_enforcement_mapping_available": counter_by(
            records, "provx_real_enforcement_mapping_available"
        ),
        "environment_blockers": list_counter_by(records, "environment_blockers"),
        "provx_observation_blockers": counter_by(records, "provx_observation_blocker"),
        "result_dimensions": {
            "attack_action_success": counter_by(records, "attack_action_success"),
            "provx_phase1_detection": counter_by(records, "provx_phase1_detection"),
            "provx_phase2_core_edge_localization_or_model_flip": counter_by(
                records, "provx_phase2_core_edge_localization_or_model_flip"
            ),
            "real_enforcement_prevention": counter_by(
                records, "real_enforcement_prevention"
            ),
        },
    }


def raw_authority_report(audit: Mapping[str, Any]) -> str:
    status = (
        "AUTHENTICATED_SOURCE_CORPUS_PLUS_VERIFIED_DERIVED_REGISTRY"
        if audit["passed"] else "BLOCKED"
    )
    lines = [
        "# E0-C Raw Authority Authentication",
        "",
        f"EXP_E0_C_RAW_AUTHORITY = {status}",
        "HISTORICAL_PROTOCOL_SCORING_METADATA = NOT_CURRENT_AUTHORITY",
        "",
        "## C1 Source Corpus",
        "",
        f"- Playbooks: `{audit['source_playbook_count']}`",
        f"- Stages: `{audit['source_stage_count']}`",
        f"- Source-derived raw actions: `{audit['source_derived_raw_count']}`",
        f"- Source-derived unique raw keys: `{audit['source_derived_unique_raw_keys']}`",
        "",
        "## C2 Source Identity",
        "",
        f"- Historical manifest rule: `{audit['historical_manifest_rule']}`",
        f"- Recomputed manifest SHA-256: `{audit['historical_manifest_recomputed_sha256']}`",
        f"- Historical manifest SHA-256: `{EXPECTED_HISTORICAL_MANIFEST_SHA256}`",
        "- Historical manifest recomputation: "
        + ("`REPRODUCED_MATCH`" if audit["historical_manifest_match"] else "`MISMATCH`"),
        "- The SHA256SUMS-list-file hash was not used as the corpus manifest hash.",
        "",
        "## C3 Registry Verification",
        "",
        f"- Registry rows: `{audit['registry_row_count']}`",
        f"- Registry unique raw keys: `{audit['registry_unique_raw_keys']}`",
        f"- Missing source rows in registry: `{len(audit['missing_in_registry'])}`",
        f"- Extra registry rows: `{len(audit['extra_in_registry'])}`",
        f"- Raw-key mismatches: `{audit['raw_key_mismatch_count']}`",
        f"- Source-file SHA mismatches: `{audit['source_file_sha_mismatch_count']}`",
        f"- Source-locator mismatches: `{audit['source_locator_mismatch_count']}`",
        "",
        "## Boundaries",
        "",
        "- No raw action, source-auth workflow, Current86 P0/P1, binding workflow, or scoring workflow was executed.",
        "- No Git refs, binding authority, scoring authority, accepted binding count, or denominator were mutated.",
        "",
    ]
    if audit["failure_reasons"]:
        lines.extend(["## Failures", ""])
        lines.extend(f"- `{reason}`" for reason in audit["failure_reasons"])
        lines.append("")
    return "\n".join(lines)


def blocker_summary(records: list[dict[str, Any]], audit: Mapping[str, Any]) -> str:
    blockers = list_counter_by(records, "environment_blockers") if records else {}
    provx_blockers = counter_by(records, "provx_observation_blocker") if records else {}
    lines = [
        "# E0-C Replay Readiness Blockers",
        "",
        f"Raw authority: `{'AUTHENTICATED' if audit['passed'] else 'BLOCKED'}`.",
        f"Readiness records: `{len(records)}`.",
        "",
        "## Environment",
        "",
    ]
    lines.extend(f"- `{blocker}`: {count}" for blocker, count in blockers.items())
    lines.extend(["", "## PROVX Observation", ""])
    lines.extend(f"- `{blocker}`: {count}" for blocker, count in provx_blockers.items())
    lines.extend(
        [
            "",
            "All records remain preparation-only. No prediction flip or model intervention is treated as real enforcement prevention.",
            "",
        ]
    )
    return "\n".join(lines)


def render_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def render_jsonl(records: Iterable[Mapping[str, Any]]) -> str:
    return "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for record in records
    )


def render_csv(records: list[dict[str, Any]]) -> str:
    fieldnames = list(records[0]) if records else []
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for record in records:
        writer.writerow(
            {
                field: json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                if isinstance(value, (list, dict))
                else value
                for field, value in record.items()
            }
        )
    return buffer.getvalue()


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def write_outputs(output_dir: Path, audit: Mapping[str, Any]) -> None:
    if not audit["passed"]:
        raise AuthorityError("raw authority is blocked; readiness matrix will not be generated")
    records = build_readiness_rows(audit["source_rows"])
    conservation = conservation_audit(audit, records)
    if conservation["conservation"] != {
        "raw_record_count": EXPECTED_RAW_COUNT,
        "unique_raw_key_count": EXPECTED_RAW_COUNT,
        "missing_raw_count": 0,
        "extra_raw_count": 0,
        "duplicate_raw_key_count": 0,
    }:
        raise AuthorityError("readiness rendering failed the conservation audit")

    write_text(output_dir / "EXP_E0_C_1796_PROVX_REPLAY_READINESS.jsonl", render_jsonl(records))
    write_text(output_dir / "EXP_E0_C_1796_PROVX_REPLAY_READINESS.csv", render_csv(records))
    write_text(output_dir / "EXP_E0_C_CONSERVATION_AUDIT.json", render_json(conservation))
    write_text(
        output_dir / "EXP_E0_C_PROVX_OBSERVABILITY_SUMMARY.json",
        render_json(observability_summary(records)),
    )
    write_text(output_dir / "EXP_E0_C_BLOCKER_SUMMARY.md", blocker_summary(records, audit))
    write_text(
        output_dir / "EXP_E0_C_RAW_AUTHORITY_AUTHENTICATION_REPORT.md",
        raw_authority_report(audit),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--playbooks-root",
        type=Path,
        default=Path("/home/cph/experiment/APT数据集/playbooks"),
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=Path(
            "/home/cph/experiment-worktrees/full-action-protocol-binding/"
            "data/full_action/raw_action_registry.jsonl"
        ),
    )
    parser.add_argument("--output-dir", type=Path, default=Path.cwd())
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    audit = audit_raw_authority(args.playbooks_root, args.registry)
    if not audit["passed"]:
        print("EXP_E0_C_RAW_AUTHORITY = BLOCKED")
        print("EXP_E0_C_CONSERVATION = BLOCKED")
        print(f"RAW_RECORD_COUNT = {audit['source_derived_raw_count']}")
        print(f"UNIQUE_RAW_KEY_COUNT = {audit['source_derived_unique_raw_keys']}")
        print("HISTORICAL_PROTOCOL_SCORING_METADATA = NOT_CURRENT_AUTHORITY")
        print("FORMAL_EXPERIMENT_EXECUTED = NO")
        print("BINDING_AUTHORITY_MUTATION = NO")
        print("SCORING_AUTHORITY_MUTATION = NO")
        print("DENOMINATOR_CHANGE = NO")
        print("NEXT_ACTION = FIX_EXACT_RAW_AUTHORITY_DEFECT")
        print("STOP = true")
        return 1
    write_outputs(args.output_dir, audit)
    print("EXP_E0_C_RAW_AUTHORITY = AUTHENTICATED_SOURCE_CORPUS_PLUS_VERIFIED_DERIVED_REGISTRY")
    print("EXP_E0_C_CONSERVATION = PASS_1796")
    print("RAW_RECORD_COUNT = 1796")
    print("UNIQUE_RAW_KEY_COUNT = 1796")
    print("HISTORICAL_PROTOCOL_SCORING_METADATA = NOT_CURRENT_AUTHORITY")
    print("FORMAL_EXPERIMENT_EXECUTED = NO")
    print("BINDING_AUTHORITY_MUTATION = NO")
    print("SCORING_AUTHORITY_MUTATION = NO")
    print("DENOMINATOR_CHANGE = NO")
    print("NEXT_ACTION = FRESH_REVIEW_OF_EXP_E0_C_1796_PROVX_REPLAY_READINESS")
    print("STOP = true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
