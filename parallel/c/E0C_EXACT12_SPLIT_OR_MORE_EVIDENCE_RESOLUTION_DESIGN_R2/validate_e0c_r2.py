#!/usr/bin/env python3
"""Strict, read-only validation for E0C Exact12 split proposal records.

JSON Schema handles shape, types, constants, and local uniqueness. This module
handles the cross-field relationships that JSON Schema cannot calculate:
frozen parent identity, canonical member-set hashes, complete/disjoint child
partitions, conservation recomputation, and cross-template boundaries.

The CLI only reads source artifacts and writes validation fixtures/evidence in
the R2 package. It never applies a split or mutates a governed state.
"""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator


PACKAGE_DIR = Path(__file__).resolve().parent
ROOT_DIR = PACKAGE_DIR.parent
SCHEMA_FILE = PACKAGE_DIR / "TEMPLATE_LEVEL_RESOLUTION_SCHEMA.json"
CROSSWALK_FILE = PACKAGE_DIR / "EXACT12_RESOLUTION_CROSSWALK.jsonl"
CONTRACT_FILE = PACKAGE_DIR / "MORE_EVIDENCE_ACQUISITION_CONTRACT.json"
BOUNDARY_FILE = PACKAGE_DIR / "ZERO_MUTATION_BOUNDARY.json"
BLOCKED31_FILE = ROOT_DIR / "E0C_R5_BLOCKED31_SOURCE_DETAIL_RECOVERY.json"
UNION_SHA256 = "ffeb2704a1c971b89129e1959ae721bbc9ef159153a5f0a20f8abda13edb441a"
EXPECTED_TEMPLATE_COUNT = 12
EXPECTED_RAW_COVERAGE = 203
EXPECTED_SOURCE_DECISION = "REQUEST_SPLIT_OR_MORE_EVIDENCE"
EXPECTED_RESOLUTION_STATE = "REQUEST_MORE_EVIDENCE"
EXPECTED_PLANNING_STATUS = "MANUAL_DESIGN_REQUIRED"
EXPECTED_SPLIT_STATUS = "NO_CURRENT_SPLIT"


class ValidationResult:
    def __init__(self, valid: bool, errors: list[str], checks: dict[str, Any]):
        self.valid = valid
        self.errors = errors
        self.checks = checks


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected object")
        rows.append(value)
    return rows


def key_hash(keys: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(str(key) for key in keys)).encode("utf-8")).hexdigest()


def _path_text(path: Iterable[Any]) -> str:
    return ".".join(str(item) for item in path) or "$"


def _schema_errors(record: Mapping[str, Any], schema: Mapping[str, Any]) -> list[str]:
    validator = Draft202012Validator(schema)
    return [
        f"schema:{_path_text(error.absolute_path)}: {error.message}"
        for error in sorted(validator.iter_errors(record), key=lambda item: list(item.absolute_path))
    ]


def _current_state_errors(current_state: Any) -> list[str]:
    expected = {
        "source_human_decision": EXPECTED_SOURCE_DECISION,
        "resolution_state": EXPECTED_RESOLUTION_STATE,
        "r3_global_planning_status": EXPECTED_PLANNING_STATUS,
        "current_split_status": EXPECTED_SPLIT_STATUS,
        "applied_split": False,
        "status_mutations": 0,
        "formal_execution_authorized": False,
    }
    if not isinstance(current_state, Mapping):
        return ["current_state must be an object"]
    return [
        f"current_state.{key}: expected {expected_value!r}, got {current_state.get(key)!r}"
        for key, expected_value in expected.items()
        if current_state.get(key) != expected_value
    ]


def _baseline_checks(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, set[str]], list[str]]:
    errors: list[str] = []
    ordered = [row.get("frozen_identity", {}).get("frozen_order") for row in rows]
    template_sets: dict[str, set[str]] = {}
    all_keys: list[str] = []
    for index, row in enumerate(rows, 1):
        identity = row.get("frozen_identity", {})
        template_id = identity.get("template_id")
        keys = identity.get("member_keys", [])
        if not isinstance(keys, list):
            errors.append(f"crosswalk[{index}].member_keys is not a list")
            keys = []
        key_set = set(keys)
        template_sets[str(template_id)] = key_set
        all_keys.extend(keys)
        if identity.get("member_count") != len(keys):
            errors.append(f"crosswalk[{index}].member_count does not equal member_keys length")
        if identity.get("member_set_sha256") != key_hash(keys):
            errors.append(f"crosswalk[{index}].member_set_sha256 does not match member_keys")
        if len(key_set) != len(keys):
            errors.append(f"crosswalk[{index}] contains duplicate members")
        errors.extend(
            f"crosswalk[{index}].{message}"
            for message in _current_state_errors(row.get("current_state"))
        )
    duplicate_count = len(all_keys) - len(set(all_keys))
    template_sets_list = list(template_sets.values())
    overlap_count = sum(
        len(left & right)
        for left_id, left in enumerate(template_sets_list)
        for right in template_sets_list[left_id + 1 :]
    )
    checks = {
        "template_count": len(rows),
        "ordered": ordered == list(range(1, EXPECTED_TEMPLATE_COUNT + 1)),
        "raw_count_sum": sum(row.get("frozen_identity", {}).get("member_count", 0) for row in rows),
        "unique_member_count": len(set(all_keys)),
        "duplicate_member_count": duplicate_count,
        "cross_template_overlap_count": overlap_count,
        "union_member_key_sha256": key_hash(all_keys),
        "all_current_states_frozen": not any(
            message.startswith("crosswalk[") for message in errors
        ),
    }
    if checks["template_count"] != EXPECTED_TEMPLATE_COUNT:
        errors.append(f"crosswalk template count must be {EXPECTED_TEMPLATE_COUNT}")
    if not checks["ordered"]:
        errors.append("crosswalk frozen_order must be exactly 1..12")
    if checks["raw_count_sum"] != EXPECTED_RAW_COVERAGE:
        errors.append(f"crosswalk raw count sum must be {EXPECTED_RAW_COVERAGE}")
    if checks["unique_member_count"] != EXPECTED_RAW_COVERAGE:
        errors.append(f"crosswalk unique member count must be {EXPECTED_RAW_COVERAGE}")
    if duplicate_count != 0:
        errors.append("crosswalk duplicate member count must be zero")
    if overlap_count != 0:
        errors.append("crosswalk cross-template overlap must be zero")
    if checks["union_member_key_sha256"] != UNION_SHA256:
        errors.append("crosswalk union member-key SHA-256 does not match frozen commitment")
    return checks, template_sets, errors


def load_blocked31_keys(path: Path = BLOCKED31_FILE) -> set[str]:
    if not path.exists():
        return set()
    data = load_json(path)
    return {str(row["raw_key"]) for row in data.get("rows", []) if isinstance(row, Mapping) and row.get("raw_key")}


def validate_baseline(rows: list[dict[str, Any]]) -> ValidationResult:
    checks, _, errors = _baseline_checks(rows)
    return ValidationResult(not errors, errors, checks)


def _expected_identity(row: Mapping[str, Any]) -> dict[str, Any]:
    identity = row["frozen_identity"]
    return {
        "template_id": identity["template_id"],
        "frozen_order": identity["frozen_order"],
        "member_count": identity["member_count"],
        "member_set_sha256": identity["member_set_sha256"],
        "member_set_reference": identity["member_set_reference"],
    }


def _compare_identity(record_identity: Any, expected: Mapping[str, Any]) -> list[str]:
    if not isinstance(record_identity, Mapping):
        return ["template_identity must be an object"]
    return [
        f"template_identity.{key}: expected {expected_value!r}, got {record_identity.get(key)!r}"
        for key, expected_value in expected.items()
        if record_identity.get(key) != expected_value
    ]


def _compare_value(actual: Mapping[str, Any], key: str, expected: Any, prefix: str, errors: list[str]) -> None:
    if actual.get(key) != expected:
        errors.append(f"{prefix}.{key}: expected {expected!r}, got {actual.get(key)!r}")


def validate_record(
    record: Mapping[str, Any],
    crosswalk_rows: list[dict[str, Any]],
    *,
    schema: Mapping[str, Any] | None = None,
    blocked31_keys: set[str] | None = None,
) -> ValidationResult:
    schema = schema or load_json(SCHEMA_FILE)
    blocked31_keys = blocked31_keys if blocked31_keys is not None else load_blocked31_keys()
    errors = _schema_errors(record, schema)
    baseline = validate_baseline(crosswalk_rows)
    errors.extend(f"baseline:{error}" for error in baseline.errors)
    checks: dict[str, Any] = {"baseline": baseline.checks}

    identity = record.get("template_identity") if isinstance(record, Mapping) else None
    template_id = identity.get("template_id") if isinstance(identity, Mapping) else None
    rows_by_id = {
        row.get("frozen_identity", {}).get("template_id"): row for row in crosswalk_rows
    }
    parent_row = rows_by_id.get(template_id)
    if parent_row is None:
        errors.append(f"template_identity.template_id is not one of the frozen Exact12 IDs: {template_id!r}")
        return ValidationResult(False, errors, checks)

    expected_identity = _expected_identity(parent_row)
    identity_errors = _compare_identity(identity, expected_identity)
    errors.extend(identity_errors)
    errors.extend(_current_state_errors(record.get("current_state")))

    future = record.get("future_resolution")
    if not isinstance(future, Mapping):
        errors.append("future_resolution must be an object")
        return ValidationResult(False, errors, checks)
    if future.get("resolution_outcome") != "JUSTIFIED_SPLIT_PROPOSAL":
        errors.append("strict split validator requires resolution_outcome JUSTIFIED_SPLIT_PROPOSAL")
    if future.get("outcome_authoritative") is not False:
        errors.append("future_resolution.outcome_authoritative must remain false for an unapplied proposal")
    _compare_value(future, "execution_authorized", False, "future_resolution", errors)
    _compare_value(future, "status_mutation", 0, "future_resolution", errors)
    _compare_value(future, "denominator_change", "NO", "future_resolution", errors)

    proposal = future.get("split_proposal")
    if not isinstance(proposal, Mapping):
        errors.append("future_resolution.split_proposal must be an object")
        return ValidationResult(False, errors, checks)

    parent_prefix = "future_resolution.split_proposal"
    parent_expected = {
        "parent_template_id": expected_identity["template_id"],
        "parent_frozen_order": expected_identity["frozen_order"],
        "parent_member_count": expected_identity["member_count"],
        "parent_member_set_sha256": expected_identity["member_set_sha256"],
        "parent_member_set_reference": expected_identity["member_set_reference"],
    }
    for key, expected_value in parent_expected.items():
        _compare_value(proposal, key, expected_value, parent_prefix, errors)

    parent_keys = set(parent_row["frozen_identity"]["member_keys"])
    children = proposal.get("child_partitions")
    child_ids_declared = proposal.get("child_partition_ids")
    if not isinstance(children, list):
        errors.append(f"{parent_prefix}.child_partitions must be an array")
        return ValidationResult(False, errors, checks)
    if len(children) < 2:
        errors.append(f"{parent_prefix}.child_partitions must contain at least two children")
    if not isinstance(child_ids_declared, list):
        errors.append(f"{parent_prefix}.child_partition_ids must be an array")
        child_ids_declared = []

    child_ids: list[str] = []
    child_orders: list[int] = []
    all_child_keys: list[str] = []
    child_hash_results: list[dict[str, Any]] = []
    for index, child in enumerate(children):
        if not isinstance(child, Mapping):
            errors.append(f"{parent_prefix}.child_partitions[{index}] must be an object")
            continue
        child_id = child.get("child_id")
        child_order = child.get("child_order")
        keys = child.get("member_keys")
        child_ids.append(str(child_id))
        if isinstance(child_order, int) and not isinstance(child_order, bool):
            child_orders.append(child_order)
        if not isinstance(keys, list):
            errors.append(f"{parent_prefix}.child_partitions[{index}].member_keys must be an array")
            keys = []
        key_strings = [str(key) for key in keys]
        all_child_keys.extend(key_strings)
        actual_hash = key_hash(key_strings)
        count_ok = child.get("member_count") == len(key_strings)
        hash_ok = child.get("member_set_sha256") == actual_hash
        if not count_ok:
            errors.append(
                f"{parent_prefix}.child_partitions[{index}].member_count must equal member_keys length"
            )
        if not hash_ok:
            errors.append(
                f"{parent_prefix}.child_partitions[{index}].member_set_sha256 must equal canonical member-key hash"
            )
        if len(key_strings) != len(set(key_strings)):
            errors.append(f"{parent_prefix}.child_partitions[{index}] contains duplicate member keys")
        outside = sorted(set(key_strings) - parent_keys)
        if outside:
            errors.append(
                f"{parent_prefix}.child_partitions[{index}] contains members outside the frozen parent: {outside}"
            )
        child_hash_results.append({
            "child_id": child_id,
            "member_count_matches": count_ok,
            "member_hash_matches": hash_ok,
            "outside_parent_members": outside,
        })

    duplicate_child_ids = sorted({child_id for child_id, count in Counter(child_ids).items() if count > 1})
    if duplicate_child_ids:
        errors.append(f"{parent_prefix}.child_partitions child_id values must be unique: {duplicate_child_ids}")
    if len(set(child_orders)) != len(child_orders):
        errors.append(f"{parent_prefix}.child_partitions child_order values must be unique")
    expected_orders = list(range(1, len(children) + 1))
    if child_orders != expected_orders:
        errors.append(
            f"{parent_prefix}.child_partitions child_order must be consecutive {expected_orders}, got {child_orders}"
        )
    if child_ids_declared != child_ids:
        errors.append(
            f"{parent_prefix}.child_partition_ids must exactly match child_partitions child_id order"
        )
    if len(child_ids_declared) != len(set(child_ids_declared)):
        errors.append(f"{parent_prefix}.child_partition_ids must contain unique IDs")

    member_counts = Counter(all_child_keys)
    duplicate_member_count = sum(count - 1 for count in member_counts.values() if count > 1)
    union_keys = set(all_child_keys)
    unassigned_member_count = len(parent_keys - union_keys)
    pairwise_overlap_count = 0
    child_sets: list[set[str]] = []
    for child in children:
        keys = child.get("member_keys", []) if isinstance(child, Mapping) else []
        child_sets.append(set(str(key) for key in keys) if isinstance(keys, list) else set())
    for index, left in enumerate(child_sets):
        for right in child_sets[index + 1 :]:
            pairwise_overlap_count += len(left & right)
    union_equals_parent = union_keys == parent_keys and len(union_keys) == len(parent_keys)
    child_member_count_sum = sum(len(child.get("member_keys", [])) for child in children if isinstance(child, Mapping) and isinstance(child.get("member_keys"), list))
    count_conserved = child_member_count_sum == expected_identity["member_count"] and duplicate_member_count == 0 and unassigned_member_count == 0
    hashes_recomputed = all(item["member_count_matches"] and item["member_hash_matches"] for item in child_hash_results)
    other_parent_keys = set().union(
        *(set(row["frozen_identity"]["member_keys"]) for row in crosswalk_rows if row is not parent_row)
    )
    cross_template_overlap_count = len(union_keys & other_parent_keys)
    blocked31_overlap_count = len(union_keys & blocked31_keys)
    computed_conservation = {
        "parent_member_count": expected_identity["member_count"],
        "child_member_count_sum": child_member_count_sum,
        "child_union_equals_parent": union_equals_parent,
        "pairwise_child_overlap_count": pairwise_overlap_count,
        "unassigned_member_count": unassigned_member_count,
        "duplicate_member_count": duplicate_member_count,
        "count_conserved": count_conserved,
        "hashes_recomputed": hashes_recomputed,
        "parent_hash_revalidated": proposal.get("parent_member_set_sha256") == expected_identity["member_set_sha256"],
        "cross_template_overlap_count": cross_template_overlap_count,
        "blocked31_overlap_count": blocked31_overlap_count,
    }
    checks["split_recomputation"] = {
        **computed_conservation,
        "child_ids_unique": not duplicate_child_ids,
        "child_orders_consecutive": child_orders == expected_orders,
        "child_partition_ids_match": child_ids_declared == child_ids,
        "child_hash_results": child_hash_results,
    }

    submitted_conservation = proposal.get("conservation_result")
    if not isinstance(submitted_conservation, Mapping):
        errors.append(f"{parent_prefix}.conservation_result must be an object")
    else:
        for key, expected_value in computed_conservation.items():
            _compare_value(submitted_conservation, key, expected_value, f"{parent_prefix}.conservation_result", errors)
        if submitted_conservation.get("conservation_check_reference") in (None, ""):
            errors.append(f"{parent_prefix}.conservation_result.conservation_check_reference is required")

    top_level_conservation = future.get("member_conservation_check")
    expected_top_level = {
        "parent_member_count": expected_identity["member_count"],
        "child_member_count": child_member_count_sum,
        "union_equals_parent": union_equals_parent,
        "pairwise_overlap_count": pairwise_overlap_count,
        "count_conserved": count_conserved,
        "hashes_recomputed": hashes_recomputed,
    }
    if not isinstance(top_level_conservation, Mapping):
        errors.append("future_resolution.member_conservation_check must be an object")
    else:
        for key, expected_value in expected_top_level.items():
            _compare_value(top_level_conservation, key, expected_value, "future_resolution.member_conservation_check", errors)

    _compare_value(proposal, "applied", False, parent_prefix, errors)
    _compare_value(proposal, "execution_authorized", False, parent_prefix, errors)
    _compare_value(proposal, "status_mutation", 0, parent_prefix, errors)
    _compare_value(proposal, "denominator_change", "NO", parent_prefix, errors)
    checks["valid_parent_identity"] = not identity_errors
    checks["valid_conservation"] = not any(
        error.startswith((f"{parent_prefix}.conservation_result", "future_resolution.member_conservation_check"))
        for error in errors
    )
    return ValidationResult(not errors, errors, checks)


def build_valid_record(crosswalk_rows: list[dict[str, Any]]) -> dict[str, Any]:
    row = crosswalk_rows[0]
    identity = row["frozen_identity"]
    keys = list(identity["member_keys"])
    split_at = len(keys) // 2
    partitions = [keys[:split_at], keys[split_at:]]
    children = []
    for order, partition in enumerate(partitions, 1):
        children.append({
            "child_id": f"{identity['template_id']}::fixture-child-{order}",
            "child_order": order,
            "member_keys": partition,
            "member_count": len(partition),
            "member_set_sha256": key_hash(partition),
            "member_set_reference": f"fixture://child/{order}",
            "child_evidence_reference": f"fixture://evidence/child/{order}",
        })
    child_sum = sum(len(partition) for partition in partitions)
    proposal = {
        "proposal_id": "fixture-valid-split-proposal",
        "parent_template_id": identity["template_id"],
        "parent_frozen_order": identity["frozen_order"],
        "parent_member_count": identity["member_count"],
        "parent_member_set_sha256": identity["member_set_sha256"],
        "parent_member_set_reference": identity["member_set_reference"],
        "partition_basis": {
            "basis_type": "SOURCE_GROUNDED_SEMANTIC_BOUNDARY",
            "rationale": "Synthetic validator fixture only; not a future disposition.",
        },
        "partition_predicate": {
            "predicate_id": "fixture-predicate",
            "expression": "fixture_member_position < midpoint",
            "input_fields": ["fixture_member_position"],
            "source_grounded_reference": "fixture://source-grounded-test-input",
            "deterministic": True,
            "source_grounded": True,
            "unknown_treatment": "UNKNOWN_IS_NOT_A_BOUNDARY",
        },
        "partition_evidence_references": ["fixture://partition-evidence"],
        "child_partition_ids": [child["child_id"] for child in children],
        "child_partitions": children,
        "conservation_result": {
            "parent_member_count": identity["member_count"],
            "child_member_count_sum": child_sum,
            "child_union_equals_parent": True,
            "pairwise_child_overlap_count": 0,
            "unassigned_member_count": 0,
            "duplicate_member_count": 0,
            "count_conserved": True,
            "hashes_recomputed": True,
            "parent_hash_revalidated": True,
            "cross_template_overlap_count": 0,
            "blocked31_overlap_count": 0,
            "conservation_check_reference": "fixture://conservation-check",
        },
        "independent_partition_review_reference": "fixture://independent-review",
        "approval_reference": None,
        "applied": False,
        "execution_authorized": False,
        "status_mutation": 0,
        "denominator_change": "NO",
    }
    return {
        "record_type": "E0C_EXACT12_TEMPLATE_LEVEL_RESOLUTION_RECORD",
        "schema_version": "e0c-exact12-template-level-resolution-schema-r2",
        "reviewed_state_anchor": {
            "materialization_commit": "f10c874513071345ddc2411004f81ee5c57f4065",
            "independent_review_commit": "38468ed7968d4030b2c070f381c35bae52452dbb",
        },
        "template_identity": {
            "template_id": identity["template_id"],
            "frozen_order": identity["frozen_order"],
            "member_count": identity["member_count"],
            "member_set_sha256": identity["member_set_sha256"],
            "member_set_reference": identity["member_set_reference"],
            "decision_packet_member_set_reference": identity["member_set_reference"],
        },
        "current_state": {
            "source_human_decision": EXPECTED_SOURCE_DECISION,
            "resolution_state": EXPECTED_RESOLUTION_STATE,
            "r3_global_planning_status": EXPECTED_PLANNING_STATUS,
            "current_split_status": EXPECTED_SPLIT_STATUS,
            "applied_split": False,
            "status_mutations": 0,
            "formal_execution_authorized": False,
        },
        "future_resolution": {
            "resolution_outcome": "JUSTIFIED_SPLIT_PROPOSAL",
            "outcome_authoritative": False,
            "evidence_manifest_reference": "fixture://evidence-manifest",
            "review_record_reference": "fixture://review-record",
            "member_conservation_check": {
                "parent_member_count": identity["member_count"],
                "child_member_count": child_sum,
                "union_equals_parent": True,
                "pairwise_overlap_count": 0,
                "count_conserved": True,
                "hashes_recomputed": True,
            },
            "execution_authorized": False,
            "status_mutation": 0,
            "denominator_change": "NO",
            "split_proposal": proposal,
        },
    }


def build_negative_records(valid_record: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    fixtures: dict[str, dict[str, Any]] = {}

    record = deepcopy(valid_record)
    record["future_resolution"]["split_proposal"]["child_partitions"][0]["member_count"] += 1
    fixtures["NEGATIVE_MALFORMED_CHILD_COUNT"] = record

    record = deepcopy(valid_record)
    record["future_resolution"]["split_proposal"]["child_partitions"][0]["member_set_sha256"] = "0" * 64
    fixtures["NEGATIVE_MALFORMED_CHILD_HASH"] = record

    record = deepcopy(valid_record)
    record["future_resolution"]["split_proposal"]["parent_template_id"] = "wrong-parent-template"
    fixtures["NEGATIVE_INVALID_PARENT_IDENTITY"] = record

    record = deepcopy(valid_record)
    first_id = record["future_resolution"]["split_proposal"]["child_partitions"][0]["child_id"]
    record["future_resolution"]["split_proposal"]["child_partitions"][1]["child_id"] = first_id
    record["future_resolution"]["split_proposal"]["child_partition_ids"][1] = first_id
    fixtures["NEGATIVE_DUPLICATE_CHILD_ID"] = record

    record = deepcopy(valid_record)
    removed = record["future_resolution"]["split_proposal"]["child_partitions"][1]["member_keys"].pop()
    del removed
    fixtures["NEGATIVE_INCOMPLETE_CHILD_PARTITION"] = record

    record = deepcopy(valid_record)
    overlap_key = record["future_resolution"]["split_proposal"]["child_partitions"][0]["member_keys"][0]
    record["future_resolution"]["split_proposal"]["child_partitions"][1]["member_keys"].append(overlap_key)
    fixtures["NEGATIVE_OVERLAPPING_CHILD_PARTITION"] = record

    record = deepcopy(valid_record)
    record["future_resolution"]["split_proposal"]["conservation_result"]["child_union_equals_parent"] = True
    record["future_resolution"]["split_proposal"]["conservation_result"]["unassigned_member_count"] = 0
    record["future_resolution"]["split_proposal"]["conservation_result"]["duplicate_member_count"] = 0
    record["future_resolution"]["split_proposal"]["child_partitions"][1]["member_keys"].pop()
    fixtures["NEGATIVE_FALSE_CONSERVATION_CLAIM"] = record

    record = deepcopy(valid_record)
    record["future_resolution"]["split_proposal"]["parent_member_set_sha256"] = "f" * 64
    fixtures["NEGATIVE_INVALID_PARENT_HASH"] = record

    record = deepcopy(valid_record)
    record["future_resolution"]["split_proposal"]["child_partitions"][0]["member_keys"].append(
        "9999999::S99::A999"
    )
    fixtures["NEGATIVE_MEMBER_OUTSIDE_PARENT"] = record

    return fixtures


def generate_fixtures(crosswalk_rows: list[dict[str, Any]], fixture_dir: Path) -> dict[str, Any]:
    fixture_dir.mkdir(parents=True, exist_ok=True)
    valid = build_valid_record(crosswalk_rows)
    (fixture_dir / "VALID_SPLIT_PROPOSAL_FIXTURE.json").write_text(
        json.dumps(valid, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    manifest = []
    for fixture_id, record in build_negative_records(valid).items():
        filename = f"{fixture_id}.json"
        (fixture_dir / filename).write_text(
            json.dumps(record, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )
        manifest.append({"fixture_id": fixture_id, "filename": filename, "expected": "REJECT"})
    (fixture_dir / "FIXTURE_MANIFEST.json").write_text(
        json.dumps({"fixture_type": "NON_AUTHORITATIVE_SPLIT_VALIDATION_ONLY", "fixtures": manifest}, indent=2) + "\n",
        encoding="utf-8",
    )
    return {"valid_fixture": "VALID_SPLIT_PROPOSAL_FIXTURE.json", "negative_fixtures": manifest}


def validate_fixture_directory(
    crosswalk_rows: list[dict[str, Any]], fixture_dir: Path
) -> dict[str, Any]:
    schema = load_json(SCHEMA_FILE)
    valid_path = fixture_dir / "VALID_SPLIT_PROPOSAL_FIXTURE.json"
    valid_result = validate_record(load_json(valid_path), crosswalk_rows, schema=schema)
    negative_results = []
    for path in sorted(fixture_dir.glob("NEGATIVE_*.json")):
        result = validate_record(load_json(path), crosswalk_rows, schema=schema)
        negative_results.append({
            "filename": path.name,
            "status": "REJECTED" if not result.valid else "ACCEPTED",
            "error_count": len(result.errors),
            "errors": result.errors,
        })
    return {
        "valid_fixture": {
            "filename": valid_path.name,
            "status": "ACCEPTED" if valid_result.valid else "REJECTED",
            "error_count": len(valid_result.errors),
            "errors": valid_result.errors,
        },
        "negative_fixtures": negative_results,
        "all_negative_rejected": all(item["status"] == "REJECTED" for item in negative_results),
    }


def build_evidence(package_dir: Path = PACKAGE_DIR) -> dict[str, Any]:
    schema = load_json(package_dir / "TEMPLATE_LEVEL_RESOLUTION_SCHEMA.json")
    Draft202012Validator.check_schema(schema)
    rows = load_jsonl(package_dir / "EXACT12_RESOLUTION_CROSSWALK.jsonl")
    baseline = validate_baseline(rows)
    classes = [item["evidence_class"] for item in load_json(package_dir / "MORE_EVIDENCE_ACQUISITION_CONTRACT.json")["evidence_request_classes"]]
    fixture_results = validate_fixture_directory(rows, package_dir / "fixtures")
    boundary = load_json(package_dir / "ZERO_MUTATION_BOUNDARY.json")
    terminal = {
        "E0C_SPLIT_RESOLUTION_DESIGN_R2": "PASS_READY_FOR_INDEPENDENT_REVIEW" if baseline.valid and fixture_results["valid_fixture"]["status"] == "ACCEPTED" and fixture_results["all_negative_rejected"] and {"PARTITION", "GOVERNANCE"}.issubset(classes) else "BLOCKED",
        "FROZEN_TEMPLATE_COUNT": baseline.checks["template_count"],
        "FROZEN_RAW_COVERAGE": baseline.checks["raw_count_sum"],
        "CURRENT_REQUEST_MORE_EVIDENCE_COUNT": sum(row["current_state"]["resolution_state"] == EXPECTED_RESOLUTION_STATE for row in rows),
        "SCHEMA_META_VALIDATION": "PASS",
        "STRICT_SEMANTIC_VALIDATION": "PASS" if fixture_results["valid_fixture"]["status"] == "ACCEPTED" and fixture_results["all_negative_rejected"] else "BLOCKED",
        "PARTITION_EVIDENCE_CLASS_PRESENT": "PASS" if "PARTITION" in classes else "BLOCKED",
        "GOVERNANCE_EVIDENCE_CLASS_PRESENT": "PASS" if "GOVERNANCE" in classes else "BLOCKED",
        "EXACT12_MEMBER_CONSERVATION": "PASS" if baseline.valid else "BLOCKED",
        "APPLIED_SPLITS": boundary["terminal"]["APPLIED_SPLITS"],
        "STATUS_MUTATIONS": boundary["terminal"]["STATUS_MUTATIONS"],
        "EXECUTION_AUTHORIZATIONS": boundary["terminal"]["EXECUTION_AUTHORIZATIONS"],
        "DENOMINATOR_CHANGE": boundary["terminal"]["DENOMINATOR_CHANGE"],
        "FORMAL_EXPERIMENT_EXECUTED": boundary["terminal"]["FORMAL_EXPERIMENT_EXECUTED"],
        "HUMAN_DECISIONS_CREATED": 0,
        "PUSH_EXECUTED": boundary["terminal"]["PUSH_EXECUTED"],
        "NEXT_ACTION": "INDEPENDENT_REVIEW_OF_RESOLUTION_DESIGN_R2",
        "STOP": True,
    }
    return {
        "artifact_type": "E0C_EXACT12_SPLIT_OR_MORE_EVIDENCE_RESOLUTION_DESIGN_R2_VALIDATION_EVIDENCE",
        "read_only": True,
        "schema_meta_validation": "PASS",
        "acquisition_evidence_classes": classes,
        "baseline": baseline.checks,
        "baseline_errors": baseline.errors,
        "fixture_results": fixture_results,
        "human_decisions_created": 0,
        "authority_mutation": "NO",
        "boundary_terminal": boundary["terminal"],
        "terminal": terminal,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate-fixtures", action="store_true")
    parser.add_argument("--write-evidence", action="store_true")
    args = parser.parse_args(argv)
    rows = load_jsonl(CROSSWALK_FILE)
    if args.generate_fixtures:
        generate_fixtures(rows, PACKAGE_DIR / "fixtures")
    if args.write_evidence:
        evidence = build_evidence(PACKAGE_DIR)
        (PACKAGE_DIR / "E0C_EXACT12_SPLIT_OR_MORE_EVIDENCE_RESOLUTION_DESIGN_R2_VALIDATION_EVIDENCE.json").write_text(
            json.dumps(evidence, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )
    baseline = validate_baseline(rows)
    fixture_dir = PACKAGE_DIR / "fixtures"
    fixture_results = validate_fixture_directory(rows, fixture_dir) if (fixture_dir / "VALID_SPLIT_PROPOSAL_FIXTURE.json").exists() else None
    if not baseline.valid:
        print("baseline=BLOCKED")
        print("\n".join(baseline.errors))
        return 1
    if fixture_results is not None:
        print(f"valid_fixture={fixture_results['valid_fixture']['status']}")
        print(f"negative_fixtures={len(fixture_results['negative_fixtures'])}")
        print(f"all_negative_rejected={fixture_results['all_negative_rejected']}")
        if fixture_results["valid_fixture"]["status"] != "ACCEPTED" or not fixture_results["all_negative_rejected"]:
            return 1
    print("baseline=PASS")
    print("strict_validation=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
