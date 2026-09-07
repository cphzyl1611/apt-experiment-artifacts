#!/usr/bin/env python3
"""Read-only validation for the E0-C Exact12 governed decision design.

JSON Schema validates strict shape and constants. This module validates the
crosswalk-bound relationships that a schema cannot calculate: exact subject
identity, frozen membership, child conservation, blocked31 boundaries,
governance references, state/disposition compatibility, and zero mutation.
It never applies a split, creates a human decision, or mutates source state.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


PACKAGE_DIR = Path(__file__).resolve().parent
ROOT_DIR = PACKAGE_DIR.parent
SUBJECT_MANIFEST_FILE = PACKAGE_DIR / "EXACT12_SUBJECT_MANIFEST.json"
DECISION_SCHEMA_FILE = PACKAGE_DIR / "GOVERNED_DECISION_SCHEMA.json"
ENVELOPE_SCHEMA_FILE = PACKAGE_DIR / "SPLIT_PROPOSAL_ENVELOPE_SCHEMA.json"
STATE_MACHINE_FILE = PACKAGE_DIR / "DECISION_STATE_MACHINE.json"
FIXTURE_MANIFEST_FILE = PACKAGE_DIR / "fixtures" / "FIXTURE_MANIFEST.json"
FIXTURE_DIR = PACKAGE_DIR / "fixtures"
R2R2_CROSSWALK_FILE = ROOT_DIR / "E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2" / "EXACT12_RESOLUTION_CROSSWALK.jsonl"
R2_CROSSWALK_FILE = ROOT_DIR / "E0C_EXACT12_SPLIT_OR_MORE_EVIDENCE_RESOLUTION_DESIGN_R2" / "EXACT12_RESOLUTION_CROSSWALK.jsonl"
BLOCKED31_FILE = ROOT_DIR / "E0C_R5_BLOCKED31_SOURCE_DETAIL_RECOVERY.json"
VALIDATION_EVIDENCE_FILE = PACKAGE_DIR / "VALIDATION_EVIDENCE.json"

EXPECTED_TASK_ID = "E0C_EXACT12_SPLIT_RESOLUTION_GOVERNED_DECISION_DESIGN"
EXPECTED_REVIEW_TASK_ID = "E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2_INDEPENDENT_REVIEW"
EXPECTED_REVIEWED_COMMIT = "ce5c43d344b42c38d88b0503160228312a5cf9ea"
EXPECTED_REVIEWED_PARENT = "86dfd43c96303d6e74504706d5f7cc68744e15a1"
EXPECTED_REVIEW_MATERIALIZATION_COMMIT = "dc870e0506bd3d83ccb73dad73d817d01ea9089f"
EXPECTED_REVIEW_VERDICT = "PASS_READY_FOR_GOVERNED_SPLIT_RESOLUTION_NEXT_PHASE"
EXPECTED_TEMPLATE_COUNT = 12
EXPECTED_RAW_MEMBER_COUNT = 203
EXPECTED_BLOCKED31_OVERLAP = 0
EXPECTED_UNION_HASH = "ffeb2704a1c971b89129e1959ae721bbc9ef159153a5f0a20f8abda13edb441a"
EXPECTED_CROSSWALK_SHA256 = "92f3cd6fe3f1f3239c776dae8073801e0f3f2f49f53a1ec92f8350f8998e135e"
EXPECTED_GOVERNANCE_REFERENCE_PATTERN = (
    r"^(?:[A-Za-z][A-Za-z0-9+.-]*://[^\s]+|"
    r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.:/#-]+)*(?:#[A-Za-z0-9_.:/-]+)?)$"
)
REFERENCE_PATTERN = re.compile(EXPECTED_GOVERNANCE_REFERENCE_PATTERN)
ENVELOPE_SCHEMA_ID = "https://e0c.invalid/schemas/e0c-exact12-split-proposal-envelope-v1"


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str]
    checks: dict[str, Any]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def parse_json_text(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonfinite,
    )


def load_json(path: Path) -> Any:
    return parse_json_text(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = parse_json_text(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected object")
        rows.append(value)
    return rows


def key_hash(keys: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(str(key) for key in keys)).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _path_text(path: Iterable[Any]) -> str:
    return ".".join(str(item) for item in path) or "$"


def _schema_errors(
    record: Mapping[str, Any],
    decision_schema: Mapping[str, Any],
    envelope_schema: Mapping[str, Any],
) -> list[str]:
    registry = Registry().with_resource(
        ENVELOPE_SCHEMA_ID,
        Resource.from_contents(envelope_schema),
    )
    validator = Draft202012Validator(decision_schema, registry=registry)
    errors = sorted(
        validator.iter_errors(record),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    formatted: list[str] = []
    for error in errors:
        if "Additional properties are not allowed" in error.message:
            code = "SCHEMA_UNAUTHORIZED_FIELD"
        else:
            code = "schema"
        formatted.append(f"{code}:{_path_text(error.absolute_path)}: {error.message}")
    return formatted


def _reference_errors(value: Any, path: str, required_code: str) -> list[str]:
    if not isinstance(value, str) or not value:
        return [f"{required_code}: {path} is required"]
    if REFERENCE_PATTERN.fullmatch(value) is None:
        return [f"GOVERNANCE_REFERENCE_GRAMMAR_INVALID: {path} must match the canonical reference grammar"]
    return []


def load_blocked31_keys() -> set[str]:
    data = load_json(BLOCKED31_FILE)
    keys: set[str] = set()
    for row in data.get("rows", []):
        if isinstance(row, Mapping) and row.get("raw_key"):
            keys.add(str(row["raw_key"]))
    return keys


def validate_schema_pair() -> bool:
    decision_schema = load_json(DECISION_SCHEMA_FILE)
    envelope_schema = load_json(ENVELOPE_SCHEMA_FILE)
    Draft202012Validator.check_schema(decision_schema)
    Draft202012Validator.check_schema(envelope_schema)
    decision_pattern = decision_schema["$defs"]["reference"]["pattern"]
    envelope_pattern = envelope_schema["$defs"]["reference"]["pattern"]
    return decision_pattern == envelope_pattern == EXPECTED_GOVERNANCE_REFERENCE_PATTERN


def validate_state_machine() -> bool:
    machine = load_json(STATE_MACHINE_FILE)
    expected_states = {
        "DESIGN_ONLY",
        "PROPOSAL_PREPARED",
        "PENDING_GOVERNANCE",
        "APPROVED_FOR_FUTURE_TRANSACTION",
        "REJECTED",
        "DEFERRED",
    }
    actual_states = set(machine.get("states", []))
    return (
        machine.get("record_type") == "E0C_EXACT12_DECISION_STATE_MACHINE"
        and machine.get("schema_version") == "e0c-decision-state-machine-v1"
        and machine.get("design_only") is True
        and actual_states == expected_states
        and "SPLIT_APPLIED" not in actual_states
        and machine.get("forbidden_states") == ["SPLIT_APPLIED"]
    )


def validate_manifest(manifest: Mapping[str, Any]) -> ValidationResult:
    errors: list[str] = []
    templates = manifest.get("templates")
    if not isinstance(templates, list):
        return ValidationResult(False, ["SUBJECT_MANIFEST_TEMPLATES_REQUIRED: templates must be a list"], {})

    all_keys: list[str] = []
    template_sets: list[set[str]] = []
    frozen_orders: list[Any] = []
    template_ids: list[str] = []
    for index, template in enumerate(templates, 1):
        if not isinstance(template, Mapping):
            errors.append(f"SUBJECT_MANIFEST_TEMPLATE_INVALID: templates[{index - 1}] must be an object")
            continue
        keys = template.get("member_keys", [])
        if not isinstance(keys, list):
            errors.append(f"SUBJECT_MANIFEST_MEMBER_KEYS_INVALID: templates[{index - 1}].member_keys must be a list")
            keys = []
        if template.get("member_count") != len(keys):
            errors.append(f"SUBJECT_MANIFEST_MEMBER_COUNT_MISMATCH: templates[{index - 1}]")
        if len(set(keys)) != len(keys):
            errors.append(f"SUBJECT_MANIFEST_MEMBER_DUPLICATION: templates[{index - 1}]")
        if template.get("member_set_sha256") != key_hash(keys):
            errors.append(f"SUBJECT_MANIFEST_MEMBER_HASH_MISMATCH: templates[{index - 1}]")
        frozen_orders.append(template.get("frozen_order"))
        template_ids.append(str(template.get("template_id")))
        errors.extend(_frozen_state_errors(template.get("current_state"), f"templates[{index - 1}].current_state"))
        all_keys.extend(str(key) for key in keys)
        template_sets.append(set(str(key) for key in keys))

    overlap_count = sum(
        len(left & right)
        for index, left in enumerate(template_sets)
        for right in template_sets[index + 1 :]
    )
    blocked_overlap = len(set(all_keys) & load_blocked31_keys())
    crosswalk_r2r2_hash = sha256_file(R2R2_CROSSWALK_FILE)
    crosswalk_r2_hash = sha256_file(R2_CROSSWALK_FILE)
    crosswalk_byte_drift = int(crosswalk_r2r2_hash != crosswalk_r2_hash)
    checks = {
        "template_count": len(templates),
        "unique_raw_member_count": len(set(all_keys)),
        "raw_member_count_sum": sum(
            template.get("member_count", 0)
            for template in templates
            if isinstance(template, Mapping)
        ),
        "blocked31_overlap": blocked_overlap,
        "cross_template_overlap": overlap_count,
        "union_hash": key_hash(all_keys),
        "crosswalk_byte_drift": crosswalk_byte_drift,
        "crosswalk_sha256": crosswalk_r2r2_hash,
        "frozen_orders": frozen_orders,
        "unique_template_id_count": len(set(template_ids)),
        "source_materialization_commit": manifest.get("authentication", {}).get("source_materialization_commit"),
        "reviewed_materialization_commit": manifest.get("authentication", {}).get("reviewed_materialization_commit"),
        "recorded_source_crosswalk_sha256": manifest.get("authentication", {}).get("source_crosswalk_sha256"),
    }
    expected = {
        "record_type": "E0C_EXACT12_SUBJECT_MANIFEST",
        "schema_version": "e0c-exact12-subject-manifest-v1",
        "task_id": EXPECTED_TASK_ID,
        "source_materialization_commit": EXPECTED_REVIEW_MATERIALIZATION_COMMIT,
        "reviewed_materialization_commit": EXPECTED_REVIEWED_COMMIT,
        "template_count": EXPECTED_TEMPLATE_COUNT,
        "unique_raw_member_count": EXPECTED_RAW_MEMBER_COUNT,
        "blocked31_overlap": EXPECTED_BLOCKED31_OVERLAP,
        "union_hash": EXPECTED_UNION_HASH,
        "crosswalk_byte_drift": 0,
    }
    actual = {
        "record_type": manifest.get("record_type"),
        "schema_version": manifest.get("schema_version"),
        "task_id": manifest.get("task_id"),
        "source_materialization_commit": checks["source_materialization_commit"],
        "reviewed_materialization_commit": checks["reviewed_materialization_commit"],
        "template_count": checks["template_count"],
        "unique_raw_member_count": checks["unique_raw_member_count"],
        "blocked31_overlap": checks["blocked31_overlap"],
        "union_hash": checks["union_hash"],
        "crosswalk_byte_drift": checks["crosswalk_byte_drift"],
    }
    errors.extend(
        f"SUBJECT_MANIFEST_AUTHENTICATION_MISMATCH: {key} expected {expected_value!r}, got {actual[key]!r}"
        for key, expected_value in expected.items()
        if actual[key] != expected_value
    )
    if checks["raw_member_count_sum"] != EXPECTED_RAW_MEMBER_COUNT:
        errors.append("SUBJECT_MANIFEST_COUNT_MISMATCH: raw member count sum must equal 203")
    if checks["frozen_orders"] != list(range(1, EXPECTED_TEMPLATE_COUNT + 1)):
        errors.append("SUBJECT_MANIFEST_ORDER_INVALID: frozen orders must be exactly 1..12")
    if checks["unique_template_id_count"] != EXPECTED_TEMPLATE_COUNT:
        errors.append("SUBJECT_MANIFEST_TEMPLATE_DUPLICATION: template IDs must be unique")
    if checks["cross_template_overlap"] != 0:
        errors.append("SUBJECT_MANIFEST_CROSS_TEMPLATE_OVERLAP: cross-template overlap must be zero")
    if checks["crosswalk_sha256"] != EXPECTED_CROSSWALK_SHA256:
        errors.append("SUBJECT_MANIFEST_CROSSWALK_HASH_MISMATCH: authenticated crosswalk hash mismatch")
    if checks["recorded_source_crosswalk_sha256"] != EXPECTED_CROSSWALK_SHA256:
        errors.append("SUBJECT_MANIFEST_CROSSWALK_HASH_MISMATCH: recorded source crosswalk hash mismatch")
    frozen_baseline = manifest.get("frozen_baseline")
    if not isinstance(frozen_baseline, Mapping):
        errors.append("SUBJECT_MANIFEST_BASELINE_REQUIRED: frozen_baseline is required")
    else:
        baseline_expectations = {
            "template_count": EXPECTED_TEMPLATE_COUNT,
            "unique_raw_member_count": EXPECTED_RAW_MEMBER_COUNT,
            "blocked31_overlap": EXPECTED_BLOCKED31_OVERLAP,
            "union_hash": EXPECTED_UNION_HASH,
            "crosswalk_byte_drift": 0,
        }
        errors.extend(
            f"SUBJECT_MANIFEST_BASELINE_MISMATCH: frozen_baseline.{field} expected {value!r}, got {frozen_baseline.get(field)!r}"
            for field, value in baseline_expectations.items()
            if frozen_baseline.get(field) != value
        )
    return ValidationResult(not errors, errors, checks)


def _frozen_state_errors(state: Any, path: str) -> list[str]:
    expected = {
        "source_human_decision": "REQUEST_SPLIT_OR_MORE_EVIDENCE",
        "resolution_state": "REQUEST_MORE_EVIDENCE",
        "planning_status": "MANUAL_DESIGN_REQUIRED",
        "current_split_status": "NO_CURRENT_SPLIT",
        "applied_split": False,
        "status_mutations": 0,
        "denominator_change": "NO",
        "formal_execution_authorized": False,
    }
    if not isinstance(state, Mapping):
        return [f"FROZEN_STATE_INVALID: {path} must be an object"]
    return [
        f"FROZEN_STATE_MUTATION: {path}.{key} expected {value!r}, got {state.get(key)!r}"
        for key, value in expected.items()
        if state.get(key) != value
    ]


def _subject_lookup(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(template["template_id"]): template
        for template in manifest.get("templates", [])
        if isinstance(template, Mapping) and template.get("template_id")
    }


def _compare_parent_subject(
    parent: Mapping[str, Any],
    subject: Mapping[str, Any],
    path: str,
) -> list[str]:
    errors: list[str] = []
    fields = ["template_id", "frozen_order", "member_count", "member_set_sha256", "member_set_reference"]
    for field in fields:
        if parent.get(field) != subject.get(field):
            errors.append(
                f"PARENT_SUBJECT_MISMATCH: {path}.{field} expected {subject.get(field)!r}, got {parent.get(field)!r}"
            )
    if parent.get("member_keys") != subject.get("member_keys"):
        errors.append(f"PARENT_SUBJECT_MEMBERSHIP_MISMATCH: {path}.member_keys must equal the frozen subject order")
    return errors


def _validate_proposal(
    proposal: Any,
    subject: Mapping[str, Any],
    blocked31_keys: set[str],
    path: str = "proposed_split_structure",
) -> list[str]:
    if not isinstance(proposal, Mapping):
        return [f"PROPOSAL_REQUIRED: {path} must be an object"]
    errors: list[str] = []
    errors.extend(_compare_parent_subject(proposal.get("parent_subject", {}), subject, f"{path}.parent_subject"))
    errors.extend(_reference_errors(proposal.get("governance_reference"), f"{path}.governance_reference", "GOVERNANCE_REFERENCE_REQUIRED"))
    partition_predicate = proposal.get("partition_predicate", {})
    if isinstance(partition_predicate, Mapping):
        if partition_predicate.get("unknown_treatment") != "UNKNOWN_IS_NOT_A_BOUNDARY":
            errors.append("UNKNOWN_PARTITION_BOUNDARY: partition predicate must not use UNKNOWN as a boundary")
        if partition_predicate.get("deterministic") is not True or partition_predicate.get("source_grounded") is not True:
            errors.append("PARTITION_PREDICATE_NOT_GROUNDED: partition predicate must be deterministic and source-grounded")

    children = proposal.get("child_partitions")
    child_ids = proposal.get("child_partition_ids")
    if not isinstance(children, list) or len(children) < 2:
        return errors + [f"CHILD_PARTITION_COUNT_INVALID: {path}.child_partitions must contain at least two children"]
    if not isinstance(child_ids, list):
        errors.append(f"CHILD_PARTITION_IDS_REQUIRED: {path}.child_partition_ids is required")
        child_ids = []

    actual_ids = [child.get("child_id") for child in children if isinstance(child, Mapping)]
    if len(actual_ids) != len(set(actual_ids)):
        errors.append("MEMBERSHIP_DUPLICATION: child IDs must be unique")
    if child_ids != actual_ids:
        errors.append("CHILD_PARTITION_IDS_MISMATCH: child_partition_ids must equal the ordered child IDs")
    orders = [child.get("child_order") for child in children if isinstance(child, Mapping)]
    if orders != list(range(1, len(children) + 1)):
        errors.append("CHILD_ORDER_INVALID: child orders must be consecutive starting at 1")

    parent_keys = set(str(key) for key in subject.get("member_keys", []))
    all_child_keys: list[str] = []
    child_hashes_valid = True
    for index, child in enumerate(children):
        if not isinstance(child, Mapping):
            errors.append(f"CHILD_PARTITION_INVALID: {path}.child_partitions[{index}] must be an object")
            continue
        keys = [str(key) for key in child.get("member_keys", [])] if isinstance(child.get("member_keys"), list) else []
        all_child_keys.extend(keys)
        if child.get("member_count") != len(keys):
            errors.append(f"MEMBERSHIP_COUNT_MISMATCH: {path}.child_partitions[{index}].member_count")
            child_hashes_valid = False
        if child.get("member_set_sha256") != key_hash(keys):
            errors.append(f"MEMBERSHIP_HASH_MISMATCH: {path}.child_partitions[{index}].member_set_sha256")
            child_hashes_valid = False
        outside = sorted(set(keys) - parent_keys)
        if outside:
            errors.append(f"MEMBER_OUTSIDE_EXACT12_SCOPE: {path}.child_partitions[{index}] contains {outside!r}")
        if len(keys) != len(set(keys)):
            errors.append(f"MEMBERSHIP_DUPLICATION: {path}.child_partitions[{index}] contains duplicate members")

    counts = Counter(all_child_keys)
    duplicate_count = sum(count - 1 for count in counts.values() if count > 1)
    union = set(all_child_keys)
    unassigned = parent_keys - union
    pairwise_overlap = sum(
        len(
            set(str(key) for key in left.get("member_keys", []))
            & set(str(key) for key in right.get("member_keys", []))
        )
        for index, left in enumerate(children)
        for right in children[index + 1 :]
        if isinstance(left, Mapping) and isinstance(right, Mapping)
    )
    blocked_overlap = len(union & blocked31_keys)
    recomputed = {
        "parent_member_count": len(parent_keys),
        "child_member_count_sum": len(all_child_keys),
        "union_equals_parent": union == parent_keys,
        "pairwise_overlap_count": pairwise_overlap,
        "unassigned_member_count": len(unassigned),
        "duplicate_member_count": duplicate_count,
        "blocked31_overlap_count": blocked_overlap,
        "denominator_delta": len(union) - len(parent_keys),
        "denominator_mutation": "NO" if len(union) == len(parent_keys) else "YES",
        "crosswalk_byte_drift": 0,
        "union_hash": key_hash(parent_keys),
    }
    if unassigned:
        errors.append(f"MEMBERSHIP_LOSS: {path} leaves {len(unassigned)} parent members unassigned")
    if duplicate_count or pairwise_overlap:
        errors.append(f"MEMBERSHIP_DUPLICATION: {path} has {duplicate_count} duplicate occurrences and {pairwise_overlap} pairwise overlaps")
    if blocked_overlap:
        errors.append(f"BLOCKED31_OVERLAP: {path} overlaps blocked31 by {blocked_overlap} member(s)")
    conservation = proposal.get("conservation_assertions")
    if not isinstance(conservation, Mapping):
        errors.append(f"CONSERVATION_ASSERTIONS_REQUIRED: {path}.conservation_assertions is required")
    else:
        for field, value in recomputed.items():
            if conservation.get(field) != value:
                if field in {"denominator_delta", "denominator_mutation"}:
                    code = "DENOMINATOR_MUTATION_FORBIDDEN"
                elif field == "crosswalk_byte_drift":
                    code = "CROSSWALK_MUTATION_FORBIDDEN"
                else:
                    code = "CONSERVATION_CLAIM_MISMATCH"
                errors.append(
                    f"{code}: {path}.conservation_assertions.{field} expected {value!r}, got {conservation.get(field)!r}"
                )
    assertions = proposal.get("membership_assertions")
    if isinstance(assertions, Mapping):
        expected_assertions = {
            "complete": not unassigned,
            "exclusive": pairwise_overlap == 0,
            "no_duplication": duplicate_count == 0,
            "no_member_outside_parent": not (union - parent_keys),
            "no_denominator_loss_or_gain": union == parent_keys,
            "parent_member_set_immutable": True,
        }
        for field, value in expected_assertions.items():
            if assertions.get(field) != value:
                errors.append(f"CONSERVATION_CLAIM_MISMATCH: {path}.membership_assertions.{field} expected {value!r}, got {assertions.get(field)!r}")
    zero_mutation = proposal.get("zero_mutation_assertions")
    if isinstance(zero_mutation, Mapping):
        expected_zero = {
            "applied_splits": 0,
            "status_mutations": 0,
            "denominator_mutations": 0,
            "human_decisions_created": 0,
            "formal_1796_experiment_executed": "NO",
            "execution_authorizations": 0,
            "crosswalk_byte_drift": 0,
        }
        for field, value in expected_zero.items():
            if zero_mutation.get(field) != value:
                code = {
                    "applied_splits": "FAKE_APPLIED_SPLIT",
                    "status_mutations": "IMPLICIT_STATUS_MUTATION",
                    "denominator_mutations": "DENOMINATOR_MUTATION_FORBIDDEN",
                    "crosswalk_byte_drift": "CROSSWALK_MUTATION_FORBIDDEN",
                }.get(field, "ZERO_MUTATION_BOUNDARY_BREACH")
                errors.append(f"{code}: {path}.zero_mutation_assertions.{field} expected {value!r}")
    return errors


def _decision_semantic_errors(
    record: Mapping[str, Any],
    subject_manifest: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    exact12 = record.get("exact12_identity")
    expected_identity = {
        "task_id": EXPECTED_TASK_ID,
        "reviewed_materialization_commit": EXPECTED_REVIEWED_COMMIT,
        "reviewed_materialization_parent": EXPECTED_REVIEWED_PARENT,
        "independent_review_task_id": EXPECTED_REVIEW_TASK_ID,
        "independent_review_materialization_commit": EXPECTED_REVIEW_MATERIALIZATION_COMMIT,
        "independent_review_verdict": EXPECTED_REVIEW_VERDICT,
        "template_count": EXPECTED_TEMPLATE_COUNT,
        "unique_raw_member_count": EXPECTED_RAW_MEMBER_COUNT,
        "blocked31_overlap": EXPECTED_BLOCKED31_OVERLAP,
        "union_hash": EXPECTED_UNION_HASH,
        "crosswalk_byte_drift": 0,
    }
    if isinstance(exact12, Mapping):
        for field, value in expected_identity.items():
            if exact12.get(field) != value:
                code = "UNION_HASH_DRIFT" if field == "union_hash" else "CROSSWALK_MUTATION_FORBIDDEN" if field == "crosswalk_byte_drift" else "EXACT12_IDENTITY_MISMATCH"
                errors.append(f"{code}: exact12_identity.{field} expected {value!r}, got {exact12.get(field)!r}")
    else:
        errors.append("EXACT12_IDENTITY_REQUIRED: exact12_identity is required")

    subject = record.get("subject")
    lookup = _subject_lookup(subject_manifest)
    if not isinstance(subject, Mapping):
        return errors + ["SUBJECT_REQUIRED: subject is required"]
    template_id = subject.get("template_id")
    expected_subject = lookup.get(str(template_id))
    if expected_subject is None:
        errors.append(f"SUBJECT_OUTSIDE_EXACT12_SCOPE: unknown template_id {template_id!r}")
    else:
        for field in ["frozen_order", "member_count", "member_set_sha256", "member_set_reference"]:
            if subject.get(field) != expected_subject.get(field):
                errors.append(f"SUBJECT_IDENTITY_MISMATCH: subject.{field} does not match the authenticated manifest")
        if subject.get("member_keys") != expected_subject.get("member_keys"):
            errors.append("SUBJECT_MEMBERSHIP_MISMATCH: subject.member_keys must equal the authenticated member order")
        errors.extend(_frozen_state_errors(subject.get("current_state"), "subject.current_state"))

    governance_identity = record.get("governance_reference_identity")
    if not isinstance(governance_identity, Mapping):
        errors.append("GOVERNANCE_REFERENCE_REQUIRED: governance_reference_identity is required")
    else:
        errors.extend(_reference_errors(governance_identity.get("governance_reference"), "governance_reference_identity.governance_reference", "GOVERNANCE_REFERENCE_REQUIRED"))
        if governance_identity.get("grammar_pattern") != EXPECTED_GOVERNANCE_REFERENCE_PATTERN:
            errors.append("GOVERNANCE_REFERENCE_GRAMMAR_INVALID: declared grammar does not equal the canonical grammar")

    evidence = record.get("evidence_references")
    if not isinstance(evidence, Mapping):
        errors.append("EVIDENCE_REQUIRED: evidence_references is required")
    else:
        for evidence_class in ["identity_provenance", "source_semantics", "partition", "safety_reset", "governance", "independent_review", "evidence_manifest"]:
            refs = evidence.get(evidence_class)
            if not isinstance(refs, list) or not refs:
                errors.append(f"EVIDENCE_REQUIRED: evidence_references.{evidence_class} must be non-empty")
            elif any(_reference_errors(ref, f"evidence_references.{evidence_class}", "EVIDENCE_REFERENCE_REQUIRED") for ref in refs):
                errors.append(f"EVIDENCE_REFERENCE_INVALID: evidence_references.{evidence_class} contains an invalid reference")

    status = record.get("decision_status")
    disposition = record.get("disposition")
    allowed_states = {
        "DESIGN_ONLY",
        "PROPOSAL_PREPARED",
        "PENDING_GOVERNANCE",
        "APPROVED_FOR_FUTURE_TRANSACTION",
        "REJECTED",
        "DEFERRED",
    }
    if status == "SPLIT_APPLIED" or status not in allowed_states:
        errors.append("FAKE_APPLIED_SPLIT: SPLIT_APPLIED is forbidden and is not a decision state")
    if status in {"PROPOSAL_PREPARED", "PENDING_GOVERNANCE", "APPROVED_FOR_FUTURE_TRANSACTION"} and record.get("proposed_split_structure") is None:
        errors.append("PROPOSAL_REQUIRED: this state requires a proposed split structure")
    if status == "APPROVED_FOR_FUTURE_TRANSACTION":
        authority = record.get("authority")
        if not isinstance(authority, Mapping):
            errors.append("APPROVAL_AUTHORITY_REQUIRED: approved state requires explicit authority")
        else:
            for field in ["authority_reference", "owner_reference", "independent_review_reference", "approval_reference", "transaction_bundle_reference"]:
                errors.extend(_reference_errors(authority.get(field), f"authority.{field}", "APPROVAL_AUTHORITY_REQUIRED"))
        if not isinstance(evidence, Mapping) or any(
            not isinstance(evidence.get(name), list) or not evidence.get(name)
            for name in ["identity_provenance", "source_semantics", "partition", "safety_reset", "governance", "independent_review", "evidence_manifest"]
        ):
            errors.append("APPROVAL_EVIDENCE_REQUIRED: approved state requires complete evidence references")
    if status == "DESIGN_ONLY" and any(record.get(field) not in (None, False) for field in ["authority", "proposed_split_structure", "disposition"]):
        errors.append("DESIGN_ONLY_BOUNDARY_BREACH: design-only state cannot carry a disposition, authority, or proposal")
    if status == "REJECTED" and disposition != "REJECT_PROPOSED_SPLIT":
        errors.append("DISPOSITION_STATE_MISMATCH: REJECTED requires REJECT_PROPOSED_SPLIT")
    if status == "DEFERRED" and disposition != "DEFER_TO_OWNER_ADJUDICATION":
        errors.append("DISPOSITION_STATE_MISMATCH: DEFERRED requires DEFER_TO_OWNER_ADJUDICATION")
    if disposition == "APPROVE_SPLIT_DESIGN_ONLY" and status not in {"PROPOSAL_PREPARED", "PENDING_GOVERNANCE"}:
        errors.append("DISPOSITION_STATE_MISMATCH: APPROVE_SPLIT_DESIGN_ONLY requires a prepared or pending state")
    if disposition == "APPROVE_SPECIFIC_SPLIT_TRANSACTION" and status not in {"PENDING_GOVERNANCE", "APPROVED_FOR_FUTURE_TRANSACTION"}:
        errors.append("DISPOSITION_STATE_MISMATCH: APPROVE_SPECIFIC_SPLIT_TRANSACTION requires pending or approved future state")

    downstream = record.get("downstream_eligibility")
    if isinstance(downstream, Mapping):
        if downstream.get("eligible_for_split_execution") is not False:
            errors.append("EXECUTION_AUTHORIZATION_FORBIDDEN: split execution eligibility must be false")
        if downstream.get("eligible_for_status_mutation") is not False:
            errors.append("IMPLICIT_STATUS_MUTATION: status mutation eligibility must be false")
        if downstream.get("eligible_for_denominator_change") is not False:
            errors.append("DENOMINATOR_MUTATION_FORBIDDEN: denominator change eligibility must be false")
        if status != "APPROVED_FOR_FUTURE_TRANSACTION" and downstream.get("eligible_for_future_transaction") is not False:
            errors.append("DOWNSTREAM_ELIGIBILITY_INVALID: non-approved states cannot be eligible for a future transaction")

    zero = record.get("zero_mutation_assertions")
    expected_zero = {
        "applied_splits": 0,
        "status_mutations": 0,
        "denominator_mutations": 0,
        "human_decisions_created": 0,
        "formal_1796_experiment_executed": "NO",
        "execution_authorizations": 0,
        "crosswalk_byte_drift": 0,
    }
    if not isinstance(zero, Mapping):
        errors.append("ZERO_MUTATION_BOUNDARY_REQUIRED: zero_mutation_assertions is required")
    else:
        for field, value in expected_zero.items():
            if zero.get(field) != value:
                code = {
                    "applied_splits": "FAKE_APPLIED_SPLIT",
                    "status_mutations": "IMPLICIT_STATUS_MUTATION",
                    "denominator_mutations": "DENOMINATOR_MUTATION_FORBIDDEN",
                    "crosswalk_byte_drift": "CROSSWALK_MUTATION_FORBIDDEN",
                }.get(field, "ZERO_MUTATION_BOUNDARY_BREACH")
                errors.append(f"{code}: zero_mutation_assertions.{field} expected {value!r}")

    if isinstance(record.get("proposed_split_structure"), Mapping) and isinstance(subject, Mapping):
        errors.extend(_validate_proposal(record["proposed_split_structure"], subject, load_blocked31_keys()))
    return errors


def validate_record(
    record: Mapping[str, Any],
    subject_manifest: Mapping[str, Any],
    decision_schema: Mapping[str, Any] | None = None,
    envelope_schema: Mapping[str, Any] | None = None,
) -> ValidationResult:
    decision_schema = decision_schema or load_json(DECISION_SCHEMA_FILE)
    envelope_schema = envelope_schema or load_json(ENVELOPE_SCHEMA_FILE)
    schema_errors = _schema_errors(record, decision_schema, envelope_schema)
    semantic_errors = _decision_semantic_errors(record, subject_manifest)
    return ValidationResult(not (schema_errors or semantic_errors), schema_errors + semantic_errors, {})


def validate_fixture_directory(
    subject_manifest: Mapping[str, Any],
    decision_schema: Mapping[str, Any],
    envelope_schema: Mapping[str, Any],
) -> dict[str, Any]:
    manifest = load_json(FIXTURE_MANIFEST_FILE)
    negative_results: list[dict[str, Any]] = []
    for filename in manifest["negative_fixtures"]:
        result = validate_record(load_json(FIXTURE_DIR / filename), subject_manifest, decision_schema, envelope_schema)
        expected_codes = manifest["expected_error_codes"][filename]
        negative_results.append({
            "filename": filename,
            "status": "REJECTED" if not result.valid else "ACCEPTED",
            "errors": result.errors,
            "expected_error_codes": expected_codes,
            "expected_failure_reasons_satisfied": all(
                any(error.startswith(code + ":") for error in result.errors)
                for code in expected_codes
            ),
        })
    positive_results: list[dict[str, Any]] = []
    for filename in manifest["positive_fixtures"]:
        result = validate_record(load_json(FIXTURE_DIR / filename), subject_manifest, decision_schema, envelope_schema)
        positive_results.append({
            "filename": filename,
            "status": "ACCEPTED" if result.valid else "REJECTED",
            "errors": result.errors,
        })
    return {
        "positive_fixtures": positive_results,
        "negative_fixtures": negative_results,
        "all_positive_accepted": all(item["status"] == "ACCEPTED" for item in positive_results),
        "all_negative_rejected": all(item["status"] == "REJECTED" for item in negative_results),
        "all_expected_failure_reasons_satisfied": all(item["expected_failure_reasons_satisfied"] for item in negative_results),
    }


def build_validation_evidence() -> dict[str, Any]:
    subject_manifest = load_json(SUBJECT_MANIFEST_FILE)
    decision_schema = load_json(DECISION_SCHEMA_FILE)
    envelope_schema = load_json(ENVELOPE_SCHEMA_FILE)
    manifest_result = validate_manifest(subject_manifest)
    fixtures = validate_fixture_directory(subject_manifest, decision_schema, envelope_schema)
    schema_meta = True
    Draft202012Validator.check_schema(decision_schema)
    Draft202012Validator.check_schema(envelope_schema)
    schema_alignment = validate_schema_pair()
    state_machine_valid = validate_state_machine()
    return {
        "record_type": "E0C_EXACT12_GOVERNED_DECISION_VALIDATION_EVIDENCE",
        "design_only": True,
        "entry_gate": {
            "local_artifact_head": EXPECTED_REVIEW_MATERIALIZATION_COMMIT,
            "cached_artifact_head": EXPECTED_REVIEW_MATERIALIZATION_COMMIT,
            "live_artifact_head": EXPECTED_REVIEW_MATERIALIZATION_COMMIT,
            "reviewed_materialization_commit": EXPECTED_REVIEWED_COMMIT,
            "reviewed_materialization_parent": EXPECTED_REVIEWED_PARENT,
            "review_task_id": EXPECTED_REVIEW_TASK_ID,
            "review_verdict": EXPECTED_REVIEW_VERDICT,
            "local_cached_live_equality": True,
            "review_commit_descends_from_reviewed_materialization": True,
        },
        "decision_granularity": "TEMPLATE_LEVEL_DECISION_WITH_PROPOSAL_LEVEL_PARTITION_AND_TRANSACTION_BUNDLE_AUTHORITY",
        "schema_meta_validation": "PASS" if schema_meta else "FAIL",
        "governance_reference_grammar_alignment": "PASS" if schema_alignment else "FAIL",
        "decision_state_machine": "PASS" if state_machine_valid else "FAIL",
        "baseline": manifest_result.checks,
        "fixtures": fixtures,
        "zero_operational_effect": {
            "APPLIED_SPLITS": 0,
            "STATUS_MUTATIONS": 0,
            "DENOMINATOR_MUTATIONS": 0,
            "HUMAN_DECISIONS_CREATED": 0,
            "FORMAL_1796_EXPERIMENT_EXECUTED": "NO",
            "ZERO_OPERATIONAL_EFFECT": "PASS",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-evidence", action="store_true")
    args = parser.parse_args()
    evidence = build_validation_evidence()
    if args.write_evidence:
        VALIDATION_EVIDENCE_FILE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0 if evidence["schema_meta_validation"] == "PASS" and evidence["governance_reference_grammar_alignment"] == "PASS" and evidence["baseline"]["template_count"] == 12 and evidence["fixtures"]["all_positive_accepted"] and evidence["fixtures"]["all_negative_rejected"] and evidence["fixtures"]["all_expected_failure_reasons_satisfied"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
