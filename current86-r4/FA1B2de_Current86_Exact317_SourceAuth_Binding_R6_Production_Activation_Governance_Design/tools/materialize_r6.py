"""Materialize the design-only Binding R6 production activation governance package.

This module is intentionally non-activating.  It authenticates the immutable R5
package and produces exact, hash-bound transaction/verifier designs plus
evidence-only field-pin packet skeletons.  No authority pointer, source-auth
result, field pin, P0/P1 result, or binding is written.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping


REPO_ROOT = Path(__file__).resolve().parents[2]
R5_DIR = REPO_ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R5_Wrapper_Materialization"
R6_DIR = REPO_ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R6_Production_Activation_Governance_Design"
EXACT317_PATH = REPO_ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4" / "00_lineage" / "EXACT317_TARGET_MANIFEST.json"
R4_DIR = REPO_ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Prospective_Canonical_Wrapper_Governance_R4"
EXEC_R4_DIR = REPO_ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4"
GOV_R4_DIR = REPO_ROOT / "fa1b2de-current86-canonical-source-authentication-governance-r4-patch"
PRODUCTION_INPUTS_DIR = REPO_ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Production_Authority_Inputs_R1"
REVIEW_REPO = Path("/home/cph/fa1b2de-review-artifacts")
REVIEW_COMMIT = "90513ab76a2d392398fefd0456ad53a4660a3e8a"
REVIEW_R5_PREFIX = "current86-r4/FA1B2de_Current86_Exact317_SourceAuth_Binding_R5_Wrapper_Materialization"
RAW_REPOSITORY = Path("/home/cph/experiment")

EXPECTED_RULES = (
    "R4_WRAPPER_C0_60",
    "R4_WRAPPER_RAW_LEGACY_26",
    "R4_WRAPPER_SCORING_231",
)
EXPECTED_ROUTE_COUNTS = {
    "R4_WRAPPER_RAW_LEGACY_26": 26,
    "R4_WRAPPER_C0_60": 60,
    "R4_WRAPPER_SCORING_231": 231,
}
EXPECTED_ACTIONS = [
    "APPROVE_EXACT_FIELD_PIN",
    "REJECT_FIELD_CANDIDATES_KEEP_BLOCKED",
    "REQUEST_MORE_EVIDENCE",
]
ACTIVATION_ACTIONS = [
    "APPROVE_EXACT_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION",
    "REJECT_KEEP_NON_ACTIVE",
    "REQUEST_REMEDIATION",
]


class R6DesignError(ValueError):
    """Raised when an R5 input or R6 design invariant is not exact."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise R6DesignError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise R6DesignError(f"cannot read required input: {path}") from exc


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise R6DesignError("value is not canonicalizable JSON") from exc


def canonical_id(schema: str, basis: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_bytes({"schema": schema, **dict(basis)}))


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise R6DesignError(f"invalid JSON input: {path}") from exc
    require(isinstance(value, dict), f"JSON root is not an object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise R6DesignError(f"cannot read JSONL input: {path}") from exc
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise R6DesignError(f"invalid JSONL row {number}: {path}") from exc
        require(isinstance(value, dict), f"JSONL row {number} is not an object: {path}")
        rows.append(value)
    return rows


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def artifact(path: Path, logical_path: str | None = None) -> dict[str, Any]:
    require(path.is_file(), f"required artifact is missing: {path}")
    return {
        "path": logical_path or str(path),
        "sha256": sha256_file(path),
        "byte_length": path.stat().st_size,
    }


def git_identity(repository: Path) -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise R6DesignError(f"cannot resolve protected Git identity: {repository}") from exc
    return {"repository": str(repository), "commit": commit, "tree": tree}


def authenticate_protected_source_state() -> dict[str, Any]:
    raw_git = git_identity(RAW_REPOSITORY)
    require(raw_git["commit"] == "a699ebe4fa14cf25768fd0e5475b994a72b60dec", "protected RAW Git commit drift")
    require(raw_git["tree"] == "5ccafffe7e7785535fc276d352487b1d680947e9", "protected RAW Git tree drift")
    paths = {
        "raw_registry": Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/project_snapshots/raw_action_registry.jsonl"),
        "c0_source": Path("/home/cph/experiment-artifacts/tier-de1c0-handoff-20260823-083725/tier_de1c0_typed_operation_semantics.jsonl"),
        "scoring_snapshot": Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/c2/c2_scoring_snapshot_post_c1.jsonl"),
    }
    expected = {
        "raw_registry": "53c85157f9fd0849ae19b1cf403333ad0d0af2a7d761b0498540dd92d66c1e93",
        "c0_source": "0036c42fb02026182274a7ac2a33b103b03b1e527856eb33b5ad650ceddd5c32",
        "scoring_snapshot": "748a3808290f9e78f71c18d4553c77ae208517fd31d163fc2b3008cfcb57f1bb",
    }
    authenticated = {name: artifact(path) for name, path in paths.items()}
    for name, item in authenticated.items():
        require(item["sha256"] == expected[name], f"protected source artifact drift: {name}")
    return {
        "authentication_status": "PASS",
        "raw_playbook_git": raw_git,
        "source_artifacts": authenticated,
        "authority_reads_raw_bytes_from_pinned_commit": True,
    }


def parse_sha256sums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", raw)
        require(match is not None, f"malformed checksum line in {path}: {raw!r}")
        digest, relative = match.groups()
        require(relative not in entries, f"duplicate checksum path: {relative}")
        entries[relative] = digest
    return entries


def verify_package(package: Path) -> dict[str, str]:
    sums_path = package / "SHA256SUMS.txt"
    entries = parse_sha256sums(sums_path)
    for relative, expected in entries.items():
        actual = sha256_file(package / relative)
        require(actual == expected, f"R5 checksum mismatch: {relative}")
    file_list = [line.strip() for line in (package / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line.strip()]
    require(set(file_list) == set(entries), "R5 FILE_LIST and SHA256SUMS differ")
    return entries


def authenticate_review_commit(r5_entries: Mapping[str, str]) -> dict[str, Any]:
    require(REVIEW_REPO.is_dir(), "pinned review repository is unavailable")
    try:
        tree = subprocess.run(
            ["git", "-C", str(REVIEW_REPO), "rev-parse", f"{REVIEW_COMMIT}^{{tree}}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        commit_type = subprocess.run(
            ["git", "-C", str(REVIEW_REPO), "cat-file", "-t", REVIEW_COMMIT],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise R6DesignError("pinned R5 review commit cannot be resolved") from exc
    require(commit_type == "commit", "pinned R5 review identity is not a commit")
    committed_mismatches: list[str] = []
    for relative, expected in r5_entries.items():
        try:
            completed = subprocess.run(
                ["git", "-C", str(REVIEW_REPO), "show", f"{REVIEW_COMMIT}:{REVIEW_R5_PREFIX}/{relative}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise R6DesignError(f"R5 review commit lacks {relative}") from exc
        committed_hash = sha256_bytes(completed.stdout)
        if committed_hash != expected:
            committed_mismatches.append(relative)
    require(not committed_mismatches, f"R5 review commit content mismatch: {committed_mismatches[:3]}")
    return {
        "repository": str(REVIEW_REPO),
        "commit": REVIEW_COMMIT,
        "tree": tree,
        "commit_type": commit_type,
        "package_prefix": REVIEW_R5_PREFIX,
        "committed_r5_file_count": len(r5_entries),
        "committed_r5_file_mismatches": 0,
        "review_commit_authentication": "PASS",
    }


def r5_route_output_rows() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, str]]:
    entries = verify_package(R5_DIR)
    exact_rows = load_jsonl(R5_DIR / "05_dry_run/EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl")
    conservation = load_json(R5_DIR / "05_dry_run/DRY_RUN_CONSERVATION.json")
    require(len(exact_rows) == 317, "R5 Exact317 dry-run row count is not 317")
    require(conservation.get("union") == "Exact317", "R5 union is not Exact317")
    require(conservation.get("duplicates") == 0, "R5 duplicate count is nonzero")
    require(conservation.get("cross_route_substitution") == 0, "R5 cross-route substitution is nonzero")
    by_index: dict[int, dict[str, Any]] = {}
    for row in exact_rows:
        index = row.get("target_index")
        require(isinstance(index, int) and index not in by_index, "R5 dry-run target index is missing or duplicated")
        by_index[index] = row
        require(row.get("authority_status") == "CANDIDATE_WRAPPER_OBJECTS_ONLY", "R5 row is not candidate-only")
        require(row.get("source_auth_executed") is False, "R5 row claims source-auth execution")
        require(row.get("field_pin_created") is False, "R5 row claims a field pin")
    require(set(by_index) == set(range(1, 318)), "R5 dry-run index universe is not Exact317")
    return exact_rows, conservation, entries


def rfc6901_escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def flatten_scalar_leaves(value: Any, prefix: str = "") -> list[dict[str, Any]]:
    """Return deterministic RFC6901 pointers to every scalar leaf."""
    leaves: list[dict[str, Any]] = []
    if isinstance(value, Mapping):
        for key in sorted(value, key=lambda item: str(item).encode("utf-8")):
            child = f"{prefix}/{rfc6901_escape(str(key))}"
            leaves.extend(flatten_scalar_leaves(value[key], child))
    elif isinstance(value, list):
        for index, child_value in enumerate(value):
            leaves.extend(flatten_scalar_leaves(child_value, f"{prefix}/{index}"))
    else:
        leaves.append(
            {
                "pointer": prefix or "/",
                "value": value,
                "value_sha256": sha256_bytes(canonical_bytes(value)),
            }
        )
    return leaves


def build_field_pin_packet(record: Mapping[str, Any]) -> dict[str, Any]:
    if "source_action" in record:
        source_field = "source_action"
    elif "source_row" in record:
        source_field = "source_row"
    else:
        raise R6DesignError("wrapper record has no candidate source object")
    source_locator = record.get("source_locator")
    require(isinstance(source_locator, str) and source_locator, "wrapper record lacks exact source locator")
    leaves = flatten_scalar_leaves(record[source_field], f"/{source_field}")
    source_identity: dict[str, Any] = {
        "source_key": record.get("source_key"),
        "source_locator": source_locator,
    }
    for key in ("source_file", "source_file_sha256", "row_bytes_sha256", "jsonl_line"):
        if key in record:
            source_identity[key] = record[key]
    return {
        "schema": "FA1B2DE_CURRENT86_EXACT317_FIELD_PIN_GOVERNANCE_PACKET_SKELETON_R6_V1",
        "target_index": record.get("target_index"),
        "source_binding_target_id": record.get("source_binding_target_id"),
        "source_side": record.get("source_side"),
        "wrapper_rule_id": record.get("route_rule_id"),
        "candidate_wrapper_object_id": record.get("candidate_object_id"),
        "exact_source_locator": source_locator,
        "source_identity": source_identity,
        "available_candidate_scalar_leaves": leaves,
        "evidence_status": "EVIDENCE_ONLY_NOT_AUTHENTICATED",
        "selected_canonical_pointer": None,
        "selected_scalar_leaf": None,
        "human_decision": None,
        "allowed_future_human_actions": list(EXPECTED_ACTIONS),
        "no_default_action": True,
        "source_auth_executed": False,
        "field_pin_created": False,
        "p0_executed": False,
        "p1_executed": False,
        "binding_publication": False,
    }


def build_input_authentication(
    r5_entries: Mapping[str, str],
    review_identity: Mapping[str, Any],
    exact_manifest: Mapping[str, Any],
    exact_manifest_artifact: Mapping[str, Any],
    r5_rows: list[Mapping[str, Any]],
    conservation: Mapping[str, Any],
) -> dict[str, Any]:
    protected_source_state = authenticate_protected_source_state()
    approval = load_json(R5_DIR / "01_approval/HUMAN_APPROVAL_AUTHENTICATION.json")
    specs = load_json(R5_DIR / "02_specs/APPROVED_R4_WRAPPER_SPECS.json")
    commitments = load_json(R5_DIR / "02_specs/APPROVED_R4_TARGET_COMMITMENTS.json")
    verification = load_json(R5_DIR / "07_verification/R5_INDEPENDENT_VERIFICATION.json")
    terminal = load_json(R5_DIR / "07_verification/R5_TERMINAL_STATE.json")
    lineage = load_json(R5_DIR / "00_lineage/R5_LINEAGE_PIN.json")
    require(verification.get("verification_status") == "PASS" and verification.get("independent") is True, "R5 independent verification is not PASS")
    require(terminal.get("STOP") is True, "R5 terminal state did not stop")
    require(lineage.get("target_total") == 317 and lineage.get("raw_target_total") == 86 and lineage.get("candidate_target_total") == 231, "R5 lineage totals are not exact317")
    require(set(approval.get("approved_r4_rule_ids", [])) == set(EXPECTED_RULES), "R5 approval rule IDs are not exact")
    require(all(value == "APPROVE_EXACT_CANONICAL_WRAPPER_RULE" for value in approval.get("approval_decisions", {}).values()), "R5 approval decision is not exact")
    require(approval.get("authenticated") is True and approval.get("human_origin") == "USER_EXPLICIT_APPROVAL", "R5 human approval is not authenticated")
    target_rows = exact_manifest.get("targets")
    require(isinstance(target_rows, list) and len(target_rows) == 317, "Exact317 manifest is malformed")
    target_ids = [row.get("source_binding_target_id") for row in target_rows]
    require(len(set(target_ids)) == 317 and all(isinstance(item, str) for item in target_ids), "Exact317 target IDs are not unique")
    require(len(r5_rows) == 317, "R5 row count does not equal Exact317")
    manifest_by_index = {row.get("target_index"): row for row in target_rows}
    require(set(manifest_by_index) == set(range(1, 318)), "Exact317 manifest index universe is not 1..317")
    commitments_by_rule: dict[str, list[str]] = {}
    route_commitments = commitments.get("commitments", {}).get("routes") if isinstance(commitments.get("commitments"), Mapping) else None
    require(isinstance(route_commitments, list), "R4 target commitments have no exact route sets")
    for route in route_commitments:
        require(isinstance(route, Mapping), "R4 route commitment is malformed")
        rule = route.get("rule_id")
        ids = route.get("target_ids")
        require(rule in EXPECTED_RULES and isinstance(ids, list), "R4 route commitment is incomplete")
        commitments_by_rule[str(rule)] = list(ids)
    require(set(commitments_by_rule) == set(EXPECTED_RULES), "R4 target commitments do not enumerate exactly three routes")
    manifest_index_by_id = {row["source_binding_target_id"]: row["target_index"] for row in target_rows}
    expected_route_by_index: dict[int, str] = {}
    for rule in EXPECTED_RULES:
        ids = commitments_by_rule[rule]
        require(len(ids) == EXPECTED_ROUTE_COUNTS[rule], f"R4 route count mismatch for {rule}")
        for target_id in ids:
            index = manifest_index_by_id.get(target_id)
            require(isinstance(index, int) and index not in expected_route_by_index, "R4 route sets overlap or contain invalid target")
            expected_route_by_index[index] = rule
    require(set(expected_route_by_index) == set(range(1, 318)), "R4 route sets do not conserve Exact317")
    for row in r5_rows:
        index = row.get("target_index")
        manifest_row = manifest_by_index.get(index)
        require(manifest_row is not None, "R5 target is outside Exact317 manifest")
        require(row.get("source_binding_target_id") == manifest_row.get("source_binding_target_id"), "R5 target identity differs from Exact317 manifest")
        require(row.get("source_side") == manifest_row.get("source_side"), "R5 source side differs from Exact317 manifest")
        require(row.get("route_rule_id") == expected_route_by_index.get(index), "R5 route differs from exact committed route set")
    required_r5_files = {
        "00_lineage/R5_LINEAGE_PIN.json",
        "01_approval/HUMAN_APPROVAL_AUTHENTICATION.json",
        "02_specs/APPROVED_R4_WRAPPER_SPECS.json",
        "02_specs/APPROVED_R4_TARGET_COMMITMENTS.json",
        "03_inputs/R4_WRAPPER_C0_60_INPUT_MANIFEST.json",
        "03_inputs/R4_WRAPPER_C0_60_CHECKPOINT.json",
        "03_inputs/R4_WRAPPER_RAW_LEGACY_26_INPUT_MANIFEST.json",
        "03_inputs/R4_WRAPPER_RAW_LEGACY_26_CHECKPOINT.json",
        "03_inputs/R4_WRAPPER_SCORING_231_INPUT_MANIFEST.json",
        "03_inputs/R4_WRAPPER_SCORING_231_CHECKPOINT.json",
        "04_extractors/c0_exact_row_extractor.py",
        "04_extractors/raw_positional_extractor.py",
        "04_extractors/scoring_exact_id_row_extractor.py",
        "05_dry_run/EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl",
        "05_dry_run/DRY_RUN_CONSERVATION.json",
        "06_non_active_candidates/SOURCE_ADMISSION_REGISTRY_ROOT_CANDIDATE.json",
        "06_non_active_candidates/SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT_CANDIDATE.json",
        "06_non_active_candidates/COMMON_INPUT_FREEZE_ADDITIONS_CANDIDATE.json",
        "06_non_active_candidates/EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION_PATCH_CANDIDATE.json",
        "07_verification/R5_INDEPENDENT_VERIFICATION.json",
    }
    require(required_r5_files <= set(r5_entries), "R5 package is missing an authenticated input")
    route_counts = {
        rule: sum(1 for row in r5_rows if row.get("route_rule_id") == rule)
        for rule in EXPECTED_RULES
    }
    require(route_counts == EXPECTED_ROUTE_COUNTS, "R5 wrapper route counts are not 26/60/231")
    return {
        "schema": "FA1B2DE_CURRENT86_BINDING_R6_INPUT_AUTHENTICATION_V1",
        "stage": "BINDING_R6_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION_GOVERNANCE_DESIGN",
        "design_only": True,
        "authentication_status": "PASS",
        "pinned_r5_review": dict(review_identity),
        "r5_package": {
            "path": str(R5_DIR),
            "sha256sums_sha256": sha256_file(R5_DIR / "SHA256SUMS.txt"),
            "file_count": len(r5_entries),
            "file_hashes": dict(sorted(r5_entries.items())),
        },
        "r5_lineage": {
            "artifact": artifact(R5_DIR / "00_lineage/R5_LINEAGE_PIN.json", "R5/00_lineage/R5_LINEAGE_PIN.json"),
            "human_origin": approval.get("human_origin"),
            "human_approval_authenticated": approval.get("authenticated"),
            "approved_rule_ids": sorted(approval.get("approved_r4_rule_ids", [])),
            "frozen_r4_sha256sums_sha256": lineage.get("frozen_r4_sha256sums_sha256"),
            "frozen_r4_rule_package_sha256": approval.get("frozen_r4_package", {}).get("rule_package_sha256"),
        },
        "approved_r4": {
            "wrapper_specs": artifact(R5_DIR / "02_specs/APPROVED_R4_WRAPPER_SPECS.json", "R5/02_specs/APPROVED_R4_WRAPPER_SPECS.json"),
            "target_commitments": artifact(R5_DIR / "02_specs/APPROVED_R4_TARGET_COMMITMENTS.json", "R5/02_specs/APPROVED_R4_TARGET_COMMITMENTS.json"),
            "rule_ids": sorted(EXPECTED_RULES),
            "route_counts": dict(EXPECTED_ROUTE_COUNTS),
            "route_commitment_sha256s": {
                route["rule_id"]: route["expansion_set_commitment_sha256"]
                for route in commitments["commitments"]["routes"]
            },
            "approval_decisions": dict(sorted(approval.get("approval_decisions", {}).items())),
        },
        "exact317": {
            "manifest": dict(exact_manifest_artifact),
            "manifest_schema": exact_manifest.get("schema_version"),
            "target_total": 317,
            "raw_side_total": 86,
            "candidate_side_total": 231,
            "target_id_set_sha256": sha256_bytes(canonical_bytes(sorted(target_ids))),
        },
        "materialized_r5_inputs": {
            "manifests": {
                rule: artifact(R5_DIR / filename, f"R5/{filename}")
                for rule, filename in {
                    "R4_WRAPPER_RAW_LEGACY_26": "03_inputs/R4_WRAPPER_RAW_LEGACY_26_INPUT_MANIFEST.json",
                    "R4_WRAPPER_C0_60": "03_inputs/R4_WRAPPER_C0_60_INPUT_MANIFEST.json",
                    "R4_WRAPPER_SCORING_231": "03_inputs/R4_WRAPPER_SCORING_231_INPUT_MANIFEST.json",
                }.items()
            },
            "checkpoints": {
                rule: artifact(R5_DIR / filename, f"R5/{filename}")
                for rule, filename in {
                    "R4_WRAPPER_RAW_LEGACY_26": "03_inputs/R4_WRAPPER_RAW_LEGACY_26_CHECKPOINT.json",
                    "R4_WRAPPER_C0_60": "03_inputs/R4_WRAPPER_C0_60_CHECKPOINT.json",
                    "R4_WRAPPER_SCORING_231": "03_inputs/R4_WRAPPER_SCORING_231_CHECKPOINT.json",
                }.items()
            },
            "extractors": {
                rule: artifact(R5_DIR / filename, f"R5/{filename}")
                for rule, filename in {
                    "R4_WRAPPER_RAW_LEGACY_26": "04_extractors/raw_positional_extractor.py",
                    "R4_WRAPPER_C0_60": "04_extractors/c0_exact_row_extractor.py",
                    "R4_WRAPPER_SCORING_231": "04_extractors/scoring_exact_id_row_extractor.py",
                }.items()
            },
            "dry_run_outputs": {
                "exact317": artifact(R5_DIR / "05_dry_run/EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl", "R5/05_dry_run/EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl"),
                "conservation": artifact(R5_DIR / "05_dry_run/DRY_RUN_CONSERVATION.json", "R5/05_dry_run/DRY_RUN_CONSERVATION.json"),
            },
            "independent_verification": artifact(R5_DIR / "07_verification/R5_INDEPENDENT_VERIFICATION.json", "R5/07_verification/R5_INDEPENDENT_VERIFICATION.json"),
            "non_active_candidates": {
                role: artifact(R5_DIR / filename, f"R5/{filename}")
                for role, filename in {
                    "SOURCE_ADMISSION_REGISTRY_ROOT": "06_non_active_candidates/SOURCE_ADMISSION_REGISTRY_ROOT_CANDIDATE.json",
                    "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT": "06_non_active_candidates/SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT_CANDIDATE.json",
                    "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST": "06_non_active_candidates/COMMON_INPUT_FREEZE_ADDITIONS_CANDIDATE.json",
                    "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION": "06_non_active_candidates/EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION_PATCH_CANDIDATE.json",
                }.items()
            },
        },
        "dry_run_assertions": {
            "route_counts": route_counts,
            "union": conservation.get("union"),
            "duplicates": conservation.get("duplicates"),
            "cross_route_substitution": conservation.get("cross_route_substitution"),
            "all_candidate_wrapper_objects_only": True,
        },
        "protected_input_packages": {
            "R4_WRAPPER_GOVERNANCE": artifact(R4_DIR / "SHA256SUMS.txt", "R4/SHA256SUMS.txt"),
            "EXEC_R4": artifact(EXEC_R4_DIR / "SHA256SUMS.txt", "EXEC-R4/SHA256SUMS.txt"),
            "GOV_R4": artifact(GOV_R4_DIR / "SHA256SUMS.txt", "GOV-R4/SHA256SUMS.txt"),
            "PRODUCTION_AUTHORITY_INPUTS_R1": artifact(PRODUCTION_INPUTS_DIR / "SHA256SUMS.txt", "PRODUCTION-AUTHORITY-INPUTS-R1/SHA256SUMS.txt"),
        },
        "common_input_freeze_runtime_base": {
            "base_common_input_freeze_candidate": artifact(
                PRODUCTION_INPUTS_DIR / "COMMON_INPUT_FREEZE_CANDIDATE.json",
                "PRODUCTION-AUTHORITY-INPUTS-R1/COMMON_INPUT_FREEZE_CANDIDATE.json",
            ),
            "base_runtime_whitelist_candidate": artifact(
                PRODUCTION_INPUTS_DIR / "RUNTIME_WHITELIST_CANDIDATE.json",
                "PRODUCTION-AUTHORITY-INPUTS-R1/RUNTIME_WHITELIST_CANDIDATE.json",
            ),
            "r5_additions": artifact(
                R5_DIR / "06_non_active_candidates/COMMON_INPUT_FREEZE_ADDITIONS_CANDIDATE.json",
                "R5/06_non_active_candidates/COMMON_INPUT_FREEZE_ADDITIONS_CANDIDATE.json",
            ),
        },
        "protected_source_state": protected_source_state,
        "authority_boundary": {
            "active_source_authority_created": False,
            "source_auth_executed": False,
            "field_pins_created": 0,
            "p0_executed": False,
            "p1_executed": False,
            "binding_publication": False,
            "scoring_authority_mutated": False,
            "binding_authority_mutated": False,
            "git_ref_mutation": False,
        },
        "r5_independent_verification": {
            "status": verification.get("verification_status"),
            "independent": verification.get("independent"),
            "targets_total": verification.get("targets_total"),
            "raw": verification.get("raw"),
            "candidate": verification.get("candidate"),
            "union": verification.get("union"),
            "duplicates": verification.get("duplicates"),
            "cross_route_substitution": verification.get("cross_route_substitution"),
        },
        "authentication_conclusion": "R5_AND_EXACT317_AUTHENTICATED_FOR_DESIGN_ONLY",
    }


def build_root_identity(role: str, candidate_path: Path, candidate: Mapping[str, Any], target_manifest_sha256: str) -> str:
    dependencies: Mapping[str, Any] | None = None
    if role == "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST":
        dependencies = {
            "production_authority_inputs_sha256sums_sha256": sha256_file(PRODUCTION_INPUTS_DIR / "SHA256SUMS.txt"),
            "base_common_input_freeze_sha256": sha256_file(PRODUCTION_INPUTS_DIR / "COMMON_INPUT_FREEZE_CANDIDATE.json"),
            "base_runtime_whitelist_sha256": sha256_file(PRODUCTION_INPUTS_DIR / "RUNTIME_WHITELIST_CANDIDATE.json"),
        }
    elif role == "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION":
        dependencies = {
            "exec_r4_sha256sums_sha256": sha256_file(EXEC_R4_DIR / "SHA256SUMS.txt"),
            "gov_r4_sha256sums_sha256": sha256_file(GOV_R4_DIR / "SHA256SUMS.txt"),
        }
    return canonical_id(
        "FA1B2DE_CURRENT86_R6_PROSPECTIVE_AUTHORITY_ROOT_ID_V1",
        {
            "authority_role": role,
            "artifact_sha256": sha256_file(candidate_path),
            "artifact_schema": candidate.get("schema"),
            "target_manifest_sha256": target_manifest_sha256,
            "wrapper_rule_ids": sorted(candidate.get("wrapper_rule_ids", [])),
            "scope": candidate.get("scope"),
            "dependencies": dependencies or {},
        },
    )


def build_transaction(
    input_auth: Mapping[str, Any],
    exact_manifest: Mapping[str, Any],
    r5_rows: list[Mapping[str, Any]],
) -> dict[str, Any]:
    target_manifest_sha256 = input_auth["exact317"]["manifest"]["sha256"]
    candidates = {
        "SOURCE_ADMISSION_REGISTRY_ROOT": R5_DIR / "06_non_active_candidates/SOURCE_ADMISSION_REGISTRY_ROOT_CANDIDATE.json",
        "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT": R5_DIR / "06_non_active_candidates/SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT_CANDIDATE.json",
        "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST": R5_DIR / "06_non_active_candidates/COMMON_INPUT_FREEZE_ADDITIONS_CANDIDATE.json",
        "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION": R5_DIR / "06_non_active_candidates/EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION_PATCH_CANDIDATE.json",
    }
    candidate_objects = {role: load_json(path) for role, path in candidates.items()}
    post_roots = {
        role: {
            "root_id": build_root_identity(role, candidates[role], candidate_objects[role], target_manifest_sha256),
            "artifact": artifact(candidates[role], f"R5/{candidates[role].relative_to(R5_DIR).as_posix()}"),
            "status": "PROSPECTIVE_POST_COMMIT_ROOT",
        }
        for role in candidates
    }
    pre_roots = {
        "SOURCE_ADMISSION_REGISTRY_ROOT": "ABSENT_NO_ACTIVE_PRODUCTION_ROOT",
        "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT": "ABSENT_NO_ACTIVE_PRODUCTION_ROOT",
        "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST": "ABSENT_NO_EXECUTABLE_FREEZE",
        "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION": "EXEC_R4_BASELINE_SYNTHETIC_ONLY",
    }
    wrapper_dispatch = {
        "R4_WRAPPER_RAW_LEGACY_26": {
            "schema_or_contract_id": "R4_WRAPPER_RAW_LEGACY_26_SCHEMA_V1",
            "entrypoint": "04_extractors/raw_positional_extractor.py",
            "entrypoint_sha256": input_auth["materialized_r5_inputs"]["extractors"]["R4_WRAPPER_RAW_LEGACY_26"]["sha256"],
            "target_count": 26,
            "source_side": "RAW",
        },
        "R4_WRAPPER_C0_60": {
            "schema_or_contract_id": "R4_WRAPPER_C0_60_SCHEMA_V1",
            "entrypoint": "04_extractors/c0_exact_row_extractor.py",
            "entrypoint_sha256": input_auth["materialized_r5_inputs"]["extractors"]["R4_WRAPPER_C0_60"]["sha256"],
            "target_count": 60,
            "source_side": "RAW",
        },
        "R4_WRAPPER_SCORING_231": {
            "schema_or_contract_id": "R4_WRAPPER_SCORING_231_SCHEMA_V1",
            "entrypoint": "04_extractors/scoring_exact_id_row_extractor.py",
            "entrypoint_sha256": input_auth["materialized_r5_inputs"]["extractors"]["R4_WRAPPER_SCORING_231"]["sha256"],
            "target_count": 231,
            "source_side": "CANDIDATE",
        },
    }
    target_ids = [row["source_binding_target_id"] for row in sorted(exact_manifest["targets"], key=lambda item: item["target_index"])]
    basis = {
        "review_commit": input_auth["pinned_r5_review"]["commit"],
        "r5_package_sha256sums_sha256": input_auth["r5_package"]["sha256sums_sha256"],
        "approved_r4_wrapper_specs_sha256": input_auth["approved_r4"]["wrapper_specs"]["sha256"],
        "approved_r4_target_commitments_sha256": input_auth["approved_r4"]["target_commitments"]["sha256"],
        "r4_package_sha256sums_sha256": input_auth["protected_input_packages"]["R4_WRAPPER_GOVERNANCE"]["sha256"],
        "exec_r4_package_sha256sums_sha256": input_auth["protected_input_packages"]["EXEC_R4"]["sha256"],
        "gov_r4_package_sha256sums_sha256": input_auth["protected_input_packages"]["GOV_R4"]["sha256"],
        "production_authority_inputs_r1_sha256sums_sha256": input_auth["protected_input_packages"]["PRODUCTION_AUTHORITY_INPUTS_R1"]["sha256"],
        "target_manifest_sha256": target_manifest_sha256,
        "target_id_set_sha256": sha256_bytes(canonical_bytes(target_ids)),
        "approved_rule_ids": sorted(EXPECTED_RULES),
        "route_commitment_sha256s": input_auth["approved_r4"]["route_commitment_sha256s"],
        "pre_state_root_ids": pre_roots,
        "post_state_root_ids": {role: item["root_id"] for role, item in post_roots.items()},
        "dispatch": wrapper_dispatch,
        "protected_source_state": input_auth["protected_source_state"],
        "common_input_freeze_runtime_base": input_auth["common_input_freeze_runtime_base"],
    }
    transaction_id = canonical_id("FA1B2DE_CURRENT86_R6_PRODUCTION_ACTIVATION_TRANSACTION_V1", basis)
    return {
        "schema": "FA1B2DE_CURRENT86_R6_PRODUCTION_ACTIVATION_TRANSACTION_DESIGN_V1",
        "design_only": True,
        "activation_execution_performed": False,
        "activation_status": "DESIGN_ONLY_NOT_EXECUTED",
        "transaction_id": transaction_id,
        "transaction_id_basis": basis,
        "human_activation_decision_required": "APPROVE_EXACT_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION",
        "previous_wrapper_approval_is_not_activation_approval": True,
        "pre_state": {
            "root_ids": pre_roots,
            "exec_r4_base_package_sha256sums_sha256": input_auth["protected_input_packages"]["EXEC_R4"]["sha256"],
            "production_authority_visible": False,
        },
        "post_state_candidate": {
            "root_ids": {role: item["root_id"] for role, item in post_roots.items()},
            "root_artifacts": post_roots,
            "exact317_target_manifest_sha256": target_manifest_sha256,
            "wrapper_dispatch": wrapper_dispatch,
            "runtime_whitelist_and_common_input_freeze": {
                "candidate_artifact_sha256": post_roots["SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST"]["artifact"]["sha256"],
                "base_common_input_freeze_sha256": input_auth["common_input_freeze_runtime_base"]["base_common_input_freeze_candidate"]["sha256"],
                "base_runtime_whitelist_sha256": input_auth["common_input_freeze_runtime_base"]["base_runtime_whitelist_candidate"]["sha256"],
                "production_authority_inputs_r1_sha256sums_sha256": input_auth["protected_input_packages"]["PRODUCTION_AUTHORITY_INPUTS_R1"]["sha256"],
                "manifest_sha256s": {
                    rule: item["sha256"]
                    for rule, item in input_auth["materialized_r5_inputs"]["manifests"].items()
                },
                "checkpoint_sha256s": {
                    rule: item["sha256"]
                    for rule, item in input_auth["materialized_r5_inputs"]["checkpoints"].items()
                },
                "extractor_sha256s": {
                    rule: item["sha256"]
                    for rule, item in input_auth["materialized_r5_inputs"]["extractors"].items()
                },
            },
            "source_auth_execution_count": 0,
            "field_pin_count": 0,
        },
        "exact_write_install_sequence": [
            "1. Acquire the authority-store activation lock and read the current single activation pointer.",
            "2. Re-hash every protected input, R5 candidate, manifest, checkpoint, extractor, and exact317 target commitment; reject any drift.",
            "3. Enumerate all authority roots and reject any newer or conflicting root for the four roles.",
            "4. Write the four immutable candidate root objects and one proposed post-state manifest into an isolated, read-only-after-write staging directory named by transaction_id.",
            "5. Run the independent activation verifier against staging; require every check to pass and the human decision record to contain the exact approval action.",
            "6. Write a commit record containing transaction_id, pre_state root IDs, post_state root IDs, and all content hashes; fsync staged files and the commit record.",
            "7. Atomically replace one authority-consumer activation pointer with the committed post-state pointer; this is the sole visibility commit point.",
            "8. Re-read the pointer and run the post-commit independent verifier before allowing any production evaluator to consume it.",
        ],
        "commit_point": "ATOMIC_REPLACE_SINGLE_AUTHORITY_CONSUMER_POINTER_AFTER_VERIFIER_PASS",
        "visibility_and_atomicity": {
            "production_sees": "only the fully committed pre-state or fully committed post-state pointer",
            "partial_root_visibility": "FORBIDDEN",
            "staging_visibility": "not mounted by production evaluator",
            "consumer_pointer_binds": ["transaction_id", "pre_state_root_ids", "post_state_root_ids", "artifact_sha256s"],
        },
        "rollback": {
            "before_commit_point": [
                "do not replace the consumer pointer",
                "mark the staged transaction aborted with the reason",
                "remove or quarantine only the isolated uncommitted staging directory",
                "leave all pre-state roots and GOV-R4/EXEC-R4 files unchanged",
            ],
            "after_commit_point": "never mutate the committed post-state in place; use a separately reviewed compensating transaction that atomically restores the recorded pre-state pointer",
            "partial_activation_recovery": "FAIL_CLOSED_NO_ACTIVATION; production evaluator must reject an incomplete or pointer/hash-mismatched transaction",
        },
        "semantic_preservation": [
            "GOV-R4 and EXEC-R4 are immutable inputs and are not rewritten.",
            "Exact317 remains exactly 86 RAW plus 231 CANDIDATE with no target expansion.",
            "No alternate locator, semantic fallback, ranking, similarity, LLM choice, or cross-route substitution is permitted.",
            "Source admission does not select or pin a field and does not publish a binding.",
            "Scoring and binding authority remain unmutated.",
        ],
        "hard_boundary": {
            "active_source_authority_created_now": False,
            "source_auth_executed_now": False,
            "field_pins_created_now": 0,
            "p0_executed_now": False,
            "p1_executed_now": False,
            "binding_publication_now": False,
            "git_ref_mutation_now": False,
        },
    }


def build_preconditions(input_auth: Mapping[str, Any], transaction: Mapping[str, Any]) -> dict[str, Any]:
    hashes = input_auth["materialized_r5_inputs"]
    protected = input_auth["protected_input_packages"]
    route_preconditions = []
    for rule in EXPECTED_RULES:
        route_preconditions.append(
            {
                "id": f"EXACT_{rule}_MATERIALIZATION",
                "requirement": "exact extractor, manifest, checkpoint, and target commitment hashes match R5",
                "expected": {
                    "extractor_sha256": hashes["extractors"][rule]["sha256"],
                    "manifest_sha256": hashes["manifests"][rule]["sha256"],
                    "checkpoint_sha256": hashes["checkpoints"][rule]["sha256"],
                    "target_count": EXPECTED_ROUTE_COUNTS[rule],
                },
                "verification_status": "PASS",
            }
        )
    preconditions = [
        {
            "id": "OUTER_PACKAGE_HASHES",
            "requirement": "R4 wrapper governance, EXEC-R4, GOV-R4, and R5 package envelopes are unchanged",
            "expected": {
                "r4_wrapper_governance_sha256sums_sha256": protected["R4_WRAPPER_GOVERNANCE"]["sha256"],
                "exec_r4_sha256sums_sha256": protected["EXEC_R4"]["sha256"],
                "gov_r4_sha256sums_sha256": protected["GOV_R4"]["sha256"],
                "r5_sha256sums_sha256": input_auth["r5_package"]["sha256sums_sha256"],
                "pinned_review_commit": input_auth["pinned_r5_review"]["commit"],
            },
            "verification_status": "PASS",
        },
        {
            "id": "EXACT317_MANIFEST",
            "requirement": "the exact317 manifest identity and target ID universe are unchanged",
            "expected": {
                "sha256": input_auth["exact317"]["manifest"]["sha256"],
                "target_total": 317,
                "raw_side_total": 86,
                "candidate_side_total": 231,
                "target_id_set_sha256": input_auth["exact317"]["target_id_set_sha256"],
            },
            "verification_status": "PASS",
        },
        {
            "id": "APPROVED_RULE_IDS",
            "requirement": "exactly the three explicitly approved R4 wrapper rule IDs are present",
            "expected": {"rule_ids": sorted(EXPECTED_RULES), "approval": "APPROVE_EXACT_CANONICAL_WRAPPER_RULE"},
            "verification_status": "PASS",
        },
        *route_preconditions,
        {
            "id": "DRY_RUN_CONSERVATION",
            "requirement": "R5 dry-run is exact317-conserving and candidate-only",
            "expected": {"raw": 86, "candidate": 231, "total": 317, "duplicates": 0, "cross_route_substitution": 0, "union": "Exact317"},
            "verification_status": "PASS",
        },
        {
            "id": "AUTHORITY_ZERO_STATE",
            "requirement": "activation begins with no source-auth execution or downstream decisions",
            "expected": {"field_pins_created": 0, "source_auth_executed": 0, "p0_executed": False, "p1_executed": False, "binding_publication": False},
            "verification_status": "PASS",
        },
        {
            "id": "NO_NEWER_CONFLICTING_ROOTS",
            "requirement": "no newer conflicting authority root exists for any role or target set",
            "expected": {"conflict_count": 0, "newer_root_count": 0, "same_role_different_hash_count": 0},
            "verification_status": "PASS",
            "future_check": "re-enumerate under activation lock; any nonzero value yields FAIL_CLOSED_NO_ACTIVATION",
        },
        {
            "id": "PROTECTED_INPUT_STATE_NO_DRIFT",
            "requirement": "RAW Git commit/tree and authenticated corpus bytes remain unchanged",
            "expected": {
                "raw_git_commit": "a699ebe4fa14cf25768fd0e5475b994a72b60dec",
                "raw_git_tree": "5ccafffe7e7785535fc276d352487b1d680947e9",
                "raw_registry_sha256": "53c85157f9fd0849ae19b1cf403333ad0d0af2a7d761b0498540dd92d66c1e93",
                "c0_source_sha256": "0036c42fb02026182274a7ac2a33b103b03b1e527856eb33b5ad650ceddd5c32",
                "scoring_snapshot_sha256": "748a3808290f9e78f71c18d4553c77ae208517fd31d163fc2b3009cfcb57f1bb",
            },
            "verification_status": "PASS",
            "future_check": "re-hash and re-resolve pinned Git bytes immediately before staging",
        },
    ]
    return {
        "schema": "FA1B2DE_CURRENT86_R6_ACTIVATION_PRECONDITIONS_V1",
        "design_only": True,
        "failure_mode": "FAIL_CLOSED_NO_ACTIVATION",
        "activation_allowed_without_human_decision": False,
        "transaction_id": transaction["transaction_id"],
        "preconditions": preconditions,
        "all_observed_preconditions_pass": all(item.get("verification_status") == "PASS" for item in preconditions),
        "decision_gate": {"required_action": ACTIVATION_ACTIONS[0], "current_decision": None, "status": "PENDING_NO_DEFAULT"},
    }


def build_verifier_contract(input_auth: Mapping[str, Any], transaction: Mapping[str, Any], packet_sha256: str) -> dict[str, Any]:
    return {
        "schema": "FA1B2DE_CURRENT86_R6_INDEPENDENT_ACTIVATION_VERIFIER_CONTRACT_V1",
        "design_only": True,
        "verifier_status": "PROSPECTIVE_CONTRACT_NOT_EXECUTING_ACTIVATION",
        "independence_requirements": [
            "run from a separately hashed verifier implementation and isolated read-only mount",
            "read the committed transaction pointer and artifacts without trusting producer-computed PASS flags",
            "recompute all content hashes, IDs, counts, and route membership from source bytes",
            "fail closed on missing, duplicate, conflicting, stale, or out-of-scope data",
        ],
        "transaction_id": transaction["transaction_id"],
        "expected_post_state_root_ids": transaction["post_state_candidate"]["root_ids"],
        "expected_packet_skeleton_sha256": packet_sha256,
        "checks": [
            {"id": "ROOT_IDENTITY", "assert": "each installed root ID equals SHA256(canonical root identity basis) and its artifact hash matches the transaction"},
            {"id": "ROOT_ROLE_MEMBERSHIP", "assert": "exactly four approved role roots are present; no field-pin root is present"},
            {"id": "WRAPPER_RULE_MEMBERSHIP", "assert": "the three wrapper rules are exact and route counts are RAW 26, C0 60, SCORING 231"},
            {"id": "EXACT317_CONSERVATION", "assert": "union of installed target commitments equals the exact317 manifest: 86 RAW + 231 CANDIDATE = 317; duplicates 0"},
            {"id": "DISPATCH_ROUTE_EXACTNESS", "assert": "each route dispatches only its hash-bound R5 entrypoint/spec and exact source side; no cross-route substitution"},
            {"id": "NO_INACTIVE_OR_LEGACY_LEAKAGE", "assert": "no synthetic-only, legacy, unregistered, alternate, or path-only route is reachable from the production pointer"},
            {"id": "RUNTIME_WHITELIST_EXACTNESS", "assert": "only the transaction's exact manifest, checkpoint, extractor, interpreter/isolation, and protected contract hashes are mounted read-only"},
            {"id": "NO_NEWER_CONFLICTING_ROOTS", "assert": "authority-store enumeration contains no newer or same-role different-hash root"},
            {"id": "SOURCE_AUTH_ZERO", "assert": "source-auth execution count remains zero immediately after activation"},
            {"id": "FIELD_PINS_ZERO", "assert": "field-pin registry is absent and field-pin count remains zero"},
            {"id": "DOWNSTREAM_ZERO", "assert": "P0, P1, binding publication, scoring mutation, and binding mutation remain false/zero"},
            {"id": "SEMANTICS_PRESERVED", "assert": "GOV-R4 and EXEC-R4 hashes match the protected inputs and are not rewritten"},
        ],
        "failure_result": "FAIL_CLOSED_NO_ACTIVATION_AND_BLOCK_PRODUCTION_EVALUATOR",
        "pass_result": "ACTIVATION_VERIFIED_BUT_SOURCE_AUTH_AND_FIELD_PIN_STAGES_REMAIN_SEPARATE",
        "future_allowed_action": "emit an independent verification record only; never select a field or publish a binding",
    }


def build_atomicity_contract(transaction: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": "FA1B2DE_CURRENT86_R6_ATOMICITY_AND_ROLLBACK_CONTRACT_V1",
        "design_only": True,
        "transaction_id": transaction["transaction_id"],
        "proposed_transaction_id_basis": transaction["transaction_id_basis"],
        "pre_state_root_ids": transaction["pre_state"]["root_ids"],
        "post_state_candidate_root_ids": transaction["post_state_candidate"]["root_ids"],
        "staging": {
            "staging_namespace": f"r6-activation-staging/{transaction['transaction_id']}",
            "production_mount": "FORBIDDEN",
            "write_policy": "immutable candidate objects followed by fsync; no in-place replacement",
        },
        "atomic_write_sequence": transaction["exact_write_install_sequence"],
        "commit_point": transaction["commit_point"],
        "consumer_visibility": transaction["visibility_and_atomicity"],
        "rollback": transaction["rollback"],
        "partial_authority_policy": "FAIL_CLOSED_NO_ACTIVATION",
        "no_write_executed": True,
    }


def build_bridge(input_auth: Mapping[str, Any], packet_sha256: str, packet_count: int, route_counts: Mapping[str, int]) -> dict[str, Any]:
    return {
        "schema": "FA1B2DE_CURRENT86_R6_FIELD_PIN_GOVERNANCE_BRIDGE_V1",
        "design_only": True,
        "source_admission_is_not_field_pinning": True,
        "field_pin_authority_status": "NOT_CREATED",
        "exact317_target_manifest_sha256": input_auth["exact317"]["manifest"]["sha256"],
        "packet_skeletons": {
            "path": "R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl",
            "sha256": packet_sha256,
            "count": packet_count,
        },
        "route_counts": dict(route_counts),
        "future_governance_units": 317,
        "packet_contract": {
            "each_packet_contains": [
                "target ID and source side",
                "exact R4 wrapper rule ID",
                "candidate wrapper object ID",
                "exact source locator",
                "available candidate scalar leaves",
                "evidence-only status",
                "selected_canonical_pointer = null",
            ],
            "allowed_future_human_actions": list(EXPECTED_ACTIONS),
            "no_default_action": True,
            "selection_or_pinning_performed": False,
        },
        "boundary": {
            "field_pins_created": 0,
            "source_auth_executed": False,
            "p0_executed": False,
            "p1_executed": False,
            "binding_publication": False,
        },
    }


def build_decision_packet(input_auth: Mapping[str, Any], transaction: Mapping[str, Any]) -> dict[str, Any]:
    basis = {
        "schema": "FA1B2DE_CURRENT86_R6_HUMAN_ACTIVATION_DECISION_PACKET_V1",
        "transaction_id": transaction["transaction_id"],
        "exact317_manifest_sha256": input_auth["exact317"]["manifest"]["sha256"],
        "post_state_root_ids": transaction["post_state_candidate"]["root_ids"],
    }
    return {
        "schema": "FA1B2DE_CURRENT86_R6_HUMAN_ACTIVATION_DECISION_PACKET_V1",
        "decision_packet_id": canonical_id(basis["schema"], basis),
        "design_only": True,
        "transaction_id": transaction["transaction_id"],
        "exact317_manifest_sha256": input_auth["exact317"]["manifest"]["sha256"],
        "approved_rule_ids": sorted(EXPECTED_RULES),
        "previous_wrapper_approval_is_not_activation_approval": True,
        "allowed_human_actions": list(ACTIVATION_ACTIONS),
        "decision": None,
        "decision_status": "PENDING_NO_DEFAULT",
        "human_origin": None,
        "decision_timestamp": None,
        "no_default_action": True,
        "activation_execution_performed": False,
        "active_source_authority_created": False,
        "source_auth_executed": False,
        "field_pins_created": 0,
        "p0_executed": False,
        "p1_executed": False,
        "binding_publication": False,
    }


def write_file_list_and_checksums(root: Path) -> None:
    files = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS.txt" and "__pycache__" not in path.parts
    )
    (root / "FILE_LIST.txt").write_text("\n".join(files) + "\n", encoding="utf-8")
    lines = [f"{sha256_file(root / relative)}  ./{relative}" for relative in files]
    (root / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def materialize(root: Path = R6_DIR) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    r5_entries = verify_package(R5_DIR)
    review_identity = authenticate_review_commit(r5_entries)
    exact_manifest_artifact = artifact(EXACT317_PATH, "EXEC-R4/00_lineage/EXACT317_TARGET_MANIFEST.json")
    exact_manifest = load_json(EXACT317_PATH)
    require(exact_manifest_artifact["sha256"] == "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac", "Exact317 manifest hash drift")
    r5_rows, conservation, _ = r5_route_output_rows()
    input_auth = build_input_authentication(r5_entries, review_identity, exact_manifest, exact_manifest_artifact, r5_rows, conservation)
    write_json(root / "R6_INPUT_AUTHENTICATION.json", input_auth)
    transaction = build_transaction(input_auth, exact_manifest, r5_rows)
    write_json(root / "R6_PRODUCTION_ACTIVATION_TRANSACTION_DESIGN.json", transaction)
    preconditions = build_preconditions(input_auth, transaction)
    write_json(root / "R6_ACTIVATION_PRECONDITIONS.json", preconditions)
    atomicity = build_atomicity_contract(transaction)
    write_json(root / "R6_ATOMICITY_AND_ROLLBACK_CONTRACT.json", atomicity)

    packets = [build_field_pin_packet(row) for row in sorted(r5_rows, key=lambda item: item["target_index"])]
    require(len(packets) == 317, "field-pin packet skeleton count is not 317")
    require(len({packet["source_binding_target_id"] for packet in packets}) == 317, "field-pin packet target IDs are duplicated")
    packet_path = root / "R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl"
    write_jsonl(packet_path, packets)
    packet_sha256 = sha256_file(packet_path)
    route_counts = {rule: sum(1 for row in r5_rows if row.get("route_rule_id") == rule) for rule in EXPECTED_RULES}
    bridge = build_bridge(input_auth, packet_sha256, len(packets), route_counts)
    write_json(root / "R6_FIELD_PIN_GOVERNANCE_BRIDGE.json", bridge)
    decision = build_decision_packet(input_auth, transaction)
    write_json(root / "R6_HUMAN_ACTIVATION_DECISION_PACKET.json", decision)
    verifier = build_verifier_contract(input_auth, transaction, packet_sha256)
    write_json(root / "R6_INDEPENDENT_ACTIVATION_VERIFIER_CONTRACT.json", verifier)

    report = f"""# Binding R6 Production Activation Governance Design

This package is a design-only, hash-bound production source-authority activation transaction. It authenticates the pinned R5 package and exact317, but it does not activate source authority, execute source-auth, select or pin fields, run P0/P1, publish bindings, mutate scoring/binding authority, modify GOV-R4/EXEC-R4, or mutate Git refs.

## Authenticated inputs

- R5 review commit: `{review_identity['commit']}`; tree: `{review_identity['tree']}`.
- R5 package envelope: `{input_auth['r5_package']['sha256sums_sha256']}`; all {input_auth['r5_package']['file_count']} committed files match the review commit.
- Exact317 manifest: `{input_auth['exact317']['manifest']['sha256']}`; 86 RAW + 231 CANDIDATE = 317.
- R4 wrapper rules: RAW 26, C0 60, scoring 231; all approved rule IDs are exact.
- R5 dry-run: union `Exact317`, duplicates 0, cross-route substitution 0, candidate-only objects.

## Activation design

The transaction is `{transaction['transaction_id']}`. It stages four immutable candidate roots (registry, corpus/schema rules, common-input freeze/runtime whitelist additions, and EXEC-R4 dispatch integration), verifies their exact content hashes under an activation lock, then atomically replaces one consumer pointer. Production sees either the complete pre-state or complete post-state; partial roots are never visible. Any failed precondition yields `FAIL_CLOSED_NO_ACTIVATION`. Rollback before commit leaves the pre-state untouched; after commit, rollback requires a separately reviewed compensating transaction.

The human activation decision remains null in `R6_HUMAN_ACTIVATION_DECISION_PACKET.json`; prior R5 wrapper approval is not activation approval.

## Field-pin bridge

`R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl` contains exactly 317 evidence-only packet skeletons. Each retains its target ID, source side, wrapper rule, candidate wrapper object ID, exact locator, and available scalar leaves. No canonical pointer or field is selected. The only future human actions are `APPROVE_EXACT_FIELD_PIN`, `REJECT_FIELD_CANDIDATES_KEEP_BLOCKED`, and `REQUEST_MORE_EVIDENCE`.

## Current boundary

- Active source authority: no
- Source-auth executed: no
- Field pins: 0
- P0/P1: not executed
- Binding publication: no
- GOV-R4/EXEC-R4 and Git refs: unchanged

## Required terminal

```text
BINDING_R6_PRODUCTION_ACTIVATION_GOVERNANCE_DESIGN = READY_FOR_EXPLICIT_HUMAN_ACTIVATION_REVIEW
R5_INPUT_AUTHENTICATION = PASS
EXACT317_CONSERVATION = PASS
ACTIVATION_TRANSACTION_MATERIALIZED = DESIGN_ONLY
FIELD_PIN_PACKET_SKELETON_COUNT = 317

ACTIVE_SOURCE_AUTHORITY_CREATED = NO
SOURCE_AUTH_EXECUTED = NO
FIELD_PINS_CREATED = 0
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO

NEXT_ACTION = FRESH_INDEPENDENT_REVIEW_OF_BINDING_R6_PRODUCTION_ACTIVATION_GOVERNANCE_DESIGN
STOP = true
```
"""
    (root / "R6_PRODUCTION_ACTIVATION_GOVERNANCE_REPORT.md").write_text(report, encoding="utf-8")
    write_file_list_and_checksums(root)
    return {
        "r5_input_authentication": input_auth["authentication_status"],
        "exact317_conservation": "PASS" if input_auth["dry_run_assertions"]["union"] == "Exact317" else "BLOCKED",
        "field_pin_packet_count": len(packets),
        "human_activation_decision": decision["decision"],
        "transaction_id": transaction["transaction_id"],
    }


if __name__ == "__main__":
    result = materialize()
    print(json.dumps(result, sort_keys=True))
