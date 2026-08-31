"""Independent, non-activating verifier for the R6 governance-design package."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
R5 = ROOT.parent / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R5_Wrapper_Materialization"
EXACT317 = ROOT.parent / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4" / "00_lineage" / "EXACT317_TARGET_MANIFEST.json"
R4 = ROOT.parent / "FA1B2de_Current86_Exact317_SourceAuth_Prospective_Canonical_Wrapper_Governance_R4"
EXEC_R4 = ROOT.parent / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4"
GOV_R4 = ROOT.parent / "fa1b2de-current86-canonical-source-authentication-governance-r4-patch"
PRODUCTION_INPUTS = ROOT.parent / "FA1B2de_Current86_Exact317_SourceAuth_Production_Authority_Inputs_R1"
REVIEW_REPO = Path("/home/cph/fa1b2de-review-artifacts")
REVIEW_COMMIT = "90513ab76a2d392398fefd0456ad53a4660a3e8a"
REVIEW_PREFIX = "current86-r4/FA1B2de_Current86_Exact317_SourceAuth_Binding_R5_Wrapper_Materialization"
RULES = ("R4_WRAPPER_C0_60", "R4_WRAPPER_RAW_LEGACY_26", "R4_WRAPPER_SCORING_231")
COUNTS = {"R4_WRAPPER_RAW_LEGACY_26": 26, "R4_WRAPPER_C0_60": 60, "R4_WRAPPER_SCORING_231": 231}
FIELD_ACTIONS = ["APPROVE_EXACT_FIELD_PIN", "REJECT_FIELD_CANDIDATES_KEEP_BLOCKED", "REQUEST_MORE_EVIDENCE"]


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    require(path.is_file(), f"missing file: {path}")
    return digest(path.read_bytes())


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"JSON root is not object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_bytes().splitlines():
        value = json.loads(line.decode("utf-8"))
        require(isinstance(value, dict), f"JSONL row is not object: {path}")
        rows.append(value)
    return rows


def parse_sums(path: Path) -> dict[str, str]:
    entries = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", line)
        require(match is not None, f"malformed checksum: {line}")
        entries[match.group(2)] = match.group(1)
    require(len(entries) == len(set(entries)), "duplicate checksum path")
    return entries


def verify_external_envelope(package: Path) -> int:
    entries: dict[str, str] = {}
    for line in (package / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?(.+)", line)
        require(match is not None, f"malformed external checksum in {package}: {line}")
        relative = match.group(2)
        require(relative not in entries, f"duplicate external checksum path in {package}: {relative}")
        entries[relative] = match.group(1)
    for relative, expected in entries.items():
        require(file_digest(package / relative) == expected, f"external package checksum mismatch: {package.name}/{relative}")
    return len(entries)


def flatten(value: Any, prefix: str) -> list[dict[str, Any]]:
    if isinstance(value, Mapping):
        result = []
        for key in sorted(value, key=lambda item: str(item).encode("utf-8")):
            token = str(key).replace("~", "~0").replace("/", "~1")
            result.extend(flatten(value[key], f"{prefix}/{token}"))
        return result
    if isinstance(value, list):
        result = []
        for index, item in enumerate(value):
            result.extend(flatten(item, f"{prefix}/{index}"))
        return result
    return [{"pointer": prefix or "/", "value": value, "value_sha256": digest(canonical(value))}]


def root_id(role: str, path: Path, candidate: Mapping[str, Any], target_manifest_sha: str) -> str:
    dependencies = {}
    if role == "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST":
        dependencies = {
            "production_authority_inputs_sha256sums_sha256": file_digest(PRODUCTION_INPUTS / "SHA256SUMS.txt"),
            "base_common_input_freeze_sha256": file_digest(PRODUCTION_INPUTS / "COMMON_INPUT_FREEZE_CANDIDATE.json"),
            "base_runtime_whitelist_sha256": file_digest(PRODUCTION_INPUTS / "RUNTIME_WHITELIST_CANDIDATE.json"),
        }
    elif role == "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION":
        dependencies = {
            "exec_r4_sha256sums_sha256": file_digest(EXEC_R4 / "SHA256SUMS.txt"),
            "gov_r4_sha256sums_sha256": file_digest(GOV_R4 / "SHA256SUMS.txt"),
        }
    basis = {
        "authority_role": role,
        "artifact_sha256": file_digest(path),
        "artifact_schema": candidate.get("schema"),
        "target_manifest_sha256": target_manifest_sha,
        "wrapper_rule_ids": sorted(candidate.get("wrapper_rule_ids", [])),
        "scope": candidate.get("scope"),
        "dependencies": dependencies,
    }
    return digest(canonical({"schema": "FA1B2DE_CURRENT86_R6_PROSPECTIVE_AUTHORITY_ROOT_ID_V1", **basis}))


def verify_r5_commit() -> tuple[dict[str, str], str]:
    entries = parse_sums(R5 / "SHA256SUMS.txt")
    for relative, expected in entries.items():
        require(file_digest(R5 / relative) == expected, f"R5 checksum mismatch: {relative}")
    listed = {line.strip() for line in (R5 / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line.strip()}
    require(listed == set(entries), "R5 FILE_LIST differs from checksum envelope")
    for relative, expected in entries.items():
        completed = subprocess.run(
            ["git", "-C", str(REVIEW_REPO), "show", f"{REVIEW_COMMIT}:{REVIEW_PREFIX}/{relative}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        require(digest(completed.stdout) == expected, f"R5 review commit mismatch: {relative}")
    tree = subprocess.run(
        ["git", "-C", str(REVIEW_REPO), "rev-parse", f"{REVIEW_COMMIT}^{{tree}}"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    return entries, tree


def verify() -> dict[str, Any]:
    required = [
        "R6_INPUT_AUTHENTICATION.json",
        "R6_PRODUCTION_ACTIVATION_TRANSACTION_DESIGN.json",
        "R6_ACTIVATION_PRECONDITIONS.json",
        "R6_ATOMICITY_AND_ROLLBACK_CONTRACT.json",
        "R6_INDEPENDENT_ACTIVATION_VERIFIER_CONTRACT.json",
        "R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl",
        "R6_FIELD_PIN_GOVERNANCE_BRIDGE.json",
        "R6_HUMAN_ACTIVATION_DECISION_PACKET.json",
        "R6_PRODUCTION_ACTIVATION_GOVERNANCE_REPORT.md",
    ]
    for relative in required:
        require((ROOT / relative).is_file(), f"R6 required output missing: {relative}")
    r6_entries = parse_sums(ROOT / "SHA256SUMS.txt")
    for relative, expected in r6_entries.items():
        require(file_digest(ROOT / relative) == expected, f"R6 package checksum mismatch: {relative}")
    r6_listed = {line.strip() for line in (ROOT / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line.strip()}
    require(r6_listed == set(r6_entries), "R6 FILE_LIST differs from checksum envelope")
    r5_entries, review_tree = verify_r5_commit()
    auth = load_json(ROOT / "R6_INPUT_AUTHENTICATION.json")
    tx = load_json(ROOT / "R6_PRODUCTION_ACTIVATION_TRANSACTION_DESIGN.json")
    pre = load_json(ROOT / "R6_ACTIVATION_PRECONDITIONS.json")
    atomic = load_json(ROOT / "R6_ATOMICITY_AND_ROLLBACK_CONTRACT.json")
    contract = load_json(ROOT / "R6_INDEPENDENT_ACTIVATION_VERIFIER_CONTRACT.json")
    bridge = load_json(ROOT / "R6_FIELD_PIN_GOVERNANCE_BRIDGE.json")
    decision = load_json(ROOT / "R6_HUMAN_ACTIVATION_DECISION_PACKET.json")
    packets = load_jsonl(ROOT / "R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl")
    exact = load_json(EXACT317)
    require(auth.get("authentication_status") == "PASS", "R6 input authentication is not PASS")
    require(auth.get("pinned_r5_review", {}).get("commit") == REVIEW_COMMIT, "R6 review commit mismatch")
    require(auth.get("pinned_r5_review", {}).get("tree") == review_tree, "R6 review tree mismatch")
    require(auth.get("r5_package", {}).get("sha256sums_sha256") == file_digest(R5 / "SHA256SUMS.txt"), "R6 R5 package hash mismatch")
    require(auth.get("exact317", {}).get("manifest", {}).get("sha256") == file_digest(EXACT317), "R6 Exact317 hash mismatch")
    require(file_digest(R4 / "SHA256SUMS.txt") == auth["protected_input_packages"]["R4_WRAPPER_GOVERNANCE"]["sha256"], "R4 package drift")
    require(file_digest(EXEC_R4 / "SHA256SUMS.txt") == auth["protected_input_packages"]["EXEC_R4"]["sha256"], "EXEC-R4 package drift")
    require(file_digest(GOV_R4 / "SHA256SUMS.txt") == auth["protected_input_packages"]["GOV_R4"]["sha256"], "GOV-R4 package drift")
    require(file_digest(PRODUCTION_INPUTS / "SHA256SUMS.txt") == auth["protected_input_packages"]["PRODUCTION_AUTHORITY_INPUTS_R1"]["sha256"], "production authority input package drift")
    require(file_digest(PRODUCTION_INPUTS / "COMMON_INPUT_FREEZE_CANDIDATE.json") == auth["common_input_freeze_runtime_base"]["base_common_input_freeze_candidate"]["sha256"], "base common freeze drift")
    require(file_digest(PRODUCTION_INPUTS / "RUNTIME_WHITELIST_CANDIDATE.json") == auth["common_input_freeze_runtime_base"]["base_runtime_whitelist_candidate"]["sha256"], "base runtime whitelist drift")
    protected_package_counts = {
        "R4_WRAPPER_GOVERNANCE": verify_external_envelope(R4),
        "EXEC_R4": verify_external_envelope(EXEC_R4),
        "GOV_R4": verify_external_envelope(GOV_R4),
        "PRODUCTION_AUTHORITY_INPUTS_R1": verify_external_envelope(PRODUCTION_INPUTS),
    }
    protected_source = auth.get("protected_source_state", {})
    require(protected_source.get("authentication_status") == "PASS", "protected source state is not authenticated")
    require(protected_source.get("raw_playbook_git", {}).get("commit") == "a699ebe4fa14cf25768fd0e5475b994a72b60dec", "RAW Git commit drift")
    require(protected_source.get("raw_playbook_git", {}).get("tree") == "5ccafffe7e7785535fc276d352487b1d680947e9", "RAW Git tree drift")
    current_raw_commit = subprocess.run(["git", "-C", "/home/cph/experiment", "rev-parse", "HEAD"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
    current_raw_tree = subprocess.run(["git", "-C", "/home/cph/experiment", "rev-parse", "HEAD^{tree}"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
    require(current_raw_commit == protected_source["raw_playbook_git"]["commit"], "current RAW Git commit differs from authenticated identity")
    require(current_raw_tree == protected_source["raw_playbook_git"]["tree"], "current RAW Git tree differs from authenticated identity")
    for source_artifact in protected_source.get("source_artifacts", {}).values():
        require(isinstance(source_artifact, Mapping), "protected source artifact is malformed")
        require(file_digest(Path(source_artifact["path"])) == source_artifact["sha256"], "protected source artifact bytes drift")
    require(len(packets) == 317, "field packet count is not 317")
    packet_ids = [packet.get("source_binding_target_id") for packet in packets]
    require(len(set(packet_ids)) == 317 and all(isinstance(item, str) for item in packet_ids), "field packet target IDs are not unique")
    require(bridge.get("packet_skeletons", {}).get("sha256") == file_digest(ROOT / "R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl"), "field packet hash mismatch")
    require(bridge.get("packet_skeletons", {}).get("count") == 317, "bridge packet count mismatch")
    require(bridge.get("field_pin_authority_status") == "NOT_CREATED", "field-pin authority is not blocked")
    require(decision.get("decision") is None and decision.get("decision_status") == "PENDING_NO_DEFAULT", "activation decision is not null/pending")
    require(decision.get("allowed_human_actions") == ["APPROVE_EXACT_PRODUCTION_SOURCE_AUTHORITY_ACTIVATION", "REJECT_KEEP_NON_ACTIVE", "REQUEST_REMEDIATION"], "activation actions changed")
    require(tx.get("design_only") is True and tx.get("activation_execution_performed") is False, "transaction is not design-only")
    require(pre.get("failure_mode") == "FAIL_CLOSED_NO_ACTIVATION", "precondition failure mode changed")
    require(atomic.get("design_only") is True and atomic.get("commit_point") == tx.get("commit_point"), "atomicity contract mismatch")

    manifest_by_index = {row["target_index"]: row for row in exact["targets"]}
    require(set(manifest_by_index) == set(range(1, 318)), "Exact317 manifest index universe changed")
    r5_rows = load_jsonl(R5 / "05_dry_run/EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl")
    require(len(r5_rows) == 317, "R5 dry-run row count changed")
    row_by_index = {row["target_index"]: row for row in r5_rows}
    require(set(row_by_index) == set(range(1, 318)), "R5 target index universe changed")
    commitments = load_json(R5 / "02_specs/APPROVED_R4_TARGET_COMMITMENTS.json")
    require(tx["transaction_id_basis"]["approved_r4_wrapper_specs_sha256"] == file_digest(R5 / "02_specs/APPROVED_R4_WRAPPER_SPECS.json"), "R4 wrapper spec hash is not transaction-bound")
    require(tx["transaction_id_basis"]["approved_r4_target_commitments_sha256"] == file_digest(R5 / "02_specs/APPROVED_R4_TARGET_COMMITMENTS.json"), "R4 target commitments hash is not transaction-bound")
    routes = commitments["commitments"]["routes"]
    expected_route: dict[int, str] = {}
    for route in routes:
        rule = route["rule_id"]
        require(rule in COUNTS and len(route["target_ids"]) == COUNTS[rule], f"route count changed: {rule}")
        require(tx["transaction_id_basis"]["route_commitment_sha256s"].get(rule) == route["expansion_set_commitment_sha256"], f"route commitment hash changed: {rule}")
        for target_id in route["target_ids"]:
            index = next((item["target_index"] for item in exact["targets"] if item["source_binding_target_id"] == target_id), None)
            require(isinstance(index, int) and index not in expected_route, "route membership is not exact")
            expected_route[index] = rule
    require(set(expected_route) == set(range(1, 318)), "route union is not Exact317")
    for index, row in row_by_index.items():
        manifest_row = manifest_by_index[index]
        require(row["source_binding_target_id"] == manifest_row["source_binding_target_id"], "R5 target identity drift")
        require(row["source_side"] == manifest_row["source_side"], "R5 source side drift")
        require(row["route_rule_id"] == expected_route[index], "R5 route substitution")
        require(row["authority_status"] == "CANDIDATE_WRAPPER_OBJECTS_ONLY", "R5 row is authoritative")

    for packet in packets:
        index = packet["target_index"]
        source = row_by_index[index]
        require(packet["source_binding_target_id"] == source["source_binding_target_id"], "packet target mismatch")
        require(packet["source_side"] == source["source_side"], "packet source-side mismatch")
        require(packet["wrapper_rule_id"] == source["route_rule_id"], "packet route mismatch")
        require(packet["candidate_wrapper_object_id"] == source["candidate_object_id"], "packet candidate identity mismatch")
        require(packet["exact_source_locator"] == source["source_locator"], "packet locator mismatch")
        source_field = "source_action" if "source_action" in source else "source_row"
        require(packet["available_candidate_scalar_leaves"] == flatten(source[source_field], f"/{source_field}"), "packet scalar leaves changed")
        require(packet["evidence_status"] == "EVIDENCE_ONLY_NOT_AUTHENTICATED", "packet evidence status changed")
        require(packet["selected_canonical_pointer"] is None and packet["selected_scalar_leaf"] is None, "packet selects a field")
        require(packet["human_decision"] is None and packet["allowed_future_human_actions"] == FIELD_ACTIONS, "packet decision contract changed")
        require(packet["field_pin_created"] is False, "packet claims a field pin")

    tx_basis = tx["transaction_id_basis"]
    expected_tx = digest(canonical({"schema": "FA1B2DE_CURRENT86_R6_PRODUCTION_ACTIVATION_TRANSACTION_V1", **tx_basis}))
    require(tx.get("transaction_id") == expected_tx, "transaction ID is not content-derived")
    for role, candidate_name in {
        "SOURCE_ADMISSION_REGISTRY_ROOT": "SOURCE_ADMISSION_REGISTRY_ROOT_CANDIDATE.json",
        "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT": "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT_CANDIDATE.json",
        "SOURCE_AUTH_COMMON_INPUT_FREEZE_AND_RUNTIME_WHITELIST": "COMMON_INPUT_FREEZE_ADDITIONS_CANDIDATE.json",
        "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION": "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION_PATCH_CANDIDATE.json",
    }.items():
        path = R5 / "06_non_active_candidates" / candidate_name
        candidate = load_json(path)
        expected_root = root_id(role, path, candidate, file_digest(EXACT317))
        require(tx["post_state_candidate"]["root_ids"][role] == expected_root, f"root ID mismatch: {role}")
        require(candidate.get("activation_status") == "NOT_ACTIVE", f"candidate is active: {role}")

    prohibited_truths = {"active_source_authority_created", "source_auth_executed", "field_pin_created", "p0_executed", "p1_executed", "binding_publication", "scoring_authority_mutated", "binding_authority_mutated", "git_ref_mutation"}
    for path in [ROOT / "R6_INPUT_AUTHENTICATION.json", ROOT / "R6_PRODUCTION_ACTIVATION_TRANSACTION_DESIGN.json", ROOT / "R6_ACTIVATION_PRECONDITIONS.json", ROOT / "R6_INDEPENDENT_ACTIVATION_VERIFIER_CONTRACT.json", ROOT / "R6_FIELD_PIN_GOVERNANCE_BRIDGE.json", ROOT / "R6_HUMAN_ACTIVATION_DECISION_PACKET.json"]:
        value = load_json(path)
        stack = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, Mapping):
                for key, child in item.items():
                    if key in prohibited_truths and (child is True or (key == "field_pin_created" and child not in (0, False, None))):
                        raise VerificationError(f"prohibited active boundary in {path.name}: {key}")
                    stack.append(child)
            elif isinstance(item, list):
                stack.extend(item)

    result = {
        "schema": "FA1B2DE_CURRENT86_R6_INDEPENDENT_DESIGN_VERIFICATION_V1",
        "verification_status": "PASS",
        "independent": True,
        "r5_review_commit": REVIEW_COMMIT,
        "r5_review_tree": review_tree,
        "r5_package_file_count": len(r5_entries),
        "protected_package_file_counts": protected_package_counts,
        "exact317": {"total": 317, "raw": 86, "candidate": 231, "union": "Exact317", "duplicates": 0, "cross_route_substitution": 0},
        "wrapper_routes": {"R4_WRAPPER_RAW_LEGACY_26": 26, "R4_WRAPPER_C0_60": 60, "R4_WRAPPER_SCORING_231": 231},
        "field_pin_packet_skeleton_count": len(packets),
        "transaction_id": tx["transaction_id"],
        "human_activation_decision": None,
        "authority_boundary": {"active_source_authority_created": False, "source_auth_executed": False, "field_pins_created": 0, "p0_executed": False, "p1_executed": False, "binding_publication": False},
    }
    return result


if __name__ == "__main__":
    try:
        result = verify()
    except (OSError, subprocess.CalledProcessError, KeyError, TypeError, ValueError, VerificationError) as exc:
        print(f"R6_VERIFY_BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)
    output = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if "--write-output" in sys.argv:
        (ROOT / "R6_INDEPENDENT_DESIGN_VERIFICATION.json").write_text(output, encoding="utf-8")
    print(output, end="")
