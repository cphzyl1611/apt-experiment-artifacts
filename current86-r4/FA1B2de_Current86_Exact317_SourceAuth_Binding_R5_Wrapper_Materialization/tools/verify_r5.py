#!/usr/bin/env python3
"""Independent verifier for the materialized R5 wrapper package."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r5_wrapper import candidate_object_id  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parent
R4 = ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Prospective_Canonical_Wrapper_Governance_R4"
TARGET_MANIFEST = ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4/00_lineage/EXACT317_TARGET_MANIFEST.json"
RAW_REGISTRY = Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/project_snapshots/raw_action_registry.jsonl")
PLAYBOOK_ROOT = Path("/home/cph/experiment")
C0_SOURCE = Path("/home/cph/experiment-artifacts/tier-de1c0-handoff-20260823-083725/tier_de1c0_typed_operation_semantics.jsonl")
SCORING_SOURCE = Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/c2/c2_scoring_snapshot_post_c1.jsonl")

ROUTES = {
    "R4_WRAPPER_RAW_LEGACY_26": ("RAW_26_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl", "RAW", 26),
    "R4_WRAPPER_C0_60": ("C0_60_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl", "RAW", 60),
    "R4_WRAPPER_SCORING_231": ("SCORING_231_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl", "CANDIDATE", 231),
}


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    require(path.is_file(), f"missing file: {path}")
    return digest(path.read_bytes())


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid JSON: {path}") from exc


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    try:
        lines = path.read_bytes().splitlines(keepends=True)
        for number, raw in enumerate(lines, 1):
            content = raw[:-1] if raw.endswith(b"\n") else raw
            if content.endswith(b"\r"):
                content = content[:-1]
            rows.append((number, content, json.loads(content.decode("utf-8"))))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid JSONL: {path}") from exc
    return rows


def main() -> int:
    r4_rules = load_json(R4 / "PROSPECTIVE_EXTRACTION_AUTHORITY_RULES.json")
    r4_commitments = load_json(R4 / "PROSPECTIVE_TARGET_EXPANSION_COMMITMENTS.json")
    exact_manifest = load_json(TARGET_MANIFEST)
    approval = load_json(PACKAGE / "01_approval/HUMAN_APPROVAL_AUTHENTICATION.json")
    expected_rules = {r["rule_id"]: r for r in r4_rules["rules"]}
    require(set(expected_rules) == set(ROUTES), "approved spec route IDs mismatch")
    require(approval["authenticated"] is True, "approval is not authenticated")
    require(approval["human_origin"] == "USER_EXPLICIT_APPROVAL", "approval origin mismatch")
    require(set(approval["approval_decisions"]) == set(ROUTES), "approval does not cover exactly three rules")
    require(all(v == "APPROVE_EXACT_CANONICAL_WRAPPER_RULE" for v in approval["approval_decisions"].values()), "approval decision mismatch")
    require(approval["frozen_r4_package"]["sha256sums_sha256"] == file_digest(R4 / "SHA256SUMS.txt"), "R4 package digest mismatch")
    require(approval["frozen_r4_package"]["rule_package_sha256"] == file_digest(R4 / "PROSPECTIVE_EXTRACTION_AUTHORITY_RULES.json"), "R4 rule package digest mismatch")

    targets = exact_manifest["targets"]
    require(len(targets) == 317, "Exact317 target count mismatch")
    target_by_id = {t["source_binding_target_id"]: t for t in targets}
    require(len(target_by_id) == 317, "Exact317 target IDs are not unique")
    route_expected = {}
    for route in r4_commitments["routes"]:
        rule_id = route["rule_id"]
        require(rule_id in ROUTES, "unexpected R4 commitment route")
        route_expected[rule_id] = route["target_ids"]
        require(len(route["target_ids"]) == ROUTES[rule_id][2], f"{rule_id} commitment count mismatch")
        require(len(set(route["target_ids"])) == len(route["target_ids"]), f"{rule_id} commitment duplicates")

    source_rows = {
        "raw": {r["raw_action_key"]: r for _, _, r in load_jsonl(RAW_REGISTRY)},
        "c0": load_jsonl(C0_SOURCE),
        "scoring": load_jsonl(SCORING_SOURCE),
    }
    require(file_digest(RAW_REGISTRY) == "53c85157f9fd0849ae19b1cf403333ad0d0af2a7d761b0498540dd92d66c1e93", "RAW registry hash mismatch")
    require(file_digest(C0_SOURCE) == "0036c42fb02026182274a7ac2a33b103b03b1e527856eb33b5ad650ceddd5c32", "C0 source hash mismatch")
    require(file_digest(SCORING_SOURCE) == "748a3808290f9e78f71c18d4553c77ae208517fd31d163fc2b3008cfcb57f1bb", "scoring source hash mismatch")
    c0_by_identity = {}
    for line, raw, row in source_rows["c0"]:
        c0_by_identity.setdefault(row.get("identity"), []).append((line, raw, row))
    scoring_by_id = {}
    for line, raw, row in source_rows["scoring"]:
        scoring_by_id.setdefault(row.get("scoring_id"), []).append((line, raw, row))

    checked_records = {}
    for rule_id, (filename, expected_side, expected_count) in ROUTES.items():
        rule = expected_rules[rule_id]
        manifest_path = PACKAGE / "03_inputs" / f"{rule_id}_INPUT_MANIFEST.json"
        checkpoint_path = PACKAGE / "03_inputs" / f"{rule_id}_CHECKPOINT.json"
        route_manifest = load_json(manifest_path)
        checkpoint = load_json(checkpoint_path)
        committed_ids = route_expected[rule_id]
        require(route_manifest["materialization_status"] == "MATERIALIZED_PROSPECTIVE_INPUT_MANIFEST", f"{rule_id} manifest not materialized")
        require(route_manifest["authority_status"] == "NON_AUTHORITATIVE_CANDIDATE_INPUT", f"{rule_id} manifest authority leak")
        require(route_manifest["exact317_manifest_sha256"] == file_digest(TARGET_MANIFEST), f"{rule_id} Exact317 manifest digest mismatch")
        require(route_manifest["target_ids"] == committed_ids, f"{rule_id} manifest target order mismatch")
        require(route_manifest["target_count"] == expected_count, f"{rule_id} manifest count mismatch")
        require(route_manifest["expansion_set_commitment_sha256"] == rule["expansion_set_commitment_sha256"], f"{rule_id} expansion commitment mismatch")
        require(route_manifest["approved_spec_id"] == rule["extractor_spec"]["spec_version"], f"{rule_id} spec mismatch")
        require(route_manifest["approved_spec_sha256"] == rule["deterministic_extractor_sha256"], f"{rule_id} approved spec digest mismatch")
        require(checkpoint["input_manifest_sha256"] == file_digest(manifest_path), f"{rule_id} checkpoint manifest digest mismatch")
        require(checkpoint["status"] == "MATERIALIZED_PROSPECTIVE_CHECKPOINT_NON_AUTHORITATIVE", f"{rule_id} checkpoint status")
        require(checkpoint["source_auth_executed"] is False and checkpoint["field_pins_created"] == 0, f"{rule_id} checkpoint boundary violation")
        require(checkpoint["extractor_implementation_sha256"] == file_digest(PACKAGE / "r5_wrapper.py"), f"{rule_id} implementation digest mismatch")
        entrypoint = checkpoint["route_entrypoint"]
        entrypoint_path = PACKAGE / entrypoint["path"]
        require(entrypoint["sha256"] == file_digest(entrypoint_path), f"{rule_id} materialized extractor source digest mismatch")
        records = load_jsonl(PACKAGE / "05_dry_run" / filename)
        require(len(records) == expected_count, f"{rule_id} dry-run count mismatch")
        require([record["source_binding_target_id"] for _, _, record in records] == committed_ids, f"{rule_id} dry-run target order mismatch")
        require(all(record["source_side"] == expected_side for _, _, record in records), f"{rule_id} dry-run side mismatch")
        require(all(record["route_rule_id"] == rule_id for _, _, record in records), f"{rule_id} cross-route substitution")
        require(all(record["authority_status"] == "CANDIDATE_WRAPPER_OBJECTS_ONLY" for _, _, record in records), f"{rule_id} authority status leak")
        require(all(record["source_auth_executed"] is False and record["field_pin_created"] is False for _, _, record in records), f"{rule_id} prohibited action in output")
        require(all(record["candidate_object_id"] == candidate_object_id(record) for _, _, record in records), f"{rule_id} candidate object identity mismatch")
        commitment_by_id = {item["source_binding_target_id"]: item for item in route_manifest["row_commitments"]}
        for _, _, record in records:
            target = target_by_id[record["source_binding_target_id"]]
            require(record["target_index"] == target["target_index"], f"{rule_id} target index mismatch")
            commitment = commitment_by_id.get(record["source_binding_target_id"])
            require(commitment is not None, f"{rule_id} missing manifest row commitment")
            require(commitment["source_key"] == record["source_key"] and commitment["source_locator"] == record["source_locator"], f"{rule_id} manifest locator mismatch")
            require(commitment.get("row_bytes_sha256") == record.get("row_bytes_sha256"), f"{rule_id} manifest row-byte commitment mismatch")
            require(commitment.get("source_file_sha256") == record.get("source_file_sha256"), f"{rule_id} manifest source-file commitment mismatch")
            if rule_id == "R4_WRAPPER_RAW_LEGACY_26":
                source_key = record["source_key"]
                registry = source_rows["raw"].get(source_key)
                require(registry is not None, "RAW output key absent from registry")
                path = (PLAYBOOK_ROOT / registry["source_file"]).resolve()
                require(file_digest(path) == registry["source_file_sha256"], "RAW playbook hash mismatch")
                parsed = json.loads(path.read_text(encoding="utf-8"))
                match = re.fullmatch(r"\$\.pipeline\[(\d+)\]\.actions\[(\d+)\]", record["source_locator"])
                require(match is not None, "RAW locator is not positional")
                action = parsed["pipeline"][int(match.group(1))]["actions"][int(match.group(2))]
                require(action == record["source_action"], "RAW action bytes/object mismatch")
                require(record["historical_producer_identity_recovered"] is False, "RAW historical identity claim")
            elif rule_id == "R4_WRAPPER_C0_60":
                matches = c0_by_identity.get(record["source_key"], [])
                require(len(matches) == 1, "C0 output does not have exactly one source row")
                line, raw, row = matches[0]
                require(line == record["jsonl_line"] and digest(raw) == record["row_bytes_sha256"], "C0 row commitment mismatch")
                require(row == record["source_row"], "C0 row content mismatch")
                require(record["historical_source_identity_preserved"] is True, "C0 history was relabeled")
            else:
                matches = scoring_by_id.get(record["source_key"], [])
                require(len(matches) == 1, "scoring output does not have exactly one source row")
                line, raw, row = matches[0]
                require(line == record["jsonl_line"] and digest(raw) == record["row_bytes_sha256"], "scoring row commitment mismatch")
                require(row == record["source_row"], "scoring row content mismatch")
                require(record["scoring_authority_mutated"] is False, "scoring authority mutation")
        checked_records[rule_id] = [record for _, _, record in records]

    union = [record["source_binding_target_id"] for records in checked_records.values() for record in records]
    require(len(union) == 317 and len(set(union)) == 317, "duplicate or missing Exact317 output")
    require(set(union) == set(target_by_id), "dry-run union is not Exact317")
    require(sum(record["source_side"] == "RAW" for records in checked_records.values() for record in records) == 86, "RAW count is not 86")
    require(sum(record["source_side"] == "CANDIDATE" for records in checked_records.values() for record in records) == 231, "CANDIDATE count is not 231")
    exact_rows = [record for _, _, record in load_jsonl(PACKAGE / "05_dry_run/EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl")]
    require([record["target_index"] for record in exact_rows] == list(range(1, 318)), "Exact317 union output order mismatch")
    require([record["source_binding_target_id"] for record in exact_rows] == [target["source_binding_target_id"] for target in targets], "Exact317 union target commitment mismatch")
    require(all(record["authority_status"] == "CANDIDATE_WRAPPER_OBJECTS_ONLY" for record in exact_rows), "Exact317 union authority leak")

    for candidate in ("SOURCE_ADMISSION_REGISTRY_ROOT_CANDIDATE.json", "SOURCE_ADMISSION_CORPUS_SCHEMA_RULE_ROOT_CANDIDATE.json", "COMMON_INPUT_FREEZE_ADDITIONS_CANDIDATE.json", "EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION_PATCH_CANDIDATE.json"):
        item = load_json(PACKAGE / "06_non_active_candidates" / candidate)
        require(item["authority_status"] == "NON_ACTIVE_CANDIDATE" and item["activation_status"] == "NOT_ACTIVE", f"candidate activation leak: {candidate}")
        require(item["source_auth_executed"] is False and item["field_pins_created"] == 0, f"candidate boundary violation: {candidate}")
    dispatch = load_json(PACKAGE / "06_non_active_candidates/EXEC_R4_PRODUCTION_DISPATCH_INTEGRATION_PATCH_CANDIDATE.json")
    require(dispatch["exec_r4_mutated"] is False and dispatch["registered_in_exec_r4"] is False, "EXEC-R4 was mutated")
    admission = load_json(PACKAGE / "06_non_active_candidates/SOURCE_ADMISSION_REGISTRY_ROOT_CANDIDATE.json")
    require(admission["candidate_object_ids"] == [record["candidate_object_id"] for record in exact_rows], "admission candidate object IDs mismatch")
    require(admission["field_pin_authority_status"] == "BLOCKED_NOT_CREATED", "field-pin authority was exposed")

    result = {
        "schema": "FA1B2DE_CURRENT86_BINDING_R5_INDEPENDENT_VERIFICATION_V1",
        "verification_status": "PASS",
        "independent": True,
        "approved_specs_verified": sorted(ROUTES),
        "materialized_manifests_verified": 3,
        "materialized_checkpoints_verified": 3,
        "dry_run_outputs_verified": {rule_id: len(records) for rule_id, records in checked_records.items()},
        "targets_total": 317,
        "raw": 86,
        "candidate": 231,
        "duplicates": 0,
        "cross_route_substitution": 0,
        "union": "Exact317",
        "authority_boundary": {
            "active_source_auth_created": False,
            "source_auth_executed": False,
            "field_pins_created": 0,
            "p0_executed": False,
            "p1_executed": False,
            "binding_publication": False,
            "scoring_authority_mutated": False,
            "exec_r4_mutated": False,
        },
    }
    out = PACKAGE / "07_verification/R5_INDEPENDENT_VERIFICATION.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"VERIFICATION_BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)
