#!/usr/bin/env python3
"""Read-only deterministic verifier for the materialized contract package."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parent
TARGET_MANIFEST = Path("/home/cph/experiment-artifacts/fa1b2de-current86-canonical-intrinsic-317-r1/CURRENT86_Canonical_Intrinsic_317_Exact_Targets.json")
GIT_REPO = Path("/home/cph/fa1b2de-review-artifacts")
R4_COMMIT = "9cec0141fb9599ca879d5d992005921585f24cbb"
R4_PARENT = "bc54c0feea1a8af346e2c70b39679cd01f4f3577"
R4_TREE = "b1cca46922be1d6779aaf4b0282254bb2533959e"
R4_PATH = "current86-r4/fa1b2de-current86-canonical-source-authentication-governance-r4-patch/Design_FA1B2de_Current86_Canonical_Intrinsic_317_Source_Authentication_Governance_R4_PATCHED.md"
R4_SHA = "b499b4cfddd4f72e404dda72c423bfa3db98b0514af52773b9bbec5cce6e2cc0"
TARGET_SHA = "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac"
AUDIT_SCOPE = "34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306"


class VerificationError(RuntimeError):
    pass


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strict_load(path: Path):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise VerificationError(f"duplicate JSON key in {path}: {key}")
            out[key] = value
        return out
    return json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_float=lambda value: (_ for _ in ()).throw(VerificationError(f"float forbidden in {path}: {value}")), parse_constant=lambda value: (_ for _ in ()).throw(VerificationError(f"nonfinite forbidden in {path}: {value}")))


def git(*args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(GIT_REPO), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise VerificationError(result.stderr.decode("utf-8", "replace"))
    return result.stdout


def canonical(value) -> bytes:
    if isinstance(value, dict):
        return b"{" + b",".join(canonical(k) + b":" + canonical(value[k]) for k in sorted(value, key=lambda k: k.encode("utf-8"))) + b"}"
    if isinstance(value, list):
        return b"[" + b",".join(canonical(item) for item in value) + b"]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def verify_git_input() -> None:
    line = git("show", "-s", "--format=%T %P", R4_COMMIT).decode().strip().split()
    if line != [R4_TREE, R4_PARENT]:
        raise VerificationError("R4 tree/parent mismatch")
    content = git("show", f"{R4_COMMIT}:{R4_PATH}")
    if hashlib.sha256(content).hexdigest() != R4_SHA:
        raise VerificationError("R4 design hash mismatch")


def verify_targets() -> set[str]:
    if sha(TARGET_MANIFEST) != TARGET_SHA:
        raise VerificationError("target manifest hash mismatch")
    data = strict_load(TARGET_MANIFEST)
    if data["audit_scope_id"] != AUDIT_SCOPE or data["totals"] != {"EXACT_TARGET_TOTAL": 317, "RAW_SIDE_TOTAL": 86, "CANDIDATE_SIDE_TOTAL": 231}:
        raise VerificationError("exact-317 scope/count mismatch")
    targets = data["targets"]
    expected_order = sorted(targets, key=lambda row: (0 if row["source_side"] == "RAW" else 1, (row["bound_raw_key"] or row["bound_candidate_scoring_id"]).encode("utf-8")))
    if targets != expected_order or [row["target_index"] for row in targets] != list(range(1, 318)):
        raise VerificationError("target ordering mismatch")
    ids = set()
    for row in targets:
        basis = {
            "audit_scope_id": AUDIT_SCOPE,
            "bound_candidate_scoring_id": row["bound_candidate_scoring_id"],
            "bound_raw_key": row["bound_raw_key"],
            "source_artifact_class": row["source_artifact_class"],
            "source_fact_type": row["required_source_fact_type"],
            "source_side": row["source_side"],
        }
        expected = hashlib.sha256(canonical(basis)).hexdigest()
        if row["source_binding_target_id"] != expected:
            raise VerificationError("target identity mismatch")
        ids.add(expected)
    if len(ids) != 317:
        raise VerificationError("target uniqueness mismatch")
    hashes = data["input_missing_identity_set_hashes"]
    if hashes != {"candidate_bindings_sha256": "3f70daaecfae52ea24bcef669d00e0ec788f88000da31e07c28db866826780c1", "raw_bindings_sha256": "dc97465eba0d2fb1235cb93e47d8be57221b85c4a75c24b5f34c087ed379a4ed"}:
        raise VerificationError("side identity-set pin mismatch")
    return ids


def verify_json_and_boundaries(production_ids: set[str]) -> None:
    for path in sorted(ROOT.rglob("*.json")):
        strict_load(path)
    auth = strict_load(ROOT / "SOURCE_AUTH_EXECUTION_CONTRACT_R1_INPUT_AUTHENTICATION.json")
    if auth["SOURCE_AUTH_EXECUTION_CONTRACT_R1_INPUT_AUTHENTICATION"] != "PASS":
        raise VerificationError("input authentication not PASS")
    summary = strict_load(ROOT / "SOURCE_AUTH_EXECUTION_CONTRACT_R1_MATERIALIZATION_SUMMARY.json")
    expected = {
        "SOURCE_AUTH_EXECUTION_CONTRACT_R1_STATUS": "COMPLETE_CONTRACT_ONLY",
        "GOVERNANCE_R4_INPUT_AUTHENTICATION": "PASS",
        "EXACT317_SCOPE": "PASS",
        "SA_B1_EXECUTABLE_CONTRACT": "CLOSED_CANDIDATE",
        "SA_B2_EXECUTABLE_CONTRACT": "CLOSED_CANDIDATE",
        "SA_B3_EXECUTABLE_ISOLATION": "CLOSED_CANDIDATE",
        "SOURCE_AUTH_EXECUTION_READINESS": "BLOCKED_MISSING_AUTHORITY_INPUTS",
    }
    for key, value in expected.items():
        if summary.get(key) != value:
            raise VerificationError(f"summary mismatch: {key}")
    zero_no = {
        "real_source_auth_targets_executed": 0,
        "source_auth_executed": "NO",
        "current86_p0_executed": "NO",
        "current86_p1_executed": "NO",
        "raw_level_human_decisions": 0,
        "binding_publication": "NO",
        "scoring_authority_mutation": "NO",
        "binding_authority_mutation": "NO",
        "denominator_change": "NO",
        "accepted_binding_count_change": "NO",
        "git_ref_mutation": "NO",
    }
    for key, value in zero_no.items():
        if summary.get(key) != value:
            raise VerificationError(f"hard boundary mismatch: {key}")
    inventory = strict_load(ROOT / "SOURCE_AUTH_EXECUTION_CONTRACT_R1_DEPENDENCY_INVENTORY.json")
    if inventory["missing_is_empty_authority_set"] or inventory["execution_readiness"] != "BLOCKED_MISSING_AUTHORITY_INPUTS":
        raise VerificationError("missing authority semantics mismatch")
    fixture = strict_load(ROOT / "fixtures/SYNTHETIC_FIXTURE_MANIFEST.json")
    synthetic = set(fixture["synthetic_target_ids"])
    if synthetic & production_ids or any(re.fullmatch(r"[0-9a-f]{64}", value) for value in synthetic):
        raise VerificationError("synthetic fixture enters production authority")
    conservation = strict_load(ROOT / "SOURCE_AUTH_EXECUTION_CONTRACT_R1_TARGET_CONSERVATION.json")
    if conservation["current_contract_only_partition"] != {"NOT_EXECUTED_PENDING_SOURCE_AUTH_GOVERNANCE": 317} or conservation["real_target_terminal_records_materialized"] != 0:
        raise VerificationError("contract-only partition mismatch")


def verify_inventory() -> None:
    file_list_path = ROOT / "FILE_LIST.txt"
    sums_path = ROOT / "SHA256SUMS.txt"
    if not file_list_path.exists() or not sums_path.exists():
        raise VerificationError("package inventories missing")
    actual = sorted(path.relative_to(ROOT).as_posix() for path in ROOT.rglob("*") if path.is_file())
    listed = file_list_path.read_text(encoding="utf-8").splitlines()
    if listed != actual:
        raise VerificationError("FILE_LIST mismatch")
    expected_lines = []
    for relative in actual:
        if relative == "SHA256SUMS.txt":
            continue
        expected_lines.append(f"{sha(ROOT / relative)}  ./{relative}")
    observed = sums_path.read_text(encoding="utf-8").splitlines()
    if observed != expected_lines:
        raise VerificationError("SHA256SUMS mismatch or nondeterministic order")


def main() -> int:
    verify_git_input()
    production_ids = verify_targets()
    verify_json_and_boundaries(production_ids)
    verify_inventory()
    print(json.dumps({
        "package_verification": "PASS",
        "governance_r4_input_authentication": "PASS",
        "exact317_scope": "PASS",
        "source_auth_execution_readiness": "BLOCKED_MISSING_AUTHORITY_INPUTS",
        "real_source_auth_targets_executed": 0,
        "git_ref_mutation": "NO"
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"PACKAGE_VERIFICATION=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
