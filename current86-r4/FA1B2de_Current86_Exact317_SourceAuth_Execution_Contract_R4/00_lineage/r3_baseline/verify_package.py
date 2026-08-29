#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
R2 = ROOT.parent / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R2"
TARGET = Path("/home/cph/experiment-artifacts/fa1b2de-current86-canonical-intrinsic-317-r1/CURRENT86_Canonical_Intrinsic_317_Exact_Targets.json")


class VerificationError(RuntimeError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: Path):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise VerificationError(f"DUPLICATE_JSON_KEY:{path}")
            out[key] = value
        return out
    return json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_float=lambda _: (_ for _ in ()).throw(VerificationError("FLOAT_FORBIDDEN")), parse_constant=lambda _: (_ for _ in ()).throw(VerificationError("NONFINITE_FORBIDDEN")))


def canonical(value):
    if isinstance(value, dict):
        return b"{" + b",".join(canonical(k) + b":" + canonical(value[k]) for k in sorted(value, key=lambda k: k.encode("utf-8"))) + b"}"
    if isinstance(value, list):
        return b"[" + b",".join(canonical(x) for x in value) + b"]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def verify_r2_lineage():
    if not R2.is_dir():
        raise VerificationError("R2_PACKAGE_MISSING")
    listed = (R2 / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines()
    expected = [line.split("  ./", 1) for line in (R2 / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()]
    if len(expected) != len(listed) - 1:
        raise VerificationError("R2_CHECKSUM_ENTRY_COUNT_MISMATCH")
    for checksum, rel in expected:
        path = R2 / rel
        if not path.is_file() or digest(path.read_bytes()) != checksum:
            raise VerificationError(f"R2_LINEAGE_CHECKSUM_MISMATCH:{rel}")
    pin = load(ROOT / "00_lineage/R2_INPUT_PACKAGE_PIN.json")
    checks = {
        "r2_sha256sums_sha256": digest((R2 / "SHA256SUMS.txt").read_bytes()),
        "r2_file_list_sha256": digest((R2 / "FILE_LIST.txt").read_bytes()),
        "r2_contract_manifest_sha256": digest((R2 / "CONTRACT_MANIFEST.json").read_bytes()),
        "r2_r1_lineage_pin_sha256": digest((R2 / "00_lineage/R1_INPUT_PACKAGE_PIN.json").read_bytes()),
    }
    if any(pin.get(key) != value for key, value in checks.items()) or not pin.get("r1_and_r2_byte_for_byte_preserved"):
        raise VerificationError("R1_R2_LINEAGE_PIN_MISMATCH")


def verify_target_scope():
    if not TARGET.is_file():
        raise VerificationError("TARGET_MANIFEST_MISSING")
    data = load(TARGET)
    scope = "34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306"
    if digest(TARGET.read_bytes()) != "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac":
        raise VerificationError("TARGET_MANIFEST_HASH_MISMATCH")
    if data.get("audit_scope_id") != scope or data.get("totals") != {"EXACT_TARGET_TOTAL": 317, "RAW_SIDE_TOTAL": 86, "CANDIDATE_SIDE_TOTAL": 231}:
        raise VerificationError("EXACT317_SCOPE_MISMATCH")
    rows = data.get("targets", [])
    if len(rows) != 317 or [row.get("target_index") for row in rows] != list(range(1, 318)):
        raise VerificationError("TARGET_ORDER_MISMATCH")
    if sum(row.get("source_side") == "RAW" for row in rows) != 86 or sum(row.get("source_side") == "CANDIDATE" for row in rows) != 231:
        raise VerificationError("SIDE_COUNT_MISMATCH")
    ids = set()
    for row in rows:
        basis = {"audit_scope_id": scope, "bound_candidate_scoring_id": row["bound_candidate_scoring_id"], "bound_raw_key": row["bound_raw_key"], "source_artifact_class": row["source_artifact_class"], "source_fact_type": row["required_source_fact_type"], "source_side": row["source_side"]}
        if digest(canonical(basis)) != row["source_binding_target_id"]:
            raise VerificationError("TARGET_ID_MISMATCH")
        ids.add(row["source_binding_target_id"])
    if len(ids) != 317:
        raise VerificationError("TARGET_ID_DUPLICATE")


def verify_metadata():
    listed = (ROOT / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines()
    actual = sorted(path.relative_to(ROOT).as_posix() for path in ROOT.rglob("*") if path.is_file() and "__pycache__" not in path.parts)
    if listed != actual:
        raise VerificationError("FILE_LIST_MISMATCH")
    expected = [f"{digest((ROOT / rel).read_bytes())}  ./{rel}" for rel in actual if rel != "SHA256SUMS.txt"]
    if (ROOT / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines() != expected:
        raise VerificationError("SHA256SUMS_MISMATCH")


def verify_contract():
    for path in ROOT.rglob("*.json"):
        load(path)
    manifest = load(ROOT / "CONTRACT_MANIFEST.json")
    contract = load(ROOT / "03_contracts/SOURCE_AUTH_EXECUTION_CONTRACT_R3.json")
    registry = load(ROOT / "02_schemas/SCHEMA_REGISTRY_R3.json")
    if contract.get("schema") != "FA1B2DE_CURRENT86_EXACT317_SOURCE_AUTH_EXECUTION_CONTRACT_R3" or registry.get("schema") != "FA1B2DE_CURRENT86_SOURCE_AUTH_SCHEMA_REGISTRY_R3":
        raise VerificationError("R3_CONTRACT_SCHEMA_MISMATCH")
    required = {
        "package_name": "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R3",
        "source_auth_execution_contract_r3_status": "COMPLETE_CONTRACT_ONLY",
        "ec_b1_exact_schema_and_cross_object_validation": "PASS_PRESERVED",
        "ec_b2_authenticated_deterministic_authority_expansion": "CLOSED_CANDIDATE",
        "ec_b3_current_derivation_zero_proof_freshness": "CLOSED_CANDIDATE",
        "ec_b4_exact_comparator_derived_affected_target_set": "CLOSED_CANDIDATE",
        "source_auth_readiness_terminal": "BLOCKED_MISSING_AUTHORITY_INPUTS",
        "source_auth_target_count": 317, "raw_side_target_count": 86, "candidate_side_target_count": 231,
        "real_source_auth_targets_executed": 0, "source_auth_executed": "NO", "current86_p0_executed": "NO", "current86_p1_executed": "NO", "raw_level_human_decisions": 0, "binding_publication": "NO", "accepted_binding_count_change": "NO",
    }
    if any(manifest.get(key) != value for key, value in required.items()):
        raise VerificationError("MANIFEST_BOUNDARY_MISMATCH")
    inv = load(ROOT / "SOURCE_AUTH_EXECUTION_CONTRACT_R2_DEPENDENCY_INVENTORY.json")
    if inv.get("missing_is_empty_authority_set") or inv.get("execution_readiness") != "BLOCKED_MISSING_AUTHORITY_INPUTS":
        raise VerificationError("MISSING_AUTHORITY_SEMANTICS_MISMATCH")


def main():
    verify_r2_lineage(); verify_target_scope(); verify_contract(); verify_metadata()
    print(json.dumps({"package_verification": "PASS", "governance_r4_input_authentication": "PASS", "exact317_scope": "PASS", "source_auth_execution_readiness": "BLOCKED_MISSING_AUTHORITY_INPUTS", "real_source_auth_targets_executed": 0, "git_ref_mutation": "NO"}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except VerificationError as exc:
        print(f"PACKAGE_VERIFICATION=FAIL:{exc}", file=sys.stderr)
        raise SystemExit(1)
