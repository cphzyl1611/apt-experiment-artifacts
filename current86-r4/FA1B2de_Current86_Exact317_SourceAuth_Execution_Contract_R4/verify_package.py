from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TARGET_SHA256 = "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac"
SCOPE_ID = "34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306"


class VerificationError(RuntimeError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def object_id(value: dict[str, object], field: str) -> str:
    return digest(canonical({key: item for key, item in value.items() if key != field}))


def load_json(path: Path):
    try:
        return json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"INVALID_JSON:{path}") from exc


def actual_files() -> list[str]:
    return sorted(path.relative_to(ROOT).as_posix() for path in ROOT.rglob("*") if path.is_file() and "__pycache__" not in path.parts)


def verify_review_authentication() -> None:
    auth = load_json(ROOT / "00_lineage/R3_REVIEW_INPUT_AUTHENTICATION.json")
    if auth.get("authentication") != "PASS" or auth.get("directory_included_in_r4_package") is not False:
        raise VerificationError("REVIEW_INPUT_AUTHENTICATION_MISMATCH")
    if auth.get("review_verdict") != "BLOCKED" or len(auth.get("required_files", [])) != 3:
        raise VerificationError("REVIEW_INPUT_AUTHENTICATION_INCOMPLETE")
    for item in auth["required_files"]:
        if not isinstance(item, dict) or not isinstance(item.get("relative_path"), str) or not isinstance(item.get("sha256"), str):
            raise VerificationError("REVIEW_INPUT_AUTHENTICATION_INVALID")
        if len(item["sha256"]) != 64:
            raise VerificationError("REVIEW_INPUT_AUTHENTICATION_INVALID")
    if any(path.startswith("review_inputs/") for path in actual_files()):
        raise VerificationError("REVIEW_INPUTS_MUST_NOT_BE_PACKAGED")


def verify_r3_baseline() -> None:
    baseline = ROOT / "00_lineage/r3_baseline"
    listed_path = baseline / "FILE_LIST.txt"
    checks_path = baseline / "SHA256SUMS.txt"
    if not listed_path.is_file() or not checks_path.is_file():
        raise VerificationError("R3_BASELINE_METADATA_MISSING")
    listed = [line for line in listed_path.read_text(encoding="utf-8").splitlines() if line]
    actual = sorted(path.relative_to(baseline).as_posix() for path in baseline.rglob("*") if path.is_file() and "__pycache__" not in path.parts)
    if listed != actual:
        raise VerificationError("R3_BASELINE_FILE_LIST_MISMATCH")
    checks: dict[str, str] = {}
    for line in checks_path.read_text(encoding="utf-8").splitlines():
        digest_value, relative = line.split("  ", 1)
        checks[relative.removeprefix("./")] = digest_value
    if set(checks) != set(actual) - {"SHA256SUMS.txt"}:
        raise VerificationError("R3_BASELINE_CHECKSUM_INVENTORY_MISMATCH")
    for relative, expected in checks.items():
        if digest((baseline / relative).read_bytes()) != expected:
            raise VerificationError(f"R3_BASELINE_CHECKSUM_MISMATCH:{relative}")
    pin = load_json(ROOT / "00_lineage/R3_LINEAGE_PIN.json")
    if pin.get("r3_git_commit") != "4654e59aac56b91687e4968ed3405024d9265c68" or pin.get("r2_parent_commit") != "366603b98cc1cc082ce3a74e63243400c9e5c1c5" or pin.get("preserved_file_count") != 37 or pin.get("r3_baseline_byte_for_byte_preserved") is not True:
        raise VerificationError("R3_LINEAGE_PIN_MISMATCH")
    for relative, expected in (
        ("FILE_LIST.txt", "d1636d13da23218516d278b4f0202478b7b2c4c09d70c76650cb117a85eba94b"),
        ("SHA256SUMS.txt", "7bbeec573a5332689753b86bf077f17e3fb2fe5d40cf4ce93cfc4cac8fcff945"),
        ("CONTRACT_MANIFEST.json", "e1943c579ebd83d6e493befb555bcf35112d4f6e9bace3011eff9f666eab29f4"),
    ):
        if pin.get({"FILE_LIST.txt": "r3_package_file_list_sha256", "SHA256SUMS.txt": "r3_package_sha256sums_sha256", "CONTRACT_MANIFEST.json": "r3_contract_manifest_sha256"}[relative]) != expected:
            raise VerificationError("R3_LINEAGE_PIN_MISMATCH")


def verify_target_universe() -> None:
    path = ROOT / "00_lineage/EXACT317_TARGET_MANIFEST.json"
    raw = path.read_bytes()
    if digest(raw) != TARGET_SHA256:
        raise VerificationError("EXACT317_TARGET_MANIFEST_HASH_MISMATCH")
    manifest = load_json(path)
    if manifest.get("audit_scope_id") != SCOPE_ID or manifest.get("totals") != {"EXACT_TARGET_TOTAL": 317, "RAW_SIDE_TOTAL": 86, "CANDIDATE_SIDE_TOTAL": 231}:
        raise VerificationError("EXACT317_SCOPE_MISMATCH")
    targets = manifest.get("targets")
    if not isinstance(targets, list) or len(targets) != 317:
        raise VerificationError("EXACT317_TARGET_COUNT_MISMATCH")
    ids = []
    for index, target in enumerate(targets, 1):
        if not isinstance(target, dict) or target.get("target_index") != index:
            raise VerificationError("EXACT317_TARGET_ORDER_MISMATCH")
        target_id = target.get("source_binding_target_id")
        basis = {
            "audit_scope_id": SCOPE_ID,
            "bound_candidate_scoring_id": target.get("bound_candidate_scoring_id"),
            "bound_raw_key": target.get("bound_raw_key"),
            "source_artifact_class": target.get("source_artifact_class"),
            "source_fact_type": target.get("required_source_fact_type"),
            "source_side": target.get("source_side"),
        }
        if not isinstance(target_id, str) or digest(canonical(basis)) != target_id:
            raise VerificationError("EXACT317_TARGET_ID_MISMATCH")
        ids.append(target_id)
    if len(set(ids)) != 317:
        raise VerificationError("EXACT317_TARGET_DUPLICATE")


def verify_contract() -> None:
    manifest = load_json(ROOT / "CONTRACT_MANIFEST.json")
    if manifest.get("contract_manifest_id") != object_id(manifest, "contract_manifest_id"):
        raise VerificationError("R4_MANIFEST_ID_MISMATCH")
    expected = {
        "package_name": "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4",
        "source_auth_execution_contract_r4_status": "COMPLETE_CONTRACT_ONLY",
        "ec_b1_exact_schema_and_cross_object_validation": "PASS_PRESERVED",
        "ec_b2_fail_closed_schema_bound_authority_evaluation": "CLOSED_CANDIDATE",
        "ec_b3_revalidated_immutable_current_derivation": "CLOSED_CANDIDATE",
        "ec_b4_frozen_exact317_target_universe_binding": "CLOSED_CANDIDATE",
        "source_auth_execution_readiness": "BLOCKED_MISSING_AUTHORITY_INPUTS",
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
        "next_action": "FRESH_TARGETED_INDEPENDENT_REVIEW_OF_CURRENT86_EXACT317_SOURCE_AUTH_EXECUTION_CONTRACT_R4",
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise VerificationError("R4_TERMINAL_BOUNDARY_MISMATCH")
    terminal = manifest.get("required_terminal")
    expected_terminal = {
        "SOURCE_AUTH_EXECUTION_CONTRACT_R4_STATUS": "COMPLETE_CONTRACT_ONLY",
        "EC_B1_EXACT_SCHEMA_AND_CROSS_OBJECT_VALIDATION": "PASS_PRESERVED",
        "EC_B2_FAIL_CLOSED_SCHEMA_BOUND_AUTHORITY_EVALUATION": "CLOSED_CANDIDATE",
        "EC_B3_REVALIDATED_IMMUTABLE_CURRENT_DERIVATION": "CLOSED_CANDIDATE",
        "EC_B4_FROZEN_EXACT317_TARGET_UNIVERSE_BINDING": "CLOSED_CANDIDATE",
        "SOURCE_AUTH_EXECUTION_READINESS": "BLOCKED_MISSING_AUTHORITY_INPUTS",
        "NEXT_ACTION": "FRESH_TARGETED_INDEPENDENT_REVIEW_OF_CURRENT86_EXACT317_SOURCE_AUTH_EXECUTION_CONTRACT_R4",
        "STOP": True,
    }
    if terminal != expected_terminal:
        raise VerificationError("R4_REQUIRED_TERMINAL_MISMATCH")
    contract = load_json(ROOT / "03_contracts/SOURCE_AUTH_EXECUTION_CONTRACT_R4.json")
    if contract.get("schema") != "FA1B2DE_CURRENT86_EXACT317_SOURCE_AUTH_EXECUTION_CONTRACT_R4":
        raise VerificationError("R4_CONTRACT_SCHEMA_MISMATCH")
    for relative in ("tools/frozen_authority_evaluator.py", "tools/authority.py", "tools/admission.py", "tools/transaction.py", "tools/target_universe.py", "tests/test_r4_contract_fixes.py"):
        if not (ROOT / relative).is_file():
            raise VerificationError(f"R4_REQUIRED_FILE_MISSING:{relative}")


def verify_metadata() -> None:
    listed = [line for line in (ROOT / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line]
    actual = actual_files()
    if listed != actual:
        raise VerificationError("R4_FILE_LIST_MISMATCH")
    expected = [f"{digest((ROOT / relative).read_bytes())}  ./{relative}" for relative in actual if relative != "SHA256SUMS.txt"]
    if (ROOT / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines() != expected:
        raise VerificationError("R4_SHA256SUMS_MISMATCH")


def main() -> None:
    verify_review_authentication()
    verify_r3_baseline()
    verify_target_universe()
    verify_contract()
    verify_metadata()
    print(json.dumps({
        "package_verification": "PASS",
        "exact317_scope": "PASS",
        "ec_b1": "PASS_PRESERVED",
        "ec_b2": "CLOSED_CANDIDATE",
        "ec_b3": "CLOSED_CANDIDATE",
        "ec_b4": "CLOSED_CANDIDATE",
        "source_auth_execution_readiness": "BLOCKED_MISSING_AUTHORITY_INPUTS",
        "real_source_auth_targets_executed": 0,
        "source_auth_executed": "NO",
        "current86_p0_executed": "NO",
        "current86_p1_executed": "NO",
        "raw_level_human_decisions": 0,
        "binding_publication": "NO",
        "git_ref_mutation": "NO",
    }, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, VerificationError) as exc:
        print(f"PACKAGE_VERIFICATION=FAIL:{exc}")
        raise SystemExit(1)
