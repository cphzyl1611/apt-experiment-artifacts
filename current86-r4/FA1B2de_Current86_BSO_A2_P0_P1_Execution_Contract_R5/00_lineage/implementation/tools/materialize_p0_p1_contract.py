#!/usr/bin/env python3
"""Materialize the Current86 BSO-A2 P0/P1 execution contract only.

This module deliberately has no proposer, verifier, human, adjudication, or publication
runtime.  It emits immutable preparation objects and pure validators for the reviewed R2
execution contract.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import gzip
import hashlib
import json
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DESIGN_NAME = "Design_FA1B2de_Current86_BSO_A2_HumanLight_Execution_P0_P4_R2_PATCHED.md"
EXPECTED_DESIGN_SHA256 = "5465c2047604b616c4966678b5fb1e823020be8011e655fb5582c556c04a837f"
EXPECTED_CANDIDATE_ID = "36831020b75a201420bd5cfce97a54ada12d44246f56a7812455bc21b99f9477"
EXPECTED_H2_EVIDENCE_ID = "939cc0c72e77bc437f0ab436cdf61c276d0ba1959273bbe0f46344e77ddff99e"
EXPECTED_ACTIVATION_TRANSACTION_ID = "bf4569d2116ac16a994feda733468faf2eeac92cc1f6eda46a77eac7312b718f"
EXPECTED_SCOPE_ID = "34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306"
EXPECTED_SOURCE_REGISTRY_ID = "8cef6206dfc3581c3e7b6358bde7a36e90f4ba99078176cc0e5aff4b238298a7"
EXPECTED_SOURCE_REGISTRY_SHA256 = "3df4262faa4137996d2ff8d163bcc665d5bed76b3d719e6ff66cf4154252d72f"
EXPECTED_V4_ARCHIVE_SHA256 = "0af337acc731595167d75f922dd39bbbb48dd1b1b9d3b31723d01408501040de"
EXPECTED_CANDIDATE_MANIFEST_SHA256 = "4810a1b5336d1672290e46f55eae056f0d1a963f4972548f5d097d1c7dd3baae"
EXPECTED_CANDIDATE_CHECKSUMS_SHA256 = "dc5ef34353243fbf6e23f1383d3f9fdd111b86080ae4e7b9b8d4140796d1c86f"
EXPECTED_CANDIDATE_VERIFICATION_JSON_SHA256 = "2a4b1dfbf3b384c5a3db79d045c052a76836eb13cbeda3643a1dcdee4b165cfa"
EXPECTED_CANDIDATE_VERIFICATION_MD_SHA256 = "c4f238702d074324f3737b237d9ae4d32fb0ab34971b95d4afd92f78dbac944c"
EXPECTED_H2_HANDOFF_SHA256 = "1ffa67fc430f0c0d0ecbe44c7b879e5671d228913227890b26120a5f68c95a63"
R1_PACKAGE_DIR_NAME = "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R1"
R2_PACKAGE_DIR_NAME = "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R2"
R1_HANDOFF_NAME = "fa1b2de-current86-bso-a2-p0-p1-execution-contract-r1-review-input.tar.gz"
R2_HANDOFF_NAME = "fa1b2de-current86-bso-a2-p0-p1-execution-contract-r2-review-input.tar.gz"
EXPECTED_R1_HANDOFF_SHA256 = "f1a5d00e58db5fc6994e4b572b8292f423ec49411b1ecf42f5f39e3bb86c7e3a"
EXPECTED_R1_FILE_SET_SHA256 = "6b859f310b11869e944f31633ad8a6bb1cc8a570c3e8fe337e9d821db7a8d4a5"
R1_PATCH_SUMMARY_NAME = "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R1_to_R2_Patch_Summary.json"
TDD_LOG_NAME = "R1_TO_R2_DEFECT_REPRODUCTION_AND_TDD_LOG.json"
NORMATIVE_SOURCE_PROFILE_HASH = "e24746c96c5f741cc35df8d992d93936911dd1de2ce7f1a0f00035cda3b33deb"
HISTORICAL_OUTPUT_DENYLIST_HASH = "f2f48a3142bf192c08cfa2bffbb722e0131bfd4a1ba55623caf5af72748b94c7"
CURRENT86_RAW_COUNT = 86
CURRENT86_RELATION_COUNT = 4219
CURRENT86_HARD_NEGATIVE_COUNT = 58
CURRENT86_FORMER_HUMAN_EQ_COUNT = 4161
RAW_KEY_RE = re.compile(r"^[0-9]+::S[0-9]{2}::A[0-9]{3}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_constant(token: str) -> None:
    raise ValueError(f"non-finite JSON number is prohibited: {token}")


def _reject_float(token: str) -> None:
    raise ValueError(f"floating-point JSON number is prohibited: {token}")


def strict_json_loads(value: str | bytes) -> Any:
    """Parse JSON without duplicate keys, floats, or non-finite values."""
    return json.loads(
        value,
        object_pairs_hook=_reject_duplicate_pairs,
        parse_float=_reject_float,
        parse_constant=_reject_constant,
    )


def _validate_string(value: str) -> None:
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("normative string is not NFC-normalized")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise ValueError("surrogate code point is not valid Unicode text")


def _canonical(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("floating-point values are prohibited in identity-bearing objects")
    if isinstance(value, str):
        _validate_string(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canonical(child) for child in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValueError("JSON object key is not a string")
            _validate_string(key)
        ordered = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(
            _canonical(key) + ":" + _canonical(value[key]) for key in ordered
        ) + "}"
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def project_canonical_json(value: Any) -> bytes:
    """PROJECT_CANONICAL_JSON_V1: RFC 8785-compatible UTF-8 bytes."""
    return _canonical(value).encode("utf-8")


def canonical_object_id(value: dict[str, Any], self_id_field: str) -> str:
    fields = {key: child for key, child in value.items() if key != self_id_field}
    return sha256_bytes(project_canonical_json(fields))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _bytewise(value: str) -> bytes:
    return value.encode("utf-8")


def _copy_exact(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def r1_file_set_sha256(root: Path) -> str:
    package = Path(root) / R1_PACKAGE_DIR_NAME
    entries = [
        {"path": path.relative_to(package).as_posix(), "sha256": sha256_file(path)}
        for path in sorted(package.rglob("*"), key=lambda item: item.relative_to(package).as_posix().encode("utf-8"))
        if path.is_file()
    ]
    return sha256_bytes(project_canonical_json(entries))


def verify_r1_byte_preservation(root: Path) -> bool:
    root = Path(root)
    if sha256_file(root / R1_HANDOFF_NAME) != EXPECTED_R1_HANDOFF_SHA256:
        raise ValueError("R1 handoff archive byte preservation failed")
    if r1_file_set_sha256(root) != EXPECTED_R1_FILE_SET_SHA256:
        raise ValueError("R1 package file-set byte preservation failed")
    return True


@dataclass(frozen=True)
class AuthenticatedInputs:
    root: Path
    design_sha256: str
    candidate_id: str
    h2_evidence_id: str
    activation_transaction_id: str
    scope_id: str
    raw_keys: tuple[str, ...]
    relations: tuple[dict[str, Any], ...]
    hard_negative_relation_ids: tuple[str, ...]
    human_review_relation_ids: tuple[str, ...]
    scope_object: dict[str, Any]
    v4_scope_object: dict[str, Any]
    candidate_registry: dict[str, Any]
    source_registry: dict[str, Any]
    candidate_manifest_sha256: str
    candidate_checksums_sha256: str
    v4_archive_sha256: str
    source_registry_sha256: str
    h2_evidence_sha256: str
    activation_sha256: str


def _require(path: Path, expected: str) -> None:
    observed = sha256_file(path)
    if observed != expected:
        raise ValueError(f"SHA256 mismatch for {path}: {expected} != {observed}")


def _load(path: Path) -> Any:
    return strict_json_loads(path.read_bytes())


def _verify_checksum_file(directory: Path, checksum_file: Path, expected_sha256: str) -> None:
    _require(checksum_file, expected_sha256)
    entries: dict[str, str] = {}
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split("  ", 1)
        if name in entries:
            raise ValueError(f"duplicate checksum entry: {name}")
        entries[name] = digest
    if set(entries) != {path.name for path in directory.iterdir() if path.name != checksum_file.name}:
        raise ValueError("checksum inventory is not exact")
    for name, digest in entries.items():
        if sha256_file(directory / name) != digest:
            raise ValueError(f"checksum mismatch: {name}")


def _extract_v4_scope(archive_path: Path) -> dict[str, Any]:
    member = (
        "fa1b2de-bso-eq-v4-clean-phase-v-verifier-r1-20260826T103658Z/"
        "independent_current86_scope_recomputation_r1.json"
    )
    with tarfile.open(archive_path, "r:gz") as archive:
        payload = archive.extractfile(member)
        if payload is None:
            raise ValueError("authenticated v4 scope member is missing")
        record = _load_bytes(payload.read())
    if record.get("status") != "PASS":
        raise ValueError("authenticated v4 Current86 scope reconstruction is not PASS")
    return record["reconstructed_scope"]


def _load_bytes(value: bytes) -> Any:
    return strict_json_loads(value)


def _raw_sort_key(raw_key: str) -> bytes:
    return _bytewise(raw_key)


def _relation_sort_key(relation: dict[str, Any]) -> tuple[bytes, bytes]:
    return (_bytewise(relation["candidate_scoring_id"]), _bytewise(relation["relation_identity"]))


def _registry_entry(registry: dict[str, Any], set_name: str) -> dict[str, Any]:
    for entry in registry.get("entries", []):
        if entry.get("schema_field_path") == set_name:
            return entry
    raise ValueError(f"normative set is not registered: {set_name}")


def _declared_identity(value: Any, entry: dict[str, Any]) -> str | tuple[str, ...]:
    field = entry.get("element_identity_field_or_tuple")
    if isinstance(field, str):
        if field == "canonical_raw_key" and isinstance(value, str):
            return value
        if not isinstance(value, dict) or field not in value or not isinstance(value[field], str):
            raise ValueError(f"set element does not contain registered identity field: {field}")
        return value[field]
    if isinstance(field, list) and field and all(isinstance(name, str) for name in field):
        if not isinstance(value, dict) or any(name not in value or not isinstance(value[name], str) for name in field):
            raise ValueError("set element does not contain registered identity tuple")
        return tuple(value[name] for name in field)
    raise ValueError("registered set identity rule is invalid")


def order_declared_set(set_name: str, values: list[Any] | tuple[Any, ...], registry: dict[str, Any]) -> list[Any]:
    """Return a deterministically ordered declared mathematical set.

    Every identity-bearing set must resolve its ordering from the registry.  This
    helper rejects duplicate identities instead of silently accepting a multiset.
    """
    entry = _registry_entry(registry, set_name)
    identities = [_declared_identity(value, entry) for value in values]
    if len(set(identities)) != len(identities):
        raise ValueError(f"duplicate identity in normative set: {set_name}")
    rule = entry.get("comparison_rule")
    if rule == "BYTEWISE_ASCENDING_UTF8":
        return sorted(list(values), key=lambda value: _bytewise(_declared_identity(value, entry)))
    if rule == "LEXICOGRAPHIC_UTF8_BYTES_FIRST_CANDIDATE_THEN_RELATION":
        return sorted(list(values), key=lambda value: tuple(_bytewise(part) for part in _declared_identity(value, entry)))
    raise ValueError(f"unregistered or unsupported ordering rule: {set_name}")


def hash_declared_set(set_name: str, values: list[Any] | tuple[Any, ...], registry: dict[str, Any]) -> str:
    return sha256_bytes(project_canonical_json(order_declared_set(set_name, values, registry)))


def validate_declared_set_hash(set_name: str, expected_hash: str, values: list[Any] | tuple[Any, ...], registry: dict[str, Any]) -> bool:
    observed = hash_declared_set(set_name, values, registry)
    if observed != expected_hash:
        raise ValueError(f"declared set hash mismatch: {set_name}")
    return True


def authenticate_inputs(root: Path = ROOT) -> AuthenticatedInputs:
    root = Path(root).resolve()
    design = root / DESIGN_NAME
    candidate_dir = root / "FA1B2de_Current86_BSO_A2_Authority_Candidate_PROSPECTIVE_R2"
    activation_dir = root / "FA1B2de_Current86_BSO_A2_Authority_Activation"
    v4_archive = root / "03_frozen_lineage/fa1b2de-bso-eq-v4-clean-phase-v-verifier-r1-20260826T103658Z.tar.gz"
    source_registry_path = root / "03_frozen_lineage/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json"
    target_review = root / "FA1B2de_Current86_BSO_A2_HumanLight_Execution_P0_P4_R2_Targeted_Independent_Review.json"
    patch_summary = root / "FA1B2de_Current86_BSO_A2_HumanLight_Execution_P0_P4_R2_Patch_Summary.json"
    design_sha = sha256_file(design)
    if design_sha != EXPECTED_DESIGN_SHA256:
        raise ValueError("reviewed R2 design hash mismatch")
    review_obj = _load(target_review)
    if review_obj.get("input_authentication", {}).get("R2_PATCHED_DESIGN_SHA256") != EXPECTED_DESIGN_SHA256:
        raise ValueError("targeted review does not authenticate the requested design")
    if review_obj.get("review_terminal", {}).get("TARGETED_REVIEW_VERDICT") != "PASS":
        raise ValueError("targeted review is not PASS")
    if review_obj.get("review_terminal", {}).get("READY_FOR_P0_P1_EXECUTION_CONTRACT_MATERIALIZATION") != "YES":
        raise ValueError("targeted review does not authorize contract materialization")
    summary = _load(patch_summary)
    if summary.get("r2_design", {}).get("sha256") != EXPECTED_DESIGN_SHA256:
        raise ValueError("R2 patch summary does not authenticate the requested design")

    _verify_checksum_file(candidate_dir, candidate_dir / "12_sha256sums.txt", EXPECTED_CANDIDATE_CHECKSUMS_SHA256)
    _require(candidate_dir / "01_transition_manifest.json", EXPECTED_CANDIDATE_MANIFEST_SHA256)
    candidate_manifest = _load(candidate_dir / "01_transition_manifest.json")
    if candidate_manifest.get("prospective_authority_candidate_id") != EXPECTED_CANDIDATE_ID:
        raise ValueError("candidate ID mismatch")
    if candidate_manifest.get("authority_scope_id") != EXPECTED_SCOPE_ID:
        raise ValueError("candidate scope mismatch")
    if candidate_manifest.get("raw_level_adjudication_execution") is not False:
        raise ValueError("candidate package claims runtime adjudication")
    for name, expected in candidate_manifest.get("component_sha256", {}).items():
        if sha256_file(candidate_dir / name) != expected:
            raise ValueError(f"candidate manifest component checksum mismatch: {name}")

    activation_checksums = activation_dir / "activation_sha256sums.txt"
    activation_entries: dict[str, str] = {}
    for line in activation_checksums.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split("  ", 1)
            activation_entries[name] = digest
    for name, digest in activation_entries.items():
        if sha256_file(activation_dir / name) != digest:
            raise ValueError(f"activation checksum mismatch: {name}")
    # The independent activation verification artifact is pinned by the transaction itself,
    # but predates the small three-member activation checksum inventory.
    if sha256_file(activation_dir / "independent_activation_transaction_verification.json") != "946f7af82865d0dc7644e2435696b1b3b69e8a2a63040c7eab3d528219cb05c9":
        raise ValueError("independent activation verification checksum mismatch")
    activation = _load(activation_dir / "current86_bso_a2_authority_activation_transaction.json")
    h2 = _load(activation_dir / "h2_native_user_event_provenance_evidence.json")
    h2_verification = _load(activation_dir / "independent_h2_provenance_verification.json")
    activation_verification = _load(activation_dir / "independent_activation_transaction_verification.json")
    if activation.get("activation_transaction_id") != EXPECTED_ACTIVATION_TRANSACTION_ID:
        raise ValueError("activation transaction ID mismatch")
    if canonical_object_id(activation, "activation_transaction_id") != EXPECTED_ACTIVATION_TRANSACTION_ID:
        raise ValueError("activation transaction ID does not recompute")
    if h2.get("evidence_id") != EXPECTED_H2_EVIDENCE_ID or canonical_object_id(h2, "evidence_id") != EXPECTED_H2_EVIDENCE_ID:
        raise ValueError("H2 evidence ID mismatch")
    if h2_verification.get("status") != "PASS" or h2_verification.get("exact_equal") is not True:
        raise ValueError("H2 provenance verification is not PASS")
    if activation_verification.get("status") != "PASS" or activation_verification.get("transaction_recomputed_exactly") is not True:
        raise ValueError("activation transaction verification is not PASS")
    if activation.get("h2_provenance_evidence_sha256") != sha256_file(activation_dir / "h2_native_user_event_provenance_evidence.json"):
        raise ValueError("activation transaction H2 evidence file pin mismatch")
    if activation.get("h2_provenance_verification_sha256") != sha256_file(activation_dir / "independent_h2_provenance_verification.json"):
        raise ValueError("activation transaction H2 verification file pin mismatch")
    candidate_verification_dir = root / "FA1B2de_Current86_BSO_A2_Authority_Candidate_R2_Independent_Verification"
    candidate_verification_json = candidate_verification_dir / "FA1B2de_Current86_BSO_A2_Authority_Candidate_R2_Independent_Verification.json"
    candidate_verification_md = candidate_verification_dir / "FA1B2de_Current86_BSO_A2_Authority_Candidate_R2_Independent_Verification.md"
    candidate_handoff = candidate_verification_dir / "FA1B2de_Current86_BSO_A2_H2_Governance_Handoff.tar.gz"
    _require(candidate_verification_json, EXPECTED_CANDIDATE_VERIFICATION_JSON_SHA256)
    _require(candidate_verification_md, EXPECTED_CANDIDATE_VERIFICATION_MD_SHA256)
    _require(candidate_handoff, EXPECTED_H2_HANDOFF_SHA256)
    candidate_verification = _load(candidate_verification_json)
    if candidate_verification.get("authority_candidate_verification_verdict") != "PASS" or candidate_verification.get("candidate", {}).get("exact_equal") is not True or candidate_verification.get("candidate", {}).get("reported_id") != EXPECTED_CANDIDATE_ID:
        raise ValueError("independent authority candidate verification is not PASS")
    if activation.get("independent_verification_json_sha256") != EXPECTED_CANDIDATE_VERIFICATION_JSON_SHA256:
        raise ValueError("activation transaction independent candidate verification pin mismatch")
    if activation.get("independent_verification_md_sha256") != EXPECTED_CANDIDATE_VERIFICATION_MD_SHA256:
        raise ValueError("activation transaction independent candidate verification MD pin mismatch")
    if activation.get("h2_governance_handoff_sha256") != EXPECTED_H2_HANDOFF_SHA256:
        raise ValueError("activation transaction H2 governance handoff pin mismatch")
    if activation.get("prospective_authority_candidate_id") != EXPECTED_CANDIDATE_ID:
        raise ValueError("activation candidate pin mismatch")
    if activation.get("h2_provenance_evidence_id") != EXPECTED_H2_EVIDENCE_ID:
        raise ValueError("activation H2 pin mismatch")
    if any(activation.get(key) != expected for key, expected in {
        "activation_scope": "EXACT_CURRENT86_ONLY",
        "binding_publication": "NO",
        "bso_a2_raw_level_adjudication_execution": "NO",
        "bso_p_execution": "NO",
        "bso_v_execution": "NO",
        "scoring_authority_mutation": "NO",
        "binding_authority_mutation": "NO",
        "denominator_change": "NO",
        "accepted_binding_change": "NO",
        "raw_positional_identity_mutation": "NO",
        "complete_candidate_universe_preserved": "YES",
    }.items()):
        raise ValueError("activation transaction violates a hard boundary")

    scope = _load(candidate_dir / "03_exact_current86_scope.json")
    candidate_registry = _load(candidate_dir / "04_complete_candidate_set_registry.json")
    v4_scope = _extract_v4_scope(v4_archive)
    if scope != v4_scope:
        raise ValueError("Current86 scope differs from authenticated v4 reconstruction")
    if scope.get("scope_id") != EXPECTED_SCOPE_ID or canonical_object_id(scope, "scope_id") != EXPECTED_SCOPE_ID:
        raise ValueError("Current86 scope ID mismatch")
    raw_keys = scope.get("raw_keys", [])
    relations = scope.get("relation_membership", [])
    hard_negatives = scope.get("preexisting_hard_negative_relation_ids", [])
    human_review = scope.get("human_review_required_relation_ids", [])
    if (len(raw_keys), len(relations), len(hard_negatives), len(human_review)) != (
        CURRENT86_RAW_COUNT, CURRENT86_RELATION_COUNT, CURRENT86_HARD_NEGATIVE_COUNT, CURRENT86_FORMER_HUMAN_EQ_COUNT
    ):
        raise ValueError("Current86 diagnostic population counts mismatch")
    if len(set(raw_keys)) != CURRENT86_RAW_COUNT or raw_keys != sorted(raw_keys, key=_raw_sort_key):
        raise ValueError("Current86 raw set is not exact/deterministically ordered")
    if any(not RAW_KEY_RE.match(raw) for raw in raw_keys):
        raise ValueError("invalid canonical raw key")
    relation_keys = {(item.get("raw_key"), item.get("candidate_scoring_id"), item.get("relation_identity")) for item in relations}
    relation_identities = [item.get("relation_identity") for item in relations]
    if len(relation_keys) != CURRENT86_RELATION_COUNT or len(set(relation_identities)) != CURRENT86_RELATION_COUNT:
        raise ValueError("Current86 relation set is not exact/uniquely identified")
    if set(hard_negatives) != {item["relation_identity"] for item in relations if item.get("disposition") == "PREEXISTING_AUTHENTICATED_HARD_NEGATIVE"}:
        raise ValueError("hard-negative set differs from relation dispositions")
    if set(human_review) != {item["relation_identity"] for item in relations if item.get("disposition") == "HUMAN_EQ_REVIEW_REQUIRED"}:
        raise ValueError("human-review set differs from relation dispositions")
    if hard_negatives != sorted(hard_negatives, key=_bytewise) or human_review != sorted(human_review, key=_bytewise):
        raise ValueError("relation partition sets are not bytewise ordered")
    for relation in relations:
        payload = {
            "candidate_scoring_id": relation["candidate_scoring_id"],
            "raw_key": relation["raw_key"],
            "schema": "BSO_EQ_RELATION_IDENTITY_PAYLOAD_V1",
        }
        if sha256_bytes(project_canonical_json(payload)) != relation["relation_identity"]:
            raise ValueError("relation identity does not recompute")
    if candidate_registry.get("authority_scope_id") != EXPECTED_SCOPE_ID:
        raise ValueError("candidate registry scope mismatch")
    registry_sets = candidate_registry.get("raw_candidate_sets", [])
    by_raw = {item["raw_key"]: item for item in registry_sets}
    if set(by_raw) != set(raw_keys) or len(registry_sets) != CURRENT86_RAW_COUNT:
        raise ValueError("candidate registry raw set differs from exact scope")
    expected_by_raw = {raw: [] for raw in raw_keys}
    for relation in relations:
        expected_by_raw[relation["raw_key"]].append(relation)
    for raw in raw_keys:
        item = by_raw[raw]
        if item["candidate_relations"] != expected_by_raw[raw]:
            raise ValueError(f"candidate universe differs for {raw}")
        if item.get("complete_candidate_universe_preserved") is not True:
            raise ValueError("candidate universe preservation flag is false")
    source_registry = _load(source_registry_path)
    _require(source_registry_path, EXPECTED_SOURCE_REGISTRY_SHA256)
    if source_registry.get("registry_id") != EXPECTED_SOURCE_REGISTRY_ID or canonical_object_id(source_registry, "registry_id") != EXPECTED_SOURCE_REGISTRY_ID:
        raise ValueError("source class/fact type registry ID mismatch")
    if source_registry.get("global_eq_scope_id") != EXPECTED_SCOPE_ID:
        raise ValueError("source registry scope mismatch")
    v4_sha = sha256_file(v4_archive)
    if v4_sha != EXPECTED_V4_ARCHIVE_SHA256:
        raise ValueError("v4 authenticated lineage archive mismatch")
    return AuthenticatedInputs(
        root=root,
        design_sha256=design_sha,
        candidate_id=EXPECTED_CANDIDATE_ID,
        h2_evidence_id=EXPECTED_H2_EVIDENCE_ID,
        activation_transaction_id=EXPECTED_ACTIVATION_TRANSACTION_ID,
        scope_id=EXPECTED_SCOPE_ID,
        raw_keys=tuple(raw_keys),
        relations=tuple(relations),
        hard_negative_relation_ids=tuple(hard_negatives),
        human_review_relation_ids=tuple(human_review),
        scope_object=scope,
        v4_scope_object=v4_scope,
        candidate_registry=candidate_registry,
        source_registry=source_registry,
        candidate_manifest_sha256=EXPECTED_CANDIDATE_MANIFEST_SHA256,
        candidate_checksums_sha256=EXPECTED_CANDIDATE_CHECKSUMS_SHA256,
        v4_archive_sha256=v4_sha,
        source_registry_sha256=EXPECTED_SOURCE_REGISTRY_SHA256,
        h2_evidence_sha256=sha256_file(activation_dir / "h2_native_user_event_provenance_evidence.json"),
        activation_sha256=sha256_file(activation_dir / "current86_bso_a2_authority_activation_transaction.json"),
    )


def build_set_ordering_registry(auth: AuthenticatedInputs) -> dict[str, Any]:
    registry: dict[str, Any] = {
        "schema": "A2_SET_ORDERING_REGISTRY_V1",
        "canonicalization_contract": "PROJECT_CANONICAL_JSON_V1",
        "entries": [
            {
                "schema_field_path": "exact_current86_raw_set",
                "mathematical_set_type": "SET",
                "element_identity_field_or_tuple": "canonical_raw_key",
                "comparison_encoding": "UTF-8",
                "comparison_rule": "BYTEWISE_ASCENDING_UTF8",
            },
            {
                "schema_field_path": "relation_set",
                "mathematical_set_type": "SET",
                "element_identity_field_or_tuple": "relation_identity",
                "comparison_encoding": "UTF-8",
                "comparison_rule": "BYTEWISE_ASCENDING_UTF8",
            },
            {
                "schema_field_path": "per_raw_complete_candidate_universe_entries",
                "mathematical_set_type": "SET",
                "element_identity_field_or_tuple": ["candidate_scoring_id", "relation_identity"],
                "comparison_encoding": "UTF-8",
                "comparison_rule": "LEXICOGRAPHIC_UTF8_BYTES_FIRST_CANDIDATE_THEN_RELATION",
            },
            {
                "schema_field_path": "normative_evidence_fact_set",
                "mathematical_set_type": "SET",
                "element_identity_field_or_tuple": "source_fact_id",
                "comparison_encoding": "UTF-8",
                "comparison_rule": "BYTEWISE_ASCENDING_UTF8",
            },
            {
                "schema_field_path": "owner_terminal_raw_set",
                "mathematical_set_type": "SET",
                "element_identity_field_or_tuple": "canonical_raw_key",
                "comparison_encoding": "UTF-8",
                "comparison_rule": "BYTEWISE_ASCENDING_UTF8",
            },
            {
                "schema_field_path": "escalation_terminal_raw_set",
                "mathematical_set_type": "SET",
                "element_identity_field_or_tuple": "canonical_raw_key",
                "comparison_encoding": "UTF-8",
                "comparison_rule": "BYTEWISE_ASCENDING_UTF8",
            },
            {
                "schema_field_path": "p3_current_state_partition_sets",
                "mathematical_set_type": "SET_OF_RAW_KEYS",
                "element_identity_field_or_tuple": "canonical_raw_key",
                "comparison_encoding": "UTF-8",
                "comparison_rule": "BYTEWISE_ASCENDING_UTF8",
                "partition_names": [
                    "S_ACCEPTED_TERMINAL",
                    "S_PENDING_REVIEW",
                    "S_IN_PROGRESS_OR_INCOMPLETE",
                    "S_BLOCKED_ATTEMPT",
                    "S_NOT_STARTED_FOR_ADJUDICATION",
                ],
            },
        ],
        "required_ordering_before_runtime_identity": True,
    }
    registry["set_ordering_registry_id"] = canonical_object_id(registry, "set_ordering_registry_id")
    return registry


def _isolation_launcher_identity() -> dict[str, Any]:
    launcher = ROOT / "tools/a2_bwrap_isolation.py"
    bwrap_path = shutil.which("bwrap")
    if bwrap_path is None:
        raise ValueError("M2_EXECUTION_BOUND_ISOLATION = BLOCKED: bubblewrap is unavailable")
    version = subprocess.run([bwrap_path, "--version"], check=True, text=True, capture_output=True).stdout.strip()
    configuration = {
        "namespace_flags": ["--unshare-all", "--unshare-user-try", "--new-session", "--die-with-parent"],
        "identity": {"uid": 65534, "gid": 65534},
        "common_input_mount": {"destination": "/frozen-input", "mode": "READ_ONLY"},
        "role_runtime_mount": {"destination": "/role-runtime", "mode": "READ_ONLY"},
        "role_output_mount": {"destination": "/role-output", "mode": "READ_WRITE"},
        "host_root_mount": "ABSENT",
        "network_namespace": "UNSHARED_NO_HOST_NETWORK",
        "environment": "CLEARED_EXCEPT_FROZEN_PATH",
    }
    return {
        "launcher_path": "tools/a2_bwrap_isolation.py",
        "launcher_sha256": sha256_file(launcher),
        "bubblewrap_executable": bwrap_path,
        "bubblewrap_executable_sha256": sha256_file(Path(bwrap_path)),
        "bubblewrap_version": version,
        "launcher_configuration": configuration,
        "launcher_configuration_hash": sha256_bytes(project_canonical_json(configuration)),
    }


def run_isolation_probe(probe_root: Path) -> dict[str, Any]:
    """Execute a non-semantic sentinel probe inside the verifier mount boundary."""
    probe_root = Path(probe_root).resolve()
    common = probe_root / "common"
    runtime = probe_root / "runtime"
    primary_private = probe_root / "primary-private"
    primary_commitment = probe_root / "primary-commitment"
    output = probe_root / "output"
    for directory in (common, runtime, primary_private, primary_commitment, output):
        directory.mkdir(parents=True, exist_ok=True)
    (common / "common.txt").write_text("COMMON_FROZEN_SENTINEL", encoding="utf-8")
    (primary_private / "private.txt").write_text("PRIMARY_PRIVATE_SENTINEL", encoding="utf-8")
    (primary_commitment / "commitment.txt").write_text("PRIMARY_COMMITMENT_SENTINEL", encoding="utf-8")
    probe_program = (
        "import json\n"
        "from pathlib import Path\n"
        "result={'common_frozen_sentinel_readable':False,'primary_private_sentinel_readable':False,'primary_commitment_sentinel_readable':False,'prohibited_read_failed_at_boundary':False}\n"
        "result['common_frozen_sentinel_readable']=Path('/frozen-input/common.txt').read_text()=='COMMON_FROZEN_SENTINEL'\n"
        "blocked=[]\n"
        "for key,path in [('primary_private_sentinel_readable','/primary-private/private.txt'),('primary_commitment_sentinel_readable','/primary-commitment/commitment.txt')]:\n"
        " try:\n"
        "  Path(path).read_bytes(); result[key]=True; blocked.append(False)\n"
        " except OSError:\n"
        "  blocked.append(True)\n"
        "result['prohibited_read_failed_at_boundary']=all(blocked)\n"
        "print(json.dumps(result,sort_keys=True))\n"
        "raise SystemExit(0 if result['common_frozen_sentinel_readable'] and result['prohibited_read_failed_at_boundary'] and not result['primary_private_sentinel_readable'] and not result['primary_commitment_sentinel_readable'] else 1)\n"
    )
    launcher = ROOT / "tools/a2_bwrap_isolation.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(launcher),
            "--common-dir", str(common),
            "--runtime-dir", str(runtime),
            "--output-dir", str(output),
            "--",
            "/usr/bin/python3", "-c", probe_program,
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ValueError(f"M2_EXECUTION_BOUND_ISOLATION = BLOCKED: sentinel probe failed: {completed.stderr.strip()}")
    try:
        result = strict_json_loads(completed.stdout)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("M2 sentinel probe emitted invalid evidence") from exc
    expected = {
        "common_frozen_sentinel_readable": True,
        "primary_private_sentinel_readable": False,
        "primary_commitment_sentinel_readable": False,
        "prohibited_read_failed_at_boundary": True,
    }
    if result != expected:
        raise ValueError("M2_EXECUTION_BOUND_ISOLATION = BLOCKED: sentinel visibility invariant failed")
    return {
        **result,
        "probe_kind": "NON_SEMANTIC_DUMMY_SENTINEL_CAPABILITY_PROBE",
        "probe_exit_code": completed.returncode,
        "semantic_role_execution": False,
    }


def build_isolation_enforcement_contract(auth: AuthenticatedInputs, ordering: dict[str, Any]) -> dict[str, Any]:
    common = sorted([
        "00_lineage/reviewed_r2_design",
        "00_lineage/activation/current86_bso_a2_authority_activation_transaction.json",
        "00_lineage/activation/h2_native_user_event_provenance_evidence.json",
        "00_lineage/activation/independent_activation_transaction_verification.json",
        "00_lineage/activation/independent_h2_provenance_verification.json",
        "00_lineage/candidate_r2/03_exact_current86_scope.json",
        "00_lineage/candidate_r2/04_complete_candidate_set_registry.json",
        "00_lineage/source_registry/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json",
        "01_canonicalization/PROJECT_CANONICAL_JSON_V1.json",
        "02_set_ordering/SET_ORDERING_REGISTRY.json",
        "05_schemas/schema_registry.json",
    ], key=_bytewise)
    whitelist = sorted([
        "tool:python-json-parser",
        "tool:python-hashlib",
        "tool:python-unicodedata",
    ], key=_bytewise)
    readable = sorted(common + whitelist, key=_bytewise)
    primary_private = sorted([
        "runtime/primary/private_output",
        "runtime/primary/commitment_output",
        "runtime/primary/mutable_derivation_artifacts",
    ], key=_bytewise)
    launcher_identity = _isolation_launcher_identity()
    with tempfile.TemporaryDirectory(prefix=".a2-m2-probe-") as probe_name:
        probe = run_isolation_probe(Path(probe_name))
    boundary = {
        "filesystem_read_scope": "FROZEN_COMMON_VERIFIER_INPUT_SET_ONLY",
        "filesystem_write_scope": "VERIFIER_WORKSPACE_ONLY_AFTER_INPUT_FREEZE",
        "network_access": False,
        "shell_execution": False,
        "external_connector_access": False,
        "mutable_workspace_access": False,
        "allowed_tools": whitelist,
        "denied_tools": ["network", "shell", "primary_output_read", "unfrozen_external_retrieval"],
    }
    contract: dict[str, Any] = {
        "schema": "A2_VERIFIER_ISOLATION_ENFORCEMENT_CONTRACT_V1",
        "common_frozen_input_root_identity": {
            "logical_root": "00_lineage+01_canonicalization+02_set_ordering+05_schemas",
            "input_set_hash": sha256_bytes(project_canonical_json(common)),
            "authenticated_content_identities": {
                "reviewed_r2_design_sha256": auth.design_sha256,
                "activation_transaction_sha256": auth.activation_sha256,
                "h2_provenance_evidence_sha256": auth.h2_evidence_sha256,
                "candidate_scope_sha256": sha256_file(auth.root / "FA1B2de_Current86_BSO_A2_Authority_Candidate_PROSPECTIVE_R2/03_exact_current86_scope.json"),
                "candidate_registry_sha256": sha256_file(auth.root / "FA1B2de_Current86_BSO_A2_Authority_Candidate_PROSPECTIVE_R2/04_complete_candidate_set_registry.json"),
                "source_registry_sha256": auth.source_registry_sha256,
                "v4_lineage_archive_sha256": auth.v4_archive_sha256,
            },
        },
        "frozen_common_verifier_input_set": common,
        "verifier_workspace_identity": "A2_VERIFIER_PRECOMMIT_WORKSPACE_V1",
        "verifier_precommit_read_roots": common,
        "verifier_precommit_readable_input_set": readable,
        "verifier_precommit_readable_input_set_hash": sha256_bytes(project_canonical_json(readable)),
        "primary_private_output_roots": [
            "runtime/primary/private_output",
            "runtime/primary/mutable_derivation_artifacts",
        ],
        "primary_commitment_output_roots": ["runtime/primary/commitment_output"],
        "primary_private_or_commitment_output_set": primary_private,
        "primary_private_or_commitment_output_set_hash": sha256_bytes(project_canonical_json(primary_private)),
        "filesystem_acl_or_permission_snapshot_hash": None,
        "container_or_sandbox_identity": launcher_identity,
        "tool_permission_boundary_identity": canonical_object_id(boundary, "tool_permission_boundary_identity"),
        "runtime_tool_whitelist": whitelist,
        "enforcement_mechanism": "BUBBLEWRAP_MOUNT_NAMESPACE_CAPABILITY_ISOLATION",
        "audit_method": [
            "bytewise_set_normalization",
            "readable_minus_whitelist_equals_frozen_common_input_set",
            "readable_intersection_primary_private_or_commitment_is_empty",
            "no_primary_result_fields_in_common_input_manifest",
        ],
        "precommit_visibility_invariant": {
            "intersection": [],
            "readable_set_equals_common_except_whitelist": True,
        },
        "tool_permission_boundary": boundary,
        "isolation_launcher_identity": launcher_identity,
        "non_semantic_isolation_probe": probe,
        "M2_EXECUTION_BOUND_ISOLATION": "VERIFIED",
        "set_ordering_registry_id": ordering["set_ordering_registry_id"],
    }
    contract["isolation_enforcement_id"] = canonical_object_id(contract, "isolation_enforcement_id")
    return contract


def validate_isolation_contract(contract: dict[str, Any]) -> bool:
    readable = set(contract["verifier_precommit_readable_input_set"])
    common = set(contract["frozen_common_verifier_input_set"])
    whitelist = set(contract.get("runtime_tool_whitelist", []))
    primary = set(contract["primary_private_or_commitment_output_set"])
    if readable & primary:
        raise ValueError("verifier precommit readable set intersects primary private/commitment outputs")
    if readable - whitelist != common:
        raise ValueError("verifier precommit readable set is not the frozen common input set plus whitelist")
    if set(contract["precommit_visibility_invariant"]["intersection"]):
        raise ValueError("isolation invariant records a non-empty intersection")
    if contract["verifier_precommit_readable_input_set_hash"] != sha256_bytes(project_canonical_json(sorted(readable, key=_bytewise))):
        raise ValueError("readable-set hash mismatch")
    if contract["primary_private_or_commitment_output_set_hash"] != sha256_bytes(project_canonical_json(sorted(primary, key=_bytewise))):
        raise ValueError("primary output-set hash mismatch")
    if contract.get("enforcement_mechanism") != "BUBBLEWRAP_MOUNT_NAMESPACE_CAPABILITY_ISOLATION":
        raise ValueError("M2 is not execution-bound to bubblewrap isolation")
    launcher = contract.get("isolation_launcher_identity", {})
    if launcher.get("launcher_sha256") != sha256_file(ROOT / "tools/a2_bwrap_isolation.py"):
        raise ValueError("M2 isolation launcher hash mismatch")
    if launcher.get("launcher_configuration_hash") != sha256_bytes(project_canonical_json(launcher.get("launcher_configuration"))):
        raise ValueError("M2 isolation launcher configuration hash mismatch")
    probe = contract.get("non_semantic_isolation_probe", {})
    if probe.get("common_frozen_sentinel_readable") is not True or probe.get("primary_private_sentinel_readable") is not False or probe.get("primary_commitment_sentinel_readable") is not False or probe.get("prohibited_read_failed_at_boundary") is not True:
        raise ValueError("M2 sentinel probe did not prove capability isolation")
    if contract.get("M2_EXECUTION_BOUND_ISOLATION") != "VERIFIED":
        raise ValueError("M2 execution-bound isolation is not verified")
    return True


def capture_execution_time_runtime_binding(exposed: dict[str, Any]) -> dict[str, Any]:
    """Freeze stable invocation fields exposed by the actual role runtime."""
    required = {"provider", "model_id", "tool_mode", "context_identity", "run_identity"}
    if not required <= exposed.keys() or any(not isinstance(exposed[name], str) or not exposed[name] for name in required):
        raise ValueError("execution-time runtime binding is missing a required exposed field")
    optional = ["model_variant_or_snapshot", "agent_or_cli_version", "decoding_or_runtime_configuration"]
    binding: dict[str, Any] = {}
    for name in sorted(required | set(optional), key=_bytewise):
        if name in exposed and exposed[name] is not None:
            binding[name] = {"field_status": "OBSERVED", "value": exposed[name]}
        else:
            binding[name] = {"field_status": "UNAVAILABLE_BY_RUNTIME", "value": None}
    binding["runtime_binding_id"] = canonical_object_id(binding, "runtime_binding_id")
    return binding


CANONICALIZATION_CONTRACT = {
    "schema": "PROJECT_CANONICAL_JSON_V1",
    "rfc8785_semantics": True,
    "encoding": "UTF-8_WITHOUT_BOM",
    "unicode": "NFC_REQUIRED_AND_VALIDATED_NO_SILENT_REWRITE",
    "object_key_order": "RFC8785_UTF16_CODE_UNIT_ORDER",
    "arrays": "ORDER_SENSITIVE_UNLESS_SCHEMA_DECLARED_SET",
    "declared_sets": "FIELD_SPECIFIC_ORDERING_REGISTRY_BEFORE_CANONICALIZATION",
    "normative_numbers": "INTEGER_ONLY_EXPLICIT_SCHEMA_RANGE",
    "floating_point": "PROHIBITED",
    "filesystem_locale_platform_independence": True,
    "raw_file_hash": "SHA256_EXACT_FILE_BYTES",
}


def _id_schema(nullable: bool = False) -> dict[str, Any]:
    value: dict[str, Any] = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {"anyOf": [value, {"const": None}]} if nullable else value


def _raw_schema(nullable: bool = False) -> dict[str, Any]:
    value: dict[str, Any] = {"type": "string", "pattern": r"^[0-9]+::S[0-9]{2}::A[0-9]{3}$"}
    return {"anyOf": [value, {"const": None}]} if nullable else value


def _schema(title: str, properties: dict[str, Any], required: list[str], cross: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": title,
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": required,
    }
    if cross:
        schema["x-cross-field-constraints"] = cross
    schema["schema_id"] = None
    schema["schema_id"] = canonical_object_id(schema, "schema_id")
    return schema


def _refresh_schema_id(schema: dict[str, Any]) -> dict[str, Any]:
    schema["schema_id"] = canonical_object_id(schema, "schema_id")
    return schema


def validate_schema_instance(name: str, instance: dict[str, Any], registry: dict[str, Any]) -> bool:
    try:
        import jsonschema
    except ImportError as exc:
        raise ValueError("jsonschema runtime is required for executable schema validation") from exc
    schema = registry.get("schemas", {}).get(name)
    if not isinstance(schema, dict):
        raise ValueError(f"unknown schema: {name}")
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(instance)
    except jsonschema.exceptions.SchemaError as exc:
        raise ValueError(f"invalid frozen schema: {name}: {exc.message}") from exc
    except jsonschema.exceptions.ValidationError as exc:
        raise ValueError(f"schema validation failed for {name}: {exc.message}") from exc
    return True


def validate_human_decision(packet: dict[str, Any], decision: dict[str, Any]) -> bool:
    action = decision.get("human_action")
    provenance = decision.get("human_provenance")
    if not isinstance(provenance, dict) or not provenance:
        raise ValueError("human decision provenance is required")
    selected_candidate = decision.get("human_selected_candidate_scoring_id")
    selected_relation = decision.get("human_selected_relation_identity")
    if action == "CONFIRM_PROPOSED_OWNER":
        if selected_candidate != packet.get("proposed_candidate_scoring_id") or selected_relation != packet.get("proposed_relation_identity"):
            raise ValueError("confirmed owner does not equal the frozen proposal")
        return True
    if action == "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE":
        option_id = decision.get("selected_packet_option_id")
        if not isinstance(option_id, str) or not option_id:
            raise ValueError("reject/select requires a packet-local option")
        matches = [item for item in packet.get("full_candidate_option_mapping", []) if item.get("packet_local_human_option_id") == option_id]
        if len(matches) != 1:
            raise ValueError("selected packet option does not resolve uniquely")
        option = matches[0]
        if selected_candidate != option.get("candidate_scoring_id") or selected_relation != option.get("relation_identity"):
            raise ValueError("selected option/candidate/relation mismatch")
        if decision.get("fresh_alternative_verification") not in {"PASS", "FAIL"}:
            raise ValueError("fresh alternative verification reference/status is required")
        return True
    if action == "NOT_SURE_ESCALATE":
        if selected_candidate is not None or selected_relation is not None:
            raise ValueError("NOT_SURE escalation cannot select an owner")
        return True
    raise ValueError("unknown human action")


def validate_human_packet(packet: dict[str, Any]) -> bool:
    mapping = packet.get("full_candidate_option_mapping")
    if not isinstance(mapping, list) or not mapping:
        raise ValueError("human packet requires the full candidate option mapping")
    count = packet.get("complete_candidate_count")
    if count != len(mapping) or packet.get("candidate_count") != count:
        raise ValueError("human packet candidate count does not equal the full option mapping")
    options = [item.get("packet_local_human_option_id") for item in mapping]
    candidates = [item.get("candidate_scoring_id") for item in mapping]
    relations = [item.get("relation_identity") for item in mapping]
    if len(set(options)) != len(options) or len(set(candidates)) != len(candidates) or len(set(relations)) != len(relations):
        raise ValueError("human packet option mapping identities are not unique")
    proposed = [item for item in mapping if item.get("candidate_scoring_id") == packet.get("proposed_candidate_scoring_id") and item.get("relation_identity") == packet.get("proposed_relation_identity")]
    if len(proposed) != 1:
        raise ValueError("human packet proposal does not resolve in the complete option mapping")
    for side in ("raw", "candidate"):
        fact_ids = packet.get(f"{side}_side_evidence_fact_ids")
        refs = packet.get(f"{side}_side_evidence_source_references")
        if not isinstance(fact_ids, list) or not isinstance(refs, list):
            raise ValueError(f"human packet {side}-side evidence binding is missing")
        if set(fact_ids) != {item.get("source_fact_id") for item in refs}:
            raise ValueError(f"human packet {side}-side fact IDs do not match source references")
    audit = packet.get("complete_universe_expansion_audit", {})
    if audit.get("expanded_option_count") != count or audit.get("complete_candidate_count_exact_match") is not True:
        raise ValueError("human packet universe expansion audit count mismatch")
    if audit.get("option_mapping_hash") != sha256_bytes(project_canonical_json(mapping)):
        raise ValueError("human packet option mapping audit hash mismatch")
    if packet.get("human_input_mode") != "PACKET_LOCAL_OPTION_ONLY_NO_MANUAL_ID_OR_HASH_ENTRY":
        raise ValueError("human packet permits manual ID/hash entry")
    return True


def validate_owner_terminal(record: dict[str, Any]) -> bool:
    if record.get("terminal_record_class") != "A2_OWNER_ADJUDICATION_FROZEN":
        raise ValueError("not an owner terminal")
    if record.get("human_action") not in {"CONFIRM_PROPOSED_OWNER", "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE"}:
        raise ValueError("owner terminal does not permit NOT_SURE")
    if record.get("unresolved_state") is not False:
        raise ValueError("owner terminal must be resolved")
    if not record.get("selected_owner_candidate_scoring_id") or not record.get("selected_relation_identity"):
        raise ValueError("owner terminal requires exact selected owner and relation")
    if not record.get("human_decision_record_id") or not record.get("human_provenance"):
        raise ValueError("owner terminal requires human decision provenance")
    if record.get("human_action") == "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE":
        verification = record.get("fresh_alternative_verification")
        status = verification.get("status") if isinstance(verification, dict) else verification
        if status != "PASS":
            raise ValueError("alternative owner requires fresh verification PASS")
    return True


SEMANTIC_ESCALATION_CLASSES = {
    "HUMAN_NOT_SURE",
    "HUMAN_SELECTED_ALTERNATIVE_VERIFICATION_FAILED",
    "PRE_HUMAN_PROPOSER_VERIFIER_DISAGREEMENT",
    "PRE_HUMAN_AMBIGUOUS",
    "PRE_HUMAN_STRUCTURE",
    "PRE_HUMAN_SCORING_AUTHORITY",
    "PRE_HUMAN_PROVENANCE",
    "PRE_HUMAN_IDENTITY",
}


def build_escalation_terminal(escalation_class: str, *, human_provenance: dict[str, Any] | None = None) -> dict[str, Any]:
    if escalation_class not in SEMANTIC_ESCALATION_CLASSES:
        raise ValueError("technical execution defects cannot become semantic escalation terminals")
    pre_human = escalation_class.startswith("PRE_HUMAN_")
    human_action = None if pre_human else (
        "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE"
        if escalation_class == "HUMAN_SELECTED_ALTERNATIVE_VERIFICATION_FAILED"
        else "NOT_SURE_ESCALATE"
    )
    if not pre_human and (not isinstance(human_provenance, dict) or not human_provenance):
        raise ValueError("human escalation requires non-null human provenance")
    result = {
        "terminal_record_class": "A2_ESCALATION_FROZEN",
        "human_action": human_action,
        "human_decision_record_id": None,
        "human_provenance": None if pre_human else human_provenance,
        "selected_owner_candidate_scoring_id": None,
        "selected_relation_identity": None,
        "unresolved_state": True,
        "escalation_class": escalation_class,
        "independent_commitment_comparison": "FAIL_CLOSED" if escalation_class == "PRE_HUMAN_PROPOSER_VERIFIER_DISAGREEMENT" else "PASS",
        "all_hard_gates": "INDETERMINATE" if pre_human else "PASS",
        "fresh_alternative_verification": "FAIL" if escalation_class == "HUMAN_SELECTED_ALTERNATIVE_VERIFICATION_FAILED" else None,
        "fresh_alternative_verification_id": "0" * 64 if escalation_class == "HUMAN_SELECTED_ALTERNATIVE_VERIFICATION_FAILED" else None,
    }
    return result


def validate_escalation_terminal(record: dict[str, Any]) -> bool:
    if record.get("terminal_record_class") != "A2_ESCALATION_FROZEN":
        raise ValueError("not an escalation terminal")
    if record.get("selected_owner_candidate_scoring_id") is not None or record.get("selected_relation_identity") is not None or record.get("unresolved_state") is not True:
        raise ValueError("escalation terminal must remain unresolved without selected owner")
    escalation_class = record.get("escalation_class")
    if escalation_class not in SEMANTIC_ESCALATION_CLASSES:
        raise ValueError("technical execution defects cannot masquerade as semantic escalation")
    if escalation_class.startswith("PRE_HUMAN_"):
        if record.get("human_action") is not None or record.get("human_decision_record_id") is not None or record.get("human_provenance") is not None:
            raise ValueError("pre-human escalation must have null human fields")
    elif record.get("human_action") not in {"NOT_SURE_ESCALATE", "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE"} or not record.get("human_provenance"):
        raise ValueError("human escalation requires human action and provenance")
    if record.get("escalation_class") == "HUMAN_SELECTED_ALTERNATIVE_VERIFICATION_FAILED":
        if record.get("human_action") != "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE" or record.get("fresh_alternative_verification") != "FAIL":
            raise ValueError("failed selected alternative must remain an explicit escalation")
    return True


def build_schema_registry(auth: AuthenticatedInputs, ordering: dict[str, Any], isolation: dict[str, Any]) -> dict[str, Any]:
    any_string = {"type": "string", "minLength": 1}
    bool_value = {"type": "boolean"}
    int_value = {"type": "integer"}
    hash_or_null = _id_schema(True)
    schemas: dict[str, dict[str, Any]] = {}
    schemas["current86_a2_execution_manifest"] = _schema(
        "Current86 A2 P0 execution manifest",
        {
            "active_bso_a2_authority_id": _id_schema(), "activation_transaction_id": _id_schema(),
            "h2_provenance_evidence_id": _id_schema(), "exact_current86_scope_id": _id_schema(),
            "exact_current86_raw_set_hash": _id_schema(), "exact_current86_relation_set_hash": _id_schema(),
            "exact_current86_candidate_registry_hash": _id_schema(), "raw_count": int_value,
            "relation_count": int_value, "hard_negative_count": int_value, "former_human_eq_relation_count": int_value,
            "canonicalization_contract": any_string, "set_ordering_registry_id": _id_schema(),
            "pilot_selection_rule": any_string, "primary_computational_contract_id": _id_schema(),
            "verifier_computational_contract_id": _id_schema(), "verifier_isolation_enforcement_contract_id": _id_schema(),
            "proposal_evidence_profile_hash": _id_schema(), "historical_output_denylist_hash": _id_schema(),
            "source_registry_id": _id_schema(), "human_packet_schema_id": _id_schema(),
            "human_decision_schema_id": _id_schema(), "terminal_record_schema_id": _id_schema(),
            "ledger_schema_id": _id_schema(), "state_partition_schema_id": _id_schema(),
            "p0_status": {"const": "PREPARED_NOT_ADJUDICATED"}, "p0_executed": {"const": "NO"},
            "p1_executed": {"const": "NO"}, "primary_proposer_executed": {"const": "NO"},
            "independent_verifier_executed": {"const": "NO"}, "raw_level_human_decisions": {"const": 0},
            "p2_executed": {"const": "NO"}, "p3_executed": {"const": "NO"}, "p4_executed": {"const": "NO"},
            "bso_v_executed": {"const": "NO"}, "bso_p_executed": {"const": "NO"}, "binding_publication": {"const": "NO"},
            "scoring_authority_mutation": {"const": "NO"}, "binding_authority_mutation": {"const": "NO"}, "accepted_binding_change": {"const": "NO"}, "denominator_change": {"const": "NO"},
            "execution_manifest_id": hash_or_null,
        },
        ["active_bso_a2_authority_id", "activation_transaction_id", "h2_provenance_evidence_id", "exact_current86_scope_id",
         "exact_current86_raw_set_hash", "exact_current86_relation_set_hash", "exact_current86_candidate_registry_hash", "raw_count",
         "relation_count", "hard_negative_count", "former_human_eq_relation_count", "canonicalization_contract", "set_ordering_registry_id",
         "pilot_selection_rule", "primary_computational_contract_id", "verifier_computational_contract_id",
         "verifier_isolation_enforcement_contract_id", "proposal_evidence_profile_hash", "historical_output_denylist_hash", "source_registry_id",
         "human_packet_schema_id", "human_decision_schema_id", "terminal_record_schema_id", "ledger_schema_id", "state_partition_schema_id",
         "p0_status", "p0_executed", "p1_executed", "p2_executed", "p3_executed", "p4_executed", "primary_proposer_executed", "independent_verifier_executed", "bso_v_executed", "bso_p_executed", "raw_level_human_decisions",
         "binding_publication", "scoring_authority_mutation", "binding_authority_mutation", "accepted_binding_change", "denominator_change", "execution_manifest_id"],
        ["execution_manifest_id is omitted only for identity calculation; generated manifest carries its self-ID"]
    )
    schemas["raw_execution_unit"] = _schema("Current86 raw execution unit", {
        "schema": any_string, "raw_key": _raw_schema(), "authority_scope_id": _id_schema(), "execution_manifest_id": _id_schema(),
        "raw_identity_hash": _id_schema(), "complete_candidate_universe_hash": _id_schema(), "complete_candidate_relation_set_hash": _id_schema(),
        "source_bundle_status": {"const": "FROZEN_REFERENCE_ONLY_NOT_RUNTIME_MATERIALIZED"}, "initial_current_state": {"const": "NOT_STARTED_FOR_ADJUDICATION"},
        "p0_prepared": {"const": True}, "adjudication_executed": {"const": False}, "raw_execution_unit_id": hash_or_null,
    }, ["schema", "raw_key", "authority_scope_id", "execution_manifest_id", "raw_identity_hash", "complete_candidate_universe_hash", "complete_candidate_relation_set_hash", "source_bundle_status", "initial_current_state", "p0_prepared", "adjudication_executed", "raw_execution_unit_id"])
    schemas["complete_candidate_universe"] = _schema("Complete candidate universe", {
        "schema": any_string, "raw_key": _raw_schema(), "candidate_relations": {"type": "array", "items": {"type": "object"}},
        "candidate_relation_count": int_value, "complete_candidate_relation_set_hash": _id_schema(), "complete_candidate_universe_hash": _id_schema(),
        "complete_candidate_universe_preserved": {"const": True}, "hidden_pruning": {"const": "PROHIBITED"}, "top_k_candidate_truncation": {"const": "PROHIBITED"},
        "materialization_status": {"const": "PREPARED_NOT_ADJUDICATED"}, "complete_candidate_universe_id": hash_or_null,
    }, ["schema", "raw_key", "candidate_relations", "candidate_relation_count", "complete_candidate_relation_set_hash", "complete_candidate_universe_hash", "complete_candidate_universe_preserved", "hidden_pruning", "top_k_candidate_truncation", "materialization_status", "complete_candidate_universe_id"])
    schemas["admissible_source_fact"] = _schema("Admissible source fact", {
        "schema": any_string, "source_fact_id": _id_schema(), "source_artifact_identity": any_string, "source_artifact_sha256_or_pinned_identity": any_string,
        "source_provenance_identity": _id_schema(), "source_fact_type": {"enum": ["PINNED_CANONICAL_INTRINSIC_FIELD", "PINNED_PROJECT_TAXONOMY_FIELD", "PINNED_RAW_SOURCE_FIELD", "PINNED_SCORING_ROW_FIELD"]},
        "source_side": {"enum": ["RAW", "CANDIDATE"]}, "raw_key": _raw_schema(True), "candidate_scoring_id": _id_schema(True),
        "exact_field_path_or_claim_id": any_string, "authenticated_value_canonical_json": {}, "authenticated_value_sha256": _id_schema(),
        "admissible_source_fact_id": hash_or_null,
    }, ["schema", "source_fact_id", "source_artifact_identity", "source_artifact_sha256_or_pinned_identity", "source_provenance_identity", "source_fact_type", "source_side", "raw_key", "candidate_scoring_id", "exact_field_path_or_claim_id", "authenticated_value_canonical_json", "authenticated_value_sha256", "admissible_source_fact_id"])
    schemas["admissible_source_fact"]["oneOf"] = [
        {"properties": {"source_side": {"const": "RAW"}, "raw_key": _raw_schema(), "candidate_scoring_id": {"const": None}}},
        {"properties": {"source_side": {"const": "CANDIDATE"}, "raw_key": {"const": None}, "candidate_scoring_id": _id_schema()}},
    ]
    _refresh_schema_id(schemas["admissible_source_fact"])
    fact_definition = {
        key: value for key, value in schemas["admissible_source_fact"].items()
        if key not in {"$schema", "title", "schema_id"}
    }
    schemas["source_fact_bundle"] = _schema("Admissible source fact bundle", {
        "schema": any_string,
        "raw_key": _raw_schema(),
        "facts": {"type": "array", "items": {"$ref": "#/$defs/admissible_source_fact"}},
        "source_registry_id": _id_schema(),
        "normative_source_profile_hash": _id_schema(),
        "source_bundle_status": {"enum": ["FROZEN_REFERENCE_ONLY_NOT_RUNTIME_MATERIALIZED", "RUNTIME_EXTRACTED"]},
        "authenticated_source_references": {"type": "array", "items": {"type": "object"}},
        "source_bundle_hash": hash_or_null,
    }, ["schema", "raw_key", "facts", "source_registry_id", "normative_source_profile_hash", "source_bundle_status", "authenticated_source_references", "source_bundle_hash"])
    schemas["source_fact_bundle"]["$defs"] = {"admissible_source_fact": fact_definition}
    schemas["source_fact_bundle"]["oneOf"] = [
        {"properties": {"source_bundle_status": {"const": "FROZEN_REFERENCE_ONLY_NOT_RUNTIME_MATERIALIZED"}, "facts": {"maxItems": 0}}},
        {"properties": {"source_bundle_status": {"const": "RUNTIME_EXTRACTED"}, "facts": {"minItems": 1}}},
    ]
    _refresh_schema_id(schemas["source_fact_bundle"])
    schemas["proposal_input_bundle"] = _schema("A2 proposer/verifier common input bundle", {"schema": any_string, "authority_scope_id": _id_schema(), "raw_key": _raw_schema(), "active_authority_id": _id_schema(), "execution_manifest_id": _id_schema(), "raw_identity_hash": _id_schema(), "raw_source_bundle_hash": _id_schema(), "complete_candidate_universe_hash": _id_schema(), "complete_candidate_relation_set_hash": _id_schema(), "candidate_source_bundle_hashes": {"type": "array", "items": _id_schema()}, "admissible_source_fact_set_hash": _id_schema(), "proposal_evidence_profile_hash": _id_schema(), "source_class_fact_type_registry_id": _id_schema(), "historical_output_denylist_hash": _id_schema(), "input_status": {"const": "FROZEN_PREPARATION_ONLY"}, "proposal_input_bundle_id": hash_or_null}, ["schema", "authority_scope_id", "raw_key", "active_authority_id", "execution_manifest_id", "raw_identity_hash", "raw_source_bundle_hash", "complete_candidate_universe_hash", "complete_candidate_relation_set_hash", "candidate_source_bundle_hashes", "admissible_source_fact_set_hash", "proposal_evidence_profile_hash", "source_class_fact_type_registry_id", "historical_output_denylist_hash", "input_status", "proposal_input_bundle_id"])
    commitment_properties = {"schema": any_string, "role": {"enum": ["PRIMARY", "VERIFIER"]}, "raw_key": _raw_schema(), "proposal_input_bundle_id": _id_schema(), "execution_manifest_id": _id_schema(), "computational_contract_id": _id_schema(), "complete_candidate_universe_hash": _id_schema(), "complete_relation_set_hash": _id_schema(), "result_status": {"enum": ["UNIQUE_EXISTING_OWNER_PROPOSAL", "ESCALATE_AMBIGUOUS", "ESCALATE_STRUCTURE", "ESCALATE_SCORING_AUTHORITY", "ESCALATE_PROVENANCE", "ESCALATE_IDENTITY", "ESCALATE_PROPOSER_VERIFIER_DISAGREEMENT"]}, "selected_candidate_scoring_id": _id_schema(True), "selected_relation_identity": _id_schema(True), "evidence_fact_ids": {"type": "array", "items": _id_schema()}, "evidence_set_hash": _id_schema(), "hard_gate_results": {"type": "object"}, "context_identity": any_string, "run_identity": any_string, "runtime_binding": {"type": "object", "minProperties": 1}, "prompt_template_identity": {"type": "object", "minProperties": 1}, "private_chain_of_thought_persisted": {"const": False}, "owner_freeze_performed": {"const": False}, "binding_publication_performed": {"const": False}, "commitment_id": hash_or_null}
    schemas["primary_commitment"] = _schema("Primary A2 commitment", commitment_properties, list(commitment_properties), ["UNIQUE_EXISTING_OWNER_PROPOSAL requires both selected IDs non-null; every escalation status requires both null", "private chain-of-thought is prohibited"])
    schemas["verifier_commitment"] = _schema("Verifier A2 commitment", commitment_properties, list(commitment_properties), ["Verifier commitment is frozen after an isolated derivation with no primary result context"])
    schemas["proposer_verifier_comparison"] = _schema("Proposer/verifier comparison", {"schema": any_string, "raw_key": _raw_schema(), "primary_commitment_id": _id_schema(), "verifier_commitment_id": _id_schema(), "same_input_bundle": {"const": True}, "same_candidate_universe": {"const": True}, "context_identities_distinct": {"const": True}, "run_identities_distinct": {"const": True}, "independent_commitment_comparison": {"enum": ["PASS", "FAIL_CLOSED"]}, "comparison_id": hash_or_null}, ["schema", "raw_key", "primary_commitment_id", "verifier_commitment_id", "same_input_bundle", "same_candidate_universe", "context_identities_distinct", "run_identities_distinct", "independent_commitment_comparison", "comparison_id"])
    schemas["human_packet"] = _schema("Immutable A2 human packet", {"schema": any_string, "raw_key": _raw_schema(), "raw_action": any_string, "machine_proposal_label": {"const": "NON_AUTHORITATIVE_MACHINE_PROPOSAL"}, "candidate_count": int_value, "complete_candidate_universe_disclosed": {"const": True}, "hidden_pruning": {"const": "NO"}, "top_k_truncation": {"const": "NO"}, "normative_actions": {"const": ["CONFIRM_PROPOSED_OWNER", "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE", "NOT_SURE_ESCALATE"]}, "proposal_hash": _id_schema(), "verifier_comparison_hash": _id_schema(), "human_packet_id": hash_or_null}, ["schema", "raw_key", "raw_action", "machine_proposal_label", "candidate_count", "complete_candidate_universe_disclosed", "hidden_pruning", "top_k_truncation", "normative_actions", "proposal_hash", "verifier_comparison_hash", "human_packet_id"])
    schemas["human_decision_record"] = _schema("Native raw-level human decision record", {"schema": any_string, "raw_key": _raw_schema(), "human_packet_id": _id_schema(), "human_packet_hash": _id_schema(), "human_action": {"enum": ["CONFIRM_PROPOSED_OWNER", "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE", "NOT_SURE_ESCALATE"]}, "native_user_event_identity": _id_schema(), "decision_literal_hash": _id_schema(), "human_origin_provenance_evidence_id": _id_schema(), "human_origin_provenance_verification": {"const": "PASS"}, "human_decision_record_id": hash_or_null}, ["schema", "raw_key", "human_packet_id", "human_packet_hash", "human_action", "native_user_event_identity", "decision_literal_hash", "human_origin_provenance_evidence_id", "human_origin_provenance_verification", "human_decision_record_id"])
    terminal_base = {"schema": any_string, "terminal_record_class": any_string, "authority_version_id": _id_schema(), "authority_scope_id": _id_schema(), "raw_key": _raw_schema(), "complete_candidate_universe_hash": _id_schema(), "complete_candidate_relation_set_hash": _id_schema(), "input_bundle_hash": _id_schema(), "proposal_hash": _id_schema(), "proposal_evidence_set_hash": _id_schema(), "primary_derivation_commitment_hash": _id_schema(), "primary_run_identity": any_string, "verifier_derivation_commitment_hash": _id_schema(), "verifier_run_identity": any_string, "independent_commitment_comparison": {"const": "PASS"}, "hard_gate_results": {"type": "object"}, "all_hard_gates": {"const": "PASS"}, "human_action": {"enum": ["CONFIRM_PROPOSED_OWNER", "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE", "NOT_SURE_ESCALATE"]}, "human_origin_provenance_evidence_id": hash_or_null, "human_origin_provenance_verification": {"enum": ["PASS", None]}, "selected_owner_candidate_scoring_id": hash_or_null, "selected_relation_identity": hash_or_null, "unresolved_state": {"type": "boolean"}, "escalation_class": {"anyOf": [{"type": "string"}, {"const": None}]}, "terminal_record_hash": hash_or_null}
    owner_props = dict(terminal_base)
    owner_props.update({"terminal_record_class": {"const": "A2_OWNER_ADJUDICATION_FROZEN"}, "selected_owner_candidate_scoring_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "selected_relation_identity": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "unresolved_state": {"const": False}, "escalation_class": {"anyOf": [{"const": None}]}})
    schemas["owner_terminal"] = _schema("A2 owner terminal", owner_props, list(owner_props), ["selected owner != null", "unresolved_state = false", "escalation_class = null"])
    escalation_props = dict(terminal_base)
    escalation_props.update({"terminal_record_class": {"const": "A2_ESCALATION_FROZEN"}, "selected_owner_candidate_scoring_id": {"anyOf": [{"const": None}]}, "selected_relation_identity": {"anyOf": [{"const": None}]}, "unresolved_state": {"const": True}, "escalation_class": {"type": "string", "minLength": 1}})
    schemas["escalation_terminal"] = _schema("A2 escalation terminal", escalation_props, list(escalation_props), ["selected owner = null", "unresolved_state = true", "escalation_class != null"])

    # R2 replaces prose-only packet/terminal conditions with executable branch schemas.
    packet_props = {
        "schema": any_string, "raw_key": _raw_schema(), "raw_action": any_string,
        "authenticated_raw_action_reference": any_string,
        "machine_proposal_label": {"const": "NON_AUTHORITATIVE_MACHINE_PROPOSAL"},
        "proposed_candidate_scoring_id": _id_schema(), "proposed_relation_identity": _id_schema(),
        "primary_commitment_id": _id_schema(), "primary_commitment_hash": _id_schema(),
        "verifier_commitment_id": _id_schema(), "verifier_commitment_hash": _id_schema(),
        "comparison_id": _id_schema(), "comparison_hash": _id_schema(),
        "raw_side_evidence_fact_ids": {"type": "array", "items": _id_schema()},
        "candidate_side_evidence_fact_ids": {"type": "array", "items": _id_schema()},
        "raw_side_evidence_source_references": {"type": "array", "items": {"type": "object", "minProperties": 1}},
        "candidate_side_evidence_source_references": {"type": "array", "items": {"type": "object", "minProperties": 1}},
        "concise_source_grounded_basis": {"type": "string", "minLength": 1},
        "complete_candidate_universe_hash": _id_schema(), "complete_candidate_count": {"type": "integer", "minimum": 0},
        "full_candidate_option_mapping": {"type": "array", "minItems": 1, "items": {"type": "object", "additionalProperties": False, "properties": {"packet_local_human_option_id": {"type": "string", "minLength": 1}, "candidate_scoring_id": _id_schema(), "relation_identity": _id_schema(), "candidate_label_or_reference": {"type": "string", "minLength": 1}}, "required": ["packet_local_human_option_id", "candidate_scoring_id", "relation_identity", "candidate_label_or_reference"]}},
        "complete_universe_expansion_audit": {"type": "object", "additionalProperties": False, "properties": {"option_mapping_hash": _id_schema(), "expanded_option_count": {"type": "integer", "minimum": 0}, "complete_candidate_count_exact_match": {"const": True}}, "required": ["option_mapping_hash", "expanded_option_count", "complete_candidate_count_exact_match"]},
        "human_input_mode": {"const": "PACKET_LOCAL_OPTION_ONLY_NO_MANUAL_ID_OR_HASH_ENTRY"},
        "candidate_count": {"type": "integer", "minimum": 0}, "complete_candidate_universe_disclosed": {"const": True},
        "hidden_pruning": {"const": "NO"}, "top_k_truncation": {"const": "NO"},
        "normative_actions": {"const": ["CONFIRM_PROPOSED_OWNER", "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE", "NOT_SURE_ESCALATE"]},
        "proposal_hash": _id_schema(), "verifier_comparison_hash": _id_schema(), "human_packet_id": hash_or_null,
    }
    schemas["human_packet"] = _schema("Immutable A2 human packet R2", packet_props, list(packet_props))

    decision_common = {
        "schema": any_string, "raw_key": _raw_schema(), "human_packet_id": _id_schema(), "human_packet_hash": _id_schema(),
        "human_action": {"enum": ["CONFIRM_PROPOSED_OWNER", "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE", "NOT_SURE_ESCALATE"]},
        "native_user_event_identity": _id_schema(), "decision_literal_hash": _id_schema(),
        "human_origin_provenance_evidence_id": _id_schema(), "human_origin_provenance_verification": {"const": "PASS"},
        "human_provenance": {"type": "object", "minProperties": 1}, "selected_packet_option_id": {"anyOf": [{"type": "string", "minLength": 1}, {"const": None}]},
        "human_selected_candidate_scoring_id": _id_schema(True), "human_selected_relation_identity": _id_schema(True),
        "fresh_alternative_verification": {"enum": ["PASS", "FAIL", None]}, "fresh_alternative_verification_id": _id_schema(True), "human_decision_record_id": hash_or_null,
    }
    decision_required = ["schema", "raw_key", "human_packet_id", "human_packet_hash", "human_action", "native_user_event_identity", "decision_literal_hash", "human_origin_provenance_evidence_id", "human_origin_provenance_verification", "human_provenance", "human_selected_candidate_scoring_id", "human_selected_relation_identity", "selected_packet_option_id", "fresh_alternative_verification", "fresh_alternative_verification_id", "human_decision_record_id"]
    schemas["human_decision_record"] = _schema("Native raw-level human decision record R2", decision_common, decision_required)
    schemas["human_decision_record"]["oneOf"] = [
        {"properties": {"human_action": {"const": "CONFIRM_PROPOSED_OWNER"}, "human_selected_candidate_scoring_id": _id_schema(), "human_selected_relation_identity": _id_schema(), "selected_packet_option_id": {"const": None}, "fresh_alternative_verification": {"const": None}, "fresh_alternative_verification_id": {"const": None}}},
        {"properties": {"human_action": {"const": "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE"}, "selected_packet_option_id": {"type": "string", "minLength": 1}, "human_selected_candidate_scoring_id": _id_schema(), "human_selected_relation_identity": _id_schema(), "fresh_alternative_verification": {"enum": ["PASS", "FAIL"]}, "fresh_alternative_verification_id": _id_schema()}},
        {"properties": {"human_action": {"const": "NOT_SURE_ESCALATE"}, "human_selected_candidate_scoring_id": {"const": None}, "human_selected_relation_identity": {"const": None}, "selected_packet_option_id": {"const": None}, "fresh_alternative_verification": {"const": None}, "fresh_alternative_verification_id": {"const": None}}},
    ]
    _refresh_schema_id(schemas["human_decision_record"])
    owner_props = dict(terminal_base)
    owner_props.update({"terminal_record_class": {"const": "A2_OWNER_ADJUDICATION_FROZEN"}, "human_action": {"enum": ["CONFIRM_PROPOSED_OWNER", "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE"]}, "human_origin_provenance_evidence_id": _id_schema(), "human_origin_provenance_verification": {"const": "PASS"}, "selected_owner_candidate_scoring_id": _id_schema(), "selected_relation_identity": _id_schema(), "unresolved_state": {"const": False}, "escalation_class": {"const": None}, "human_decision_record_id": _id_schema(), "human_provenance": {"type": "object", "minProperties": 1}, "selected_packet_option_id": {"anyOf": [{"type": "string", "minLength": 1}, {"const": None}]}, "fresh_alternative_verification": {"anyOf": [{"const": "PASS"}, {"const": None}]}, "fresh_alternative_verification_id": _id_schema(True)})
    owner_props["independent_commitment_comparison"] = {"const": "PASS"}
    owner_props["all_hard_gates"] = {"const": "PASS"}
    schemas["owner_terminal"] = _schema("A2 owner terminal R2", owner_props, list(owner_props), ["owner human_action is CONFIRM or REJECT_SELECT only", "REJECT_SELECT requires fresh alternative verification PASS"])
    schemas["owner_terminal"]["oneOf"] = [
        {"properties": {"human_action": {"const": "CONFIRM_PROPOSED_OWNER"}, "selected_packet_option_id": {"const": None}, "fresh_alternative_verification": {"const": None}, "fresh_alternative_verification_id": {"const": None}}},
        {"properties": {"human_action": {"const": "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE"}, "selected_packet_option_id": {"type": "string", "minLength": 1}, "fresh_alternative_verification": {"const": "PASS"}, "fresh_alternative_verification_id": _id_schema()}},
    ]
    _refresh_schema_id(schemas["owner_terminal"])
    escalation_props = dict(terminal_base)
    escalation_props.update({"terminal_record_class": {"const": "A2_ESCALATION_FROZEN"}, "human_action": {"enum": ["NOT_SURE_ESCALATE", "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE", None]}, "human_origin_provenance_evidence_id": _id_schema(True), "human_origin_provenance_verification": {"enum": ["PASS", None]}, "selected_owner_candidate_scoring_id": {"const": None}, "selected_relation_identity": {"const": None}, "unresolved_state": {"const": True}, "escalation_class": {"enum": sorted(SEMANTIC_ESCALATION_CLASSES)}, "human_decision_record_id": hash_or_null, "human_provenance": {"anyOf": [{"type": "object", "minProperties": 1}, {"const": None}]}, "selected_packet_option_id": {"anyOf": [{"type": "string", "minLength": 1}, {"const": None}]}, "human_selected_alternative_candidate_scoring_id": _id_schema(True), "human_selected_alternative_relation_identity": _id_schema(True), "fresh_alternative_verification": {"anyOf": [{"enum": ["PASS", "FAIL"]}, {"const": None}]}, "fresh_alternative_verification_id": _id_schema(True), "independent_commitment_comparison": {"enum": ["PASS", "FAIL_CLOSED"]}, "all_hard_gates": {"enum": ["PASS", "INDETERMINATE", "FAIL_CLOSED"]}})
    schemas["escalation_terminal"] = _schema("A2 escalation terminal R2", escalation_props, list(escalation_props), ["selected owner is null", "unresolved_state is true", "pre-human escalation has null human fields", "human escalation has NOT_SURE plus provenance"])
    schemas["escalation_terminal"]["oneOf"] = [
        {"properties": {"human_action": {"const": None}, "human_origin_provenance_evidence_id": {"const": None}, "human_origin_provenance_verification": {"const": None}, "human_decision_record_id": {"const": None}, "human_provenance": {"const": None}, "selected_packet_option_id": {"const": None}, "human_selected_alternative_candidate_scoring_id": {"const": None}, "human_selected_alternative_relation_identity": {"const": None}, "fresh_alternative_verification": {"const": None}, "fresh_alternative_verification_id": {"const": None}}},
        {"properties": {"human_action": {"const": "NOT_SURE_ESCALATE"}, "human_origin_provenance_evidence_id": _id_schema(), "human_origin_provenance_verification": {"const": "PASS"}, "human_decision_record_id": _id_schema(), "human_provenance": {"type": "object", "minProperties": 1}, "selected_packet_option_id": {"const": None}, "human_selected_alternative_candidate_scoring_id": {"const": None}, "human_selected_alternative_relation_identity": {"const": None}, "fresh_alternative_verification": {"const": None}, "fresh_alternative_verification_id": {"const": None}}},
        {"properties": {"human_action": {"const": "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE"}, "escalation_class": {"const": "HUMAN_SELECTED_ALTERNATIVE_VERIFICATION_FAILED"}, "human_origin_provenance_evidence_id": _id_schema(), "human_origin_provenance_verification": {"const": "PASS"}, "human_decision_record_id": _id_schema(), "human_provenance": {"type": "object", "minProperties": 1}, "selected_packet_option_id": {"type": "string", "minLength": 1}, "human_selected_alternative_candidate_scoring_id": _id_schema(), "human_selected_alternative_relation_identity": _id_schema(), "fresh_alternative_verification": {"const": "FAIL"}, "fresh_alternative_verification_id": _id_schema()}},
    ]
    _refresh_schema_id(schemas["escalation_terminal"])
    schemas["execution_attempt_ledger_entry"] = _schema("Execution attempt ledger entry", {"schema": any_string, "raw_key": _raw_schema(), "attempt_id": _id_schema(), "attempt_sequence": int_value, "stage": any_string, "status": any_string, "error_class": {"anyOf": [{"type": "string"}, {"const": None}]}, "entry_id": hash_or_null}, ["schema", "raw_key", "attempt_id", "attempt_sequence", "stage", "status", "error_class", "entry_id"])
    schemas["pending_terminal_ledger_entry"] = _schema("Pending terminal ledger entry", {"schema": any_string, "raw_key": _raw_schema(), "pending_terminal_id": _id_schema(), "terminal_record_hash": _id_schema(), "current_membership_derived_from_disposition_head": {"const": True}, "entry_id": hash_or_null}, ["schema", "raw_key", "pending_terminal_id", "terminal_record_hash", "current_membership_derived_from_disposition_head", "entry_id"])
    schemas["accepted_terminal_ledger_entry"] = _schema("Accepted terminal ledger entry", {"schema": any_string, "raw_key": _raw_schema(), "accepted_terminal_id": _id_schema(), "terminal_record_hash": _id_schema(), "independent_review_id": _id_schema(), "entry_id": hash_or_null}, ["schema", "raw_key", "accepted_terminal_id", "terminal_record_hash", "independent_review_id", "entry_id"])
    disposition_properties = {"schema": any_string, "raw_key": _raw_schema(), "disposition_type": any_string, "prior_state": {"anyOf": [{"type": "string"}, {"const": None}]}, "next_state": {"enum": ["NOT_STARTED_FOR_ADJUDICATION", "IN_PROGRESS_OR_INCOMPLETE", "PENDING_REVIEW", "BLOCKED_ATTEMPT", "ACCEPTED_TERMINAL"]}, "disposition_sequence": {"type": "integer", "minimum": 0}, "prior_disposition_id": _id_schema(True), "referenced_attempt_id": _id_schema(True), "referenced_pending_terminal_id": _id_schema(True), "referenced_review_id": _id_schema(True), "referenced_accepted_terminal_id": _id_schema(True), "remediation_reference": _id_schema(True), "reason_class": {"anyOf": [{"type": "string", "minLength": 1}, {"const": None}]}, "disposition_id": hash_or_null}
    schemas["authoritative_disposition_record"] = _schema("Authoritative disposition record", disposition_properties, list(disposition_properties), ["each raw has one linear sequence starting at 0", "every non-initial record references the immediately prior disposition_id", "fork, duplicate sequence, missing parent, invalid transition, or multiple heads fail closed"])
    invalidated_properties = dict(disposition_properties)
    invalidated_properties.update({"disposition_type": {"const": "PENDING_TERMINAL_INVALIDATED"}, "prior_state": {"const": "PENDING_REVIEW"}, "next_state": {"const": "BLOCKED_ATTEMPT"}, "referenced_pending_terminal_id": _id_schema(), "referenced_review_id": _id_schema(), "reason_class": {"type": "string", "minLength": 1}})
    schemas["pending_terminal_invalidated"] = _schema("PENDING_TERMINAL_INVALIDATED disposition", invalidated_properties, list(invalidated_properties), ["prior_state=PENDING_REVIEW", "next_state=BLOCKED_ATTEMPT", "pending terminal remains historical and stale for current pending membership"])
    accepted_properties = dict(disposition_properties)
    accepted_properties.update({"disposition_type": {"const": "TERMINAL_ACCEPTED"}, "prior_state": {"const": "PENDING_REVIEW"}, "next_state": {"const": "ACCEPTED_TERMINAL"}, "referenced_pending_terminal_id": _id_schema(), "referenced_review_id": _id_schema(), "referenced_accepted_terminal_id": _id_schema()})
    schemas["terminal_accepted"] = _schema("TERMINAL_ACCEPTED disposition", accepted_properties, list(accepted_properties), ["prior_state=PENDING_REVIEW", "next_state=ACCEPTED_TERMINAL", "accepted terminal supersedes historical blocked/pending/incomplete rows"])
    remediation_properties = dict(disposition_properties)
    remediation_properties.update({"disposition_type": {"const": "REMEDIATION_RESTARTED"}, "prior_state": {"const": "BLOCKED_ATTEMPT"}, "next_state": {"const": "IN_PROGRESS_OR_INCOMPLETE"}, "remediation_reference": _id_schema()})
    schemas["remediation_restarted"] = _schema("REMEDIATION_RESTARTED disposition", remediation_properties, list(remediation_properties), ["prior_state=BLOCKED_ATTEMPT", "next_state=IN_PROGRESS_OR_INCOMPLETE"])
    schemas["state_partition_snapshot"] = _schema("Current86 state partition snapshot", {"schema": any_string, "exact_current86_raw_set_hash": _id_schema(), "S_ACCEPTED_TERMINAL": {"type": "array", "items": _raw_schema()}, "S_PENDING_REVIEW": {"type": "array", "items": _raw_schema()}, "S_IN_PROGRESS_OR_INCOMPLETE": {"type": "array", "items": _raw_schema()}, "S_BLOCKED_ATTEMPT": {"type": "array", "items": _raw_schema()}, "S_NOT_STARTED_FOR_ADJUDICATION": {"type": "array", "items": _raw_schema()}, "pairwise_disjoint": {"const": True}, "exhaustive_exact_current86": {"const": True}, "state_partition_snapshot_id": hash_or_null}, ["schema", "exact_current86_raw_set_hash", "S_ACCEPTED_TERMINAL", "S_PENDING_REVIEW", "S_IN_PROGRESS_OR_INCOMPLETE", "S_BLOCKED_ATTEMPT", "S_NOT_STARTED_FOR_ADJUDICATION", "pairwise_disjoint", "exhaustive_exact_current86", "state_partition_snapshot_id"])
    schemas["promotion_record"] = _schema("Accepted terminal promotion record", {"schema": any_string, "source_terminal_record_id": _id_schema(), "source_terminal_record_hash": _id_schema(), "independent_review_id": _id_schema(), "independent_review_hash": _id_schema(), "promotion_sequence": int_value, "promotion_record_id": hash_or_null}, ["schema", "source_terminal_record_id", "source_terminal_record_hash", "independent_review_id", "independent_review_hash", "promotion_sequence", "promotion_record_id"])
    schemas["resume_token"] = _schema("P3 resume token", {"schema": any_string, "active_authority_id": _id_schema(), "execution_contract_hash": _id_schema(), "current_disposition_head_set_hash": _id_schema(), "disposition_ledger_head_hash": _id_schema(), "accepted_raw_set_hash": _id_schema(), "pending_raw_set_hash": _id_schema(), "in_progress_or_incomplete_raw_set_hash": _id_schema(), "blocked_attempt_raw_set_hash": _id_schema(), "not_started_raw_set_hash": _id_schema(), "full_partition_object_hash": _id_schema(), "accepted_count": int_value, "pending_count": int_value, "in_progress_or_incomplete_count": int_value, "blocked_attempt_count": int_value, "not_started_count": int_value, "last_checkpoint_id": _id_schema(), "accepted_ledger_head_hash": _id_schema(), "pending_ledger_head_hash": _id_schema(), "attempt_ledger_head_hash": _id_schema(), "resume_token_id": hash_or_null}, ["schema", "active_authority_id", "execution_contract_hash", "current_disposition_head_set_hash", "disposition_ledger_head_hash", "accepted_raw_set_hash", "pending_raw_set_hash", "in_progress_or_incomplete_raw_set_hash", "blocked_attempt_raw_set_hash", "not_started_raw_set_hash", "full_partition_object_hash", "accepted_count", "pending_count", "in_progress_or_incomplete_count", "blocked_attempt_count", "not_started_count", "last_checkpoint_id", "accepted_ledger_head_hash", "pending_ledger_head_hash", "attempt_ledger_head_hash", "resume_token_id"])
    schemas["pilot_selection"] = _schema("Deterministic P1 pilot selection", {"schema": any_string, "selection_input_scope_id": _id_schema(), "selection_input_exact_current86": {"const": True}, "canonical_raw_key_format": {"const": "{playbook_id}::S{stage:02d}::A{action:03d}"}, "ordering": {"const": "BYTEWISE_ASCENDING_UTF8"}, "selection": {"const": "MINIMUM_CANONICAL_RAW_KEY"}, "pilot_is_real_a2_adjudication": {"const": "YES"}, "semantic_fields_influenced_selection": {"const": []}, "excluded_semantic_fields": {"type": "array", "items": any_string}, "pilot_raw_key": _raw_schema(), "p1_executed": {"const": "NO"}, "pilot_selection_id": hash_or_null}, ["schema", "selection_input_scope_id", "selection_input_exact_current86", "canonical_raw_key_format", "ordering", "selection", "pilot_is_real_a2_adjudication", "semantic_fields_influenced_selection", "excluded_semantic_fields", "pilot_raw_key", "p1_executed", "pilot_selection_id"])
    schemas["workload_metric"] = _schema("Non-authoritative workload metric", {"schema": any_string, "raw_key": _raw_schema(), "metric_status": {"const": "NON_AUTHORITATIVE_WORKLOAD_EVIDENCE"}, "decision_wall_clock_ms": {"anyOf": [{"type": "integer", "minimum": 0}, {"const": None}]}, "session_continuity_status": any_string, "known_interruption_events": {"type": "array"}, "measurement_interpretation": any_string, "manual_candidate_id_copy_count": {"const": 0}, "manual_relation_id_copy_count": {"const": 0}, "manual_evidence_id_copy_count": {"const": 0}, "manual_hash_copy_count": {"const": 0}, "relation_level_manual_outcome_count": {"const": 0}, "workload_metric_id": hash_or_null}, ["schema", "raw_key", "metric_status", "decision_wall_clock_ms", "session_continuity_status", "known_interruption_events", "measurement_interpretation", "manual_candidate_id_copy_count", "manual_relation_id_copy_count", "manual_evidence_id_copy_count", "manual_hash_copy_count", "relation_level_manual_outcome_count", "workload_metric_id"])
    schemas["final_freeze_normative_manifest"] = _schema("P4 normative final-freeze manifest schema", {
        "schema": {"const": "FINAL_FREEZE_NORMATIVE_MANIFEST_SCHEMA_V1"},
        "materialization_status": {"const": "SCHEMA_ONLY_NO_P4_FREEZE"},
        "identity_field": {"const": "CURRENT86_A2_FINAL_FREEZE_ID"},
        "identity_rule": any_string,
        "workload_excluded": {"const": True},
        "excluded_fields": {"type": "array", "items": any_string},
        "identity_inputs": {"type": "array", "items": any_string},
        "schema_id": hash_or_null,
    }, ["schema", "materialization_status", "identity_field", "identity_rule", "workload_excluded", "excluded_fields", "identity_inputs", "schema_id"], ["No CURRENT86_A2_FINAL_FREEZE_ID is materialized in this contract-only turn", "workload telemetry cannot be an identity input"])
    schemas["final_freeze_package_manifest"] = _schema("P4 package manifest schema", {
        "schema": {"const": "FINAL_FREEZE_PACKAGE_MANIFEST_SCHEMA_V1"},
        "materialization_status": {"const": "SCHEMA_ONLY_NO_P4_FREEZE"},
        "identity_field": {"const": "FINAL_FREEZE_PACKAGE_MANIFEST_ID"},
        "identity_rule": any_string,
        "includes_workload_files": {"const": True},
        "workload_summary": any_string,
        "identity_excludes_from_normative_freeze": {"type": "array", "items": any_string},
        "normative_identity_reference": {"const": "CURRENT86_A2_FINAL_FREEZE_ID"},
        "package_identity_may_change_when_workload_files_change": {"const": True},
        "schema_id": hash_or_null,
    }, ["schema", "materialization_status", "identity_field", "identity_rule", "includes_workload_files", "workload_summary", "identity_excludes_from_normative_freeze", "normative_identity_reference", "package_identity_may_change_when_workload_files_change", "schema_id"], ["Package identity may include workload files while normative identity excludes them"])
    for schema in schemas.values():
        if not isinstance(schema.get("schema_id"), str):
            raise ValueError("schema ID missing")
    registry: dict[str, Any] = {
        "schema": "A2_P0_P1_SCHEMA_REGISTRY_V1",
        "canonicalization_contract": "PROJECT_CANONICAL_JSON_V1",
        "set_ordering_registry_id": ordering["set_ordering_registry_id"],
        "isolation_enforcement_id": isolation["isolation_enforcement_id"],
        "schemas": schemas,
    }
    registry["schema_registry_id"] = canonical_object_id(registry, "schema_registry_id")
    return registry


def _schema_id(registry: dict[str, Any], name: str) -> str:
    return registry["schemas"][name]["schema_id"]


def build_computational_contract(role: str, auth: AuthenticatedInputs, ordering: dict[str, Any], isolation: dict[str, Any], schemas: dict[str, Any]) -> dict[str, Any]:
    try:
        from tools.a2_role_runtime import role_prompt_template
    except ModuleNotFoundError:
        from a2_role_runtime import role_prompt_template

    if role not in {"PRIMARY", "VERIFIER"}:
        raise ValueError("computational role must be PRIMARY or VERIFIER")
    wrapper_name = "run_a2_primary.py" if role == "PRIMARY" else "run_a2_verifier.py"
    implementation_paths = [
        ROOT / f"tools/{wrapper_name}",
        ROOT / "tools/a2_role_runtime.py",
        ROOT / "tools/a2_bwrap_isolation.py",
    ]
    prompt = role_prompt_template(role)
    boundary = {
        "filesystem_read_scope": isolation["frozen_common_verifier_input_set"],
        "filesystem_write_scope": ["runtime/verifier_workspace" if role == "VERIFIER" else "runtime/primary_workspace"],
        "network_access": False,
        "shell_execution": False,
        "external_connector_access": False,
        "mutable_workspace_access": False,
        "allowed_tools": isolation["runtime_tool_whitelist"],
        "denied_tools": ["network", "shell", "primary_output_read", "unfrozen_external_retrieval"],
    }
    contract: dict[str, Any] = {
        "schema": "A2_COMPUTATIONAL_CONTRACT_V1",
        "role": role,
        "static_execution_implementation_identity": {
            "repository_commit": "UNAVAILABLE_BY_RUNTIME",
            "entrypoint": f"tools/{wrapper_name}",
            "implementation_files": [
                {"path": path.relative_to(ROOT).as_posix(), "raw_file_sha256": sha256_file(path)}
                for path in implementation_paths
            ],
            "dependency_lockfile_hashes": [],
            "interpreter_or_runtime_version": platform.python_version(),
            "agent_or_cli_version": "UNAVAILABLE_BY_RUNTIME",
            "configuration_file_hashes": [isolation["isolation_launcher_identity"]["launcher_configuration_hash"]],
        },
        "prompt_template_identity": prompt,
        "model_runtime_identity": {
            "provider": {"value": None, "field_status": "UNAVAILABLE_BY_RUNTIME"},
            "model_id": {"value": None, "field_status": "UNAVAILABLE_BY_RUNTIME"},
            "model_variant_or_snapshot_if_exposed": {"value": None, "field_status": "UNAVAILABLE_BY_RUNTIME"},
            "runtime_or_agent_version": {"value": None, "field_status": "UNAVAILABLE_BY_RUNTIME"},
            "decoding_parameters": {"value": None, "field_status": "UNAVAILABLE_BY_RUNTIME"},
            "seed_if_supported": {"value": None, "field_status": "UNAVAILABLE_BY_RUNTIME"},
            "context_policy_version_if_exposed": {"value": None, "field_status": "UNAVAILABLE_BY_RUNTIME"},
            "tool_mode": f"A2_{role}_ROLE_RUNTIME",
        },
        "execution_time_runtime_binding": {
            "binding_status_before_invocation": "REQUIRED_NOT_YET_CAPTURED",
            "capture_rule": "CAPTURE_EVERY_STABLE_FIELD_EXPOSED_AT_ACTUAL_INVOCATION_AND_FAIL_CLOSED_ON_MISSING_REQUIRED_FIELDS",
            "provider": {"field_status": "REQUIRED_AT_INVOCATION", "value": None},
            "model_id": {"field_status": "REQUIRED_AT_INVOCATION", "value": None},
            "model_variant_or_snapshot": {"field_status": "UNAVAILABLE_BY_RUNTIME_ALLOWED_IF_NOT_EXPOSED", "value": None},
            "agent_or_cli_version": {"field_status": "UNAVAILABLE_BY_RUNTIME_ALLOWED_IF_NOT_EXPOSED", "value": None},
            "tool_mode": {"field_status": "FROZEN", "value": f"A2_{role}_ROLE_RUNTIME"},
            "decoding_or_runtime_configuration": {"field_status": "UNAVAILABLE_BY_RUNTIME_ALLOWED_IF_NOT_EXPOSED", "value": None},
            "context_identity": {"field_status": "REQUIRED_AT_INVOCATION", "value": None},
            "run_identity": {"field_status": "REQUIRED_AT_INVOCATION", "value": None},
        },
        "tool_permission_boundary": boundary,
        "input_schema_identity": {
            "proposal_input_bundle": _schema_id(schemas, "proposal_input_bundle"),
            "raw_execution_unit": _schema_id(schemas, "raw_execution_unit"),
            "complete_candidate_universe": _schema_id(schemas, "complete_candidate_universe"),
            "admissible_source_fact": _schema_id(schemas, "admissible_source_fact"),
            "source_fact_bundle": _schema_id(schemas, "source_fact_bundle"),
        },
        "output_schema_identity": {
            "primary_commitment": _schema_id(schemas, "primary_commitment"),
            "verifier_commitment": _schema_id(schemas, "verifier_commitment"),
            "proposer_verifier_comparison": _schema_id(schemas, "proposer_verifier_comparison"),
        },
        "normative_source_profile_identity": {"profile_hash": NORMATIVE_SOURCE_PROFILE_HASH, "scope_id": auth.scope_id},
        "source_class_fact_type_registry_identity": {"registry_id": EXPECTED_SOURCE_REGISTRY_ID, "raw_file_sha256": auth.source_registry_sha256},
        "historical_output_denylist_identity": {"denylist_hash": HISTORICAL_OUTPUT_DENYLIST_HASH, "scope_id": auth.scope_id},
        "isolation_contract_identity": {"contract_schema": "A2_VERIFIER_ISOLATION_ENFORCEMENT_CONTRACT_V1", "isolation_enforcement_id": isolation["isolation_enforcement_id"]},
        "isolation_enforcement_identity": isolation["isolation_enforcement_id"],
        "isolation_launcher_sha256": isolation["isolation_launcher_identity"]["launcher_sha256"],
        "isolation_launcher_configuration_hash": isolation["isolation_launcher_identity"]["launcher_configuration_hash"],
        "canonicalization_contract": "PROJECT_CANONICAL_JSON_V1",
        "set_ordering_registry_identity": ordering["set_ordering_registry_id"],
        "private_chain_of_thought_normative_artifact": False,
    }
    contract["computational_contract_id"] = canonical_object_id(contract, "computational_contract_id")
    return contract


def _set_hash(values: list[Any]) -> str:
    return sha256_bytes(project_canonical_json(values))


def build_execution_manifest(auth: AuthenticatedInputs, ordering: dict[str, Any], isolation: dict[str, Any], primary: dict[str, Any], verifier: dict[str, Any], schemas: dict[str, Any]) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema": "CURRENT86_A2_EXECUTION_MANIFEST_V1",
        "active_bso_a2_authority_id": auth.candidate_id,
        "activation_transaction_id": auth.activation_transaction_id,
        "h2_provenance_evidence_id": auth.h2_evidence_id,
        "exact_current86_scope_id": auth.scope_id,
        "exact_current86_raw_set_hash": _set_hash(list(auth.raw_keys)),
        "exact_current86_relation_set_hash": hash_declared_set("relation_set", list(auth.relations), ordering),
        "exact_current86_candidate_registry_hash": sha256_file(auth.root / "FA1B2de_Current86_BSO_A2_Authority_Candidate_PROSPECTIVE_R2/04_complete_candidate_set_registry.json"),
        "raw_count": CURRENT86_RAW_COUNT,
        "relation_count": CURRENT86_RELATION_COUNT,
        "hard_negative_count": CURRENT86_HARD_NEGATIVE_COUNT,
        "former_human_eq_relation_count": CURRENT86_FORMER_HUMAN_EQ_COUNT,
        "canonicalization_contract": "PROJECT_CANONICAL_JSON_V1",
        "set_ordering_registry_id": ordering["set_ordering_registry_id"],
        "pilot_selection_rule": "MINIMUM_CANONICAL_RAW_KEY_BYTEWISE_ASCENDING_UTF8_EXACT_CURRENT86",
        "primary_computational_contract_id": primary["computational_contract_id"],
        "verifier_computational_contract_id": verifier["computational_contract_id"],
        "verifier_isolation_enforcement_contract_id": isolation["isolation_enforcement_id"],
        "proposal_evidence_profile_hash": NORMATIVE_SOURCE_PROFILE_HASH,
        "historical_output_denylist_hash": HISTORICAL_OUTPUT_DENYLIST_HASH,
        "source_registry_id": EXPECTED_SOURCE_REGISTRY_ID,
        "human_packet_schema_id": _schema_id(schemas, "human_packet"),
        "human_decision_schema_id": _schema_id(schemas, "human_decision_record"),
        "terminal_record_schema_id": _schema_id(schemas, "owner_terminal"),
        "ledger_schema_id": _schema_id(schemas, "accepted_terminal_ledger_entry"),
        "state_partition_schema_id": _schema_id(schemas, "state_partition_snapshot"),
        "p0_status": "PREPARED_NOT_ADJUDICATED",
        "p0_executed": "NO",
        "p1_executed": "NO",
        "primary_proposer_executed": "NO",
        "independent_verifier_executed": "NO",
        "p2_executed": "NO",
        "p3_executed": "NO",
        "p4_executed": "NO",
        "bso_v_executed": "NO",
        "bso_p_executed": "NO",
        "raw_level_human_decisions": 0,
        "binding_publication": "NO",
        "scoring_authority_mutation": "NO",
        "binding_authority_mutation": "NO",
        "accepted_binding_change": "NO",
        "denominator_change": "NO",
    }
    manifest["execution_manifest_id"] = canonical_object_id(manifest, "execution_manifest_id")
    return manifest


def select_pilot_raw(raw_keys: list[str] | tuple[str, ...], scope_id: str = EXPECTED_SCOPE_ID) -> dict[str, Any]:
    if not raw_keys or len(set(raw_keys)) != len(raw_keys):
        raise ValueError("pilot selection input must be a non-empty exact set")
    pilot = min(raw_keys, key=_bytewise)
    result: dict[str, Any] = {
        "schema": "A2_PILOT_SELECTION_V1",
        "selection_input_scope_id": scope_id,
        "selection_input_exact_current86": True,
        "canonical_raw_key_format": "{playbook_id}::S{stage:02d}::A{action:03d}",
        "ordering": "BYTEWISE_ASCENDING_UTF8",
        "selection": "MINIMUM_CANONICAL_RAW_KEY",
        "pilot_is_real_a2_adjudication": "YES",
        "semantic_fields_influenced_selection": [],
        "excluded_semantic_fields": ["candidate_count", "model_confidence", "evidence_richness", "historical_disposition", "historical_owner", "historical_eq_result", "proposal_agreement", "candidate_popularity", "embedding_similarity", "semantic_difficulty"],
        "pilot_raw_key": pilot,
        "p1_executed": "NO",
    }
    result["pilot_selection_id"] = canonical_object_id(result, "pilot_selection_id")
    return result


LEGAL_TRANSITIONS = {
    "INITIAL_STATE": (None, "NOT_STARTED_FOR_ADJUDICATION"),
    "EXECUTION_STARTED": ("NOT_STARTED_FOR_ADJUDICATION", "IN_PROGRESS_OR_INCOMPLETE"),
    "ATTEMPT_BLOCKED": ("IN_PROGRESS_OR_INCOMPLETE", "BLOCKED_ATTEMPT"),
    "PENDING_TERMINAL_CREATED": ("IN_PROGRESS_OR_INCOMPLETE", "PENDING_REVIEW"),
    "PENDING_TERMINAL_INVALIDATED": ("PENDING_REVIEW", "BLOCKED_ATTEMPT"),
    "REMEDIATION_RESTARTED": ("BLOCKED_ATTEMPT", "IN_PROGRESS_OR_INCOMPLETE"),
    "TERMINAL_ACCEPTED": ("PENDING_REVIEW", "ACCEPTED_TERMINAL"),
}


def _require_lineage_id(record: dict[str, Any], field: str) -> None:
    value = record.get(field)
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise ValueError(f"{record.get('disposition_type')} requires exact non-null {field}")


def validate_disposition_record(record: dict[str, Any]) -> bool:
    typ = record.get("disposition_type")
    if typ not in LEGAL_TRANSITIONS:
        raise ValueError(f"unknown disposition type: {typ}")
    expected_prior, expected_next = LEGAL_TRANSITIONS[typ]
    if record.get("prior_state") != expected_prior or record.get("next_state") != expected_next:
        raise ValueError("invalid disposition transition")
    if typ == "PENDING_TERMINAL_INVALIDATED":
        _require_lineage_id(record, "referenced_pending_terminal_id")
        _require_lineage_id(record, "referenced_review_id")
        if not isinstance(record.get("reason_class"), str) or not record["reason_class"]:
            raise ValueError("PENDING_TERMINAL_INVALIDATED requires invalidation reason_class")
    elif typ == "TERMINAL_ACCEPTED":
        _require_lineage_id(record, "referenced_pending_terminal_id")
        _require_lineage_id(record, "referenced_review_id")
        _require_lineage_id(record, "referenced_accepted_terminal_id")
    elif typ == "REMEDIATION_RESTARTED":
        _require_lineage_id(record, "remediation_reference")
    if canonical_object_id(record, "disposition_id") != record.get("disposition_id"):
        raise ValueError("disposition ID mismatch")
    return True


def validate_disposition_chain(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        raise ValueError("empty disposition chain")
    raw = records[0].get("raw_key")
    if not isinstance(raw, str) or any(record.get("raw_key") != raw for record in records):
        raise ValueError("disposition chain mixes raw keys")
    sequences = [record.get("disposition_sequence") for record in records]
    if sequences != list(range(len(records))) or len(set(sequences)) != len(sequences):
        raise ValueError("duplicate sequence, fork, or sequence gap")
    for index, record in enumerate(records):
        validate_disposition_record(record)
        typ = record.get("disposition_type")
        prior_state, next_state = LEGAL_TRANSITIONS[typ]
        if index == 0:
            if record.get("prior_disposition_id") is not None or typ != "INITIAL_STATE":
                raise ValueError("initial disposition has a parent")
        elif record.get("prior_disposition_id") != records[index - 1].get("disposition_id"):
            raise ValueError("missing or non-immediate disposition parent")
    head = records[-1]
    current_pending = head.get("referenced_pending_terminal_id") if head["next_state"] == "PENDING_REVIEW" else None
    return {
        "raw_key": raw,
        "current_state": head["next_state"],
        "current_disposition_id": head["disposition_id"],
        "current_pending_terminal_id": current_pending,
        "validated_chain": True,
    }


def reconstruct_partitions(raw_keys: list[str] | tuple[str, ...], chains: dict[str, list[dict[str, Any]]]) -> dict[str, list[str]]:
    expected = set(raw_keys)
    if set(chains) != expected:
        raise ValueError("partition input is not exact Current86")
    partitions = {name: [] for name in ["S_ACCEPTED_TERMINAL", "S_PENDING_REVIEW", "S_IN_PROGRESS_OR_INCOMPLETE", "S_BLOCKED_ATTEMPT", "S_NOT_STARTED_FOR_ADJUDICATION"]}
    state_to_set = {name.removeprefix("S_"): name for name in partitions}
    for raw in raw_keys:
        state = validate_disposition_chain(chains[raw])["current_state"]
        partitions[state_to_set[state]].append(raw)
    for values in partitions.values():
        values.sort(key=_bytewise)
    all_values = [raw for values in partitions.values() for raw in values]
    if len(all_values) != len(set(all_values)) or set(all_values) != expected:
        raise ValueError("state partition is not disjoint/exhaustive")
    return partitions


def reviewer_infrastructure_failure(current_state: str) -> dict[str, Any]:
    if current_state != "PENDING_REVIEW":
        raise ValueError("reviewer infrastructure failure rule applies only to pending review")
    return {"current_state": "PENDING_REVIEW", "global_pause": True, "append_disposition": False}


def normative_freeze_id(normative_manifest: dict[str, Any]) -> str:
    return canonical_object_id(normative_manifest, "CURRENT86_A2_FINAL_FREEZE_ID")


def package_manifest_id(package_manifest: dict[str, Any]) -> str:
    return canonical_object_id(package_manifest, "FINAL_FREEZE_PACKAGE_MANIFEST_ID")


def _materialized_candidate_universe(auth: AuthenticatedInputs, item: dict[str, Any], ordering: dict[str, Any]) -> dict[str, Any]:
    relations = order_declared_set("relation_set", item["candidate_relations"], ordering)
    relation_set_hash = hash_declared_set("relation_set", relations, ordering)
    result = {
        "schema": "COMPLETE_CANDIDATE_UNIVERSE_CONTRACT_V1",
        "raw_key": item["raw_key"],
        "candidate_relations": relations,
        "candidate_relation_count": len(relations),
        "complete_candidate_relation_set_hash": relation_set_hash,
        "complete_candidate_universe_hash": canonical_object_id({"raw_key": item["raw_key"], "candidate_relations": relations, "complete_candidate_relation_set_hash": relation_set_hash}, "complete_candidate_universe_hash"),
        "complete_candidate_universe_preserved": True,
        "hidden_pruning": "PROHIBITED",
        "top_k_candidate_truncation": "PROHIBITED",
        "materialization_status": "PREPARED_NOT_ADJUDICATED",
    }
    result["complete_candidate_universe_id"] = canonical_object_id(result, "complete_candidate_universe_id")
    return result


def _write_lineage(auth: AuthenticatedInputs, output: Path) -> None:
    root = auth.root
    _copy_exact(root / R1_HANDOFF_NAME, output / f"00_lineage/r1_baseline/{R1_HANDOFF_NAME}")
    for name in ("CONTRACT_MANIFEST.json", "10_summary/SUMMARY.json", "FILE_LIST.txt", "SHA256SUMS.txt"):
        _copy_exact(root / R1_PACKAGE_DIR_NAME / name, output / f"00_lineage/r1_baseline/{name}")
    _copy_exact(root / DESIGN_NAME, output / f"00_lineage/reviewed_r2_design/{DESIGN_NAME}")
    for source, dest in [
        (root / "FA1B2de_Current86_BSO_A2_HumanLight_Execution_P0_P4_R2_Targeted_Independent_Review.json", output / "00_lineage/reviewed_r2_design/targeted_review.json"),
        (root / "FA1B2de_Current86_BSO_A2_HumanLight_Execution_P0_P4_R2_Targeted_Independent_Review.md", output / "00_lineage/reviewed_r2_design/targeted_review.md"),
        (root / "FA1B2de_Current86_BSO_A2_HumanLight_Execution_P0_P4_R2_Patch_Summary.json", output / "00_lineage/reviewed_r2_design/r2_patch_summary.json"),
        (root / "Independent_Design_Review_FA1B2de_Current86_BSO_A2_HumanLight_Execution_P0_P4.md", output / "00_lineage/reviewed_r2_design/prior_independent_design_review.md"),
        (root / "03_frozen_lineage/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json", output / "00_lineage/source_registry/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json"),
        (root / "03_frozen_lineage/BSO_EQ_Candidate_Level_Policy_Schema_Authority_Bundle_PROSPECTIVE_v4.json", output / "00_lineage/source_registry/BSO_EQ_Candidate_Level_Policy_Schema_Authority_Bundle_PROSPECTIVE_v4.json"),
        (root / "03_frozen_lineage/fa1b2de-bso-eq-v4-clean-phase-v-verifier-r1-20260826T103658Z.tar.gz", output / "00_lineage/source_registry/v4_clean_phase_v_verifier_r1.tar.gz"),
    ]:
        _copy_exact(source, dest)
    for source in sorted((root / "FA1B2de_Current86_BSO_A2_Authority_Activation").iterdir(), key=lambda p: p.name):
        if source.is_file():
            _copy_exact(source, output / f"00_lineage/activation/{source.name}")
    candidate_dir = root / "FA1B2de_Current86_BSO_A2_Authority_Candidate_PROSPECTIVE_R2"
    for source in sorted(candidate_dir.iterdir(), key=lambda p: p.name):
        if source.is_file():
            _copy_exact(source, output / f"00_lineage/candidate_r2/{source.name}")
    candidate_verification_dir = root / "FA1B2de_Current86_BSO_A2_Authority_Candidate_R2_Independent_Verification"
    for source in sorted(candidate_verification_dir.iterdir(), key=lambda p: p.name):
        if source.is_file():
            _copy_exact(source, output / f"00_lineage/candidate_verification/{source.name}")
    handoff_dir = candidate_verification_dir / "FA1B2de_Current86_BSO_A2_H2_Governance_Handoff"
    for source in sorted(handoff_dir.iterdir(), key=lambda p: p.name):
        if source.is_file():
            _copy_exact(source, output / f"00_lineage/candidate_verification/h2_governance_handoff/{source.name}")


def build_tdd_log() -> dict[str, Any]:
    blockers = {
        "B1": {
            "blocker_id": "R1_M1_SET_ORDERING_REGISTRY_NOT_UNIQUELY_AND_CONSISTENTLY_APPLIED",
            "red": {"command": "python -m unittest tests.test_r2_contract_fixes -v", "exit_code": 1, "observed": ["source_fact_id_or_canonical_fact_id != source_fact_id", "hash_declared_set missing"]},
            "green": {"command": "python -m unittest tests.test_r2_contract_fixes.B1OrderingRegressionTests -v", "exit_code": 0, "tests_passed": 3},
        },
        "B2": {
            "blocker_id": "R1_COMPUTATIONAL_RUNTIME_IDENTITY_AND_M2_ENFORCEMENT_NOT_EXECUTION_BOUND",
            "red": {"command": "python -m unittest tests.test_r2_contract_fixes -v", "exit_code": 1, "observed": ["entrypoint was tools/materialize_p0_p1_contract.py", "run_isolation_probe missing", "capture_execution_time_runtime_binding missing"]},
            "green": {"command": "python -m unittest tests.test_r2_contract_fixes.B2RuntimeIsolationRegressionTests -v", "exit_code": 0, "tests_passed": 3},
        },
        "B3": {
            "blocker_id": "R1_P1_HUMAN_DECISION_AND_TERMINAL_SCHEMAS_UNDERMODEL_REVIEWED_SEMANTICS",
            "red": {"command": "python -m unittest tests.test_r2_contract_fixes -v", "exit_code": 1, "observed": ["validate_human_decision missing", "owner/escalation executable branch validators missing"]},
            "green": {"command": "python -m unittest tests.test_r2_contract_fixes.B3HumanTerminalRegressionTests -v", "exit_code": 0, "tests_passed": 3},
        },
        "B4": {
            "blocker_id": "R1_EVIDENCE_AND_DISPOSITION_SCHEMA_ENFORCEMENT_INCOMPLETE",
            "red": {"command": "python -m unittest tests.test_r2_contract_fixes.B4SchemaDispositionRegressionTests -v", "exit_code": 1, "observed": ["Unresolvable: admissible_source_fact", "validate_disposition_record missing"]},
            "green": {"command": "python -m unittest tests.test_r2_contract_fixes.B4SchemaDispositionRegressionTests -v", "exit_code": 0, "tests_passed": 5},
        },
    }
    return {
        "schema": "R1_TO_R2_DEFECT_REPRODUCTION_AND_TDD_LOG_V1",
        "test_method": "FAIL_FIRST_THEN_MINIMUM_CORRECTION_THEN_GREEN",
        "blockers": blockers,
        "tests_weakened": False,
        "semantic_proposer_or_verifier_execution": False,
        "raw_level_human_adjudication": False,
    }


def _identity_value(path: Path, field: str) -> Any:
    if not path.is_file():
        return None
    value = _load(path)
    return value.get(field) if isinstance(value, dict) else None


def build_r1_to_r2_patch_summary(root: Path, staging: Path) -> dict[str, Any]:
    schema_names = [
        "admissible_source_fact", "source_fact_bundle", "human_packet", "human_decision_record",
        "owner_terminal", "escalation_terminal", "authoritative_disposition_record",
        "pending_terminal_invalidated", "terminal_accepted", "remediation_restarted",
    ]
    specifications: list[tuple[str, str, str]] = [
        ("02_set_ordering/SET_ORDERING_REGISTRY.json", "set_ordering_registry_id", "B1"),
        ("03_isolation/A2_VERIFIER_ISOLATION_ENFORCEMENT_CONTRACT.json", "isolation_enforcement_id", "B2"),
        ("04_computational_contracts/PRIMARY_A2_COMPUTATIONAL_CONTRACT.json", "computational_contract_id", "B2"),
        ("04_computational_contracts/VERIFIER_A2_COMPUTATIONAL_CONTRACT.json", "computational_contract_id", "B2"),
        ("current86_a2_execution_manifest.json", "execution_manifest_id", "B1+B2+B3+B4"),
        ("05_schemas/schema_registry.json", "schema_registry_id", "B3+B4"),
        ("CONTRACT_MANIFEST.json", "contract_manifest_id", "B1+B2+B3+B4"),
    ]
    specifications.extend((f"05_schemas/{name}.schema.json", "schema_id", "B3" if name in {"human_packet", "human_decision_record", "owner_terminal", "escalation_terminal"} else "B4") for name in schema_names)
    for directory, field, blocker in (
        ("05_schemas/candidate_universes", "complete_candidate_universe_id", "B1"),
        ("05_schemas/execution_units", "raw_execution_unit_id", "B1+B2+B3+B4"),
        ("05_schemas/proposal_input_bundles", "proposal_input_bundle_id", "B1+B2+B3+B4"),
    ):
        specifications.extend((path.relative_to(staging).as_posix(), field, blocker) for path in sorted((staging / directory).glob("*.json"), key=lambda p: p.name.encode("utf-8")))
    changes = []
    for relative, field, blocker in specifications:
        old_id = _identity_value(Path(root) / R1_PACKAGE_DIR_NAME / relative, field)
        new_id = _identity_value(staging / relative, field)
        if old_id != new_id:
            changes.append({"file": relative, "identity_field": field, "old_id": old_id, "new_id": new_id, "changed_for_blocker": blocker})
    corrected_files = sorted({
        "tools/materialize_p0_p1_contract.py", "tools/a2_role_runtime.py", "tools/a2_bwrap_isolation.py",
        "tools/run_a2_primary.py", "tools/run_a2_verifier.py", "tests/test_p0_p1_contract.py",
        "tests/test_r2_contract_fixes.py", "requirements-contract-tests.txt",
        *(item["file"] for item in changes),
    }, key=_bytewise)
    return {
        "schema": "FA1B2DE_CURRENT86_BSO_A2_P0_P1_EXECUTION_CONTRACT_R1_TO_R2_PATCH_SUMMARY_V1",
        "r1_handoff_sha256": EXPECTED_R1_HANDOFF_SHA256,
        "r1_package_identity": {
            "package_directory": R1_PACKAGE_DIR_NAME,
            "contract_manifest_id": _identity_value(Path(root) / R1_PACKAGE_DIR_NAME / "CONTRACT_MANIFEST.json", "contract_manifest_id"),
            "file_set_sha256": EXPECTED_R1_FILE_SET_SHA256,
        },
        "r2_package_identity": {
            "package_directory": R2_PACKAGE_DIR_NAME,
            "contract_manifest_id": _identity_value(staging / "CONTRACT_MANIFEST.json", "contract_manifest_id"),
        },
        "blocker_ids": [
            "R1_M1_SET_ORDERING_REGISTRY_NOT_UNIQUELY_AND_CONSISTENTLY_APPLIED",
            "R1_COMPUTATIONAL_RUNTIME_IDENTITY_AND_M2_ENFORCEMENT_NOT_EXECUTION_BOUND",
            "R1_P1_HUMAN_DECISION_AND_TERMINAL_SCHEMAS_UNDERMODEL_REVIEWED_SEMANTICS",
            "R1_EVIDENCE_AND_DISPOSITION_SCHEMA_ENFORCEMENT_INCOMPLETE",
        ],
        "exact_corrected_files": corrected_files,
        "identity_changes": changes,
        "why_changed": {
            "B1": "one registry-driven identity ordering per normative mathematical set",
            "B2": "actual role runtimes, invocation-time runtime binding, and bubblewrap capability isolation",
            "B3": "executable Human-Light packet, decision, owner, and escalation branch semantics",
            "B4": "self-contained source-fact schema and exact disposition lineage requirements",
        },
        "non_regression": {
            "reviewed_design_sha256_unchanged": EXPECTED_DESIGN_SHA256,
            "scoring_authority_mutation": "NO",
            "binding_authority_mutation": "NO",
            "accepted_binding_change": "NO",
            "denominator": 1796,
            "denominator_change": "NO",
            "r1_byte_preserved": "YES",
        },
        "no_runtime_adjudication": {
            "p0_executed": "NO", "p1_executed": "NO", "primary_proposer_executed": "NO",
            "independent_verifier_semantic_execution": "NO", "raw_level_human_decisions": 0,
            "owner_terminal_records_created": 0, "escalation_terminal_records_created": 0,
            "binding_publication": "NO", "bso_v_executed": "NO", "bso_p_executed": "NO",
        },
    }


def materialize(root: Path = ROOT, output_dir: Path | None = None) -> dict[str, Any]:
    verify_r1_byte_preservation(root)
    auth = authenticate_inputs(root)
    if output_dir is None:
        output_dir = Path(root) / R2_PACKAGE_DIR_NAME
    output_dir = Path(output_dir).resolve()
    if output_dir.exists():
        raise ValueError(f"refusing to overwrite existing output: {output_dir}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".a2-contract-staging-", dir=output_dir.parent) as staging_name:
        staging = Path(staging_name) / output_dir.name
        staging.mkdir()
        _write_lineage(auth, staging)
        _write_json(staging / f"00_lineage/{TDD_LOG_NAME}", build_tdd_log())
        for source_name in (
            "tools/materialize_p0_p1_contract.py", "tools/a2_role_runtime.py", "tools/a2_bwrap_isolation.py",
            "tools/run_a2_primary.py", "tools/run_a2_verifier.py", "requirements-contract-tests.txt",
        ):
            _copy_exact(auth.root / source_name, staging / source_name)
        _write_json(staging / "01_canonicalization/PROJECT_CANONICAL_JSON_V1.json", CANONICALIZATION_CONTRACT)
        ordering = build_set_ordering_registry(auth)
        _write_json(staging / "02_set_ordering/SET_ORDERING_REGISTRY.json", ordering)
        isolation = build_isolation_enforcement_contract(auth, ordering)
        validate_isolation_contract(isolation)
        _write_json(staging / "03_isolation/A2_VERIFIER_ISOLATION_ENFORCEMENT_CONTRACT.json", isolation)
        # Schemas are identity-bearing and are materialized after M1/M2, before computational IDs.
        schemas = build_schema_registry(auth, ordering, isolation)
        _write_json(staging / "05_schemas/schema_registry.json", schemas)
        for name, schema in sorted(schemas["schemas"].items()):
            _write_json(staging / f"05_schemas/{name}.schema.json", schema)
        primary = build_computational_contract("PRIMARY", auth, ordering, isolation, schemas)
        verifier = build_computational_contract("VERIFIER", auth, ordering, isolation, schemas)
        _write_json(staging / "04_computational_contracts/PRIMARY_A2_COMPUTATIONAL_CONTRACT.json", primary)
        _write_json(staging / "04_computational_contracts/VERIFIER_A2_COMPUTATIONAL_CONTRACT.json", verifier)
        _write_json(staging / "04_computational_contracts/PROMPT_TEMPLATE_IDENTITY_PRIMARY.json", primary["prompt_template_identity"])
        _write_json(staging / "04_computational_contracts/PROMPT_TEMPLATE_IDENTITY_VERIFIER.json", verifier["prompt_template_identity"])
        source_profile = {
            "schema": "A2_NORMATIVE_SOURCE_PROFILE_REFERENCE_V1",
            "authority_scope_id": auth.scope_id,
            "normative_source_profile_hash": NORMATIVE_SOURCE_PROFILE_HASH,
            "source_class_fact_type_registry_id": EXPECTED_SOURCE_REGISTRY_ID,
            "source_class_fact_type_registry_sha256": auth.source_registry_sha256,
            "historical_output_denylist_hash": HISTORICAL_OUTPUT_DENYLIST_HASH,
            "text_claim_fact_types": "PROHIBITED",
            "profile_status": "AUTHENTICATED_PROFILE_ONLY_NO_RUNTIME_FACT_EXTRACTION",
        }
        source_profile["source_profile_reference_id"] = canonical_object_id(source_profile, "source_profile_reference_id")
        _write_json(staging / "04_computational_contracts/NORMATIVE_SOURCE_PROFILE_REFERENCE.json", source_profile)
        manifest = build_execution_manifest(auth, ordering, isolation, primary, verifier, schemas)
        _write_json(staging / "current86_a2_execution_manifest.json", manifest)
        # Per-raw P0 substrate: preparation references only; no model, verifier, human, or ledger execution.
        by_raw = {item["raw_key"]: item for item in auth.candidate_registry["raw_candidate_sets"]}
        for raw in auth.raw_keys:
            safe = raw.replace("::", "__")
            candidate = _materialized_candidate_universe(auth, by_raw[raw], ordering)
            _write_json(staging / f"05_schemas/candidate_universes/{safe}.json", candidate)
            raw_unit = {
                "schema": "RAW_EXECUTION_UNIT_CONTRACT_V1", "raw_key": raw, "authority_scope_id": auth.scope_id,
                "execution_manifest_id": manifest["execution_manifest_id"], "raw_identity_hash": hash_declared_set("exact_current86_raw_set", [raw], ordering),
                "complete_candidate_universe_hash": candidate["complete_candidate_universe_hash"], "complete_candidate_relation_set_hash": candidate["complete_candidate_relation_set_hash"],
                "source_bundle_status": "FROZEN_REFERENCE_ONLY_NOT_RUNTIME_MATERIALIZED", "initial_current_state": "NOT_STARTED_FOR_ADJUDICATION", "p0_prepared": True, "adjudication_executed": False,
            }
            raw_unit["raw_execution_unit_id"] = canonical_object_id(raw_unit, "raw_execution_unit_id")
            _write_json(staging / f"05_schemas/execution_units/{safe}.json", raw_unit)
            source_bundle = {
                "schema": "SOURCE_FACT_BUNDLE_CONTRACT_V1", "raw_key": raw, "facts": [], "source_registry_id": EXPECTED_SOURCE_REGISTRY_ID,
                "normative_source_profile_hash": NORMATIVE_SOURCE_PROFILE_HASH, "source_bundle_status": "FROZEN_REFERENCE_ONLY_NOT_RUNTIME_MATERIALIZED",
                "authenticated_source_references": [
                    {"path": "00_lineage/source_registry/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json", "raw_file_sha256": auth.source_registry_sha256},
                    {"path": "00_lineage/candidate_r2/03_exact_current86_scope.json", "raw_file_sha256": sha256_file(auth.root / "FA1B2de_Current86_BSO_A2_Authority_Candidate_PROSPECTIVE_R2/03_exact_current86_scope.json")},
                ],
            }
            source_bundle["source_bundle_hash"] = canonical_object_id(source_bundle, "source_bundle_hash")
            _write_json(staging / f"05_schemas/source_fact_bundles/{safe}.json", source_bundle)
            candidate_hashes = sorted({item["candidate_scoring_id"] for item in by_raw[raw]["candidate_relations"]}, key=_bytewise)
            proposal_input = {
                "schema": "PROPOSAL_INPUT_BUNDLE_CONTRACT_V1", "authority_scope_id": auth.scope_id, "raw_key": raw,
                "active_authority_id": auth.candidate_id, "execution_manifest_id": manifest["execution_manifest_id"], "raw_identity_hash": hash_declared_set("exact_current86_raw_set", [raw], ordering),
                "raw_source_bundle_hash": source_bundle["source_bundle_hash"], "complete_candidate_universe_hash": candidate["complete_candidate_universe_hash"],
                "complete_candidate_relation_set_hash": candidate["complete_candidate_relation_set_hash"], "candidate_source_bundle_hashes": [_set_hash([raw, c]) for c in candidate_hashes],
                "admissible_source_fact_set_hash": hash_declared_set("normative_evidence_fact_set", [], ordering), "proposal_evidence_profile_hash": NORMATIVE_SOURCE_PROFILE_HASH,
                "source_class_fact_type_registry_id": EXPECTED_SOURCE_REGISTRY_ID, "historical_output_denylist_hash": HISTORICAL_OUTPUT_DENYLIST_HASH,
                "input_status": "FROZEN_PREPARATION_ONLY",
            }
            proposal_input["proposal_input_bundle_id"] = canonical_object_id(proposal_input, "proposal_input_bundle_id")
            _write_json(staging / f"05_schemas/proposal_input_bundles/{safe}.json", proposal_input)
        pilot = select_pilot_raw(auth.raw_keys, auth.scope_id)
        _write_json(staging / "06_pilot_selection_contract/a2_pilot_selection.json", pilot)
        _write_json(staging / "a2_pilot_selection.json", pilot)
        initial_chains = {}
        for raw in auth.raw_keys:
            record = {"schema": "A2_AUTHORITATIVE_DISPOSITION_RECORD_V2", "raw_key": raw, "disposition_type": "INITIAL_STATE", "prior_state": None, "next_state": "NOT_STARTED_FOR_ADJUDICATION", "disposition_sequence": 0, "prior_disposition_id": None, "referenced_attempt_id": None, "referenced_pending_terminal_id": None, "referenced_review_id": None, "referenced_accepted_terminal_id": None, "remediation_reference": None, "reason_class": None}
            record["disposition_id"] = canonical_object_id(record, "disposition_id")
            initial_chains[raw] = [record]
        partitions = reconstruct_partitions(auth.raw_keys, initial_chains)
        snapshot = {"schema": "CURRENT86_STATE_PARTITION_SNAPSHOT_V1", "exact_current86_raw_set_hash": _set_hash(list(auth.raw_keys)), **partitions, "pairwise_disjoint": True, "exhaustive_exact_current86": True}
        snapshot["state_partition_snapshot_id"] = canonical_object_id(snapshot, "state_partition_snapshot_id")
        _write_json(staging / "07_disposition_contract/current_state_partition_snapshot.json", snapshot)
        disposition_contract = {"schema": "A2_APPEND_ONLY_CURRENT_DISPOSITION_CONTRACT_V1", "current_state_derived_only_from": "UNIQUE_VALIDATED_CURRENT_AUTHORITATIVE_DISPOSITION_HEAD", "historical_row_existence_is_not_current_membership": True, "fork_duplicate_sequence_missing_parent_multiple_heads": "FAIL_CLOSED_GLOBAL_PAUSE", "transitions": ["PENDING_REVIEW -> PENDING_TERMINAL_INVALIDATED -> BLOCKED_ATTEMPT", "PENDING_REVIEW + reviewer/infrastructure failure -> PENDING_REVIEW + GLOBAL_PAUSE", "BLOCKED_ATTEMPT -> REMEDIATION_RESTARTED -> IN_PROGRESS_OR_INCOMPLETE", "PENDING_REVIEW -> TERMINAL_ACCEPTED -> ACCEPTED_TERMINAL"]}
        disposition_contract["disposition_contract_id"] = canonical_object_id(disposition_contract, "disposition_contract_id")
        _write_json(staging / "07_disposition_contract/APPEND_ONLY_CURRENT_DISPOSITION_CONTRACT.json", disposition_contract)
        normative_manifest = {"schema": "FINAL_FREEZE_NORMATIVE_MANIFEST_SCHEMA_V1", "schema_id": _schema_id(schemas, "final_freeze_normative_manifest"), "materialization_status": "SCHEMA_ONLY_NO_P4_FREEZE", "identity_field": "CURRENT86_A2_FINAL_FREEZE_ID", "identity_rule": "CANONICAL_OBJECT_ID(normative manifest, CURRENT86_A2_FINAL_FREEZE_ID)", "workload_excluded": True, "excluded_fields": ["workload_summary_hash", "decision_time_telemetry", "idle_interruption_telemetry", "ui_presentation_metrics", "performance_only_metrics", "human_packet_character_counts", "candidate_universe_expansion_telemetry", "other_NON_AUTHORITATIVE_WORKLOAD_EVIDENCE"], "identity_inputs": ["active authority", "exact Current86 scope", "execution contract", "set ordering registry", "current disposition heads", "accepted terminal ledger", "accepted terminal raw set", "owner/escalation terminal sets", "terminal lineage", "normative conservation snapshot"]}
        package_manifest = {"schema": "FINAL_FREEZE_PACKAGE_MANIFEST_SCHEMA_V1", "schema_id": _schema_id(schemas, "final_freeze_package_manifest"), "materialization_status": "SCHEMA_ONLY_NO_P4_FREEZE", "identity_field": "FINAL_FREEZE_PACKAGE_MANIFEST_ID", "identity_rule": "CANONICAL_OBJECT_ID(package manifest, FINAL_FREEZE_PACKAGE_MANIFEST_ID)", "includes_workload_files": True, "workload_summary": "MAY_BE_INCLUDED_NON_AUTHORITATIVE", "identity_excludes_from_normative_freeze": ["workload telemetry"], "normative_identity_reference": "CURRENT86_A2_FINAL_FREEZE_ID", "package_identity_may_change_when_workload_files_change": True}
        _write_json(staging / "08_p4_identity_separation_contract/FINAL_FREEZE_NORMATIVE_MANIFEST.schema.json", normative_manifest)
        _write_json(staging / "08_p4_identity_separation_contract/FINAL_FREEZE_PACKAGE_MANIFEST.schema.json", package_manifest)
        _copy_exact(auth.root / "tests/test_p0_p1_contract.py", staging / "09_tests/test_materialization_contract.py")
        _copy_exact(auth.root / "tests/test_r2_contract_fixes.py", staging / "09_tests/test_r2_contract_fixes.py")
        _copy_exact(auth.root / "tools/materialize_p0_p1_contract.py", staging / "00_lineage/implementation/tools/materialize_p0_p1_contract.py")
        for source_name in ("a2_role_runtime.py", "a2_bwrap_isolation.py", "run_a2_primary.py", "run_a2_verifier.py"):
            _copy_exact(auth.root / "tools" / source_name, staging / "00_lineage/implementation/tools" / source_name)
        _write_json(staging / "09_tests/STATIC_TEST_CATALOG.json", {
            "schema": "A2_P0_P1_IMPLEMENTATION_TEST_CATALOG_V1",
            "implementation_verification_only": True,
            "runtime_adjudication_executed": False,
            "tests": {
                "B1": "registry relation identity ordering, manifest recomputation, alternative tuple rejection, exact evidence identity, duplicate and unregistered set rejection",
                "B2": "actual role entrypoints, execution-time runtime binding, and bubblewrap common/private/commitment sentinel isolation",
                "B3": "human packet mapping, confirm/reject/not-sure actions, owner terminal paths, human/pre-human/alternative-failure escalations, technical defect exclusion",
                "B4": "self-contained RAW/CANDIDATE source facts, invalid/empty facts, disposition lineage requirements, remediation reference, stale pending exclusion",
                "NON_REGRESSION": "retained R1 canonicalization, authentication, disposition, pilot, P4 identity-separation, and no-execution tests",
            },
        })
        _write_json(staging / "09_tests/VERIFICATION_SCOPE.json", {"real_p1_adjudication_run": False, "primary_proposer_run": False, "independent_verifier_run": False, "independent_verifier_semantic_execution": False, "non_semantic_m2_sentinel_probe": True, "human_decision_capture": False, "ledger_append": False, "tests_are_static_contract_verification": True})
        summary_object = {
            "P0_P1_EXECUTION_CONTRACT_MATERIALIZATION": "COMPLETE_CONTRACT_ONLY", "INPUT_AUTHENTICATION": "PASS",
            "M1_SET_ORDERING_REGISTRY": "MATERIALIZED_AND_VERIFIED", "M2_VERIFIER_ISOLATION": "MATERIALIZED_AND_VERIFIED",
            "SET_ORDERING_REGISTRY_ID": ordering["set_ordering_registry_id"], "SET_ORDERING_REGISTRY_SHA256": sha256_file(staging / "02_set_ordering/SET_ORDERING_REGISTRY.json"),
            "VERIFIER_ISOLATION_ENFORCEMENT_ID": isolation["isolation_enforcement_id"], "VERIFIER_ISOLATION_ENFORCEMENT_SHA256": sha256_file(staging / "03_isolation/A2_VERIFIER_ISOLATION_ENFORCEMENT_CONTRACT.json"),
            "ISOLATION_ENFORCEMENT_ID": isolation["isolation_enforcement_id"],
            "PRIMARY_COMPUTATIONAL_CONTRACT_ID": primary["computational_contract_id"], "PRIMARY_COMPUTATIONAL_CONTRACT_SHA256": sha256_file(staging / "04_computational_contracts/PRIMARY_A2_COMPUTATIONAL_CONTRACT.json"),
            "VERIFIER_COMPUTATIONAL_CONTRACT_ID": verifier["computational_contract_id"], "VERIFIER_COMPUTATIONAL_CONTRACT_SHA256": sha256_file(staging / "04_computational_contracts/VERIFIER_A2_COMPUTATIONAL_CONTRACT.json"),
            "EXECUTION_MANIFEST_ID": manifest["execution_manifest_id"], "EXECUTION_MANIFEST_SHA256": sha256_file(staging / "current86_a2_execution_manifest.json"),
            "PILOT_RAW_KEY": pilot["pilot_raw_key"], "PILOT_SELECTION_ID": pilot["pilot_selection_id"], "PILOT_IS_REAL_A2_ADJUDICATION": "YES",
            "COMPLETE_CANDIDATE_UNIVERSE_PRESERVED": "YES", "HIDDEN_PRUNING": "PROHIBITED", "TOP_K_CANDIDATE_TRUNCATION": "PROHIBITED",
            "HUMAN_NORMATIVE_UNIT": "ONE_RAW", "NO_RELATION_LEVEL_MANUAL_OUTCOMES": "YES", "NO_MANUAL_EVIDENCE_ID_OR_HASH_COPYING": "YES",
            "RETURN_TO_4161_RELATION_EQ": "NO", "CONTINUE_OLD_44_RELATION_EQ_PILOT": "NO", "P4_FREEZE_DISTINCT_FROM_BINDING_PUBLICATION": "YES", "BSO_V_MUST_NOT_RE_ADJUDICATE_OWNER": "YES",
            "P0_EXECUTED": "NO", "P1_EXECUTED": "NO", "PRIMARY_PROPOSER_EXECUTED": "NO", "INDEPENDENT_VERIFIER_EXECUTED": "NO", "INDEPENDENT_VERIFIER_SEMANTIC_EXECUTION": "NO",
            "RAW_LEVEL_HUMAN_DECISIONS": 0, "OWNER_TERMINAL_RECORDS_CREATED": 0, "ESCALATION_TERMINAL_RECORDS_CREATED": 0,
            "BINDING_PUBLICATION": "NO", "BSO_V_EXECUTED": "NO", "BSO_P_EXECUTED": "NO",
            "P0_P1_EXECUTION_CONTRACT_R2_PATCH_STATUS": "COMPLETE_CONTRACT_ONLY",
            "R1_BYTE_PRESERVED": "YES",
            "B1_M1_UNIQUE_ORDERING": "CLOSED_BY_R2_MATERIALIZATION",
            "B2_EXECUTION_BOUND_RUNTIME_AND_M2": "CLOSED_BY_R2_MATERIALIZATION",
            "B3_HUMAN_AND_TERMINAL_SCHEMAS": "CLOSED_BY_R2_MATERIALIZATION",
            "B4_EVIDENCE_AND_DISPOSITION_ENFORCEMENT": "CLOSED_BY_R2_MATERIALIZATION",
            "NEXT_ACTION": "FRESH_TARGETED_INDEPENDENT_REVIEW_OF_FOUR_R1_TO_R2_CONTRACT_FIXES_ONLY",
        }
        _write_json(staging / "10_summary/SUMMARY.json", summary_object)
        auth_record = {"schema": "P0_P1_INPUT_AUTHENTICATION_RECORD_V1", "reviewed_design_sha256": auth.design_sha256, "active_authority_candidate_id": auth.candidate_id, "h2_provenance_evidence_id": auth.h2_evidence_id, "activation_transaction_id": auth.activation_transaction_id, "exact_current86_scope_id": auth.scope_id, "raw_count": CURRENT86_RAW_COUNT, "relation_count": CURRENT86_RELATION_COUNT, "hard_negative_count": CURRENT86_HARD_NEGATIVE_COUNT, "former_human_eq_relation_count": CURRENT86_FORMER_HUMAN_EQ_COUNT, "exact_scope_object_equality_v4": True, "exact_candidate_universe_equality": True, "candidate_manifest_sha256": auth.candidate_manifest_sha256, "candidate_checksums_sha256": auth.candidate_checksums_sha256, "v4_archive_sha256": auth.v4_archive_sha256, "source_registry_sha256": auth.source_registry_sha256, "active_authority_lineage_design_sha256_as_recorded_in_prior_activation": _load(auth.root / "FA1B2de_Current86_BSO_A2_Authority_Candidate_PROSPECTIVE_R2/11_supersession_lineage.json")["accepted_r2_design_sha256"], "authentication_status": "PASS"}
        auth_record["authentication_record_id"] = canonical_object_id(auth_record, "authentication_record_id")
        _write_json(staging / "00_lineage/authentication_record.json", auth_record)
        contract_manifest = {"schema": "A2_P0_P1_CONTRACT_MANIFEST_V1", "materialization_mode": "COMPLETE_CONTRACT_ONLY", "execution_manifest_id": manifest["execution_manifest_id"], "set_ordering_registry_id": ordering["set_ordering_registry_id"], "isolation_enforcement_id": isolation["isolation_enforcement_id"], "primary_computational_contract_id": primary["computational_contract_id"], "verifier_computational_contract_id": verifier["computational_contract_id"], "pilot_selection_id": pilot["pilot_selection_id"], "reviewed_design_sha256": auth.design_sha256, "p0_executed": "NO", "p1_executed": "NO", "p2_executed": "NO", "p3_executed": "NO", "p4_executed": "NO", "bso_v_executed": "NO", "bso_p_executed": "NO", "raw_level_human_decisions": 0, "binding_publication": "NO", "scoring_authority_mutation": "NO", "binding_authority_mutation": "NO", "accepted_binding_change": "NO", "denominator_change": "NO", "runtime_adjudication_artifacts_generated": False}
        contract_manifest["contract_manifest_id"] = canonical_object_id(contract_manifest, "contract_manifest_id")
        _write_json(staging / "CONTRACT_MANIFEST.json", contract_manifest)
        patch_summary = build_r1_to_r2_patch_summary(auth.root, staging)
        _write_json(staging / f"00_lineage/{R1_PATCH_SUMMARY_NAME}", patch_summary)
        summary_path = staging / "10_summary/SUMMARY.json"
        packaged_summary = _load(summary_path)
        packaged_summary["R2_PACKAGE_FILE_COUNT"] = sum(1 for path in staging.rglob("*") if path.is_file()) + 2
        _write_json(summary_path, packaged_summary)
        paths = sorted(path.relative_to(staging).as_posix() for path in staging.rglob("*") if path.is_file())
        paths.extend(["FILE_LIST.txt", "SHA256SUMS.txt"])
        paths = sorted(set(paths), key=_bytewise)
        (staging / "FILE_LIST.txt").write_text("\n".join(paths) + "\n", encoding="utf-8")
        checksum_paths = [path for path in paths if path != "SHA256SUMS.txt"]
        (staging / "SHA256SUMS.txt").write_text("\n".join(f"{sha256_file(staging / path)}  {path}" for path in checksum_paths) + "\n", encoding="utf-8")
        staging.rename(output_dir)
    verify_package(output_dir)
    verify_r1_byte_preservation(root)
    summary = json.loads((output_dir / "10_summary/SUMMARY.json").read_text(encoding="utf-8"))
    archive_path = output_dir.parent / R2_HANDOFF_NAME
    if archive_path.exists():
        raise ValueError(f"refusing to overwrite handoff archive: {archive_path}")
    with archive_path.open("wb") as raw_file:
        with gzip.GzipFile(fileobj=raw_file, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for path in sorted(output_dir.rglob("*"), key=lambda item: item.relative_to(output_dir).as_posix().encode("utf-8")):
                    if not path.is_file():
                        continue
                    relative = path.relative_to(output_dir).as_posix()
                    info = tarfile.TarInfo(f"{output_dir.name}/{relative}")
                    data = path.read_bytes()
                    info.size = len(data); info.mode = 0o644; info.mtime = 0; info.uid = 0; info.gid = 0; info.uname = ""; info.gname = ""
                    archive.addfile(info, __import__("io").BytesIO(data))
    summary["REVIEW_HANDOFF_ARCHIVE_SHA256"] = sha256_file(archive_path)
    if output_dir.parent == Path(root).resolve() and output_dir.name == R2_PACKAGE_DIR_NAME:
        _copy_exact(output_dir / f"00_lineage/{R1_PATCH_SUMMARY_NAME}", Path(root) / R1_PATCH_SUMMARY_NAME)
        _copy_exact(output_dir / f"00_lineage/{TDD_LOG_NAME}", Path(root) / TDD_LOG_NAME)
    return summary


def verify_package(output_dir: Path) -> None:
    output_dir = Path(output_dir)
    required = ["CONTRACT_MANIFEST.json", "FILE_LIST.txt", "SHA256SUMS.txt", "current86_a2_execution_manifest.json", "02_set_ordering/SET_ORDERING_REGISTRY.json", "03_isolation/A2_VERIFIER_ISOLATION_ENFORCEMENT_CONTRACT.json", "05_schemas/schema_registry.json", "06_pilot_selection_contract/a2_pilot_selection.json", "07_disposition_contract/current_state_partition_snapshot.json", "08_p4_identity_separation_contract/FINAL_FREEZE_NORMATIVE_MANIFEST.schema.json", "08_p4_identity_separation_contract/FINAL_FREEZE_PACKAGE_MANIFEST.schema.json"]
    for relative in required:
        if not (output_dir / relative).is_file():
            raise ValueError(f"missing required package file: {relative}")
    listed = [line for line in (output_dir / "FILE_LIST.txt").read_text(encoding="utf-8").splitlines() if line]
    actual = sorted(path.relative_to(output_dir).as_posix() for path in output_dir.rglob("*") if path.is_file())
    if listed != sorted(actual, key=_bytewise):
        raise ValueError("FILE_LIST is not exact")
    checks = (output_dir / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
    if {line.split("  ", 1)[1] for line in checks} != set(actual) - {"SHA256SUMS.txt"}:
        raise ValueError("SHA256SUMS inventory is not exact")
    for line in checks:
        digest, relative = line.split("  ", 1)
        if sha256_file(output_dir / relative) != digest:
            raise ValueError(f"package checksum mismatch: {relative}")
    ordering = _load(output_dir / "02_set_ordering/SET_ORDERING_REGISTRY.json")
    if ordering["set_ordering_registry_id"] != canonical_object_id(ordering, "set_ordering_registry_id"):
        raise ValueError("M1 registry ID mismatch")
    relation_entry = _registry_entry(ordering, "relation_set")
    if relation_entry.get("element_identity_field_or_tuple") != "relation_identity" or relation_entry.get("comparison_rule") != "BYTEWISE_ASCENDING_UTF8":
        raise ValueError("M1 relation ordering is not the unique identity ordering")
    evidence_entry = _registry_entry(ordering, "normative_evidence_fact_set")
    if evidence_entry.get("element_identity_field_or_tuple") != "source_fact_id":
        raise ValueError("normative evidence identity field is not source_fact_id")
    isolation = _load(output_dir / "03_isolation/A2_VERIFIER_ISOLATION_ENFORCEMENT_CONTRACT.json")
    validate_isolation_contract(isolation)
    manifest = _load(output_dir / "current86_a2_execution_manifest.json")
    if manifest["execution_manifest_id"] != canonical_object_id(manifest, "execution_manifest_id"):
        raise ValueError("execution manifest ID mismatch")
    flags = {"p0_executed": "NO", "p1_executed": "NO", "primary_proposer_executed": "NO", "independent_verifier_executed": "NO", "raw_level_human_decisions": 0, "binding_publication": "NO"}
    if any(manifest.get(key) != value for key, value in flags.items()):
        raise ValueError("execution manifest violates no-execution boundary")
    pilot = _load(output_dir / "06_pilot_selection_contract/a2_pilot_selection.json")
    if pilot["pilot_selection_id"] != canonical_object_id(pilot, "pilot_selection_id") or pilot["pilot_raw_key"] != "6000002::S02::A001" or pilot.get("pilot_is_real_a2_adjudication") != "YES":
        raise ValueError("pilot selection is not deterministic minimum")
    schema_registry = _load(output_dir / "05_schemas/schema_registry.json")
    if schema_registry["schema_registry_id"] != canonical_object_id(schema_registry, "schema_registry_id"):
        raise ValueError("schema registry ID mismatch")
    for schema_name, schema in schema_registry.get("schemas", {}).items():
        validate_schema_instance_schema(schema_name, schema)
    manifest_relations = _load(output_dir / "00_lineage/candidate_r2/03_exact_current86_scope.json")["relation_membership"]
    if manifest["exact_current86_relation_set_hash"] != hash_declared_set("relation_set", manifest_relations, ordering):
        raise ValueError("execution manifest relation set hash does not recompute under M1 registry")
    for relative, role, expected_entrypoint in (
        ("04_computational_contracts/PRIMARY_A2_COMPUTATIONAL_CONTRACT.json", "PRIMARY", "tools/run_a2_primary.py"),
        ("04_computational_contracts/VERIFIER_A2_COMPUTATIONAL_CONTRACT.json", "VERIFIER", "tools/run_a2_verifier.py"),
    ):
        role_contract = _load(output_dir / relative)
        if role_contract.get("role") != role or role_contract.get("static_execution_implementation_identity", {}).get("entrypoint") != expected_entrypoint:
            raise ValueError("computational contract is not bound to actual role runtime")
        if role_contract.get("model_runtime_identity", {}).get("tool_mode") != f"A2_{role}_ROLE_RUNTIME":
            raise ValueError("computational contract tool mode is not the intended role")
        if role_contract.get("isolation_launcher_sha256") != isolation.get("isolation_launcher_identity", {}).get("launcher_sha256"):
            raise ValueError("computational contract does not pin isolation launcher")
    normative_p4 = _load(output_dir / "08_p4_identity_separation_contract/FINAL_FREEZE_NORMATIVE_MANIFEST.schema.json")
    package_p4 = _load(output_dir / "08_p4_identity_separation_contract/FINAL_FREEZE_PACKAGE_MANIFEST.schema.json")
    if normative_p4.get("materialization_status") != "SCHEMA_ONLY_NO_P4_FREEZE" or "CURRENT86_A2_FINAL_FREEZE_ID" in normative_p4:
        raise ValueError("an actual P4 normative freeze ID was materialized")
    if package_p4.get("materialization_status") != "SCHEMA_ONLY_NO_P4_FREEZE" or "FINAL_FREEZE_PACKAGE_MANIFEST_ID" in package_p4:
        raise ValueError("an actual P4 package freeze ID was materialized")
    forbidden = {"execution_attempt_ledger.jsonl", "pending_terminal_ledger.jsonl", "accepted_terminal_ledger.jsonl", "human_decision_record.jsonl"}
    if forbidden & {path.name for path in output_dir.rglob("*") if path.is_file()}:
        raise ValueError("runtime adjudication ledger artifact was generated")
    if list(output_dir.rglob("*.jsonl")):
        raise ValueError("runtime JSONL adjudication artifact was generated")
    contract_manifest = _load(output_dir / "CONTRACT_MANIFEST.json")
    if contract_manifest["contract_manifest_id"] != canonical_object_id(contract_manifest, "contract_manifest_id"):
        raise ValueError("contract manifest ID mismatch")
    if contract_manifest["runtime_adjudication_artifacts_generated"] is not False:
        raise ValueError("contract manifest claims runtime artifacts")
    for relative in (f"00_lineage/{R1_PATCH_SUMMARY_NAME}", f"00_lineage/{TDD_LOG_NAME}", "tools/a2_role_runtime.py", "tools/a2_bwrap_isolation.py", "tools/run_a2_primary.py", "tools/run_a2_verifier.py", "09_tests/test_r2_contract_fixes.py"):
        if not (output_dir / relative).is_file():
            raise ValueError(f"R2 self-contained review input is missing: {relative}")


def validate_schema_instance_schema(name: str, schema: dict[str, Any]) -> bool:
    try:
        import jsonschema
        jsonschema.Draft202012Validator.check_schema(schema)
    except ImportError as exc:
        raise ValueError("jsonschema runtime is required for package schema verification") from exc
    except jsonschema.exceptions.SchemaError as exc:
        raise ValueError(f"invalid package schema {name}: {exc.message}") from exc
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["materialize", "verify"])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "materialize":
            summary = materialize(args.root, args.output_dir)
            print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            verify_package(args.output_dir)
            print("PASS")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"FAIL_CLOSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
