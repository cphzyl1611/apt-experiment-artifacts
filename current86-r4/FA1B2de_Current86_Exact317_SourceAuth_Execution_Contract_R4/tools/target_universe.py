from __future__ import annotations

import json
import re
from pathlib import Path

from .canonical import ContractError, canonical_json_bytes, sha256_hex


TARGET_MANIFEST_SHA256 = "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac"
AUDIT_SCOPE_ID = "34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306"
TARGET_COUNT = 317
RAW_TARGET_COUNT = 86
CANDIDATE_TARGET_COUNT = 231
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MANIFEST_PATH = Path(__file__).resolve().parents[1] / "00_lineage" / "EXACT317_TARGET_MANIFEST.json"


def _load_manifest() -> dict[str, object]:
    try:
        raw = _MANIFEST_PATH.read_bytes()
    except OSError as exc:
        raise ContractError("FROZEN_EXACT317_TARGET_MANIFEST_UNAVAILABLE") from exc
    if sha256_hex(raw) != TARGET_MANIFEST_SHA256:
        raise ContractError("FROZEN_EXACT317_TARGET_MANIFEST_IDENTITY_MISMATCH")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("FROZEN_EXACT317_TARGET_MANIFEST_INVALID") from exc
    if not isinstance(manifest, dict) or manifest.get("audit_scope_id") != AUDIT_SCOPE_ID:
        raise ContractError("FROZEN_EXACT317_TARGET_MANIFEST_INVALID")
    if manifest.get("totals") != {"EXACT_TARGET_TOTAL": TARGET_COUNT, "RAW_SIDE_TOTAL": RAW_TARGET_COUNT, "CANDIDATE_SIDE_TOTAL": CANDIDATE_TARGET_COUNT}:
        raise ContractError("FROZEN_EXACT317_TARGET_COUNTS_MISMATCH")
    targets = manifest.get("targets")
    if not isinstance(targets, list) or len(targets) != TARGET_COUNT:
        raise ContractError("FROZEN_EXACT317_TARGET_COUNT_MISMATCH")
    ids: list[str] = []
    previous_key: tuple[int, bytes] | None = None
    for expected_index, target in enumerate(targets, 1):
        if not isinstance(target, dict) or target.get("target_index") != expected_index:
            raise ContractError("FROZEN_EXACT317_TARGET_ORDER_INVALID")
        target_id = target.get("source_binding_target_id")
        if not isinstance(target_id, str) or not _SHA256.fullmatch(target_id):
            raise ContractError("FROZEN_EXACT317_TARGET_ID_INVALID")
        side = target.get("source_side")
        if side not in ("RAW", "CANDIDATE"):
            raise ContractError("FROZEN_EXACT317_TARGET_SIDE_INVALID")
        bound_raw = target.get("bound_raw_key")
        bound_candidate = target.get("bound_candidate_scoring_id")
        if side == "RAW":
            if not isinstance(bound_raw, str) or bound_candidate is not None:
                raise ContractError("FROZEN_EXACT317_TARGET_BINDING_INVALID")
            identity = bound_raw
            side_rank = 0
        else:
            if bound_raw is not None or not isinstance(bound_candidate, str):
                raise ContractError("FROZEN_EXACT317_TARGET_BINDING_INVALID")
            identity = bound_candidate
            side_rank = 1
        ordering_key = (side_rank, identity.encode("utf-8"))
        if previous_key is not None and ordering_key < previous_key:
            raise ContractError("FROZEN_EXACT317_TARGET_ORDER_INVALID")
        previous_key = ordering_key
        basis = {
            "audit_scope_id": AUDIT_SCOPE_ID,
            "bound_candidate_scoring_id": bound_candidate,
            "bound_raw_key": bound_raw,
            "source_artifact_class": target.get("source_artifact_class"),
            "source_fact_type": target.get("required_source_fact_type"),
            "source_side": side,
        }
        if sha256_hex(canonical_json_bytes(basis)) != target_id:
            raise ContractError("FROZEN_EXACT317_TARGET_ID_INVALID")
        ids.append(target_id)
    if len(set(ids)) != TARGET_COUNT:
        raise ContractError("FROZEN_EXACT317_TARGET_DUPLICATE")
    if sum(target.get("source_side") == "RAW" for target in targets) != RAW_TARGET_COUNT:
        raise ContractError("FROZEN_EXACT317_RAW_COUNT_MISMATCH")
    if sum(target.get("source_side") == "CANDIDATE" for target in targets) != CANDIDATE_TARGET_COUNT:
        raise ContractError("FROZEN_EXACT317_CANDIDATE_COUNT_MISMATCH")
    return manifest


def frozen_exact317_target_ids() -> tuple[str, ...]:
    manifest = _load_manifest()
    return tuple(target["source_binding_target_id"] for target in manifest["targets"])


def frozen_exact317_target_set_commitment() -> str:
    return sha256_hex(canonical_json_bytes(list(frozen_exact317_target_ids())))
