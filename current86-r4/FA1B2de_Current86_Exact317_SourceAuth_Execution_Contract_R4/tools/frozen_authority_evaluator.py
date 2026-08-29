from __future__ import annotations

import json
import re
from typing import Any

from .canonical import ContractError, canonical_json_bytes, sha256_hex


R4_EVALUATOR_CONFIGURATION_ID = "FA1B2DE_MACHINE_AUTHORITY_EVALUATOR_CONFIG_R4"

# Dispatch is deliberately keyed by both authenticated role and artifact
# schema.  There is no generic content-based or parse-failure fallback.
_TUPLE_FIELDS = frozenset(
    {"source_binding_target_id", "candidate_object_id", "canonical_intrinsic_field_semantics_id", "exact_RFC6901_pointer"}
)
SUPPORTED_AUTHORITY_DISPATCH: dict[tuple[str, str], frozenset[str]] = {
    (role, "synthetic-schema-r2"): _TUPLE_FIELDS
    for role in (
        "EXACT_TARGET_POINTER_AUTHORITY",
        "FIELD_PIN_REGISTRY",
        "DETERMINISTIC_CORPUS_SCHEMA_FIELD_PIN_RULE",
    )
}

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ContractError("NONFINITE_JSON_VALUE")


def _parse(raw: bytes) -> Any:
    if not isinstance(raw, bytes):
        raise ContractError("AUTHORITY_BYTES_REQUIRED")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ContractError("INVALID_UTF8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ContractError("INVALID_JSON") from exc


def _validate_tuple(item: Any, expected_fields: frozenset[str]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ContractError("AUTHORITY_TUPLE_NOT_OBJECT")
    if set(item) != set(expected_fields):
        raise ContractError("AUTHORITY_TUPLE_SCHEMA_INVALID")
    for field in ("source_binding_target_id", "candidate_object_id", "canonical_intrinsic_field_semantics_id"):
        value = item[field]
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise ContractError("AUTHORITY_TUPLE_SCHEMA_INVALID")
    pointer = item["exact_RFC6901_pointer"]
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ContractError("AUTHORITY_TUPLE_SCHEMA_INVALID")
    return item


def evaluate_authority_bytes(
    raw: bytes,
    authority_role: str | None = None,
    schema_or_contract_id: str | None = None,
    evaluator_configuration_id: str | None = None,
) -> list[dict[str, Any]]:
    """Parse and deterministically enumerate one authenticated authority artifact."""
    if not isinstance(authority_role, str) or not isinstance(schema_or_contract_id, str):
        raise ContractError("AUTHORITY_DISPATCH_METADATA_REQUIRED")
    if evaluator_configuration_id != R4_EVALUATOR_CONFIGURATION_ID:
        raise ContractError("UNSUPPORTED_EVALUATOR_CONFIGURATION")
    expected_fields = SUPPORTED_AUTHORITY_DISPATCH.get((authority_role, schema_or_contract_id))
    if expected_fields is None:
        raise ContractError("UNSUPPORTED_AUTHORITY_ROLE_OR_SCHEMA")
    parsed = _parse(raw)
    if not isinstance(parsed, list):
        raise ContractError("AUTHORITY_TOP_LEVEL_NOT_LIST")
    tuples = [_validate_tuple(item, expected_fields) for item in parsed]
    return sorted(tuples, key=lambda item: sha256_hex(canonical_json_bytes(item)).encode("utf-8"))
