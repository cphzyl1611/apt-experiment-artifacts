#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

AUDIT_SCOPE_ID = "34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306"
TARGET_MANIFEST_SHA256 = "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac"
SCALAR_FORMAT_ID = "FA1B2DE_CANONICAL_INTRINSIC_SCALAR_V1"


class ContractError(ValueError):
    pass


def fail(code: str, detail: str = "") -> None:
    raise ContractError(code + ((": " + detail) if detail else ""))


def strict_text(value: Any) -> str:
    if not isinstance(value, str):
        fail("WRONG_TYPE", "expected string")
    try:
        value.encode("utf-8", "strict")
    except UnicodeError as exc:
        fail("INVALID_UNICODE_SCALAR", str(exc))
    return value


def _canonical(value: Any) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if type(value) is int:
        return str(value).encode("ascii")
    if isinstance(value, float):
        fail("FLOAT_FORBIDDEN")
    if isinstance(value, str):
        strict_text(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(_canonical(item) for item in value) + b"]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            fail("NON_STRING_JSON_KEY")
        keys = sorted(value, key=lambda key: strict_text(key).encode("utf-8"))
        return b"{" + b",".join(_canonical(key) + b":" + _canonical(value[key]) for key in keys) + b"}"
    fail("UNSUPPORTED_JSON_TYPE", type(value).__name__)


def canonical_json_bytes(value: Any) -> bytes:
    return _canonical(value)


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def self_excluding_id(record: Mapping[str, Any], field: str) -> str:
    return sha256_hex(canonical_json_bytes({key: value for key, value in record.items() if key != field}))


def pointer_sha256(pointer: str) -> str:
    return sha256_hex(strict_text(pointer).encode("utf-8"))


def admission_tuple_basis(record: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "candidate_object_id",
        "canonical_intrinsic_field_semantics_id",
        "exact_RFC6901_pointer",
        "source_binding_target_id",
    )
    if any(field not in record for field in fields):
        fail("MISSING_ADMISSION_TUPLE_COMPONENT")
    return {field: record[field] for field in fields}


def admission_tuple_id(record: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(admission_tuple_basis(record)))


def canonical_scalar(value: Any) -> tuple[str, bytes]:
    if value is None:
        tag, payload = "null", b""
    elif value is True:
        tag, payload = "boolean", b"true"
    elif value is False:
        tag, payload = "boolean", b"false"
    elif type(value) is int:
        tag, payload = "integer", str(value).encode("ascii")
    elif isinstance(value, str):
        tag, payload = "string", strict_text(value).encode("utf-8")
    elif isinstance(value, float):
        fail("FLOAT_FORBIDDEN")
    elif isinstance(value, (dict, list)):
        fail("COMPOSITE_TERMINAL_FORBIDDEN")
    else:
        fail("SCALAR_TYPE_FORBIDDEN")
    envelope = SCALAR_FORMAT_ID.encode("ascii") + b"\x00" + tag.encode("ascii") + b"\x00" + str(len(payload)).encode("ascii") + b"\x00" + payload
    return tag, envelope


def authenticated_value_sha256(value: Any) -> str:
    return sha256_hex(canonical_scalar(value)[1])


def require_sha256(value: Any, field: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        fail("INVALID_SHA256", field)
