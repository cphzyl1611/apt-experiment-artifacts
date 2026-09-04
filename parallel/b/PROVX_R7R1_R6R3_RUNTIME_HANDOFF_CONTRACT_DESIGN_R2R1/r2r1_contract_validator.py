"""Pure, read-only validation helpers for the R6R3 handoff R2R1 design.

The module validates a proposed handoff and inert negative fixtures. It never
starts a producer, runs privileged commands, creates runtime evidence, or
modifies the source repository supplied for lineage checks.
"""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import json
import math
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from jsonschema import Draft202012Validator


PACKAGE = Path(__file__).resolve().parent
REGISTRY_PATH = PACKAGE / "R6R3_RUNTIME_HANDOFF_OPERATOR_SEMANTICS_R2R1.json"
RULES_PATH = PACKAGE / "R6R3_RUNTIME_HANDOFF_AUTHENTICATION_RULES_R2R1.json"
SCHEMA_PATH = PACKAGE / "R6R3_RUNTIME_HANDOFF_SCHEMA_R2R1.json"
REQUIRED_BINDINGS_PATH = PACKAGE / "R6R3_REQUIRED_ARTIFACT_PATH_BINDINGS_R2R1.json"
CONTENT_SCHEMAS_PATH = PACKAGE / "R6R3_RUNTIME_ARTIFACT_CONTENT_SCHEMAS_R2R1.json"
RECEIPT_SCHEMA_PATH = PACKAGE / "R6R3_PRIVILEGED_EXECUTION_RECEIPT_SCHEMA_R2R1.json"
JOIN_CONTRACT_PATH = PACKAGE / "R6R3_JOIN_IDENTITY_AND_ROUNDTRIP_CONTRACT_R2R1.json"
CLEANUP_CONTRACT_PATH = PACKAGE / "R6R3_CLEANUP_RECOMPUTATION_CONTRACT_R2R1.json"

EXPECTED_RULE_IDS = [
    "H001_PACKAGE_SHAPE_AND_SCHEMA",
    "H002_MANIFEST_CANONICAL_HASH",
    "H003_MANIFEST_ENTRY_UNIQUENESS_AND_COMPLETENESS",
    "H004_EXACT_PATH_AND_FILE_HASH_BINDING",
    "H005_SOURCE_COMMIT_AND_CONTRACT_LINEAGE",
    "H006_EXPLICIT_PRIVILEGED_EXECUTION",
    "H007_RUN_ID_CLOSURE",
    "H008_RAW_RECORD_INTEGRITY",
    "H009_NORMALIZED_RECORD_INTEGRITY",
    "H010_RAW_NORMALIZED_SAME_SERIAL_AND_BYTE_LINK",
    "H011_FILE_READ_OR_WRITE_STRICT_EVIDENCE",
    "H012_PID_START_TICKS_NETNS_LOGICAL_HOST_JOIN",
    "H013_EVENT_CLASS_COVERAGE_AND_LOSS_CLOSURE",
    "H014_PCAP_AUTHENTICATION",
    "H015_CLEANUP_INVERSE_RULE_AND_BASELINE_RESTORATION",
    "H016_HARD_BOUNDARIES",
    "H017_FINAL_CANONICAL_RECHECK",
]
JOIN_KEY_FIELDS = (
    "run_id",
    "logical_host_id",
    "pid",
    "pid_start_time_ticks",
    "netns_inode",
    "role",
)
CLEANUP_ARTIFACT_IDS = {
    "r6_audit_pre_state",
    "r6_rule_remediation_journal",
    "r6_transient_rule_contract",
    "r6_residual_remediation",
    "r6_post_cleanup",
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ContractError(ValueError):
    """A deterministic fail-closed contract error."""

    def __init__(self, code: str, detail: str | None = None):
        self.code = code
        super().__init__(f"{code}{': ' + detail if detail else ''}")


def _reject_constant(value: str) -> None:
    raise ContractError("NONFINITE_JSON_NUMBER", value)


def _reject_duplicate_key(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("DUPLICATE_JSON_KEY", key)
        result[key] = value
    return result


def _reject_nonfinite(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        raise ContractError("NONFINITE_JSON_NUMBER")
    if isinstance(value, list):
        return [_reject_nonfinite(item) for item in value]
    if isinstance(value, dict):
        return {key: _reject_nonfinite(item) for key, item in value.items()}
    return value


def _parse_json_bytes_strict(data: bytes, *, object_required: bool = False) -> Any:
    if data.startswith(b"\xef\xbb\xbf"):
        raise ContractError("JSON_BOM")
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_key,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("MALFORMED_JSON", str(exc)) from exc
    value = _reject_nonfinite(value)
    if object_required and not isinstance(value, dict):
        raise ContractError("MALFORMED_JSON", "root is not an object")
    return value


def load_json_strict(path: str | os.PathLike[str]) -> Any:
    """Read one UTF-8 JSON value with duplicate-key and finite-number checks."""

    try:
        return _parse_json_bytes_strict(Path(path).read_bytes())
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError("MALFORMED_JSON", str(exc)) from exc


def _parse_jsonl_bytes_strict(data: bytes) -> list[dict[str, Any]]:
    if data.startswith(b"\xef\xbb\xbf") or b"\r" in data:
        raise ContractError("MALFORMED_JSONL", "BOM and CR bytes are not allowed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("MALFORMED_JSONL", str(exc)) from exc

    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or any(not line.strip() for line in lines):
        raise ContractError("MALFORMED_JSONL", "blank record")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        try:
            row = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_key,
                parse_constant=_reject_constant,
            )
            row = _reject_nonfinite(row)
        except ContractError as exc:
            raise ContractError(exc.code, f"line {line_number}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ContractError("MALFORMED_JSONL", f"line {line_number}: {exc}") from exc
        if not isinstance(row, dict):
            raise ContractError("MALFORMED_JSONL", f"line {line_number} is not an object")
        rows.append(row)
    return rows


def load_jsonl_strict(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Read JSONL as exact LF-delimited object records."""

    try:
        return _parse_jsonl_bytes_strict(Path(path).read_bytes())
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError("MALFORMED_JSONL", str(exc)) from exc


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize according to the R2R1 canonical JSON profile."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContractError("CANONICAL_JSON_FAILURE", str(exc)) from exc


def _require_object(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(code)
    return value


def _schema_errors(schema: dict[str, Any], instance: Any) -> list[str]:
    return sorted(error.message for error in Draft202012Validator(schema).iter_errors(instance))


def _load_documents() -> dict[str, dict[str, Any]]:
    paths = {
        "registry": REGISTRY_PATH,
        "rules": RULES_PATH,
        "handoff": SCHEMA_PATH,
        "bindings": REQUIRED_BINDINGS_PATH,
        "content": CONTENT_SCHEMAS_PATH,
        "receipt": RECEIPT_SCHEMA_PATH,
        "join": JOIN_CONTRACT_PATH,
        "cleanup": CLEANUP_CONTRACT_PATH,
    }
    return {name: _require_object(load_json_strict(path), "CONTRACT_DOCUMENT_SHAPE") for name, path in paths.items()}


def _operator_ids(registry: dict[str, Any] | None = None) -> set[str]:
    registry = registry or _load_documents()["registry"]
    operators = registry.get("operators")
    if not isinstance(operators, list) or not operators:
        raise ContractError("OPERATOR_REGISTRY_SHAPE")
    ids: list[str] = []
    for operator in operators:
        if not isinstance(operator, dict) or not isinstance(operator.get("operator_id"), str):
            raise ContractError("OPERATOR_REGISTRY_SHAPE")
        ids.append(operator["operator_id"])
    if len(ids) != len(set(ids)):
        raise ContractError("DUPLICATE_OPERATOR_DEFINITION")
    return set(ids)


def _binding_configuration() -> tuple[list[str], dict[str, str], dict[str, str], dict[str, Any]]:
    document = _load_documents()["bindings"]
    ids = document.get("required_artifact_ids")
    roles = document.get("artifact_roles")
    schemas = document.get("parsed_artifact_schemas")
    if (
        not isinstance(ids, list)
        or len(ids) != 20
        or len(ids) != len(set(ids))
        or any(not isinstance(item, str) for item in ids)
        or not isinstance(roles, dict)
        or not isinstance(schemas, dict)
        or set(roles) != set(ids)
        or set(schemas) != set(ids)
        or any(not isinstance(value, str) or not value for value in roles.values())
        or any(not isinstance(value, str) or not value for value in schemas.values())
    ):
        raise ContractError("REQUIRED_ARTIFACT_REGISTRY_INVALID")
    return ids, roles, schemas, document


def _required_ids() -> list[str]:
    return _binding_configuration()[0]


def _normalize_schema_ref(reference: str) -> str:
    if "#/$defs/" in reference:
        return "#/$defs/" + reference.split("#/$defs/", 1)[1]
    return reference


def validate_operator_references() -> dict[str, Any]:
    """Require every declared operator application to resolve in the registry."""

    documents = _load_documents()
    known = _operator_ids(documents["registry"])
    rules = documents["rules"].get("rules")
    if not isinstance(rules, list):
        raise ContractError("RULE_INVENTORY_SHAPE")
    references: list[str] = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise ContractError("RULE_INVENTORY_SHAPE")
        applications = rule.get("operator_applications")
        if not isinstance(applications, list) or not applications:
            raise ContractError("OPERATOR_APPLICATION_SHAPE")
        for application in applications:
            if not isinstance(application, dict):
                raise ContractError("OPERATOR_APPLICATION_SHAPE")
            operator_id = application.get("operator_id")
            if (
                not isinstance(operator_id, str)
                or not isinstance(application.get("subject"), str)
                or not application["subject"]
                or not isinstance(application.get("expected"), str)
                or not application["expected"]
            ):
                raise ContractError("OPERATOR_APPLICATION_SHAPE")
            if operator_id not in known:
                raise ContractError("UNKNOWN_OPERATOR", operator_id)
            references.append(operator_id)
    return {
        "status": "PASS",
        "referenced_operator_ids": references,
        "known_operator_count": len(known),
    }


def validate_operator_registry_and_rules() -> dict[str, Any]:
    """Validate complete operator semantics and all application references."""

    documents = _load_documents()
    registry = documents["registry"]
    required_fields = {
        "operator_id",
        "input_shape",
        "evaluation_procedure",
        "canonicalization",
        "success_condition",
        "failure_disposition",
        "ambiguity_behavior",
        "duplicate_handling",
        "ordering_semantics",
        "error_propagation",
    }
    for operator in registry.get("operators", []):
        if (
            not isinstance(operator, dict)
            or required_fields - set(operator)
            or not isinstance(operator.get("evaluation_procedure"), list)
            or not operator["evaluation_procedure"]
            or any(not isinstance(operator.get(field), str) or not operator[field] for field in required_fields - {"evaluation_procedure"})
        ):
            raise ContractError("OPERATOR_SEMANTICS_INCOMPLETE")
    return validate_operator_references()


def validate_contract_static() -> dict[str, Any]:
    """Validate schemas, cross-file bindings, registry uniqueness, and rule order."""

    documents = _load_documents()
    schema_names: list[str] = []
    for path in sorted(PACKAGE.glob("*.json")):
        document = _require_object(load_json_strict(path), "CONTRACT_DOCUMENT_SHAPE")
        if "$schema" in document:
            try:
                Draft202012Validator.check_schema(document)
            except Exception as exc:
                raise ContractError("SCHEMA_META_VALIDATION_FAILED", f"{path.name}: {exc}") from exc
            schema_names.append(path.name)

    operator_result = validate_operator_registry_and_rules()
    rules = documents["rules"].get("rules")
    if not isinstance(rules, list):
        raise ContractError("RULE_INVENTORY_SHAPE")
    rule_ids = [rule.get("rule_id") if isinstance(rule, dict) else None for rule in rules]
    if rule_ids != EXPECTED_RULE_IDS or len(rule_ids) != len(set(rule_ids)):
        raise ContractError("RULE_ORDER_OR_COVERAGE_INVALID")
    for rule in rules:
        if (
            not isinstance(rule, dict)
            or rule.get("severity") != "BLOCK"
            or not isinstance(rule.get("failure_code"), str)
            or not rule["failure_code"]
            or not isinstance(rule.get("requirement"), str)
            or not rule["requirement"]
        ):
            raise ContractError("RULE_INVENTORY_SHAPE")

    required_ids, roles, schema_refs, binding_document = _binding_configuration()
    binding_schema = binding_document.get("binding_map_schema")
    if not isinstance(binding_schema, dict) or binding_schema.get("required") != required_ids:
        raise ContractError("REQUIRED_ARTIFACT_REGISTRY_INVALID")
    binding_definition = binding_document.get("$defs", {}).get("binding")
    if not isinstance(binding_definition, dict) or "content_schema" not in binding_definition.get("required", []):
        raise ContractError("ARTIFACT_CONTENT_SCHEMA_UNBOUND")

    handoff = documents["handoff"]
    selected = handoff.get("$defs", {}).get("selectedInputs", {})
    path_bindings = selected.get("properties", {}).get("path_bindings", {}) if isinstance(selected, dict) else {}
    if not isinstance(path_bindings, dict) or path_bindings.get("required") != required_ids:
        raise ContractError("REQUIRED_ARTIFACT_REGISTRY_INVALID")
    handoff_binding = handoff.get("$defs", {}).get("artifactBinding", {})
    if not isinstance(handoff_binding, dict) or "content_schema" not in handoff_binding.get("required", []):
        raise ContractError("ARTIFACT_CONTENT_SCHEMA_UNBOUND")

    content = documents["content"]
    content_refs = content.get("artifact_schema_refs")
    if not isinstance(content_refs, dict) or set(content_refs) != set(required_ids):
        raise ContractError("ARTIFACT_CONTENT_SCHEMA_UNBOUND")
    for artifact_id in required_ids:
        configured = _normalize_schema_ref(schema_refs[artifact_id])
        routed = _normalize_schema_ref(content_refs[artifact_id])
        if configured != routed:
            raise ContractError("ARTIFACT_CONTENT_SCHEMA_UNBOUND", artifact_id)
        if routed.startswith("#/$defs/"):
            target = content.get("$defs", {}).get(routed.removeprefix("#/$defs/"))
            if not isinstance(target, dict) or target.get("type") != "object":
                raise ContractError("ARTIFACT_CONTENT_SCHEMA_UNBOUND", artifact_id)
    if set(roles) != set(required_ids):
        raise ContractError("REQUIRED_ARTIFACT_REGISTRY_INVALID")

    return {
        "status": "PASS",
        "schema_meta_validated": schema_names,
        "validated_rule_ids": rule_ids,
        "required_artifact_ids": required_ids,
        "known_operator_count": operator_result["known_operator_count"],
    }


def _component_prefix(path: str, root: str) -> bool:
    p = PurePosixPath(path)
    r = PurePosixPath(root)
    return p.is_absolute() and r.is_absolute() and p.parts[: len(r.parts)] == r.parts


def check_path_reference(path: str, runtime_root: str, symlink_components: set[str] | None = None) -> str:
    """Validate lexical exact-path semantics before filesystem resolution."""

    if not isinstance(path, str) or not isinstance(runtime_root, str):
        raise ContractError("PATH_TYPE")
    if "\x00" in path or "\x00" in runtime_root:
        raise ContractError("PATH_NUL")
    if not path.startswith("/") or not runtime_root.startswith("/"):
        raise ContractError("PATH_NOT_ABSOLUTE")
    if path.startswith("//") or runtime_root.startswith("//"):
        raise ContractError("PATH_NONCANONICAL")
    if any(part in {".", ".."} for part in PurePosixPath(runtime_root).parts):
        raise ContractError("PATH_DOT_SEGMENT")
    if any(part in {".", ".."} for part in PurePosixPath(path).parts):
        raise ContractError("PATH_DOT_SEGMENT")
    if os.path.normpath(runtime_root) != runtime_root or os.path.normpath(path) != path:
        raise ContractError("PATH_NONCANONICAL")
    if any(char in path for char in "*?[]{}"):
        raise ContractError("PATH_GLOB")
    if not _component_prefix(path, runtime_root):
        raise ContractError("PATH_CROSS_ROOT")
    if symlink_components:
        root_parts = PurePosixPath(runtime_root).parts
        for component in PurePosixPath(path).parts[len(root_parts) :]:
            if component in symlink_components:
                raise ContractError("PATH_SYMLINK", component)
    return path


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        stat.S_IFMT(left.st_mode),
    ) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
    )


def _open_at(directory_fd: int, component: str, flags: int) -> int:
    try:
        return os.open(component, flags, dir_fd=directory_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ContractError("PATH_SYMLINK", component) from exc
        raise ContractError("PATH_OPEN_FAILED", f"{component}: {exc}") from exc


def _open_absolute_directory_no_symlink(path: str) -> tuple[int, os.stat_result]:
    """Open every component below / without trusting path resolution."""

    canonical = PurePosixPath(path)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    root_fd = os.open("/", os.O_RDONLY | directory_flag | no_follow | close_on_exec)
    current_fd = root_fd
    try:
        for component in canonical.parts[1:]:
            before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise ContractError("PATH_SYMLINK", component)
            if not stat.S_ISDIR(before.st_mode):
                raise ContractError("PATH_COMPONENT_NOT_DIRECTORY", component)
            next_fd = _open_at(current_fd, component, os.O_RDONLY | directory_flag | no_follow | close_on_exec)
            opened = os.fstat(next_fd)
            if not _same_object(before, opened):
                os.close(next_fd)
                raise ContractError("PATH_DEVICE_INODE_MISMATCH", component)
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd
        opened_root = os.fstat(current_fd)
        if current_fd != root_fd:
            os.close(root_fd)
        return current_fd, opened_root
    except ContractError:
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)
        raise
    except OSError as exc:
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)
        raise ContractError("PATH_OPEN_FAILED", f"{path}: {exc}") from exc
    if current_fd != root_fd:
        os.close(root_fd)


def _read_stable_regular_file(runtime_root: str, path: str) -> tuple[bytes, os.stat_result]:
    """Read one stable regular file through a no-follow root file descriptor."""

    check_path_reference(path, runtime_root)
    relative_parts = PurePosixPath(path).relative_to(PurePosixPath(runtime_root)).parts
    if not relative_parts:
        raise ContractError("PATH_NOT_REGULAR", path)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    root_fd, root_before = _open_absolute_directory_no_symlink(runtime_root)
    current_fd = root_fd
    file_fd: int | None = None
    try:
        for component in relative_parts[:-1]:
            before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise ContractError("PATH_SYMLINK", component)
            if not stat.S_ISDIR(before.st_mode):
                raise ContractError("PATH_COMPONENT_NOT_DIRECTORY", component)
            next_fd = _open_at(current_fd, component, os.O_RDONLY | directory_flag | no_follow | close_on_exec)
            opened = os.fstat(next_fd)
            if not _same_object(before, opened):
                os.close(next_fd)
                raise ContractError("PATH_DEVICE_INODE_MISMATCH", component)
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd
        name = relative_parts[-1]
        before = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            raise ContractError("PATH_SYMLINK", name)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError("PATH_NOT_REGULAR", path)
        file_fd = _open_at(current_fd, name, os.O_RDONLY | no_follow | close_on_exec)
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode) or not _same_object(before, opened):
            raise ContractError("PATH_DEVICE_INODE_MISMATCH", path)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after_opened = os.fstat(file_fd)
        after_named = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        if not _same_object(opened, after_opened) or not _same_object(opened, after_named) or opened.st_size != after_opened.st_size:
            raise ContractError("PATH_OBJECT_REPLACED", path)
        recheck_fd, root_after = _open_absolute_directory_no_symlink(runtime_root)
        try:
            if not _same_object(root_before, root_after):
                raise ContractError("PATH_OBJECT_REPLACED", runtime_root)
        finally:
            os.close(recheck_fd)
        return b"".join(chunks), after_opened
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError("PATH_READ_FAILED", str(exc)) from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)


def _entry_schema_valid(entry: dict[str, Any], binding_document: dict[str, Any]) -> bool:
    definitions = binding_document.get("$defs")
    binding = definitions.get("binding") if isinstance(definitions, dict) else None
    if not isinstance(binding, dict) or not isinstance(definitions, dict):
        return False
    # The binding subschema has local references to the enclosing document's defs.
    schema = {"$defs": definitions, **binding}
    return not _schema_errors(schema, entry)


def check_artifact_bindings(
    binding_document: dict[str, Any],
    required_ids: Iterable[str] | None = None,
    *,
    allow_unmaterialized: bool = False,
) -> dict[str, Any]:
    """Authenticate exact 20-ID bindings and their stable selected file objects."""

    canonical_ids, roles, schemas, configured_document = _binding_configuration()
    required = list(canonical_ids if required_ids is None else required_ids)
    if not required or len(required) != len(set(required)) or not set(required) <= set(canonical_ids):
        raise ContractError("REQUIRED_ARTIFACT_REGISTRY_INVALID")
    root = binding_document.get("runtime_root") if isinstance(binding_document, dict) else None
    entries = binding_document.get("entries", binding_document.get("runtime_entries", [])) if isinstance(binding_document, dict) else None
    if not isinstance(root, str) or not isinstance(entries, list):
        raise ContractError("ARTIFACT_BINDING_SHAPE")
    check_path_reference(root, root)
    ids: list[str] = []
    paths: list[str] = []
    object_identities: set[tuple[int, int]] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ContractError("ARTIFACT_BINDING_SHAPE")
        artifact_id = entry.get("artifact_id")
        path = entry.get("path")
        if not isinstance(artifact_id, str) or not isinstance(path, str):
            raise ContractError("ARTIFACT_BINDING_SHAPE")
        try:
            check_path_reference(path, root)
        except ContractError as exc:
            if exc.code == "PATH_CROSS_ROOT":
                raise ContractError("CROSS_ROOT_ARTIFACT", str(exc)) from exc
            raise
        if (
            artifact_id not in required
            or entry.get("role") != roles.get(artifact_id)
            or entry.get("content_schema") != schemas.get(artifact_id)
            or entry.get("runtime_root") != root
            or not _entry_schema_valid(entry, configured_document)
        ):
            raise ContractError("ARTIFACT_BINDING_INCOMPLETE", artifact_id)
        if path in paths:
            raise ContractError("DUPLICATE_ARTIFACT_PATH", artifact_id)
        ids.append(artifact_id)
        paths.append(path)
        if allow_unmaterialized:
            continue
        content, identity = _read_stable_regular_file(root, path)
        if entry["sha256"] != hashlib.sha256(content).hexdigest():
            raise ContractError("FILE_HASH_MISMATCH", artifact_id)
        if entry["byte_length"] != len(content):
            raise ContractError("FILE_LENGTH_MISMATCH", artifact_id)
        declared_identity = entry["object_identity"]
        if declared_identity["device"] != identity.st_dev or declared_identity["inode"] != identity.st_ino:
            raise ContractError("PATH_DEVICE_INODE_MISMATCH", artifact_id)
        object_identity = (identity.st_dev, identity.st_ino)
        if object_identity in object_identities:
            raise ContractError("DUPLICATE_ARTIFACT_OBJECT", artifact_id)
        object_identities.add(object_identity)
    if len(ids) != len(set(ids)):
        raise ContractError("DUPLICATE_ARTIFACT_ID")
    if len(paths) != len(set(paths)):
        raise ContractError("DUPLICATE_ARTIFACT_PATH")
    if set(ids) != set(required):
        missing = sorted(set(required) - set(ids))
        unexpected = sorted(set(ids) - set(required))
        raise ContractError("ARTIFACT_ID_COVERAGE", f"missing={missing};unexpected={unexpected}")
    return {"status": "PASS", "bound_artifact_ids": ids, "runtime_root": root}


def _decode_b64(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ContractError("INVALID_BASE64")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ContractError("INVALID_BASE64") from exc


def _canonical_hash_without(value: dict[str, Any], excluded_key: str) -> str:
    if excluded_key not in value:
        raise ContractError("CANONICAL_HASH_INPUT_MISSING", excluded_key)
    copy = dict(value)
    del copy[excluded_key]
    return hashlib.sha256(canonical_json_bytes(copy)).hexdigest()


def check_receipt(
    receipt: dict[str, Any],
    privileged_summary: dict[str, Any] | None = None,
    manifest_sha256: str | None = None,
    run_id: str | None = None,
    runtime_root: str | None = None,
) -> dict[str, Any]:
    """Validate the dedicated receipt and all immutable summary bindings."""

    if not isinstance(receipt, dict) or receipt.get("schema") != "R6R3_PRIVILEGED_EXECUTION_RECEIPT_R2R1":
        raise ContractError("RECEIPT_MALFORMED")
    invocations = receipt.get("invocations", receipt.get("invocation"))
    count = len(invocations) if isinstance(invocations, list) else 1 if isinstance(invocations, dict) else 0
    if receipt.get("invocation_count") not in (None, 1) or count != 1:
        raise ContractError("RECEIPT_INVOCATION_COUNT")
    binding = receipt.get("manifest_binding")
    if not isinstance(binding, dict) or binding.get("artifact_id") != "r6_privileged_execution_receipt":
        raise ContractError("RECEIPT_MANIFEST_BINDING")
    schema = _load_documents()["receipt"]
    if _schema_errors(schema, receipt):
        raise ContractError("RECEIPT_SCHEMA_INVALID")
    if receipt["receipt_hash"] != _canonical_hash_without(receipt, "receipt_hash"):
        raise ContractError("RECEIPT_HASH_MISMATCH")
    if manifest_sha256 is not None and binding["manifest_sha256"] != manifest_sha256:
        raise ContractError("RECEIPT_MANIFEST_BINDING")
    runtime_binding = receipt["runtime_binding"]
    if run_id is not None and runtime_binding["run_id"] != run_id:
        raise ContractError("RECEIPT_RUN_BINDING")
    if runtime_root is not None and runtime_binding["runtime_root"] != runtime_root:
        raise ContractError("RECEIPT_RUNTIME_ROOT_BINDING")
    invocation = receipt["invocation"]
    if invocation["program_path"] != receipt["producer_identity"]["program_path"]:
        raise ContractError("RECEIPT_PRODUCER_IDENTITY_MISMATCH")
    if privileged_summary is not None:
        if not isinstance(privileged_summary, dict):
            raise ContractError("RECEIPT_SUMMARY_MISMATCH")
        pairs = {
            "human_initiated": (receipt["authorization"]["human_initiated"], privileged_summary.get("human_initiated")),
            "producer_id": (receipt["producer_identity"]["producer_id"], privileged_summary.get("producer_id")),
            "program_path": (invocation["program_path"], privileged_summary.get("program_path")),
            "producer_source_sha256": (receipt["producer_identity"]["producer_source_sha256"], privileged_summary.get("producer_source_sha256")),
            "authorization_reference": (receipt["authorization"]["authorization_reference"], privileged_summary.get("authorization_reference")),
            "exact_command": (invocation["exact_command"], privileged_summary.get("exact_command")),
            "uid": (invocation["uid"], privileged_summary.get("uid")),
            "effective_uid": (invocation["euid"], privileged_summary.get("effective_uid")),
            "pid": (invocation["pid"], privileged_summary.get("pid")),
            "pid_start_time_ticks": (invocation["pid_start_time_ticks"], privileged_summary.get("pid_start_time_ticks")),
            "netns_inode": (invocation["netns_inode"], privileged_summary.get("netns_inode")),
            "exit_code": (invocation["exit_code"], privileged_summary.get("exit_code")),
            "result_status": (invocation["result_status"], privileged_summary.get("result_status")),
            "classification": (invocation["classification"], privileged_summary.get("classification")),
            "micro_probe_verdict": (invocation["micro_probe_verdict"], privileged_summary.get("micro_probe_verdict")),
            "micro_probe_cleanup_state": (invocation["micro_probe_cleanup_state"], privileged_summary.get("micro_probe_cleanup_state")),
            "mininet_executed": (invocation["mininet_executed"], privileged_summary.get("mininet_executed")),
        }
        if any(left != right for left, right in pairs.values()):
            raise ContractError("RECEIPT_SUMMARY_MISMATCH")
    return {"status": "PASS", "invocation_count": 1, "invocation_id": invocation["invocation_id"]}


def _join_tuple(row: dict[str, Any]) -> tuple[Any, ...]:
    if any(field not in row for field in JOIN_KEY_FIELDS):
        raise ContractError("ROLE_NOT_ROUNDTRIPPABLE")
    values = tuple(row[field] for field in JOIN_KEY_FIELDS)
    if "join_key" in row:
        candidate = row["join_key"]
        if not isinstance(candidate, list) or tuple(candidate) != values:
            raise ContractError("ROLE_NOT_ROUNDTRIPPABLE")
    if any(not isinstance(value, str) or not value for value in (values[0], values[1], values[5])):
        raise ContractError("JOIN_KEY_TYPE_COERCION")
    if any(type(value) is not int or value <= 0 for value in (values[2], values[3], values[4])):
        raise ContractError("JOIN_KEY_TYPE_COERCION")
    return values


def check_join_roundtrip(join_document: dict[str, Any]) -> dict[str, Any]:
    """Require exact-one role-bearing six-field joins in both directions."""

    if not isinstance(join_document, dict):
        raise ContractError("JOIN_SHAPE")
    normalized = join_document.get("normalized_rows", [])
    joins = join_document.get("join_rows", [])
    if not isinstance(normalized, list) or not isinstance(joins, list):
        raise ContractError("JOIN_SHAPE")
    normalized_rows = [_require_object(row, "JOIN_SHAPE") for row in normalized]
    join_rows = [_require_object(row, "JOIN_SHAPE") for row in joins]

    def has_duplicate_compact_keys(rows: list[dict[str, Any]]) -> bool:
        keys: list[list[Any]] = []
        for row in rows:
            candidate = row.get("join_key")
            if isinstance(candidate, list):
                if any(candidate == existing for existing in keys):
                    return True
                keys.append(candidate)
        return False

    if has_duplicate_compact_keys(normalized_rows) or has_duplicate_compact_keys(join_rows):
        raise ContractError("AMBIGUOUS_JOIN")
    normalized_keys = [_join_tuple(row) for row in normalized_rows]
    join_keys = [_join_tuple(row) for row in join_rows]
    if len(join_keys) != len(set(join_keys)) or len(normalized_keys) != len(set(normalized_keys)):
        raise ContractError("AMBIGUOUS_JOIN")
    for key in normalized_keys:
        candidates = [row for row, candidate_key in zip(join_rows, join_keys) if candidate_key == key]
        if len(candidates) != 1:
            raise ContractError("AMBIGUOUS_JOIN" if len(candidates) > 1 else "MISSING_JOIN")
        candidate = candidates[0]
        if candidate.get("join_status") != "JOINED" or candidate.get("captured_while_alive") is not True:
            raise ContractError("MISSING_JOIN")
    for key in join_keys:
        if sum(candidate == key for candidate in normalized_keys) != 1:
            raise ContractError("MISSING_JOIN")
    return {"status": "PASS", "joined_rows": len(normalized_keys), "join_key_fields": list(JOIN_KEY_FIELDS)}


def check_record_hash_lineage(raw_row: dict[str, Any], normalized_row: dict[str, Any]) -> dict[str, Any]:
    """Recompute raw/normalized record hashes and their exact serial link."""

    try:
        raw_bytes = _decode_b64(raw_row["raw_bytes_b64"])
        normalized_bytes = _decode_b64(normalized_row["raw_event_bytes_b64"])
    except KeyError as exc:
        raise ContractError("RECORD_LINEAGE_INPUT_MISSING") from exc
    raw_digest = hashlib.sha256(raw_bytes).hexdigest()
    normalized_digest = hashlib.sha256(normalized_bytes).hexdigest()
    if raw_digest != raw_row.get("raw_sha256") or normalized_digest != normalized_row.get("raw_event_sha256"):
        raise ContractError("RECORD_HASH_MISMATCH")
    if raw_row.get("serial") != normalized_row.get("raw_serial"):
        raise ContractError("SAME_SERIAL_LINK_MISMATCH")
    if raw_bytes != normalized_bytes or raw_digest != normalized_digest:
        raise ContractError("SAME_SERIAL_BYTE_LINK_MISMATCH")
    return {"status": "PASS", "serial": raw_row["serial"], "sha256": raw_digest}


def check_file_event_same_serial(event: dict[str, Any], raw_records: list[dict[str, Any]]) -> dict[str, Any]:
    """Require one exact same-serial syscall/PATH proof for a file event."""

    serial = event.get("raw_serial")
    if not isinstance(serial, int) or serial <= 0:
        raise ContractError("SAME_SERIAL_AUDIT_EVENT_MISMATCH")
    if event.get("syscall_record_serial") != serial or event.get("path_record_serial") != serial:
        raise ContractError("SAME_SERIAL_AUDIT_EVENT_MISMATCH")
    candidates = [record for record in raw_records if record.get("serial") == serial]
    if len(candidates) != 1:
        raise ContractError("SAME_SERIAL_AUDIT_EVENT_MISMATCH")
    bundle = candidates[0]
    if {"SYSCALL", "PATH"} - set(bundle.get("record_types", [])):
        raise ContractError("SAME_SERIAL_AUDIT_EVENT_MISMATCH")
    if event.get("same_serial_linkage") != "PASS":
        raise ContractError("SAME_SERIAL_AUDIT_EVENT_MISMATCH")
    audit_records = bundle.get("audit_records")
    if not isinstance(audit_records, list):
        raise ContractError("SAME_SERIAL_AUDIT_EVENT_MISMATCH")
    syscall_records = [
        record for record in audit_records
        if isinstance(record, dict)
        and record.get("serial") == serial
        and record.get("record_kind") == "SYSCALL"
        and record.get("syscall_name") == event.get("underlying_syscall")
        and record.get("syscall_success") is True
        and record.get("audit_key") == event.get("audit_key")
    ]
    path_records = [
        record for record in audit_records
        if isinstance(record, dict)
        and record.get("serial") == serial
        and record.get("record_kind") == "PATH"
        and record.get("path_name") == event.get("watched_path")
        and record.get("audit_key") == event.get("audit_key")
    ]
    if len(syscall_records) != 1 or len(path_records) != 1:
        raise ContractError("SAME_SERIAL_AUDIT_EVENT_MISMATCH")
    return {"status": "PASS", "serial": serial}


def check_pcap_binding(document: dict[str, Any]) -> dict[str, Any]:
    """Recompute exact PCAP bytes and require all declared sources to match."""

    try:
        pcap_bytes = _decode_b64(document["pcap_bytes_b64"])
        actual = hashlib.sha256(pcap_bytes).hexdigest()
        source_ids = document["hash_source_artifact_ids"]
        hashes = [document["pcap_sha256"], document["coverage_sha256"], document["post_cleanup_sha256"]]
    except (KeyError, TypeError) as exc:
        raise ContractError("PCAP_BINDING_INPUT_MISSING") from exc
    if source_ids != ["r6_pcap", "r6_coverage_and_loss", "r6_post_cleanup"]:
        raise ContractError("PCAP_HASH_SOURCE_SET_MISMATCH")
    if any(value != actual for value in hashes):
        raise ContractError("PCAP_HASH_MISMATCH")
    if document.get("provenance_only") is not True or document.get("used_as_graph_edge_source") is not False:
        raise ContractError("PCAP_GRAPH_SOURCE_BOUNDARY")
    return {"status": "PASS", "sha256": actual}


def check_cleanup_recomputation(
    cleanup: dict[str, Any],
    authenticated_artifact_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Recompute cleanup only from the five authenticated evidence artifacts."""

    if authenticated_artifact_ids is None or not CLEANUP_ARTIFACT_IDS <= set(authenticated_artifact_ids):
        raise ContractError("CLEANUP_EVIDENCE_UNBOUND")
    try:
        pre = _require_object(cleanup["pre_state"], "CLEANUP_RECOMPUTATION_INPUT_MISSING")
        journal = _require_object(cleanup["rule_remediation_journal"], "CLEANUP_RECOMPUTATION_INPUT_MISSING")
        transient = _require_object(cleanup["transient_rule_contract"], "CLEANUP_RECOMPUTATION_INPUT_MISSING")
        residual = _require_object(cleanup["residual_remediation_evidence"], "CLEANUP_RECOMPUTATION_INPUT_MISSING")
        post_cleanup = _require_object(cleanup["post_cleanup_revalidation"], "CLEANUP_RECOMPUTATION_INPUT_MISSING")
        entries = journal["entries"]
        allowed = set(transient["allowed_rule_ids"])
        remaining = set(residual["remaining_transient_rules"])
    except (KeyError, TypeError) as exc:
        raise ContractError("CLEANUP_RECOMPUTATION_INPUT_MISSING") from exc
    if not isinstance(entries, list):
        raise ContractError("CLEANUP_RECOMPUTATION_INPUT_MISSING")
    rules = transient.get("rules")
    if not isinstance(rules, list):
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "authorized rule evidence missing")
    authorized_rule_hashes: dict[str, str] = {}
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("rule_id"), str) or not _SHA256_RE.fullmatch(str(rule.get("rule_sha256", ""))):
            raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "authorized rule evidence malformed")
        if rule["rule_id"] in authorized_rule_hashes:
            raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "duplicate authorized rule")
        authorized_rule_hashes[rule["rule_id"]] = rule["rule_sha256"]
    if set(authorized_rule_hashes) != allowed:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "authorized rule definitions differ")
    try:
        adds = {entry["rule_id"] for entry in entries if entry["operation"] == "ADD" and entry["result"] == "SUCCESS"}
        deletes = {entry["rule_id"] for entry in entries if entry["operation"] == "DELETE" and entry["result"] == "SUCCESS"}
    except (KeyError, TypeError) as exc:
        raise ContractError("CLEANUP_RECOMPUTATION_INPUT_MISSING") from exc
    if not adds:
        raise ContractError("CLEANUP_NO_SUCCESSFUL_ADD")
    if adds != deletes:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "successful add/delete sets differ")
    if set(journal.get("successful_add_ids", [])) != adds or set(journal.get("successful_delete_ids", [])) != deletes:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "declared journal sets differ")
    operation_ids = [entry.get("operation_id") if isinstance(entry, dict) else None for entry in entries]
    if any(not isinstance(value, str) or not value for value in operation_ids):
        raise ContractError("CLEANUP_OPERATION_ID_MISSING")
    if len(operation_ids) != len(set(operation_ids)):
        raise ContractError("CLEANUP_DUPLICATE_OPERATION_ID")
    if any(not _SHA256_RE.fullmatch(str(entry.get("rule_sha256", ""))) for entry in entries):
        raise ContractError("CLEANUP_JOURNAL_EVIDENCE_MALFORMED")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ContractError("CLEANUP_JOURNAL_EVIDENCE_MALFORMED")
        if entry.get("operation") in {"ADD", "DELETE"} and entry.get("result") == "SUCCESS":
            if entry.get("rule_id") not in authorized_rule_hashes or entry.get("rule_sha256") != authorized_rule_hashes[entry["rule_id"]]:
                raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "journal rule is not authorized")
    if not adds <= allowed or remaining:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH")
    if residual.get("baseline_rule_dump_sha256_after") != pre.get("baseline_rule_dump_sha256"):
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "baseline hash differs")
    if residual.get("persistent_rule_files_sha256_after") != pre.get("persistent_rule_files_sha256"):
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "persistent hash differs")
    if journal.get("global_delete_observed") is not False:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "global delete observed")
    if post_cleanup.get("performed_after_all_reads") is not True:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "post-read revalidation missing")
    if post_cleanup.get("audit_lost_events") != 0 or post_cleanup.get("audit_backlog") != 0:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "audit drain failed")
    if post_cleanup.get("baseline_rule_dump_sha256_after") != pre.get("baseline_rule_dump_sha256"):
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "post-cleanup baseline hash differs")
    if post_cleanup.get("persistent_rule_files_sha256_after") != pre.get("persistent_rule_files_sha256"):
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "post-cleanup persistent hash differs")
    residue_fields = ("run_owned_children_remaining", "reserved_test_interfaces_remaining", "reserved_test_ovs_objects_remaining", "tcpdump_process_remaining")
    if any(residual.get(field) != 0 for field in residue_fields):
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "residual objects remain")
    if any(residual.get(field) is not True for field in ("topology_residue_zero", "child_residue_zero", "tcpdump_residue_zero")):
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "residue assertions fail")
    return {"status": "PASS", "successful_add_ids": sorted(adds), "successful_delete_ids": sorted(deletes)}


def check_cleanup_recomputation_from_authenticated_artifacts(parsed: dict[str, Any]) -> dict[str, Any]:
    """Derive cleanup acceptance solely from five manifest-authenticated artifacts."""

    if not isinstance(parsed, dict) or set(parsed) != CLEANUP_ARTIFACT_IDS:
        raise ContractError("CLEANUP_EVIDENCE_UNBOUND")
    return check_cleanup_recomputation(
        {
            "pre_state": parsed["r6_audit_pre_state"],
            "transient_rule_contract": parsed["r6_transient_rule_contract"],
            "rule_remediation_journal": parsed["r6_rule_remediation_journal"],
            "residual_remediation_evidence": parsed["r6_residual_remediation"],
            "post_cleanup_revalidation": parsed["r6_post_cleanup"],
        },
        authenticated_artifact_ids=CLEANUP_ARTIFACT_IDS,
    )


def _git(repository: Path, *args: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repository), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED", str(exc)) from exc
    if completed.returncode != 0:
        raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED", completed.stderr.decode("utf-8", "replace").strip())
    return completed.stdout


def _git_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED")
    return path.as_posix()


def check_source_lineage(
    lineage: dict[str, Any],
    repository: Path | None,
    manifest_source_entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Authenticate source bytes from a declared immutable Git commit only."""

    if not isinstance(lineage, dict) or lineage.get("disposition") != "AUTHENTICATED_COMMITTED_SOURCE":
        raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED")
    committed = lineage.get("committed_source", lineage)
    if not isinstance(committed, dict) or committed.get("resolution_method") != "INDEPENDENT_COMMITTED_STATE_RESOLUTION":
        raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED")
    commit = committed.get("resolved_commit")
    source_files = committed.get("source_files")
    if (
        repository is None
        or not repository.is_dir()
        or not isinstance(commit, str)
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not isinstance(source_files, list)
        or not source_files
        or not isinstance(manifest_source_entries, list)
        or source_files != manifest_source_entries
        or committed.get("hashes_match") is not True
    ):
        raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED")
    _git(repository, "cat-file", "-e", f"{commit}^{{commit}}")
    seen_paths: set[str] = set()
    checked: list[str] = []
    for source in source_files:
        if not isinstance(source, dict) or not isinstance(source.get("source_id"), str):
            raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED")
        path = _git_path(source.get("repository_relative_path", source.get("path")))
        digest = source.get("sha256")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest) or path in seen_paths:
            raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED")
        seen_paths.add(path)
        content = _git(repository, "show", f"{commit}:{path}")
        if hashlib.sha256(content).hexdigest() != digest:
            raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED")
        checked.append(path)
    return {"status": "PASS", "resolved_commit": commit, "source_paths": checked}


def validate_handoff_shape(candidate: dict[str, Any]) -> dict[str, Any]:
    """Check independently useful fail-closed template, operator, and producer states."""

    if not isinstance(candidate, dict):
        raise ContractError("HANDOFF_NOT_OBJECT")
    if candidate.get("template_status") == "NOT_RUNTIME_EVIDENCE" or candidate.get("must_not_be_consumed") is True or candidate.get("runtime_evidence_present") is False:
        raise ContractError("TEMPLATE_NOT_RUNTIME_EVIDENCE")
    refs = candidate.get("operator_references", [])
    if not isinstance(refs, list):
        raise ContractError("OPERATOR_REFERENCE_SHAPE")
    unknown = [ref for ref in refs if not isinstance(ref, str) or ref not in _operator_ids()]
    if unknown:
        raise ContractError("UNKNOWN_OPERATOR", ",".join(map(str, unknown)))
    compatibility = candidate.get("producer_compatibility")
    if isinstance(compatibility, dict) and compatibility.get("receipt_emission_status") != "IMPLEMENTED":
        raise ContractError("PRODUCER_RECEIPT_EMISSION_NOT_IMPLEMENTED")
    lineage = candidate.get("source_lineage")
    if isinstance(lineage, dict) and lineage.get("disposition") != "AUTHENTICATED_COMMITTED_SOURCE":
        raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED")
    return {"status": "PASS"}


def _manifest_hash(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("manifest_hash_scope") != "canonical(package_manifest_without_manifest_sha256)":
        raise ContractError("PACKAGE_MANIFEST_HASH_INVALID")
    if manifest.get("manifest_sha256") != _canonical_hash_without(manifest, "manifest_sha256"):
        raise ContractError("PACKAGE_MANIFEST_HASH_INVALID")
    return {"status": "PASS"}


def _exact_id_list(value: Any, required: list[str]) -> None:
    if not isinstance(value, list) or value != required or len(value) != len(set(value)):
        raise ContractError("ARTIFACT_ID_COVERAGE")


def _check_manifest_completeness(candidate: dict[str, Any]) -> dict[str, Any]:
    required = _required_ids()
    manifest = candidate["package_manifest"]
    selected = candidate["selected_inputs"]
    root = candidate["run_identity"]["runtime_root"]
    if selected["runtime_root"] != root or manifest["runtime_root"] != root:
        raise ContractError("CROSS_ROOT_ARTIFACT")
    entries = manifest["runtime_entries"]
    if not isinstance(entries, list):
        raise ContractError("ARTIFACT_ID_COVERAGE")
    _exact_id_list([entry.get("artifact_id") for entry in entries if isinstance(entry, dict)], required)
    bindings = selected["path_bindings"]
    if not isinstance(bindings, dict) or list(bindings) != required:
        raise ContractError("ARTIFACT_ID_COVERAGE")
    parsed = selected["parsed_bindings"]
    if not isinstance(parsed, list):
        raise ContractError("ARTIFACT_ID_COVERAGE")
    _exact_id_list([entry.get("artifact_id") for entry in parsed if isinstance(entry, dict)], required)
    for artifact_id in required:
        binding = bindings.get(artifact_id)
        if not isinstance(binding, dict) or binding.get("artifact_id") != artifact_id or binding.get("runtime_root") != root:
            raise ContractError("ARTIFACT_BINDING_INCOMPLETE", artifact_id)
        manifest_entry = entries[required.index(artifact_id)]
        if manifest_entry != binding:
            raise ContractError("MANIFEST_SELECTED_BINDING_MISMATCH", artifact_id)
    return {"status": "PASS", "runtime_root": root}


def _read_parsed_artifacts(candidate: dict[str, Any]) -> dict[str, Any]:
    _, _, expected_schemas, _ = _binding_configuration()
    content_schema = _load_documents()["content"]
    bindings = candidate["selected_inputs"]["path_bindings"]
    parser_bindings = candidate["selected_inputs"]["parsed_bindings"]
    by_id = {entry["artifact_id"]: entry for entry in parser_bindings}
    parsed: dict[str, Any] = {}
    for artifact_id in _required_ids():
        binding = bindings[artifact_id]
        parser_binding = by_id.get(artifact_id)
        if not isinstance(parser_binding, dict) or parser_binding.get("path_binding_artifact_id") != artifact_id:
            raise ContractError("ARTIFACT_CONTENT_SCHEMA_UNBOUND", artifact_id)
        if binding.get("content_schema") != expected_schemas[artifact_id]:
            raise ContractError("ARTIFACT_CONTENT_SCHEMA_UNBOUND", artifact_id)
        data, _ = _read_stable_regular_file(candidate["run_identity"]["runtime_root"], binding["path"])
        parser = parser_binding.get("parser")
        schema_ref = _normalize_schema_ref(expected_schemas[artifact_id])
        if artifact_id == "r6_privileged_execution_receipt":
            value = _parse_json_bytes_strict(data, object_required=True)
            schema = _load_documents()["receipt"]
        elif parser == "STRICT_JSON_OBJECT":
            value = _parse_json_bytes_strict(data, object_required=True)
            schema = content_schema.get("$defs", {}).get(schema_ref.removeprefix("#/$defs/"))
        elif parser == "STRICT_JSONL_OBJECTS":
            value = _parse_jsonl_bytes_strict(data)
            schema = content_schema.get("$defs", {}).get(schema_ref.removeprefix("#/$defs/"))
        elif parser == "EXACT_BINARY_BYTES" and artifact_id == "r6_pcap":
            value = data
            schema = None
        else:
            raise ContractError("ARTIFACT_CONTENT_SCHEMA_UNBOUND", artifact_id)
        if schema is not None:
            values = value if isinstance(value, list) else [value]
            if not isinstance(schema, dict):
                raise ContractError("ARTIFACT_CONTENT_SCHEMA_INVALID", artifact_id)
            resolved_schema = {"$defs": content_schema.get("$defs", {}), **schema}
            if any(_schema_errors(resolved_schema, item) for item in values):
                raise ContractError("ARTIFACT_CONTENT_SCHEMA_INVALID", artifact_id)
        parsed[artifact_id] = value
    return parsed


def _check_run_id_closure(candidate: dict[str, Any], parsed: dict[str, Any]) -> dict[str, Any]:
    run_id = candidate["run_identity"]["run_id"]
    root = candidate["run_identity"]["runtime_root"]
    for artifact_id, value in parsed.items():
        rows = value if isinstance(value, list) else [value]
        for row in rows:
            if isinstance(row, dict) and (row.get("run_id") != run_id or row.get("runtime_root", root) != root):
                raise ContractError("RUN_ID_OR_RUNTIME_ROOT_MISMATCH", artifact_id)
    return {"status": "PASS"}


def _check_raw_integrity(rows: Any) -> dict[str, Any]:
    if not isinstance(rows, list):
        raise ContractError("RAW_AUDIT_RECORD_INVALID")
    serials: set[int] = set()
    for row in rows:
        if not isinstance(row, dict) or type(row.get("serial")) is not int or row["serial"] <= 0 or row["serial"] in serials:
            raise ContractError("RAW_AUDIT_RECORD_INVALID")
        serials.add(row["serial"])
        if hashlib.sha256(_decode_b64(row.get("raw_bytes_b64"))).hexdigest() != row.get("raw_sha256"):
            raise ContractError("RAW_AUDIT_RECORD_INVALID")
    return {"status": "PASS", "record_count": len(rows)}


def _check_normalized_integrity(rows: Any) -> dict[str, Any]:
    if not isinstance(rows, list):
        raise ContractError("NORMALIZED_EVENT_INVALID")
    event_ids: set[str] = set()
    serials: set[int] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("event_id"), str) or row["event_id"] in event_ids or type(row.get("raw_serial")) is not int or row["raw_serial"] in serials:
            raise ContractError("NORMALIZED_EVENT_INVALID")
        event_ids.add(row["event_id"])
        serials.add(row["raw_serial"])
        _join_tuple(row)
        if hashlib.sha256(_decode_b64(row.get("raw_event_bytes_b64"))).hexdigest() != row.get("raw_event_sha256"):
            raise ContractError("NORMALIZED_EVENT_INVALID")
    return {"status": "PASS", "event_count": len(rows)}


def _check_event_coverage(normalized: Any, coverage: Any) -> dict[str, Any]:
    if not isinstance(normalized, list) or not isinstance(coverage, dict):
        raise ContractError("EVENT_CLASS_COVERAGE_OR_LOSS_INVALID")
    required_classes = _load_documents()["rules"].get("required_event_class_order")
    if not isinstance(required_classes, list) or coverage.get("required_classes") != required_classes:
        raise ContractError("EVENT_CLASS_COVERAGE_OR_LOSS_INVALID")
    counts = {event: 0 for event in required_classes}
    for row in normalized:
        event = row.get("event_type") if isinstance(row, dict) else None
        if event not in counts:
            raise ContractError("EVENT_CLASS_COVERAGE_OR_LOSS_INVALID")
        counts[event] += 1
    if coverage.get("normalized_class_counts") != counts or any(value == 0 for value in counts.values()):
        raise ContractError("EVENT_CLASS_COVERAGE_OR_LOSS_INVALID")
    zero_fields = ("raw_link_failures", "pid_netns_join_failure_count", "duplicate_raw_serials", "duplicate_event_ids", "audit_lost_events", "audit_backlog")
    if any(coverage.get(field) != 0 for field in zero_fields):
        raise ContractError("EVENT_CLASS_COVERAGE_OR_LOSS_INVALID")
    return {"status": "PASS", "counts": counts}


def _check_hard_boundaries(candidate: dict[str, Any]) -> dict[str, Any]:
    boundaries = candidate["hard_boundaries"]
    if not isinstance(boundaries, dict) or any(value is not False for value in boundaries.values()):
        raise ContractError("HANDOFF_SCOPE_BOUNDARY_VIOLATED")
    if candidate["pcap_authentication"].get("used_as_graph_edge_source") is not False:
        raise ContractError("PCAP_GRAPH_SOURCE_BOUNDARY")
    return {"status": "PASS"}


def _run_rule(rule_id: str, function: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return function()
    except ContractError as exc:
        raise ContractError(f"{rule_id}:{exc.code}", str(exc)) from exc


def validate_handoff(candidate: dict[str, Any], *, source_repository: Path | None) -> dict[str, Any]:
    """Execute H001-H017 once, in declared order, with no partial success."""

    static = validate_contract_static()
    rules = _load_documents()["rules"]["rules"]
    rule_ids = [rule["rule_id"] for rule in rules]
    if rule_ids != static["validated_rule_ids"] or rule_ids != EXPECTED_RULE_IDS:
        raise ContractError("RULE_ORDER_OR_COVERAGE_INVALID")
    handoff_schema = _load_documents()["handoff"]
    parsed: dict[str, Any] | None = None

    def h001() -> dict[str, Any]:
        if not isinstance(candidate, dict) or _schema_errors(handoff_schema, candidate):
            raise ContractError("HANDOFF_SCHEMA_INVALID")
        return validate_handoff_shape(candidate)

    def h002() -> dict[str, Any]:
        return _manifest_hash(candidate["package_manifest"])

    def h003() -> dict[str, Any]:
        return _check_manifest_completeness(candidate)

    def h004() -> dict[str, Any]:
        selected = candidate["selected_inputs"]
        return check_artifact_bindings({"runtime_root": selected["runtime_root"], "entries": list(selected["path_bindings"].values())})

    def h005() -> dict[str, Any]:
        return check_source_lineage(candidate["source_lineage"], source_repository, candidate["package_manifest"]["source_entries"])

    def h006() -> dict[str, Any]:
        binding = candidate["selected_inputs"]["path_bindings"]["r6_privileged_execution_receipt"]
        bytes_value, _ = _read_stable_regular_file(candidate["run_identity"]["runtime_root"], binding["path"])
        receipt = _parse_json_bytes_strict(bytes_value, object_required=True)
        return check_receipt(receipt, candidate["privileged_execution"], candidate["package_manifest"]["manifest_sha256"], candidate["run_identity"]["run_id"], candidate["run_identity"]["runtime_root"])

    def h007() -> dict[str, Any]:
        nonlocal parsed
        parsed = _read_parsed_artifacts(candidate)
        return _check_run_id_closure(candidate, parsed)

    def h008() -> dict[str, Any]:
        return _check_raw_integrity(parsed["r6_raw_audit"] if parsed is not None else None)

    def h009() -> dict[str, Any]:
        return _check_normalized_integrity(parsed["r6_normalized_events"] if parsed is not None else None)

    def h010() -> dict[str, Any]:
        raw_rows = parsed["r6_raw_audit"] if parsed is not None else []
        normalized_rows = parsed["r6_normalized_events"] if parsed is not None else []
        raw_by_serial = {row["serial"]: row for row in raw_rows}
        for row in normalized_rows:
            raw = raw_by_serial.get(row["raw_serial"])
            if raw is None:
                raise ContractError("SAME_SERIAL_LINK_MISMATCH")
            check_record_hash_lineage(raw, row)
        return {"status": "PASS"}

    def h011() -> dict[str, Any]:
        raw_rows = parsed["r6_raw_audit"] if parsed is not None else []
        for event in candidate["file_read_or_write_evidence"]:
            check_file_event_same_serial(event, raw_rows)
        return {"status": "PASS"}

    def h012() -> dict[str, Any]:
        return check_join_roundtrip({"normalized_rows": parsed["r6_normalized_events"], "join_rows": parsed["r6_pid_netns_join"]})

    def h013() -> dict[str, Any]:
        return _check_event_coverage(parsed["r6_normalized_events"], parsed["r6_coverage_and_loss"])

    def h014() -> dict[str, Any]:
        pcap = parsed["r6_pcap"]
        coverage = parsed["r6_coverage_and_loss"]
        post = parsed["r6_post_cleanup"]
        declared = candidate["pcap_authentication"]
        return check_pcap_binding({
            "pcap_bytes_b64": base64.b64encode(pcap).decode("ascii"),
            "pcap_sha256": declared.get("pcap_sha256"),
            "coverage_sha256": coverage.get("pcap_sha256"),
            "post_cleanup_sha256": post.get("pcap_sha256"),
            "hash_source_artifact_ids": declared.get("hash_source_artifact_ids"),
            "provenance_only": declared.get("provenance_only"),
            "used_as_graph_edge_source": declared.get("used_as_graph_edge_source"),
        })

    def h015() -> dict[str, Any]:
        if parsed is None:
            raise ContractError("CLEANUP_EVIDENCE_UNBOUND")
        return check_cleanup_recomputation_from_authenticated_artifacts({
            artifact_id: parsed[artifact_id] for artifact_id in CLEANUP_ARTIFACT_IDS
        })

    def h016() -> dict[str, Any]:
        return _check_hard_boundaries(candidate)

    def h017() -> dict[str, Any]:
        _manifest_hash(candidate["package_manifest"])
        h004()
        reread = _read_parsed_artifacts(candidate)
        _check_run_id_closure(candidate, reread)
        return {"status": "PASS"}

    dispatch: dict[str, Callable[[], dict[str, Any]]] = {
        "H001_PACKAGE_SHAPE_AND_SCHEMA": h001,
        "H002_MANIFEST_CANONICAL_HASH": h002,
        "H003_MANIFEST_ENTRY_UNIQUENESS_AND_COMPLETENESS": h003,
        "H004_EXACT_PATH_AND_FILE_HASH_BINDING": h004,
        "H005_SOURCE_COMMIT_AND_CONTRACT_LINEAGE": h005,
        "H006_EXPLICIT_PRIVILEGED_EXECUTION": h006,
        "H007_RUN_ID_CLOSURE": h007,
        "H008_RAW_RECORD_INTEGRITY": h008,
        "H009_NORMALIZED_RECORD_INTEGRITY": h009,
        "H010_RAW_NORMALIZED_SAME_SERIAL_AND_BYTE_LINK": h010,
        "H011_FILE_READ_OR_WRITE_STRICT_EVIDENCE": h011,
        "H012_PID_START_TICKS_NETNS_LOGICAL_HOST_JOIN": h012,
        "H013_EVENT_CLASS_COVERAGE_AND_LOSS_CLOSURE": h013,
        "H014_PCAP_AUTHENTICATION": h014,
        "H015_CLEANUP_INVERSE_RULE_AND_BASELINE_RESTORATION": h015,
        "H016_HARD_BOUNDARIES": h016,
        "H017_FINAL_CANONICAL_RECHECK": h017,
    }
    if set(dispatch) != set(rule_ids):
        raise ContractError("RULE_ORDER_OR_COVERAGE_INVALID")
    completed: list[str] = []
    for rule_id in rule_ids:
        _run_rule(rule_id, dispatch[rule_id])
        completed.append(rule_id)
    return {"status": "PASS_READY_FOR_AUTHENTICATED_RUNTIME_HANDOFF", "validated_rule_ids": completed}
