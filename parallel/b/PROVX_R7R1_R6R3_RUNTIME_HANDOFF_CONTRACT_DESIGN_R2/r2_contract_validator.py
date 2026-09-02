"""Pure, read-only validation helpers for the R6R3 handoff R2 design.

This module intentionally validates contracts and inert fixtures only. It does
not execute a producer, inspect privileged state, or create runtime evidence.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


PACKAGE = Path(__file__).resolve().parent
REGISTRY_PATH = PACKAGE / "R6R3_RUNTIME_HANDOFF_OPERATOR_SEMANTICS_R2.json"
RULES_PATH = PACKAGE / "R6R3_RUNTIME_HANDOFF_AUTHENTICATION_RULES_R2.json"
SCHEMA_PATH = PACKAGE / "R6R3_RUNTIME_HANDOFF_SCHEMA_R2.json"
REQUIRED_BINDINGS_PATH = PACKAGE / "R6R3_REQUIRED_ARTIFACT_PATH_BINDINGS_R2.json"


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


def load_json_strict(path: str | os.PathLike[str]) -> Any:
    """Read one UTF-8 JSON value with duplicate-key and finite-number checks."""

    try:
        data = Path(path).read_bytes()
        if data.startswith(b"\xef\xbb\xbf"):
            raise ContractError("JSON_BOM")
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_key,
            parse_constant=_reject_constant,
        )
        return _reject_nonfinite(value)
    except ContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
        raise ContractError("MALFORMED_JSON", str(exc)) from exc


def load_jsonl_strict(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Read JSONL as exact LF-delimited object records."""

    try:
        data = Path(path).read_bytes()
        if b"\r" in data:
            raise ContractError("MALFORMED_JSONL", "CR byte is not allowed")
        text = data.decode("utf-8")
    except ContractError:
        raise
    except (UnicodeDecodeError, OSError) as exc:
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
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContractError("MALFORMED_JSONL", f"line {line_number}: {exc}") from exc
        if not isinstance(row, dict):
            raise ContractError("MALFORMED_JSONL", f"line {line_number} is not an object")
        rows.append(row)
    return rows


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize according to the R2 canonical JSON profile."""

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


def _operator_ids() -> set[str]:
    registry = load_json_strict(REGISTRY_PATH)
    operators = registry.get("operators")
    if not isinstance(operators, list):
        raise ContractError("OPERATOR_REGISTRY_SHAPE")
    ids = [item.get("operator_id") for item in operators if isinstance(item, dict)]
    if any(not isinstance(item, str) for item in ids):
        raise ContractError("OPERATOR_REGISTRY_SHAPE")
    if len(ids) != len(set(ids)):
        raise ContractError("DUPLICATE_OPERATOR_DEFINITION")
    return set(ids)


def validate_operator_references() -> dict[str, Any]:
    """Require every operator application in the rule inventory to resolve."""

    known = _operator_ids()
    rules = load_json_strict(RULES_PATH)
    unknown: list[str] = []
    references: list[str] = []
    for rule in rules.get("rules", []):
        for application in rule.get("operator_applications", []):
            operator_id = application.get("operator_id") if isinstance(application, dict) else application
            if not isinstance(application, dict) or not application.get("subject") or "expected" not in application:
                raise ContractError("OPERATOR_APPLICATION_SHAPE")
            references.append(operator_id)
            if operator_id not in known:
                unknown.append(operator_id)
    if unknown:
        raise ContractError("UNKNOWN_OPERATOR", ",".join(sorted(set(unknown))))
    return {"status": "PASS", "referenced_operator_ids": references, "known_operator_count": len(known)}


def _required_ids() -> list[str]:
    data = load_json_strict(REQUIRED_BINDINGS_PATH)
    ids = data.get("required_artifact_ids")
    if not isinstance(ids, list) or len(ids) != 20 or len(ids) != len(set(ids)):
        raise ContractError("REQUIRED_ARTIFACT_REGISTRY_INVALID")
    return ids


def _component_prefix(path: str, root: str) -> bool:
    p = PurePosixPath(path)
    r = PurePosixPath(root)
    return p.is_absolute() and r.is_absolute() and p.parts[: len(r.parts)] == r.parts


def check_path_reference(path: str, runtime_root: str, symlink_components: set[str] | None = None) -> str:
    """Validate lexical and modelled filesystem semantics for one exact path."""

    if not isinstance(path, str) or not isinstance(runtime_root, str):
        raise ContractError("PATH_TYPE")
    if "\x00" in path or "\x00" in runtime_root:
        raise ContractError("PATH_NUL")
    if not path.startswith("/") or not runtime_root.startswith("/"):
        raise ContractError("PATH_NOT_ABSOLUTE")
    if any(part in {".", ".."} for part in PurePosixPath(runtime_root).parts):
        raise ContractError("PATH_DOT_SEGMENT")
    if any(part in {".", ".."} for part in PurePosixPath(path).parts):
        raise ContractError("PATH_DOT_SEGMENT")
    if os.path.normpath(runtime_root) != runtime_root or os.path.normpath(path) != path:
        raise ContractError("PATH_NONCANONICAL")
    if any(char in path for char in "*?[]{}"):
        raise ContractError("PATH_GLOB")
    if symlink_components:
        root_parts = PurePosixPath(runtime_root).parts
        for component in PurePosixPath(path).parts[len(root_parts) :]:
            if component in symlink_components:
                raise ContractError("PATH_SYMLINK", component)
    if not _component_prefix(path, runtime_root):
        raise ContractError("PATH_CROSS_ROOT")
    return path


def _assert_no_symlink_components(path: str) -> None:
    """Reject symlinks in every existing component, including parents."""

    parts = PurePosixPath(path).parts
    current = Path(parts[0])
    for component in parts[1:]:
        current /= component
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            return
        if stat.S_ISLNK(mode):
            raise ContractError("PATH_SYMLINK", str(current))


def _read_stable_regular_file(path: str) -> tuple[bytes, os.stat_result]:
    """Read one stable regular file without following the final symlink."""

    _assert_no_symlink_components(path)
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ContractError("PATH_NOT_REGULAR", path)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, os.O_RDONLY | no_follow | close_on_exec)
    except OSError as exc:
        raise ContractError("PATH_OPEN_FAILED", str(exc)) from exc
    try:
        opened = os.fstat(fd)
        if (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)) != (
            opened.st_dev,
            opened.st_ino,
            stat.S_IFMT(opened.st_mode),
        ):
            raise ContractError("PATH_DEVICE_INODE_MISMATCH", path)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode), opened.st_size) != (
            after.st_dev,
            after.st_ino,
            stat.S_IFMT(after.st_mode),
            after.st_size,
        ):
            raise ContractError("PATH_OBJECT_REPLACED", path)
        return b"".join(chunks), after
    except OSError as exc:
        raise ContractError("PATH_READ_FAILED", str(exc)) from exc
    finally:
        os.close(fd)


def check_artifact_bindings(
    binding_document: dict[str, Any],
    required_ids: Iterable[str] | None = None,
    *,
    allow_unmaterialized: bool = False,
) -> dict[str, Any]:
    """Check exact artifact ID/path/root coverage and stable local files."""

    required = list(required_ids or _required_ids())
    root = binding_document.get("runtime_root")
    entries = binding_document.get("entries", binding_document.get("runtime_entries", []))
    if not isinstance(root, str) or not isinstance(entries, list):
        raise ContractError("ARTIFACT_BINDING_SHAPE")
    ids: list[str] = []
    paths: list[str] = []
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
            if exc.code in {"PATH_CROSS_ROOT", "PATH_DOT_SEGMENT", "PATH_SYMLINK", "PATH_GLOB"}:
                raise ContractError("CROSS_ROOT_ARTIFACT", str(exc)) from exc
            raise
        ids.append(artifact_id)
        paths.append(path)
        if not Path(path).exists() and not allow_unmaterialized:
            raise ContractError("PATH_MISSING")
        if Path(path).exists():
            if "sha256" not in entry or "byte_length" not in entry:
                raise ContractError("ARTIFACT_DECLARED_HASH_MISSING")
            actual, identity = _read_stable_regular_file(path)
            if entry["sha256"] != hashlib.sha256(actual).hexdigest():
                raise ContractError("FILE_HASH_MISMATCH")
            if entry["byte_length"] != len(actual):
                raise ContractError("FILE_LENGTH_MISMATCH")
            declared_identity = entry.get("object_identity")
            if isinstance(declared_identity, dict) and (
                declared_identity.get("device") != identity.st_dev
                or declared_identity.get("inode") != identity.st_ino
            ):
                raise ContractError("PATH_DEVICE_INODE_MISMATCH")
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


def check_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Apply the receipt multiplicity and manifest-binding checks."""

    if not isinstance(receipt, dict) or receipt.get("schema") != "R6R3_PRIVILEGED_EXECUTION_RECEIPT_R2":
        raise ContractError("RECEIPT_MALFORMED")
    invocations = receipt.get("invocations", receipt.get("invocation"))
    if isinstance(invocations, list):
        count = len(invocations)
    elif isinstance(invocations, dict):
        count = 1
    else:
        count = 0
    if receipt.get("invocation_count") not in (None, 1) or count != 1:
        raise ContractError("RECEIPT_INVOCATION_COUNT")
    binding = receipt.get("manifest_binding")
    if not isinstance(binding, dict) or binding.get("artifact_id") != "r6_privileged_execution_receipt":
        raise ContractError("RECEIPT_MANIFEST_BINDING")
    return {"status": "PASS", "invocation_count": count}


def check_join_roundtrip(join_document: dict[str, Any]) -> dict[str, Any]:
    """Require unique, role-bearing, exact-one join tuples."""

    normalized = join_document.get("normalized_rows", [])
    joins = join_document.get("join_rows", [])
    if not isinstance(normalized, list) or not isinstance(joins, list):
        raise ContractError("JOIN_SHAPE")
    join_keys = [tuple(row.get("join_key", [])) for row in joins if isinstance(row, dict)]
    if any(len(key) != 6 for key in join_keys):
        raise ContractError("ROLE_NOT_ROUNDTRIPPABLE")
    if len(join_keys) != len(set(join_keys)):
        raise ContractError("AMBIGUOUS_JOIN")
    normalized_keys = [tuple(row.get("join_key", [])) for row in normalized if isinstance(row, dict)]
    if any(len(key) != 6 for key in normalized_keys):
        raise ContractError("ROLE_NOT_ROUNDTRIPPABLE")
    for key in normalized_keys:
        matches = sum(candidate == key for candidate in join_keys)
        if matches != 1:
            raise ContractError("AMBIGUOUS_JOIN" if matches > 1 else "MISSING_JOIN")
    return {"status": "PASS", "joined_rows": len(normalized_keys)}


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
    required = {"SYSCALL", "PATH"}
    if not required <= set(bundle.get("record_types", [])):
        raise ContractError("SAME_SERIAL_AUDIT_EVENT_MISMATCH")
    if event.get("same_serial_linkage") != "PASS" or event.get("raw_bundle_assertions", {}).get("audit_key_exact") is not True or event.get("raw_bundle_assertions", {}).get("path_exact") is not True:
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


def check_cleanup_recomputation(cleanup: dict[str, Any]) -> dict[str, Any]:
    """Recompute inverse cleanup and restoration from evidence objects."""

    try:
        pre = cleanup["pre_state"]
        journal = cleanup["rule_remediation_journal"]
        transient = cleanup["transient_rule_contract"]
        residual = cleanup["residual_remediation_evidence"]
        post_cleanup = cleanup["post_cleanup_revalidation"]
        claimed = cleanup.get("claimed", {})
        entries = journal["entries"]
        adds = {entry["rule_id"] for entry in entries if entry["operation"] == "ADD" and entry["result"] == "SUCCESS"}
        deletes = {entry["rule_id"] for entry in entries if entry["operation"] == "DELETE" and entry["result"] == "SUCCESS"}
        allowed = set(transient["allowed_rule_ids"])
        remaining = set(residual["remaining_transient_rules"])
    except (KeyError, TypeError) as exc:
        raise ContractError("CLEANUP_RECOMPUTATION_INPUT_MISSING") from exc
    if not adds:
        raise ContractError("CLEANUP_NO_SUCCESSFUL_ADD")
    if adds != deletes:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "successful add/delete sets differ")
    if set(journal.get("successful_add_ids", adds)) != adds or set(journal.get("successful_delete_ids", deletes)) != deletes:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "declared journal sets differ from recomputed sets")
    if not adds <= allowed:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "rule outside transient contract")
    if remaining:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "residual transient rules remain")
    if residual.get("baseline_rule_dump_sha256_after") != pre.get("baseline_rule_dump_sha256"):
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "baseline hash differs")
    if residual.get("persistent_rule_files_sha256_after") != pre.get("persistent_rule_files_sha256"):
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "persistent rule file hash differs")
    if journal.get("global_delete_observed") is not False:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "global delete observed")
    if post_cleanup.get("performed_after_all_reads") is not True:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "post-cleanup revalidation missing")
    if post_cleanup.get("audit_lost_events") != 0 or post_cleanup.get("audit_backlog") != 0:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "audit not drained")
    if residual.get("run_owned_children_remaining") != 0 or residual.get("reserved_test_interfaces_remaining") != 0 or residual.get("reserved_test_ovs_objects_remaining") != 0 or residual.get("tcpdump_process_remaining") != 0:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "residual process or network objects remain")
    if residual.get("topology_residue_zero") is not True or residual.get("child_residue_zero") is not True or residual.get("tcpdump_residue_zero") is not True:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "residual topology state remains")
    if claimed and claimed.get("inverse_complete") is not True:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "claim is false")
    if claimed and claimed.get("baseline_restored") is not True:
        raise ContractError("CLEANUP_RECOMPUTATION_MISMATCH", "baseline claim is false")
    return {"status": "PASS", "successful_add_ids": sorted(adds), "successful_delete_ids": sorted(deletes)}


def validate_handoff_shape(candidate: dict[str, Any]) -> dict[str, Any]:
    """Check fail-closed statuses and operator references used by a candidate."""

    if not isinstance(candidate, dict):
        raise ContractError("HANDOFF_NOT_OBJECT")
    if candidate.get("template_status") == "NOT_RUNTIME_EVIDENCE" or candidate.get("must_not_be_consumed") is True or candidate.get("runtime_evidence_present") is False:
        raise ContractError("TEMPLATE_NOT_RUNTIME_EVIDENCE")
    refs = candidate.get("operator_references", [])
    if not isinstance(refs, list):
        raise ContractError("OPERATOR_REFERENCE_SHAPE")
    known = _operator_ids()
    unknown = [ref for ref in refs if ref not in known]
    if unknown:
        raise ContractError("UNKNOWN_OPERATOR", ",".join(unknown))
    compatibility = candidate.get("producer_compatibility")
    if isinstance(compatibility, dict) and compatibility.get("receipt_emission_status") != "IMPLEMENTED":
        raise ContractError("PRODUCER_RECEIPT_EMISSION_NOT_IMPLEMENTED")
    lineage = candidate.get("source_lineage")
    if isinstance(lineage, dict):
        disposition = lineage.get("disposition")
        if disposition != "AUTHENTICATED_COMMITTED_SOURCE":
            raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED")
        committed = lineage.get("committed_source", lineage)
        if committed.get("hashes_match") is False or not committed.get("resolved_commit"):
            raise ContractError("SOURCE_LINEAGE_NOT_AUTHENTICATED")
    return {"status": "PASS"}


def validate_operator_registry_and_rules() -> dict[str, Any]:
    """Validate the registry shape and every rule operator reference."""

    registry = load_json_strict(REGISTRY_PATH)
    operators = registry.get("operators")
    if not isinstance(operators, list) or not operators:
        raise ContractError("OPERATOR_REGISTRY_SHAPE")
    required_fields = {
        "operator_id", "input_shape", "evaluation_procedure", "canonicalization",
        "success_condition", "failure_disposition", "ambiguity_behavior",
        "duplicate_handling", "ordering_semantics", "error_propagation",
    }
    for operator in operators:
        if not isinstance(operator, dict) or set(required_fields) - set(operator):
            raise ContractError("OPERATOR_SEMANTICS_INCOMPLETE")
    return validate_operator_references()
