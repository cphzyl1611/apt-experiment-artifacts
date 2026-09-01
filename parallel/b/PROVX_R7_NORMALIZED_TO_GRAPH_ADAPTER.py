"""Deterministic Stage-A adapter for the pinned PROVX R5 evidence.

The adapter is deliberately a small, evidence-first boundary.  It validates
the R5 JSONL hash links before consuming an event, quarantines records whose
identity cannot be joined without guessing, builds a reversible causal graph,
and delegates the final 32-dimensional representation to the frozen R4
encoder.  It never loads the packaged 21D checkpoint and never performs
training or host actions.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from PROVX_R4_ENCODER_IMPLEMENTATION import EncodedGraph, encode_records, encoded_to_jsonable


R5_RUN_ID = "e1c-r5-run-20260831T111849Z"
R5_REVIEW_COMMIT = "64854aeb8ad688b4423d600193fa6be5c2cbc390"
PINNED_LATEST_FIXED_COMMIT = "107ef9f69a734a10b320d552cfe18a6cb9a2ac0c"
ENCODER_ID = "provx-adapted-live-v1"
RAW_NAME = "MININET_E1C_R5_RAW_AUDIT_EVIDENCE.jsonl"
NORMALIZED_NAME = "MININET_E1C_R5_NORMALIZED_EVENTS.jsonl"
JOIN_NAME = "MININET_E1C_R5_PID_NETNS_JOIN.jsonl"
REVIEW_NAME = "MININET_E1C_R5_RUNTIME_EVIDENCE_REVIEW.json"
REQUIRED_CLASSES = [
    "PROCESS_START_OR_EXEC", "PROCESS_EXIT", "FILE_CREATE_OR_OPEN",
    "FILE_READ_OR_WRITE", "FILE_DELETE", "SOCKET_BIND", "SOCKET_CONNECT",
    "SOCKET_ACCEPT",
]


class AdapterError(ValueError):
    """Raised for an input that cannot satisfy the frozen adapter contract."""


@dataclass(frozen=True)
class RuntimeInputDescriptor:
    """Explicit, immutable binding for one authenticated runtime evidence set.

    No discovery or filename guessing is performed.  A caller must bind every
    input path (and expected SHA-256) before authentication or graph building.
    ``for_r5`` is the compatibility-preserving historical default; R6 callers
    construct this descriptor explicitly with the R6 run ID and paths.
    """

    run_id: str
    raw_path: Path
    normalized_path: Path
    join_path: Path
    coverage_path: Path
    runtime_review_path: Path
    pcap_path: Path
    pcap_hash_source: Path | None = None
    expected_sha256: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if not _text(self.run_id):
            raise AdapterError("runtime descriptor run_id is required")
        for name in (
            "raw_path", "normalized_path", "join_path", "coverage_path",
            "runtime_review_path", "pcap_path",
        ):
            value = getattr(self, name)
            if not isinstance(value, Path):
                object.__setattr__(self, name, Path(value))
        if self.pcap_hash_source is not None and not isinstance(self.pcap_hash_source, Path):
            object.__setattr__(self, "pcap_hash_source", Path(self.pcap_hash_source))
        if self.pcap_hash_source is None:
            raise AdapterError("pcap_hash_source must be explicitly bound")
        if self.expected_sha256 is not None and not isinstance(self.expected_sha256, dict):
            raise AdapterError("expected_sha256 must be a mapping")

    @classmethod
    def for_r5(cls, evidence_dir: str | Path) -> "RuntimeInputDescriptor":
        """Return the explicit descriptor for the historical R5 fixture."""
        root = Path(evidence_dir)
        review_path = root / REVIEW_NAME
        review = json.loads(review_path.read_text(encoding="utf-8"))
        expected = {
            name: (value.get("sha256") if isinstance(value, dict) else value)
            for name, value in review.get("artifact_hashes_sha256", {}).items()
        }
        expected[REVIEW_NAME] = sha256_bytes(review_path.read_bytes())
        return cls(
            run_id=R5_RUN_ID,
            raw_path=root / RAW_NAME,
            normalized_path=root / NORMALIZED_NAME,
            join_path=root / JOIN_NAME,
            coverage_path=root / "MININET_E1C_R5_COVERAGE_AND_LOSS.json",
            runtime_review_path=review_path,
            pcap_path=root / "MININET_E1C_R5_SMOKE.pcap",
            pcap_hash_source=root / "MININET_E1C_R5_POST_CLEANUP.json",
            expected_sha256=expected,
        )

    @property
    def selected_paths(self) -> dict[str, Path]:
        paths = {
            "raw": self.raw_path,
            "normalized": self.normalized_path,
            "join": self.join_path,
            "coverage": self.coverage_path,
            "runtime_review": self.runtime_review_path,
            "pcap": self.pcap_path,
        }
        if self.pcap_hash_source is None:  # Guarded by __post_init__; narrows the type.
            raise AdapterError("pcap_hash_source must be explicitly bound")
        paths["pcap_hash_source"] = self.pcap_hash_source
        return paths


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _timestamp_ms(record: dict[str, Any]) -> int:
    # R5 emits an epoch-seconds string.  Keep the fractional component exactly
    # enough to produce a deterministic integer millisecond ordering.
    raw = record.get("timestamp_ms", record.get("timestamp_source"))
    if raw is None:
        raise AdapterError("timestamp is required")
    number = float(raw)
    if not math.isfinite(number):
        raise AdapterError("timestamp must be finite")
    if "timestamp_ms" in record:
        value = number
    else:
        value = number * 1000.0
    if not value.is_integer():
        # Collector timestamps have microsecond precision.  Round once, and
        # record the original source in the evidence mapping.
        value = round(value)
    return int(value)


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AdapterError(f"invalid JSON at {path}:{line_no}") from exc
        if not isinstance(row, dict):
            raise AdapterError(f"JSONL row is not an object at {path}:{line_no}")
        rows.append(row)
    return rows


def _json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"invalid JSON object at {path}") from exc
    if not isinstance(value, dict):
        raise AdapterError(f"JSON document is not an object: {path}")
    return value


def _expected_hash_for(path: Path, expected_sha256: dict[str, str]) -> str | None:
    """Resolve only an explicitly supplied exact-path or basename binding."""
    for key in (str(path), path.name):
        if key in expected_sha256:
            value = expected_sha256[key]
            if isinstance(value, dict):
                value = value.get("sha256")
            if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value):
                return value.lower()
            return None
    return None


def _recursive_values(value: Any, key: str) -> list[Any]:
    values: list[Any] = []
    if isinstance(value, dict):
        for name, child in value.items():
            if name == key:
                values.append(child)
            values.extend(_recursive_values(child, key))
    elif isinstance(value, list):
        for child in value:
            values.extend(_recursive_values(child, key))
    return values


def authenticate_runtime_evidence(descriptor: RuntimeInputDescriptor) -> dict[str, Any]:
    """Authenticate one explicitly bound runtime evidence set.

    Every graph input is selected by the immutable descriptor and must have an
    expected SHA-256 before any JSONL row is made available to the adapter.
    Links are recomputed from the encoded raw bytes; a failed link is fatal.
    """
    if not isinstance(descriptor, RuntimeInputDescriptor):
        raise AdapterError("runtime evidence requires RuntimeInputDescriptor")
    expected_sha256 = descriptor.expected_sha256 or {}
    selected_authentication: dict[str, Any] = {}
    for label, path in descriptor.selected_paths.items():
        expected = _expected_hash_for(path, expected_sha256)
        present = path.exists() and path.is_file()
        actual = sha256_bytes(path.read_bytes()) if present else None
        selected_authentication[label] = {
            "path": str(path), "present": present, "expected_sha256": expected,
            "actual_sha256": actual, "bytes": path.stat().st_size if present else None,
            "status": "PASS" if present and expected is not None and actual == expected else "BLOCKED",
        }
    if not all(row["status"] == "PASS" for row in selected_authentication.values()):
        raise AdapterError("selected runtime evidence file authentication failed")

    review_path = descriptor.runtime_review_path
    review = _json_object(review_path)
    if review.get("run_id") != descriptor.run_id:
        raise AdapterError("runtime review run_id does not match descriptor")
    raw = load_jsonl(descriptor.raw_path)
    normalized = load_jsonl(descriptor.normalized_path)
    joins = load_jsonl(descriptor.join_path)
    coverage = _json_object(descriptor.coverage_path)
    if coverage.get("run_id") != descriptor.run_id:
        raise AdapterError("coverage run_id does not match descriptor")

    for row in raw + normalized + joins:
        row_run_id = row.get("run_id")
        if row_run_id is not None and row_run_id != descriptor.run_id:
            raise AdapterError("runtime evidence row run_id does not match descriptor")

    raw_by_serial: dict[int, dict[str, Any]] = {}
    raw_serial_duplicates: list[int] = []
    for row in raw:
        serial = row.get("serial", row.get("raw_serial"))
        if not isinstance(serial, int):
            raise AdapterError("raw serial must be an integer")
        if serial in raw_by_serial:
            raw_serial_duplicates.append(serial)
        raw_by_serial[serial] = row

    serial_pass: list[int] = []
    hash_pass: list[int] = []
    link_pass: list[int] = []
    link_failures: list[dict[str, Any]] = []
    normalized_serials: set[int] = set()
    for row in normalized:
        serial = row.get("raw_serial")
        if not isinstance(serial, int):
            raise AdapterError("normalized raw_serial must be an integer")
        if serial in normalized_serials:
            raise AdapterError("duplicate normalized raw_serial")
        normalized_serials.add(serial)
        raw_row = raw_by_serial.get(serial)
        checks = {
            "serial_present": raw_row is not None,
            "normalized_hash_matches_decoded": False,
            "raw_hash_matches_decoded": False,
            "normalized_hash_matches_raw": False,
        }
        blob = b""
        if raw_row is not None:
            serial_pass.append(serial)
            try:
                blob = base64.b64decode(row.get("raw_event_bytes_b64", ""), validate=True)
                checks["normalized_hash_matches_decoded"] = row.get("raw_event_sha256") == sha256_bytes(blob)
                raw_blob = base64.b64decode(raw_row.get("raw_bytes_b64", ""), validate=True)
                checks["raw_hash_matches_decoded"] = raw_row.get("raw_sha256") == sha256_bytes(raw_blob)
                checks["normalized_hash_matches_raw"] = (
                    row.get("raw_event_sha256") == raw_row.get("raw_sha256")
                    and blob == raw_blob
                )
            except (binascii.Error, ValueError, TypeError):
                pass
        if checks["normalized_hash_matches_decoded"] and checks["raw_hash_matches_decoded"]:
            hash_pass.append(serial)
        if all(checks.values()):
            link_pass.append(serial)
        else:
            link_failures.append({"raw_serial": serial, "checks": checks})

    if link_failures or raw_serial_duplicates:
        raise AdapterError("raw/normalized evidence link authentication failed")

    if descriptor.pcap_hash_source is None:  # Guarded by descriptor construction.
        raise AdapterError("pcap_hash_source must be explicitly bound")
    pcap_hash_values = _recursive_values(_json_object(descriptor.pcap_hash_source), "pcap_sha256")
    pcap_hashes = {str(value).lower() for value in pcap_hash_values if isinstance(value, str) and value}
    actual_pcap_hash = sha256_bytes(descriptor.pcap_path.read_bytes())
    if not pcap_hashes or actual_pcap_hash not in pcap_hashes:
        raise AdapterError("pcap hash source does not authenticate pcap")

    review_links = review.get("normalized_raw_link_review", {})
    expected_artifacts = review.get("artifact_hashes_sha256", {})
    artifact_authentication: dict[str, Any] = {}
    for name, expected in expected_artifacts.items():
        path = review_path.parent / name
        present = path.exists() and path.is_file()
        actual = sha256_bytes(path.read_bytes()) if present else None
        artifact_authentication[name] = {
            "path": str(path), "present": present, "expected_sha256": expected.get("sha256") if isinstance(expected, dict) else expected,
            "actual_sha256": actual, "bytes": path.stat().st_size if present else None,
            "status": "PASS" if present and actual == (expected.get("sha256") if isinstance(expected, dict) else expected) else "BLOCKED",
        }
    return {
        "schema": "PROVX_R7_RUNTIME_EVIDENCE_AUTHENTICATION_V1",
        "run_id": descriptor.run_id,
        "source_review": str(review_path),
        "pinned_review_commit": R5_REVIEW_COMMIT,
        "pinned_latest_fixed_commit": PINNED_LATEST_FIXED_COMMIT,
        "review_runtime_classification": review.get("decision"),
        "reviewed_artifact_hashes": review.get("artifact_hashes_sha256", {}),
        "required_artifact_authentication": artifact_authentication,
        "all_required_artifacts_authenticated": all(row["status"] == "PASS" for row in artifact_authentication.values()),
        "selected_file_authentication": selected_authentication,
        "all_selected_files_authenticated": all(row["status"] == "PASS" for row in selected_authentication.values()),
        "raw_record_count": len(raw),
        "normalized_event_count": len(normalized),
        "pid_netns_join_record_count": len(joins),
        "raw_serials_unique": not raw_serial_duplicates,
        "duplicate_raw_serials": sorted(set(raw_serial_duplicates)),
        "independent_recomputation": {
            "serial_links": f"{len(serial_pass)}/{len(normalized)}",
            "decoded_byte_hash_links": f"{len(hash_pass)}/{len(normalized)}",
            "raw_event_sha256_matches_raw_sha256": f"{len(link_pass)}/{len(normalized)}",
            "consumed_records": len(link_pass),
            "status": "PASS" if len(link_pass) == len(normalized) and not raw_serial_duplicates else "BLOCKED",
        },
        "historical_normalized_raw_links_valid": review_links.get("coverage_declared_normalized_raw_links_valid"),
        "historical_discrepancy_recorded": (
            review_links.get("coverage_declared_normalized_raw_links_valid") is False
            and len(link_pass) == len(normalized)
        ),
        "link_failures": link_failures,
        "required_classes": REQUIRED_CLASSES,
        "normalized_class_counts": review.get("normalized_audit_class_counts", {}),
        "file_read_or_write_present": review.get("normalized_audit_class_counts", {}).get("FILE_READ_OR_WRITE", 0) > 0,
        "audit_lost_events": review.get("audit", {}).get("AUDIT_LOST_EVENTS"),
        "namespace_assertions": review.get("namespace_assertions", {}),
        "network": review.get("network", {}),
        "hard_boundaries": review.get("hard_boundaries", {}),
        "coverage": coverage,
        "source_files": {label: sha256_bytes(path.read_bytes()) for label, path in descriptor.selected_paths.items()},
        "_raw": raw,
        "_normalized": normalized,
        "_joins": joins,
        "_consumed_serials": sorted(link_pass),
    }


def authenticate_r5_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    """Compatibility wrapper preserving the historical R5 route."""
    auth = authenticate_runtime_evidence(RuntimeInputDescriptor.for_r5(evidence_dir))
    # Keep the historical schema marker for callers that persisted this object.
    auth["schema"] = "PROVX_R7_R5_EVIDENCE_AUTHENTICATION_V1"
    auth["run_id"] = R5_RUN_ID
    auth["pinned_review_commit"] = R5_REVIEW_COMMIT
    auth["pinned_latest_fixed_commit"] = PINNED_LATEST_FIXED_COMMIT
    return auth


def _join_by_pid(joins: Iterable[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    result: dict[tuple[str, int], dict[str, Any]] = {}
    for row in joins:
        host = row.get("logical_host_id")
        process = row.get("process", {})
        pid = process.get("pid", row.get("pid")) if isinstance(process, dict) else row.get("pid")
        if _text(host) and isinstance(pid, int):
            result[(_text(host), pid)] = row
    return result


def _file_identity_paths(event: dict[str, Any]) -> list[str]:
    identity = event.get("file_identity")
    values = identity.get("paths", []) if isinstance(identity, dict) else []
    return [_text(value) for value in values] if isinstance(values, list) else []


def _process_entity(host: str, pid: int, start_ticks: int, event: dict[str, Any]) -> dict[str, Any]:
    executable = event.get("executable") or {}
    if not isinstance(executable, dict):
        executable = {}
    command_line = executable.get("proctitle")
    image_path = executable.get("path")
    entity: dict[str, Any] = {
        "host_id": host, "type": "PROCESS",
        "id": f"pid:{pid}:start:{start_ticks}",
        "pid": pid, "ppid": event.get("ppid"),
    }
    if image_path:
        entity["image_path"] = image_path
        entity["executable"] = image_path
    if command_line:
        entity["command_line"] = command_line
    if event.get("user"):
        entity["user"] = event["user"]
    return entity


def _file_entity(host: str, event: dict[str, Any], *, run_id: str) -> dict[str, Any]:
    path = _text(event.get("path"))
    paths = _file_identity_paths(event)
    if not path:
        path = next((_text(value) for value in reversed(paths) if _text(value)), "")
    if not path:
        raise AdapterError("file identity path is required")
    file_id = f"path:{path}" if run_id == R5_RUN_ID else f"host:{host}|path:{path}"
    return {"host_id": host, "type": "FILE", "id": file_id, "path": path}


def _socket_entity(host: str, event: dict[str, Any]) -> dict[str, Any]:
    identity = event.get("socket_identity")
    if not isinstance(identity, dict):
        raise AdapterError("socket identity is required")
    family = _text(identity.get("family")).casefold()
    local_address = identity.get("local_address")
    remote_address = identity.get("remote_address")
    local_port = identity.get("local_port")
    remote_port = identity.get("remote_port")
    if not family or (local_address is None and remote_address is None and local_port is None and remote_port is None):
        raise AdapterError("socket endpoint identity is incomplete")
    # R5's authenticated runtime review records a completed TCP handshake.
    # The pcap is not consulted for graph edges; this is only a socket feature.
    protocol = "tcp" if family in {"inet", "inet6"} else family
    identity_key = canonical_json({
        "family": family, "local_address": local_address, "local_port": local_port,
        "remote_address": remote_address, "remote_port": remote_port,
    })
    entity: dict[str, Any] = {
        "host_id": host, "type": "SOCKET", "id": "socket:" + sha256_bytes((host + "|" + identity_key).encode()),
        "socket_id": identity_key, "protocol": protocol,
    }
    for key, value in (("local_address", local_address), ("local_port", local_port), ("remote_address", remote_address), ("remote_port", remote_port)):
        if value is not None:
            if key.endswith("_port"):
                try:
                    value = int(value)
                except (TypeError, ValueError) as exc:
                    raise AdapterError(f"invalid socket port: {value!r}") from exc
            entity[key] = value
    return entity


def _event_class(event_type: str) -> str:
    return {
        "PROCESS_START_OR_EXEC": "execute",
        "PROCESS_EXIT": "close_delete",
        "FILE_CREATE_OR_OPEN": "read_open",
        "FILE_READ_OR_WRITE": "write",
        "FILE_DELETE": "close_delete",
        "SOCKET_BIND": "connect_send",
        "SOCKET_CONNECT": "connect_send",
        "SOCKET_ACCEPT": "connect_send",
    }.get(event_type, "other")


@dataclass(frozen=True)
class GraphBuild:
    encoder_records: list[dict[str, Any]]
    node_map: list[dict[str, Any]]
    edge_map: list[dict[str, Any]]
    reversibility: dict[str, Any]
    quarantine: list[dict[str, Any]]
    manifest: dict[str, Any]


def build_graph(records: Iterable[dict[str, Any]], joins: Iterable[dict[str, Any]], *, run_id: str = R5_RUN_ID) -> GraphBuild:
    """Build graph records from consumed normalized records only."""
    rows = list(records)
    join_by_pid = _join_by_pid(joins)
    starts: dict[tuple[str, int], int] = {}
    for event in rows:
        host = _text(event.get("logical_host_id"))
        pid, ticks = event.get("pid"), event.get("pid_start_time_ticks")
        if host and isinstance(pid, int) and isinstance(ticks, int):
            starts.setdefault((host, pid), ticks)
    candidates: list[dict[str, Any]] = []
    quarantine: list[dict[str, Any]] = []
    for event in rows:
        serial = event.get("raw_serial")
        reason: str | None = None
        host = _text(event.get("logical_host_id"))
        pid, ticks = event.get("pid"), event.get("pid_start_time_ticks")
        if event.get("run_id") != run_id:
            reason = "run_boundary_mismatch"
        elif not _text(event.get("event_id")) or not isinstance(event.get("raw_serial"), int) or not re.fullmatch(r"[0-9a-fA-F]{64}", _text(event.get("raw_event_sha256"))):
            reason = "missing_event_evidence_identity"
        elif event.get("join_status") != "JOINED" or not host or not isinstance(event.get("netns_inode"), int):
            reason = "missing_or_unjoined_logical_host_identity"
        elif not isinstance(pid, int) or not isinstance(ticks, int):
            reason = "missing_process_pid_or_start_time_identity"
        elif (host, pid) not in join_by_pid:
            reason = "pid_netns_join_not_authenticated"
        else:
            join = join_by_pid[(host, pid)]
            join_process = join.get("process", {}) if isinstance(join.get("process"), dict) else {}
            join_ticks = join_process.get("start_ticks", join.get("start_ticks"))
            if (
                join.get("join_status") != "JOINED"
                or join.get("netns_inode") != event.get("netns_inode")
                or join_ticks != ticks
            ):
                reason = "pid_netns_join_not_authenticated"
        file_paths = _file_identity_paths(event)
        if reason is None and event.get("event_type") in {"FILE_CREATE_OR_OPEN", "FILE_READ_OR_WRITE", "FILE_DELETE"} and not _text(event.get("path")) and not file_paths:
            reason = "missing_file_identity"
        elif reason is None and event.get("event_type") == "FILE_READ_OR_WRITE" and (
            event.get("evidence_basis") != "AUDIT_FILESYSTEM_PERMISSION_FILTER"
            or not _text(event.get("watched_path"))
            or not _text(event.get("watched_path")).startswith("/")
            or event.get("requested_access") not in {"r", "w", "rw"}
            or not _text(event.get("underlying_syscall"))
            or _text(event.get("watched_path")) not in set(file_paths + [_text(event.get("path"))])
        ):
            reason = "missing_file_read_write_permission_evidence"
        elif reason is None and event.get("event_type") in {"SOCKET_BIND", "SOCKET_CONNECT", "SOCKET_ACCEPT"} and not isinstance(event.get("socket_identity"), dict):
            reason = "missing_socket_identity"
        elif reason is None:
            try:
                _timestamp_ms(event)
            except (AdapterError, TypeError, ValueError) as exc:
                reason = f"invalid_timestamp:{exc}"
        if reason:
            quarantine.append({"raw_serial": serial, "event_id": event.get("event_id"), "reason": reason})
        else:
            candidates.append(event)

    # First pass creates the stable process identity universe.  Parent edges
    # are emitted only when the parent has an authenticated identity.
    entities: dict[str, dict[str, Any]] = {}
    entity_refs: dict[str, set[str]] = {}
    edge_inputs: list[dict[str, Any]] = []
    for event in candidates:
        event_type = event.get("event_type")
        host = _text(event["logical_host_id"])
        pid, ticks = int(event["pid"]), int(event["pid_start_time_ticks"])
        process = _process_entity(host, pid, ticks, event)
        process_id = process["id"]
        entities[process_id] = process
        entity_refs.setdefault(process_id, set()).add(str(event.get("event_id", event.get("raw_serial"))))

        if event_type in {"FILE_CREATE_OR_OPEN", "FILE_READ_OR_WRITE", "FILE_DELETE"}:
            try:
                destination = _file_entity(host, event, run_id=run_id)
            except AdapterError as exc:
                quarantine.append({"raw_serial": event.get("raw_serial"), "event_id": event.get("event_id"), "reason": str(exc)})
                continue
            src, dst = process, destination
        elif event_type in {"SOCKET_BIND", "SOCKET_CONNECT"}:
            try:
                destination = _socket_entity(host, event)
            except AdapterError as exc:
                quarantine.append({"raw_serial": event.get("raw_serial"), "event_id": event.get("event_id"), "reason": str(exc)})
                continue
            src, dst = process, destination
        elif event_type == "SOCKET_ACCEPT":
            try:
                destination = _socket_entity(host, event)
            except AdapterError as exc:
                quarantine.append({"raw_serial": event.get("raw_serial"), "event_id": event.get("event_id"), "reason": str(exc)})
                continue
            src, dst = destination, process
        else:
            # Process start/exit records are incident self-loops unless an
            # authenticated parent identity is available for a child start.
            parent_pid = event.get("ppid")
            parent_ticks = starts.get((host, parent_pid)) if isinstance(parent_pid, int) else None
            if event_type == "PROCESS_START_OR_EXEC" and parent_ticks is not None and parent_pid != pid:
                src = _process_entity(host, parent_pid, parent_ticks, event)
                entities[src["id"]] = src
                entity_refs.setdefault(src["id"], set()).add(str(event.get("event_id", event.get("raw_serial"))))
                dst = process
            else:
                src = dst = process

        entities[src["id"]] = src
        entities[dst["id"]] = dst
        entity_refs.setdefault(src["id"], set()).add(str(event.get("event_id", event.get("raw_serial"))))
        entity_refs.setdefault(dst["id"], set()).add(str(event.get("event_id", event.get("raw_serial"))))
        event_id = str(event.get("event_id", f"serial-{event.get('raw_serial')}"))
        edge_inputs.append({
            "event": event, "src": src, "dst": dst, "event_id": event_id,
            "event_type": _event_class(str(event_type)), "timestamp_ms": _timestamp_ms(event),
        })

    node_ids = sorted(entities, key=lambda value: (entities[value]["host_id"], {"PROCESS": 0, "FILE": 1, "SOCKET": 2, "OTHER": 3}[entities[value]["type"]], value))
    model_index = {node_id: index for index, node_id in enumerate(node_ids)}
    edge_inputs.sort(key=lambda item: (item["timestamp_ms"], model_index[item["src"]["id"]], model_index[item["dst"]["id"]], {"create": 0, "read_open": 1, "write": 2, "execute": 3, "connect_send": 4, "close_delete": 5, "other": 6}[item["event_type"]], item["event_id"]))

    encoder_records: list[dict[str, Any]] = []
    edge_map: list[dict[str, Any]] = []
    seen: dict[tuple[str, str, str, str], int] = {}
    for item in edge_inputs:
        key = (item["src"]["id"], item["dst"]["id"], item["event_type"], item["event_id"])
        if key in seen:
            edge_map[seen[key]]["coalesced_event_ids"].append(item["event_id"])
            continue
        event = item["event"]
        encoder_records.append({
            "id": item["event_id"], "timestamp_ms": item["timestamp_ms"],
            "event_type": item["event_type"], "source": item["src"], "destination": item["dst"],
        })
        column = len(edge_map)
        seen[key] = column
        edge_map.append({
            "input_edge_column": column,
            "src_graph_node_id": item["src"]["id"], "dst_graph_node_id": item["dst"]["id"],
            "src_model_node_index": model_index[item["src"]["id"]], "dst_model_node_index": model_index[item["dst"]["id"]],
            "normalized_event_id": item["event_id"], "raw_serial": event.get("raw_serial"),
            "raw_event_sha256": event.get("raw_event_sha256"), "event_type": item["event_type"],
            "timestamp_ms": item["timestamp_ms"], "coalesced_event_ids": [item["event_id"]],
        })

    node_map = []
    for index, node_id in enumerate(node_ids):
        entity = entities[node_id]
        node_map.append({
            "graph_node_id": node_id, "model_node_index": index, "host_id": entity["host_id"],
            "entity_type": entity["type"].casefold(), "canonical_entity_id": node_id,
            "source_normalized_event_ids": sorted(entity_refs.get(node_id, set())),
        })
    reversibility = {
        "schema": "PROVX_R7_R5_GRAPH_RAW_REVERSIBILITY_V1",
        "graph_node_id_to_evidence": {
            row["graph_node_id"]: {"normalized_event_ids": row["source_normalized_event_ids"], "raw_serials": sorted({edge["raw_serial"] for edge in edge_map if edge["src_graph_node_id"] == row["graph_node_id"] or edge["dst_graph_node_id"] == row["graph_node_id"]})}
            for row in node_map
        },
        "edge_column_to_evidence": {str(edge["input_edge_column"]): {"normalized_event_ids": edge["coalesced_event_ids"], "raw_serials": [edge["raw_serial"]]} for edge in edge_map},
        "pcap_used_as_provenance_edge_evidence": False,
    }
    quarantine.sort(key=lambda row: (str(row.get("raw_serial")), str(row.get("event_id")), row.get("reason", "")))
    graph_payload = {"run_id": run_id, "nodes": node_map, "edges": edge_map, "encoder_records": encoder_records, "quarantine": quarantine}
    manifest = {
        "schema": "PROVX_R7_R5_PARTIAL_GRAPH_MANIFEST_V1", "run_id": run_id,
        "node_count": len(node_map), "edge_count": len(edge_map), "consumed_normalized_event_count": len(encoder_records),
        "quarantined_event_count": len(quarantine), "graph_sha256": sha256_json(graph_payload),
        "node_order": "(host_id, entity_type_rank, graph_node_id)",
        "edge_order": "(timestamp_ms, src_model_node_index, dst_model_node_index, event_class_rank, normalized_event_id)",
        "duplicate_policy": "coalesce exact (src,dst,event_class,event_id), preserving all evidence refs",
        "orphan_policy": "quarantine unjoined or missing process/file/socket identity; never guess",
        "run_boundary": run_id, "host_boundary": "logical_host_id plus authenticated netns join",
        "timestamp_policy": "collector timestamp_source normalized to integer epoch milliseconds; stable event_id tie-break",
        "file_read_or_write_present": any(item["event_type"] == "write" for item in edge_map),
    }
    return GraphBuild(encoder_records, node_map, edge_map, reversibility, quarantine, manifest)


def encode_graph(graph: GraphBuild, *, run_id: str = R5_RUN_ID) -> tuple[EncodedGraph, dict[str, Any]]:
    encoded = encode_records(graph.encoder_records, run_id=run_id, graph_id="r5-partial-stage-a")
    tensor_manifest = {
        "schema": "PROVX_R7_R5_32D_TENSOR_MANIFEST_V1", "run_id": run_id,
        "encoder_id": ENCODER_ID, "encoder_sha256": encoded.run_manifest["encoder_sha256"],
        "schema_sha256": encoded.run_manifest["schema_sha256"],
        "x": {"shape": list(encoded.x.shape), "dtype": str(encoded.x.dtype), "finite": bool(__import__("numpy").isfinite(encoded.x).all()), "sha256": sha256_bytes(encoded.x.tobytes())},
        "edge_index": {"shape": list(encoded.edge_index.shape), "dtype": str(encoded.edge_index.dtype), "sha256": sha256_bytes(encoded.edge_index.tobytes())},
        "graph_sha256": graph.manifest["graph_sha256"],
        "encoded_json_sha256": sha256_json(encoded_to_jsonable(encoded)),
        "checkpoint_loaded": False, "detector_trained": False, "formal_experiment_executed": False,
    }
    return encoded, tensor_manifest


def write_r7_outputs(
    evidence_dir: str | Path | None = None,
    output_dir: str | Path = ".",
    *,
    descriptor: RuntimeInputDescriptor | None = None,
) -> dict[str, Any]:
    """Regenerate adapter outputs from an explicitly authenticated descriptor.

    The positional ``evidence_dir`` form remains the reproducible historical
    R5 default.  A future R6 route must pass ``descriptor=`` explicitly.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    if descriptor is None:
        if evidence_dir is None:
            raise AdapterError("evidence_dir or explicit descriptor is required")
        descriptor = RuntimeInputDescriptor.for_r5(evidence_dir)
    auth = authenticate_runtime_evidence(descriptor)
    consumed = [row for row in auth["_normalized"] if row.get("raw_serial") in set(auth["_consumed_serials"])]
    run_id = descriptor.run_id
    graph = build_graph(consumed, auth["_joins"], run_id=run_id)
    encoded, tensor_manifest = encode_graph(graph, run_id=run_id)
    regen = build_graph(list(reversed(consumed)), auth["_joins"], run_id=run_id)
    regen_encoded, regen_tensor = encode_graph(regen, run_id=run_id)
    graph_hashes = [graph.manifest["graph_sha256"], regen.manifest["graph_sha256"]]
    deterministic = {
        "schema": "PROVX_R7_DETERMINISTIC_REGENERATION_VERIFICATION_V1", "run_id": run_id,
        "regenerations": 2, "graph_hashes": graph_hashes,
        "graph_hash_identical": graph_hashes[0] == graph_hashes[1],
        "x_hash_identical": tensor_manifest["x"]["sha256"] == regen_tensor["x"]["sha256"],
        "edge_index_hash_identical": tensor_manifest["edge_index"]["sha256"] == regen_tensor["edge_index"]["sha256"],
        "status": "PASS" if graph_hashes[0] == graph_hashes[1] and tensor_manifest["x"]["sha256"] == regen_tensor["x"]["sha256"] else "BLOCKED",
    }
    auth_public = {k: v for k, v in auth.items() if not k.startswith("_")}
    tensor_manifest["hash_chain"] = {
        "evidence_authentication_sha256": sha256_json(auth_public),
        "graph_manifest_sha256": sha256_json(graph.manifest),
        "graph_reversibility_sha256": sha256_json(graph.reversibility),
        "x_sha256": tensor_manifest["x"]["sha256"],
        "edge_index_sha256": tensor_manifest["edge_index"]["sha256"],
    }
    outputs = {
        "PROVX_R7_R5_EVIDENCE_AUTHENTICATION.json": auth_public,
        "PROVX_R7_NORMALIZED_GRAPH_INPUT_SCHEMA.json": normalized_graph_schema(),
        "PROVX_R7_R5_PARTIAL_GRAPH_MANIFEST.json": {**graph.manifest, "node_map": graph.node_map, "edge_map": graph.edge_map, "quarantine": graph.quarantine},
        "PROVX_R7_R5_GRAPH_RAW_REVERSIBILITY.json": graph.reversibility,
        "PROVX_R7_R5_32D_TENSOR_MANIFEST.json": tensor_manifest,
        "PROVX_R7_DETERMINISTIC_REGENERATION_VERIFICATION.json": deterministic,
        "PROVX_R7_E1C_R6_REVALIDATION_CONTRACT.json": revalidation_contract(),
    }
    for name, payload in outputs.items():
        (out / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = render_report(auth_public, graph, tensor_manifest, deterministic)
    (out / "PROVX_R7_STAGE_A_PARTIAL_ADAPTER_REPORT.md").write_text(report, encoding="utf-8")
    return {"auth": auth_public, "graph": graph, "tensor": tensor_manifest, "deterministic": deterministic, "encoded": encoded}


def normalized_graph_schema() -> dict[str, Any]:
    return {
        "schema": "PROVX_R7_NORMALIZED_GRAPH_INPUT_SCHEMA_V1", "status": "FROZEN_FOR_STAGE_A_DEVELOPMENT_FIXTURE",
        "mandatory_common": ["run_id", "event_id", "event_type", "raw_serial", "raw_event_sha256", "timestamp_source", "pid", "pid_start_time_ticks", "ppid", "logical_host_id", "netns_inode", "join_status"],
        "mandatory_by_event": {"PROCESS_START_OR_EXEC": ["pid", "pid_start_time_ticks"], "PROCESS_EXIT": ["pid", "pid_start_time_ticks"], "FILE_CREATE_OR_OPEN": ["path or file_identity.paths"], "FILE_READ_OR_WRITE": ["path or file_identity.paths", "evidence_basis=AUDIT_FILESYSTEM_PERMISSION_FILTER", "watched_path", "requested_access", "underlying_syscall"], "FILE_DELETE": ["path or file_identity.paths"], "SOCKET_BIND": ["socket_identity.family", "socket_identity endpoint"], "SOCKET_CONNECT": ["socket_identity.family", "socket_identity endpoint"], "SOCKET_ACCEPT": ["socket_identity.family", "socket_identity endpoint"]},
        "node_types": {"PROCESS": "host_id + pid + pid_start_time_ticks", "FILE": "host_id + canonical path", "SOCKET": "host_id + canonical family/endpoints", "OTHER": "not emitted without explicit stable identity"},
        "event_to_encoder_class": {"PROCESS_START_OR_EXEC": "execute", "PROCESS_EXIT": "close_delete", "FILE_CREATE_OR_OPEN": "read_open", "FILE_READ_OR_WRITE": "write", "FILE_DELETE": "close_delete", "SOCKET_BIND": "connect_send", "SOCKET_CONNECT": "connect_send", "SOCKET_ACCEPT": "connect_send"},
        "forbidden": ["FILE_READ_OR_WRITE synthesis without authenticated evidence", "pcap-derived provenance edges", "analyst labels", "21D checkpoint", "host actions"],
    }


def revalidation_contract() -> dict[str, Any]:
    return {
        "schema": "PROVX_R7_E1C_R6_REVALIDATION_CONTRACT_V1", "status": "WAITING_FOR_E1C_R6_FILE_RW",
        "required_inputs": ["fresh authenticated runtime review", "raw audit JSONL", "normalized JSONL", "PID/netns joins", "coverage/loss", "pcap hash"],
        "revalidation_steps": ["recompute serial and decoded-byte SHA256 links", "reject any failed links", "require FILE_READ_OR_WRITE > 0", "rebuild with the frozen schema", "regenerate twice and compare graph/tensor hashes", "verify 32D finite float32 and int64 edge_index"],
        "promotion_rule": "Stage-A full collector-adapter PASS remains NO until FILE_READ_OR_WRITE is present and all release gates pass",
        "training": False, "formal_experiment": False, "corpus_acquisition": False,
    }


def render_report(auth: dict[str, Any], graph: GraphBuild, tensor: dict[str, Any], deterministic: dict[str, Any]) -> str:
    status = "PASS_PARTIAL_WAITING_FOR_E1C_R6_FILE_RW" if deterministic["status"] == "PASS" else "BLOCKED"
    return f"""# PROVX-R7 Stage-A Partial Adapter Report\n\nPROVX_R7_STAGE_A_PARTIAL_ADAPTER = {status}\n\nR5_CONSUMED_NORMALIZED_RECORDS = {auth['independent_recomputation']['consumed_records']}\nR5_RAW_LINK_RECOMPUTATION = {auth['independent_recomputation']['status']}\nGRAPH_DETERMINISM = {deterministic['status']}\nGRAPH_TO_32D_TENSOR = {'PASS' if tensor['x']['finite'] and tensor['x']['shape'][1] == 32 else 'BLOCKED'}\n\nFILE_READ_OR_WRITE_PRESENT = NO\nSTAGE_A_FULL_COLLECTOR_ADAPTER_PASS = NO\n\nNodes: {graph.manifest['node_count']}\nEdges: {graph.manifest['edge_count']}\nQuarantined normalized records: {graph.manifest['quarantined_event_count']}\nGraph SHA-256: `{graph.manifest['graph_sha256']}`\nTensor x SHA-256: `{tensor['x']['sha256']}`\nEdge index SHA-256: `{tensor['edge_index']['sha256']}`\n\nThe historical R5 `normalized_raw_links_valid=false` declaration is retained as an artifact-quality discrepancy. Independent serial, decoded-byte, and raw-hash recomputation passed for every consumed record. Unjoined `ip` helper records and records missing mandatory identity are quarantined; no identity is guessed. FILE_READ_OR_WRITE edges are not synthesized, and pcap is not used as provenance edge evidence.\n\nCORPUS_ACQUIRED = NO\nDETECTOR_TRAINED = NO\nFORMAL_EXPERIMENT_EXECUTED = NO\n\nNEXT_ACTION = FRESH_REVIEW_OF_PROVX_R7_STAGE_A_PARTIAL_ADAPTER\n"""


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    args = parser.parse_args()
    result = write_r7_outputs(args.evidence_dir, args.output_dir)
    print(json.dumps({"status": result["deterministic"]["status"], "graph_sha256": result["graph"].manifest["graph_sha256"]}, sort_keys=True))
