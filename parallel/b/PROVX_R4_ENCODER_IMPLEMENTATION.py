"""Pure deterministic encoder for the frozen PROVX Track-L schema.

The converter accepts normalized provenance records only.  It has no access to
the packaged checkpoint, labels, benchmark data, or host-enforcement APIs.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import numbers
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np


ENCODER_ID = "provx-adapted-live-v1"
ENCODER_DIMENSION = 32
ENCODER_IDENTITY_SHA256 = "f27984513a39a004534f7bb409e3ff6410c48b442645656435c0534e64a15188"
SCHEMA_SHA256 = "53caab007f9cea84e83a5fb92ddea0cb9082cb816d19752db896cc58c675f68a"
SCHEMA_PATH = Path(__file__).with_name("PROVX_R3_ADAPTED_LIVE_FEATURE_SCHEMA.json")

FEATURE_NAMES = (
    "entity_process", "entity_file", "entity_socket", "entity_other",
    "entity_type_unknown", "entity_id_present", "process_pid_present",
    "process_ppid_present", "process_executable_present",
    "process_command_line_present", "process_user_present", "file_path_present",
    "file_hash_present", "socket_protocol_tcp", "socket_protocol_udp",
    "socket_local_endpoint_present", "socket_remote_endpoint_present",
    "socket_remote_external", "socket_port_present", "event_create_norm",
    "event_read_open_norm", "event_write_norm", "event_execute_norm",
    "event_connect_send_norm", "event_close_delete_norm", "event_other_norm",
    "event_count_norm", "in_degree_norm", "out_degree_norm",
    "first_seen_delta_norm", "last_seen_delta_norm", "unknown_field_fraction_norm",
)

ENTITY_RANK = {"process": 0, "file": 1, "socket": 2, "other": 3}
EVENT_RANK = {
    "create": 0,
    "read_open": 1,
    "write": 2,
    "execute": 3,
    "connect_send": 4,
    "close_delete": 5,
    "other": 6,
}
EVENT_ALIASES = {
    "create": {"create", "process_create", "file_create"},
    "read_open": {"read", "open", "file_read", "file_open"},
    "write": {"write", "file_write", "modify", "append"},
    "execute": {"execute", "exec", "process_execute", "command"},
    "connect_send": {"connect", "send", "network_connect", "network_send", "flow_start"},
    "close_delete": {"close", "delete", "unlink", "remove"},
}
TYPE_ALIASES = {
    "process": "process",
    "proc": "process",
    "file": "file",
    "regular_file": "file",
    "socket": "socket",
    "network_socket": "socket",
}
ALLOWED_FIELDS = {
    "process": {"pid", "ppid", "image_path", "executable", "executable_path", "command_line", "user", "principal"},
    "file": {"path", "file_path", "sha256", "hash", "file_hash"},
    "socket": {"protocol", "local_address", "local_port", "remote_address", "remote_port", "socket_id"},
    "other": set(),
}
PID_UNAVAILABLE = {"-1", "0", "00000000-0000-0000-0000-000000000000"}
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7")
)


class EncodingError(ValueError):
    """Raised when a normalized record cannot satisfy the frozen contract."""


class SchemaMismatchError(EncodingError):
    """Raised when the frozen R3 schema has been altered or is unavailable."""


@dataclass(frozen=True)
class EncodedGraph:
    x: np.ndarray
    edge_index: np.ndarray
    node_map: list[dict[str, Any]]
    edge_map: list[dict[str, Any]]
    normalization_map: dict[str, Any]
    run_manifest: dict[str, Any]


def _canonical_text(value: Any) -> str:
    return unicodedata.normalize("NFC", str(value).strip())


def _enum_token(value: Any) -> str:
    return _canonical_text(value).casefold()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _reject_nonfinite(value: Any, path: str) -> None:
    if isinstance(value, numbers.Real) and not isinstance(value, bool) and not math.isfinite(float(value)):
        raise EncodingError(f"non-finite value at {path}")
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_nonfinite(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_nonfinite(child, f"{path}[{index}]")


def _finite_number(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        raise EncodingError(f"numeric value required at {path}")
    number = float(value)
    if not math.isfinite(number):
        raise EncodingError(f"non-finite value at {path}")
    return number


def _timestamp(value: Any, path: str) -> int:
    number = _finite_number(value, path)
    if not number.is_integer():
        raise EncodingError(f"timestamp must be integral at {path}")
    return int(number)


def _available(value: Any, path: str) -> bool:
    if value is None:
        return False
    if isinstance(value, numbers.Real) and not isinstance(value, bool):
        number = _finite_number(value, path)
        return number not in (-1.0, 0.0)
    token = _canonical_text(value).casefold()
    return token not in PID_UNAVAILABLE


def _valid_port(value: Any, path: str) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError as exc:
            raise EncodingError(f"numeric value required at {path}") from exc
        if not math.isfinite(number):
            raise EncodingError(f"non-finite value at {path}")
    else:
        number = _finite_number(value, path)
    return number.is_integer() and 0 <= int(number) <= 65535


def _normalize_type(value: Any) -> tuple[str, bool]:
    if value is None:
        return "other", True
    token = _enum_token(value)
    normalized = TYPE_ALIASES.get(token)
    return (normalized, False) if normalized else ("other", True)


def _normalize_event(value: Any) -> str:
    if value is None:
        return "other"
    token = _enum_token(value)
    for event_name, aliases in EVENT_ALIASES.items():
        if token in aliases:
            return event_name
    return "other"


def _entity_id(entity: dict[str, Any], host_id: str, normalized_type: str, unknown_type: bool) -> tuple[str, bool]:
    raw_id = entity.get("id", entity.get("entity_id"))
    if raw_id is not None and _canonical_text(raw_id):
        return _canonical_text(raw_id), True
    if not unknown_type and normalized_type in {"process", "file", "socket"}:
        payload = _canonical_json({k: v for k, v in entity.items() if k not in {"id", "entity_id"}})
        return "missing:" + _sha256_text(host_id + "|" + normalized_type + "|" + payload), False
    raise EncodingError("entity identity is missing for unknown/other entity")


def _normalized_entity(entity: Any) -> dict[str, Any]:
    if not isinstance(entity, dict):
        raise EncodingError("source and destination entities must be objects")
    _reject_nonfinite(entity, "entity")
    if "host_id" not in entity or not _canonical_text(entity["host_id"]):
        raise EncodingError("entity host_id is required")
    host_id = _canonical_text(entity["host_id"])
    normalized_type, unknown_type = _normalize_type(entity.get("type", entity.get("entity_type")))
    canonical_id, id_present = _entity_id(entity, host_id, normalized_type, unknown_type)
    fields = {k: v for k, v in entity.items() if k not in {"host_id", "type", "entity_type", "id", "entity_id"}}
    return {
        "host_id": host_id,
        "entity_type": normalized_type,
        "entity_type_unknown": unknown_type,
        "canonical_entity_id": canonical_id,
        "entity_id_present": id_present,
        "fields": fields,
    }


def _entity_key(entity: dict[str, Any]) -> tuple[str, int, str]:
    return (entity["host_id"], ENTITY_RANK[entity["entity_type"]], entity["canonical_entity_id"])


def _merge_field(aggregate: dict[str, set[str]], key: str, value: Any) -> None:
    aggregate.setdefault(key, set()).add(_canonical_text(value))


def _norm_count(value: int) -> float:
    return float(np.clip(np.log1p(value) / np.log1p(1024), 0.0, 1.0))


def _norm_time(delta_seconds: int) -> float:
    return float(np.clip(delta_seconds / 3600.0, 0.0, 1.0))


def _one_value(fields: dict[str, set[str]], names: set[str]) -> str | None:
    values = [value for key in names for value in fields.get(key, set())]
    return sorted(values)[0] if values else None


def _has_field(fields: dict[str, set[str]], names: set[str]) -> bool:
    return any(fields.get(name) for name in names)


def _address_is_external(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not any(address in network for network in PRIVATE_NETWORKS)


def verify_frozen_schema(schema_path: str | Path = SCHEMA_PATH) -> dict[str, Any]:
    path = Path(schema_path)
    if not path.exists():
        raise SchemaMismatchError(f"frozen schema not found: {path}")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SCHEMA_SHA256:
        raise SchemaMismatchError(f"schema sha256 mismatch: {digest}")
    schema = json.loads(raw.decode("utf-8"))
    identity = schema.get("encoder", {}).get("identity_payload")
    identity_digest = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    if identity_digest != ENCODER_IDENTITY_SHA256:
        raise SchemaMismatchError(f"encoder identity mismatch: {identity_digest}")
    if schema.get("encoder", {}).get("encoder_id") != ENCODER_ID or schema.get("encoder", {}).get("output_dimension") != ENCODER_DIMENSION:
        raise SchemaMismatchError("encoder ID or dimension changed")
    if len(schema.get("feature_columns", [])) != ENCODER_DIMENSION:
        raise SchemaMismatchError("feature column count changed")
    return schema


def _implementation_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def encode_records(
    records: Iterable[dict[str, Any]],
    *,
    run_id: str,
    graph_id: str = "live-subgraph",
    schema_path: str | Path = SCHEMA_PATH,
) -> EncodedGraph:
    """Encode normalized provenance records into the frozen Track-L graph contract."""
    verify_frozen_schema(schema_path)
    run_id = _canonical_text(run_id)
    graph_id = _canonical_text(graph_id)
    if not run_id:
        raise EncodingError("run_id is required")
    records_list = list(records)
    if not records_list:
        raise EncodingError("at least one provenance record is required")

    aggregates: dict[tuple[str, int, str], dict[str, Any]] = {}
    edge_groups: dict[tuple[tuple[str, int, str], tuple[str, int, str], str, str], dict[str, Any]] = {}
    global_timestamps: list[int] = []

    for record_index, record in enumerate(records_list):
        if not isinstance(record, dict):
            raise EncodingError(f"record {record_index} must be an object")
        _reject_nonfinite(record, f"record[{record_index}]")
        if "id" not in record or not _canonical_text(record["id"]):
            raise EncodingError(f"record {record_index} id is required")
        if "source" not in record or "destination" not in record:
            raise EncodingError(f"record {record_index} source and destination are required")
        record_ref = _canonical_text(record["id"])
        timestamp_ms = _timestamp(record.get("timestamp_ms"), f"record[{record_index}].timestamp_ms")
        global_timestamps.append(timestamp_ms)
        event_type = _normalize_event(record.get("event_type", record.get("action")))
        source = _normalized_entity(record["source"])
        destination = _normalized_entity(record["destination"])
        normalized_entities = (source, destination)
        canonical_record = {
            "id": record_ref,
            "timestamp_ms": timestamp_ms,
            "event_type": event_type,
            "source": source,
            "destination": destination,
        }
        raw_key = _sha256_text(run_id + "|" + record_ref + "|" + _canonical_json(canonical_record))

        for entity in normalized_entities:
            key = _entity_key(entity)
            aggregate = aggregates.setdefault(
                key,
                {
                    "host_id": entity["host_id"],
                    "entity_type": entity["entity_type"],
                    "entity_type_unknown": False,
                    "entity_id_present": False,
                    "canonical_entity_id": entity["canonical_entity_id"],
                    "fields": {},
                    "unknown_fields": set(),
                    "source_record_refs": set(),
                    "event_counts": {name: 0 for name in EVENT_RANK},
                    "event_count": 0,
                    "timestamps": [],
                    "in_degree": 0,
                    "out_degree": 0,
                },
            )
            aggregate["entity_type_unknown"] = aggregate["entity_type_unknown"] or entity["entity_type_unknown"]
            aggregate["entity_id_present"] = aggregate["entity_id_present"] or entity["entity_id_present"]
            aggregate["source_record_refs"].add(record_ref)
            aggregate["event_counts"][event_type] += 1
            aggregate["event_count"] += 1
            aggregate["timestamps"].append(timestamp_ms)
            for field_name, value in entity["fields"].items():
                if field_name not in ALLOWED_FIELDS[entity["entity_type"]]:
                    aggregate["unknown_fields"].add(field_name)
                _merge_field(aggregate["fields"], field_name, value)
                if field_name in {"pid", "ppid", "local_port", "remote_port"}:
                    _finite_number(value, f"record[{record_index}].{field_name}")

        source_key = _entity_key(source)
        destination_key = _entity_key(destination)
        edge_key = (source_key, destination_key, event_type, record_ref)
        group = edge_groups.setdefault(
            edge_key,
            {
                "src_key": source_key,
                "dst_key": destination_key,
                "event_type": event_type,
                "canonical_event_id": record_ref,
                "timestamps": [],
                "raw_keys": [],
                "source_record_refs": [],
            },
        )
        group["timestamps"].append(timestamp_ms)
        group["raw_keys"].append(raw_key)
        group["source_record_refs"].append(record_ref)

    node_keys = sorted(aggregates)
    node_index = {key: index for index, key in enumerate(node_keys)}
    first_timestamp = min(global_timestamps)
    node_rows: list[dict[str, Any]] = []
    x_rows: list[list[float]] = []
    for index, key in enumerate(node_keys):
        aggregate = aggregates[key]
        fields = aggregate["fields"]
        entity_type = aggregate["entity_type"]
        row = [0.0] * ENCODER_DIMENSION
        row[ENTITY_RANK[entity_type]] = 1.0
        row[4] = float(aggregate["entity_type_unknown"])
        row[5] = float(aggregate["entity_id_present"])
        if entity_type == "process":
            row[6] = float(_has_field(fields, {"pid"}) and any(_available(v, "pid") for v in fields.get("pid", set())))
            row[7] = float(_has_field(fields, {"ppid"}) and any(_available(v, "ppid") for v in fields.get("ppid", set())))
            row[8] = float(_has_field(fields, {"image_path", "executable", "executable_path"}))
            row[9] = float(_has_field(fields, {"command_line"}))
            row[10] = float(_has_field(fields, {"user", "principal"}))
        elif entity_type == "file":
            row[11] = float(_has_field(fields, {"path", "file_path"}))
            row[12] = float(_has_field(fields, {"sha256", "hash", "file_hash"}))
        elif entity_type == "socket":
            protocols = {_enum_token(value) for value in fields.get("protocol", set())}
            row[13] = float("tcp" in protocols)
            row[14] = float("udp" in protocols)
            local_address = _one_value(fields, {"local_address"})
            remote_address = _one_value(fields, {"remote_address"})
            local_present = bool(local_address) or any(_valid_port(v, "local_port") for v in fields.get("local_port", set()))
            remote_present = bool(remote_address) or any(_valid_port(v, "remote_port") for v in fields.get("remote_port", set()))
            row[15] = float(local_present)
            row[16] = float(remote_present)
            row[17] = float(_address_is_external(remote_address))
            row[18] = float(
                any(_valid_port(v, "local_port") for v in fields.get("local_port", set()))
                or any(_valid_port(v, "remote_port") for v in fields.get("remote_port", set()))
            )
        for event_name, event_rank in EVENT_RANK.items():
            row[19 + event_rank] = _norm_count(aggregate["event_counts"][event_name])
        row[26] = _norm_count(aggregate["event_count"])
        row[27] = _norm_count(aggregate["in_degree"])
        row[28] = _norm_count(aggregate["out_degree"])
        row[29] = _norm_time(min(aggregate["timestamps"]) - first_timestamp)
        row[30] = _norm_time(max(aggregate["timestamps"]) - first_timestamp)
        row[31] = float(np.clip(len(aggregate["unknown_fields"]) / max(aggregate["event_count"], 1), 0.0, 1.0))
        x_rows.append(row)
        node_raw_key = _sha256_text(run_id + "|node|" + _canonical_json({"host_id": key[0], "entity_type": entity_type, "canonical_entity_id": key[2]}))
        node_rows.append(
            {
                "model_node_index": index,
                "raw_key": node_raw_key,
                "host_id": aggregate["host_id"],
                "canonical_entity_id": aggregate["canonical_entity_id"],
                "entity_type": entity_type,
                "entity_type_unknown": bool(aggregate["entity_type_unknown"]),
                "source_record_refs": sorted(aggregate["source_record_refs"]),
            }
        )

    sorted_groups = sorted(
        edge_groups.values(),
        key=lambda group: (
            min(group["timestamps"]),
            node_index[group["src_key"]],
            node_index[group["dst_key"]],
            EVENT_RANK[group["event_type"]],
            group["canonical_event_id"],
        ),
    )
    edge_rows: list[dict[str, Any]] = []
    edge_pairs: list[tuple[int, int]] = []
    duplicate_columns: list[dict[str, Any]] = []
    coalesced_edge_to_raw_keys: dict[str, list[str]] = {}
    for column, group in enumerate(sorted_groups):
        src_index = node_index[group["src_key"]]
        dst_index = node_index[group["dst_key"]]
        edge_pairs.append((src_index, dst_index))
        group_raw_keys = sorted(group["raw_keys"])
        refs = sorted(group["source_record_refs"])
        edge_raw_key = _sha256_text(run_id + "|edge|" + _canonical_json({"src": src_index, "dst": dst_index, "event_type": group["event_type"], "canonical_event_id": group["canonical_event_id"]}))
        edge_rows.append(
            {
                "input_edge_column": column,
                "src_model_node_index": src_index,
                "dst_model_node_index": dst_index,
                "raw_key": edge_raw_key,
                "source_record_refs": refs,
                "event_type": group["event_type"],
                "canonical_event_id": group["canonical_event_id"],
                "timestamp_ms": min(group["timestamps"]),
                "coalesced_raw_keys": group_raw_keys,
            }
        )
        coalesced_edge_to_raw_keys[str(column)] = group_raw_keys
        if len(refs) > 1:
            duplicate_columns.append({"input_edge_columns": [column], "source_record_refs": refs, "raw_keys": group_raw_keys})
        aggregates[group["src_key"]]["out_degree"] += 1
        aggregates[group["dst_key"]]["in_degree"] += 1

    # Degree features depend on the coalesced edge set, so update rows in place.
    for row, key in zip(x_rows, node_keys):
        row[27] = _norm_count(aggregates[key]["in_degree"])
        row[28] = _norm_count(aggregates[key]["out_degree"])

    self_loop_columns = [index for index, (src, dst) in enumerate(edge_pairs) if src == dst]
    normalization_map = {
        "input_edge_count": len(records_list),
        "coalesced_edge_count": len(edge_rows),
        "duplicate_columns_coalesced": duplicate_columns,
        "coalesced_edge_to_raw_keys": coalesced_edge_to_raw_keys,
        "self_loop_columns": self_loop_columns,
        "post_coalesce_edge_order": [row["input_edge_column"] for row in edge_rows],
        "phase2_self_loop_policy": "retain input mapping; artifact-compatible Phase-II may remove self-loops, add remaining self-loops for message passing, then remove them from returned explanation",
    }
    source_record_hashes = sorted({raw_key for group in edge_groups.values() for raw_key in group["raw_keys"]})
    run_manifest = {
        "run_id": run_id,
        "graph_id": graph_id,
        "encoder_id": ENCODER_ID,
        "encoder_sha256": ENCODER_IDENTITY_SHA256,
        "schema_sha256": SCHEMA_SHA256,
        "implementation_sha256": _implementation_sha256(),
        "source_record_count": len(records_list),
        "source_record_hashes": source_record_hashes,
        "node_count": len(node_rows),
        "edge_count": len(edge_rows),
        "formal_data_used": False,
        "evaluation_labels_used": False,
        "ordering": "node=(host_id,entity_type_rank,canonical_entity_id); edge=(timestamp_ms,src,dst,event_class_rank,canonical_event_id)",
        "adapter_errors": [],
    }
    x = np.asarray(x_rows, dtype=np.float32)
    edge_index = np.asarray(edge_pairs, dtype=np.int64).T if edge_pairs else np.empty((2, 0), dtype=np.int64)
    x.setflags(write=False)
    edge_index.setflags(write=False)
    return EncodedGraph(x, edge_index, node_rows, edge_rows, normalization_map, run_manifest)


def encoded_to_jsonable(encoded: EncodedGraph) -> dict[str, Any]:
    """Return a JSON-safe representation for manifests and golden hashes."""
    return {
        "x": encoded.x.tolist(),
        "x_dtype": str(encoded.x.dtype),
        "edge_index": encoded.edge_index.tolist(),
        "edge_index_dtype": str(encoded.edge_index.dtype),
        "node_map": encoded.node_map,
        "edge_map": encoded.edge_map,
        "normalization_map": encoded.normalization_map,
        "run_manifest": encoded.run_manifest,
    }
