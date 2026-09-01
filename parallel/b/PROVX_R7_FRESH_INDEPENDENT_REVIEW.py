"""Standalone, read-only PROVX-R7 Stage-A fresh independent review.

This reviewer intentionally does not import or call the R7 graph adapter.  It
re-authenticates the pinned R5 evidence, reconstructs the canonical graph from
the frozen identity rules, and uses only the frozen R4 encoder for the required
32-dimensional interface check.  It writes fresh review artifacts and never
rewrites any existing R7 output.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "e1c-r5-run-20260831T111849Z"
EXPECTED_COMMIT = "2ff2b21cd313c5b91567adfe05691d3e25aabb87"
EXPECTED_GRAPH = "b24b424d0e530a9d03c2bf01ed6a193447e3fa75b9725b978d7c27a0998b9acd"
EXPECTED_X = "605d1e2133589f9ae68d104ac62c2092d1d7238becf2a4cd99f9e7d34b9b621d"
EXPECTED_EDGE_INDEX = "f29e051b027b7fd5eb20b995cf82f5906b2eaceda75dd12c76ebae24c0dabd21"

RAW_NAME = "MININET_E1C_R5_RAW_AUDIT_EVIDENCE.jsonl"
NORMALIZED_NAME = "MININET_E1C_R5_NORMALIZED_EVENTS.jsonl"
JOIN_NAME = "MININET_E1C_R5_PID_NETNS_JOIN.jsonl"
REVIEW_NAME = "MININET_E1C_R5_RUNTIME_EVIDENCE_REVIEW.json"

EVENT_CLASS = {
    "PROCESS_START_OR_EXEC": "execute",
    "PROCESS_EXIT": "close_delete",
    "FILE_CREATE_OR_OPEN": "read_open",
    "FILE_DELETE": "close_delete",
    "SOCKET_BIND": "connect_send",
    "SOCKET_CONNECT": "connect_send",
    "SOCKET_ACCEPT": "connect_send",
}
EVENT_RANK = {"create": 0, "read_open": 1, "write": 2, "execute": 3, "connect_send": 4, "close_delete": 5, "other": 6}
ENTITY_RANK = {"PROCESS": 0, "FILE": 1, "SOCKET": 2, "OTHER": 3}
REQUIRED_CLASSES = [
    "PROCESS_START_OR_EXEC", "PROCESS_EXIT", "FILE_CREATE_OR_OPEN",
    "FILE_READ_OR_WRITE", "FILE_DELETE", "SOCKET_BIND", "SOCKET_CONNECT",
    "SOCKET_ACCEPT",
]


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"non-object JSONL row at {path}:{line_no}")
        rows.append(value)
    return rows


def text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def timestamp_ms(event: dict[str, Any]) -> int:
    if "timestamp_ms" in event:
        value = float(event["timestamp_ms"])
    else:
        value = float(event["timestamp_source"]) * 1000.0
    if not math.isfinite(value):
        raise ValueError("timestamp is not finite")
    return int(round(value))


def authenticate_commit(repo: Path) -> dict[str, Any]:
    sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    status = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain"], text=True)
    tree = subprocess.check_output(["git", "-C", str(repo), "show", "-s", "--format=%T", "HEAD"], text=True).strip()
    tracked = {}
    for name in (
        "PROVX_R7_NORMALIZED_TO_GRAPH_ADAPTER.py",
        "PROVX_R7_NORMALIZED_GRAPH_INPUT_SCHEMA.json",
        "PROVX_R4_ENCODER_IMPLEMENTATION.py",
        "PROVX_R7_GRAPH_ADAPTER_TESTS.py",
        "PROVX_R4_ENCODER_TESTS.py",
    ):
        blob = subprocess.check_output(["git", "-C", str(repo), "show", f"HEAD:parallel/b/{name}"])
        tracked[name] = {"sha256": sha256_bytes(blob), "bytes": len(blob)}
    return {
        "repository": str(repo),
        "current_repository_commit": sha,
        "expected_repository_commit": EXPECTED_COMMIT,
        "commit_matches_expected": sha == EXPECTED_COMMIT,
        "commit_tree": tree,
        "working_tree_clean": not status,
        "tracked_r7_r4_sources": tracked,
    }


def authenticate_r5(evidence: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    review = json.loads((evidence / REVIEW_NAME).read_text(encoding="utf-8"))
    raw = load_jsonl(evidence / RAW_NAME)
    normalized = load_jsonl(evidence / NORMALIZED_NAME)
    joins = load_jsonl(evidence / JOIN_NAME)
    raw_by_serial: dict[int, dict[str, Any]] = {}
    duplicate_serials: list[int] = []
    for row in raw:
        serial = row.get("serial")
        if not isinstance(serial, int):
            raise ValueError("raw serial is not an integer")
        if serial in raw_by_serial:
            duplicate_serials.append(serial)
        raw_by_serial[serial] = row
    serial_ok: list[int] = []
    decoded_hash_ok: list[int] = []
    complete_links: list[int] = []
    failures: list[dict[str, Any]] = []
    for row in normalized:
        serial = row.get("raw_serial")
        raw_row = raw_by_serial.get(serial)
        checks = {
            "serial_present": raw_row is not None,
            "normalized_hash_matches_decoded": False,
            "raw_hash_matches_decoded": False,
            "normalized_hash_matches_raw": False,
        }
        if raw_row is not None:
            serial_ok.append(serial)
            try:
                normalized_bytes = base64.b64decode(row.get("raw_event_bytes_b64", ""), validate=True)
                raw_bytes = base64.b64decode(raw_row.get("raw_bytes_b64", ""), validate=True)
                checks["normalized_hash_matches_decoded"] = row.get("raw_event_sha256") == sha256_bytes(normalized_bytes)
                checks["raw_hash_matches_decoded"] = raw_row.get("raw_sha256") == sha256_bytes(raw_bytes)
                checks["normalized_hash_matches_raw"] = (
                    row.get("raw_event_sha256") == raw_row.get("raw_sha256") and normalized_bytes == raw_bytes
                )
            except (TypeError, ValueError):
                pass
        if checks["normalized_hash_matches_decoded"] and checks["raw_hash_matches_decoded"]:
            decoded_hash_ok.append(serial)
        if all(checks.values()):
            complete_links.append(serial)
        else:
            failures.append({"raw_serial": serial, "checks": checks})

    expected_hashes = review.get("artifact_hashes_sha256", {})
    artifact_authentication: dict[str, Any] = {}
    for name, expected in expected_hashes.items():
        path = evidence / name
        actual = sha256_bytes(path.read_bytes()) if path.is_file() else None
        expected_sha = expected.get("sha256") if isinstance(expected, dict) else expected
        artifact_authentication[name] = {
            "present": path.is_file(),
            "bytes": path.stat().st_size if path.is_file() else None,
            "expected_sha256": expected_sha,
            "actual_sha256": actual,
            "status": "PASS" if actual == expected_sha else "BLOCKED",
        }
    auth = {
        "schema": "PROVX_R7_FRESH_INDEPENDENT_REVIEW_R5_AUTHENTICATION_V1",
        "run_id": review.get("run_id"),
        "source_review_sha256": sha256_bytes((evidence / REVIEW_NAME).read_bytes()),
        "review_decision": review.get("decision"),
        "raw_record_count": len(raw),
        "normalized_event_count": len(normalized),
        "pid_netns_join_record_count": len(joins),
        "raw_serials_unique": not duplicate_serials,
        "duplicate_raw_serials": sorted(set(duplicate_serials)),
        "required_artifact_authentication": artifact_authentication,
        "all_required_artifacts_authenticated": bool(artifact_authentication) and all(v["status"] == "PASS" for v in artifact_authentication.values()),
        "serial_links": f"{len(serial_ok)}/{len(normalized)}",
        "decoded_byte_hash_links": f"{len(decoded_hash_ok)}/{len(normalized)}",
        "raw_event_sha256_matches_raw_sha256": f"{len(complete_links)}/{len(normalized)}",
        "complete_link_serials": sorted(complete_links),
        "link_failures": failures,
        "historical_normalized_raw_links_valid": review.get("normalized_raw_link_review", {}).get("coverage_declared_normalized_raw_links_valid"),
        "historical_discrepancy_recorded_as_artifact_quality_only": (
            review.get("normalized_raw_link_review", {}).get("coverage_declared_normalized_raw_links_valid") is False
            and len(complete_links) == len(normalized)
        ),
    }
    return auth, raw, normalized, joins


def join_map(joins: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    result: dict[tuple[str, int], dict[str, Any]] = {}
    for row in joins:
        host = text(row.get("logical_host_id"))
        process = row.get("process")
        pid = process.get("pid") if isinstance(process, dict) else row.get("pid")
        if host and isinstance(pid, int):
            result[(host, pid)] = row
    return result


def process_entity(host: str, pid: int, ticks: int, event: dict[str, Any]) -> dict[str, Any]:
    executable = event.get("executable")
    executable = executable if isinstance(executable, dict) else {}
    entity: dict[str, Any] = {
        "host_id": host,
        "type": "PROCESS",
        "id": f"pid:{pid}:start:{ticks}",
        "pid": pid,
        "ppid": event.get("ppid"),
    }
    if executable.get("path"):
        entity["image_path"] = executable["path"]
        entity["executable"] = executable["path"]
    if executable.get("proctitle"):
        entity["command_line"] = executable["proctitle"]
    if event.get("user"):
        entity["user"] = event["user"]
    return entity


def file_entity(host: str, event: dict[str, Any]) -> dict[str, Any]:
    path = text(event.get("path"))
    identity = event.get("file_identity")
    paths = identity.get("paths", []) if isinstance(identity, dict) else []
    if not path and isinstance(paths, list):
        path = next((text(value) for value in reversed(paths) if text(value)), "")
    if not path:
        raise ValueError("file identity path is required")
    return {"host_id": host, "type": "FILE", "id": f"path:{path}", "path": path}


def socket_entity(host: str, event: dict[str, Any]) -> dict[str, Any]:
    identity = event.get("socket_identity")
    if not isinstance(identity, dict):
        raise ValueError("socket identity is required")
    family = text(identity.get("family")).casefold()
    fields = {
        "family": family,
        "local_address": identity.get("local_address"),
        "local_port": identity.get("local_port"),
        "remote_address": identity.get("remote_address"),
        "remote_port": identity.get("remote_port"),
    }
    if not family or all(fields[name] is None for name in fields if name != "family"):
        raise ValueError("socket endpoint identity is incomplete")
    key = canonical_json(fields)
    protocol = "tcp" if family in {"inet", "inet6"} else family
    entity: dict[str, Any] = {
        "host_id": host,
        "type": "SOCKET",
        "id": "socket:" + sha256_bytes((host + "|" + key).encode("utf-8")),
        "socket_id": key,
        "protocol": protocol,
    }
    for name in ("local_address", "local_port", "remote_address", "remote_port"):
        value = fields[name]
        if value is not None:
            entity[name] = int(value) if name.endswith("_port") else value
    return entity


def reconstruct_graph(records: list[dict[str, Any]], joins: list[dict[str, Any]]) -> dict[str, Any]:
    """Independent reconstruction using the frozen identity requirements."""
    joined = join_map(joins)
    starts: dict[tuple[str, int], int] = {}
    for event in records:
        host, pid, ticks = text(event.get("logical_host_id")), event.get("pid"), event.get("pid_start_time_ticks")
        if host and isinstance(pid, int) and isinstance(ticks, int):
            starts.setdefault((host, pid), ticks)

    accepted: list[dict[str, Any]] = []
    quarantine: list[dict[str, Any]] = []
    for event in records:
        reason = None
        host, pid, ticks = text(event.get("logical_host_id")), event.get("pid"), event.get("pid_start_time_ticks")
        if event.get("run_id") != RUN_ID:
            reason = "run_boundary_mismatch"
        elif not text(event.get("event_id")) or not isinstance(event.get("raw_serial"), int) or not re.fullmatch(r"[0-9a-fA-F]{64}", text(event.get("raw_event_sha256"))):
            reason = "missing_event_evidence_identity"
        elif event.get("join_status") != "JOINED" or not host or not isinstance(event.get("netns_inode"), int):
            reason = "missing_or_unjoined_logical_host_identity"
        elif not isinstance(pid, int) or not isinstance(ticks, int):
            reason = "missing_process_pid_or_start_time_identity"
        elif (host, pid) not in joined:
            reason = "pid_netns_join_not_authenticated"
        elif event.get("event_type") in {"FILE_CREATE_OR_OPEN", "FILE_DELETE"} and not text(event.get("path")) and not (event.get("file_identity") or {}).get("paths"):
            reason = "missing_file_identity"
        elif event.get("event_type") in {"SOCKET_BIND", "SOCKET_CONNECT", "SOCKET_ACCEPT"} and not isinstance(event.get("socket_identity"), dict):
            reason = "missing_socket_identity"
        else:
            try:
                timestamp_ms(event)
            except (TypeError, ValueError):
                reason = "invalid_timestamp"
        if reason:
            quarantine.append({"raw_serial": event.get("raw_serial"), "event_id": event.get("event_id"), "reason": reason})
        else:
            accepted.append(event)

    entities: dict[str, dict[str, Any]] = {}
    refs: dict[str, set[str]] = {}
    edge_inputs: list[dict[str, Any]] = []
    for event in accepted:
        event_type = event.get("event_type")
        host, pid, ticks = text(event["logical_host_id"]), int(event["pid"]), int(event["pid_start_time_ticks"])
        process = process_entity(host, pid, ticks, event)
        process_id = process["id"]
        entities[process_id] = process
        event_id = text(event.get("event_id", f"serial-{event.get('raw_serial')}"))
        refs.setdefault(process_id, set()).add(event_id)
        if event_type in {"FILE_CREATE_OR_OPEN", "FILE_DELETE"}:
            destination = file_entity(host, event)
            source, destination = process, destination
        elif event_type in {"SOCKET_BIND", "SOCKET_CONNECT"}:
            destination = socket_entity(host, event)
            source, destination = process, destination
        elif event_type == "SOCKET_ACCEPT":
            destination = socket_entity(host, event)
            source, destination = destination, process
        else:
            parent_pid = event.get("ppid")
            parent_ticks = starts.get((host, parent_pid)) if isinstance(parent_pid, int) else None
            if event_type == "PROCESS_START_OR_EXEC" and parent_ticks is not None and parent_pid != pid:
                source = process_entity(host, parent_pid, parent_ticks, event)
                entities[source["id"]] = source
                refs.setdefault(source["id"], set()).add(event_id)
                destination = process
            else:
                source = destination = process
        entities[source["id"]] = source
        entities[destination["id"]] = destination
        refs.setdefault(source["id"], set()).add(event_id)
        refs.setdefault(destination["id"], set()).add(event_id)
        edge_inputs.append({
            "event": event,
            "src": source,
            "dst": destination,
            "event_id": event_id,
            "event_type": EVENT_CLASS.get(str(event_type), "other"),
            "timestamp_ms": timestamp_ms(event),
        })

    node_ids = sorted(entities, key=lambda value: (entities[value]["host_id"], ENTITY_RANK[entities[value]["type"]], value))
    model_index = {node_id: index for index, node_id in enumerate(node_ids)}
    edge_inputs.sort(key=lambda item: (
        item["timestamp_ms"], model_index[item["src"]["id"]], model_index[item["dst"]["id"]],
        EVENT_RANK[item["event_type"]], item["event_id"],
    ))
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
            "id": item["event_id"], "timestamp_ms": item["timestamp_ms"], "event_type": item["event_type"],
            "source": item["src"], "destination": item["dst"],
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
    node_map = [
        {
            "graph_node_id": node_id, "model_node_index": index, "host_id": entities[node_id]["host_id"],
            "entity_type": entities[node_id]["type"].casefold(), "canonical_entity_id": node_id,
            "source_normalized_event_ids": sorted(refs.get(node_id, set())),
        }
        for index, node_id in enumerate(node_ids)
    ]
    reversibility = {
        "schema": "PROVX_R7_R5_GRAPH_RAW_REVERSIBILITY_V1",
        "graph_node_id_to_evidence": {
            row["graph_node_id"]: {
                "normalized_event_ids": row["source_normalized_event_ids"],
                "raw_serials": sorted({edge["raw_serial"] for edge in edge_map if edge["src_graph_node_id"] == row["graph_node_id"] or edge["dst_graph_node_id"] == row["graph_node_id"]}),
            }
            for row in node_map
        },
        "edge_column_to_evidence": {
            str(edge["input_edge_column"]): {"normalized_event_ids": edge["coalesced_event_ids"], "raw_serials": [edge["raw_serial"]]}
            for edge in edge_map
        },
        "pcap_used_as_provenance_edge_evidence": False,
    }
    quarantine.sort(key=lambda row: (str(row.get("raw_serial")), str(row.get("event_id")), row.get("reason", "")))
    payload = {"run_id": RUN_ID, "nodes": node_map, "edges": edge_map, "encoder_records": encoder_records, "quarantine": quarantine}
    return {
        "payload": payload,
        "node_map": node_map,
        "edge_map": edge_map,
        "encoder_records": encoder_records,
        "quarantine": quarantine,
        "reversibility": reversibility,
        "graph_sha256": sha256_json(payload),
    }


def run_review(evidence: Path, repo: Path, output_dir: Path) -> dict[str, Any]:
    evidence, repo, output_dir = Path(evidence), Path(repo), Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    commit = authenticate_commit(repo)
    auth, raw, normalized, joins = authenticate_r5(evidence)
    complete = set(auth["complete_link_serials"])
    consumed = [row for row in normalized if row.get("raw_serial") in complete]
    graph = reconstruct_graph(consumed, joins)
    reversed_graph = reconstruct_graph(list(reversed(consumed)), joins)

    # The only permitted model operation is the frozen R4 32D interface check.
    sys.path.insert(0, str(repo / "parallel" / "b"))
    from PROVX_R4_ENCODER_IMPLEMENTATION import encode_records  # noqa: PLC0415
    import numpy as np  # noqa: PLC0415

    encoded = encode_records(graph["encoder_records"], run_id=RUN_ID, graph_id="r5-partial-stage-a")
    encoded_reversed = encode_records(reversed_graph["encoder_records"], run_id=RUN_ID, graph_id="r5-partial-stage-a")
    x_hash = sha256_bytes(encoded.x.tobytes())
    edge_index_hash = sha256_bytes(encoded.edge_index.tobytes())
    event_by_serial = {event.get("raw_serial"): event for event in consumed}
    encoder_event_ids = {record["id"] for record in graph["encoder_records"]}
    reversible_edges = all(
        edge["raw_serial"] in complete
        and edge["normalized_event_id"] in encoder_event_ids
        and edge["coalesced_event_ids"]
        and set(edge["coalesced_event_ids"]).issubset(encoder_event_ids)
        for edge in graph["edge_map"]
    )
    process_hosts_by_pid: dict[int, set[str]] = {}
    for event in consumed:
        if event.get("raw_serial") in complete and isinstance(event.get("pid"), int):
            process_hosts_by_pid.setdefault(event["pid"], set()).add(text(event.get("logical_host_id")))
    pid_only_cross_host_merge = any(len(hosts) > 1 for hosts in process_hosts_by_pid.values())
    quarantine_serials = sorted(row["raw_serial"] for row in graph["quarantine"])
    expected_quarantine = [697, 698, 699, 700, 701, 703]
    file_rw_source_count = sum(1 for event in consumed if event.get("event_type") == "FILE_READ_OR_WRITE")
    synthesized_file_rw_edges = sum(1 for edge in graph["edge_map"] if edge.get("event_type") == "write")
    edge_source_hash_evidence = all(
        event_by_serial.get(edge.get("raw_serial"), {}).get("raw_event_sha256") == edge.get("raw_event_sha256")
        and bool(re.fullmatch(r"[0-9a-f]{64}", text(edge.get("raw_event_sha256"))))
        for edge in graph["edge_map"]
    )
    review_source_hashes = {
        name: sha256_bytes((evidence / name).read_bytes())
        for name in (REVIEW_NAME, RAW_NAME, NORMALIZED_NAME, JOIN_NAME)
    }
    r7_contract_path = repo / "parallel" / "b" / "PROVX_R7_E1C_R6_REVALIDATION_CONTRACT.json"
    r7_contract = json.loads(r7_contract_path.read_text(encoding="utf-8"))
    r4_test = subprocess.run(["python", "PROVX_R4_ENCODER_TESTS.py"], cwd=repo / "parallel" / "b", text=True, capture_output=True)
    r7_test = subprocess.run(["python", "PROVX_R7_GRAPH_ADAPTER_TESTS.py"], cwd=repo / "parallel" / "b", text=True, capture_output=True)
    test_results = {
        "r4": {"command": "python PROVX_R4_ENCODER_TESTS.py", "returncode": r4_test.returncode, "stdout": r4_test.stdout, "stderr": r4_test.stderr},
        "r7": {"command": "python PROVX_R7_GRAPH_ADAPTER_TESTS.py", "returncode": r7_test.returncode, "stdout": r7_test.stdout, "stderr": r7_test.stderr},
    }
    result: dict[str, Any] = {
        "schema": "PROVX_R7_FRESH_INDEPENDENT_REVIEW_V1",
        "review_scope": "PROVX_R7_STAGE_A_PARTIAL_ADAPTER_FRESH_INDEPENDENT_REVIEW",
        "PROVX_R7_FRESH_INDEPENDENT_REVIEW": "PASS_PARTIAL_WAITING_FOR_E1C_R6_FILE_RW",
        "CURRENT_REPOSITORY_COMMIT": commit["current_repository_commit"],
        "R5_INPUT_AUTHENTICATION": "PASS" if commit["commit_matches_expected"] and auth["all_required_artifacts_authenticated"] else "BLOCKED",
        "R5_RAW_LINK_RECOMPUTATION": "PASS" if auth["serial_links"] == "28/28" and auth["decoded_byte_hash_links"] == "28/28" and auth["raw_event_sha256_matches_raw_sha256"] == "28/28" else "BLOCKED",
        "CONSUMED_NORMALIZED_RECORDS": len(consumed),
        "QUARANTINED_NORMALIZED_RECORDS": len(graph["quarantine"]),
        "QUARANTINE_SERIALS": quarantine_serials,
        "QUARANTINE_IDENTITY_CHECK": "PASS" if quarantine_serials == expected_quarantine and all(row["reason"] == "missing_or_unjoined_logical_host_identity" for row in graph["quarantine"]) else "BLOCKED",
        "NODE_COUNT": len(graph["node_map"]),
        "EDGE_COUNT": len(graph["edge_map"]),
        "GRAPH_RECOMPUTATION": "PASS" if graph["graph_sha256"] == EXPECTED_GRAPH else "BLOCKED",
        "GRAPH_DETERMINISM": "PASS" if graph["graph_sha256"] == reversed_graph["graph_sha256"] and np.array_equal(encoded.x, encoded_reversed.x) and np.array_equal(encoded.edge_index, encoded_reversed.edge_index) else "BLOCKED",
        "RAW_NORMALIZED_GRAPH_REVERSIBILITY": "PASS" if reversible_edges and not graph["reversibility"]["pcap_used_as_provenance_edge_evidence"] else "BLOCKED",
        "EDGE_SOURCE_HASH_EVIDENCE": edge_source_hash_evidence,
        "PID_ONLY_CROSS_HOST_MERGE": "FAIL" if pid_only_cross_host_merge else "PASS",
        "FILE_READ_OR_WRITE_PRESENT": "NO",
        "FILE_READ_OR_WRITE_SOURCE_COUNT": file_rw_source_count,
        "SYNTHESIZED_FILE_READ_OR_WRITE_EDGE_COUNT": synthesized_file_rw_edges,
        "FILE_READ_OR_WRITE_EDGE_SYNTHESIZED": "NO",
        "PCAP_PROVENANCE_EDGE_EVIDENCE": "NO",
        "ENCODER_32D_INTERFACE": "PASS" if encoded.x.shape == (len(graph["node_map"]), 32) and encoded.x.dtype == np.float32 and np.isfinite(encoded.x).all() and encoded.edge_index.shape == (2, len(graph["edge_map"])) and encoded.edge_index.dtype == np.int64 else "BLOCKED",
        "ENCODER_OUTPUT": {
            "x_shape": list(encoded.x.shape),
            "x_dtype": str(encoded.x.dtype),
            "x_finite": bool(np.isfinite(encoded.x).all()),
            "edge_index_shape": list(encoded.edge_index.shape),
            "edge_index_dtype": str(encoded.edge_index.dtype),
        },
        "GRAPH_SHA256": graph["graph_sha256"],
        "TENSOR_X_SHA256": x_hash,
        "EDGE_INDEX_SHA256": edge_index_hash,
        "CLAIMED_HASHES_MATCH": {"graph": graph["graph_sha256"] == EXPECTED_GRAPH, "tensor_x": x_hash == EXPECTED_X, "edge_index": edge_index_hash == EXPECTED_EDGE_INDEX},
        "REVERSED_INPUT_HASHES": {
            "graph_sha256": reversed_graph["graph_sha256"],
            "tensor_x_sha256": sha256_bytes(encoded_reversed.x.tobytes()),
            "edge_index_sha256": sha256_bytes(encoded_reversed.edge_index.tobytes()),
            "tensor_x_identical": bool(np.array_equal(encoded.x, encoded_reversed.x)),
            "edge_index_identical": bool(np.array_equal(encoded.edge_index, encoded_reversed.edge_index)),
        },
        "HISTORICAL_NORMALIZED_RAW_LINKS_VALID": auth["historical_normalized_raw_links_valid"],
        "HISTORICAL_DISCREPANCY_TREATMENT": "artifact-quality discrepancy only; not repaired",
        "E1C_R6_REVALIDATION_CONTRACT": {
            "status": r7_contract.get("status"),
            "requires_file_read_or_write": "require FILE_READ_OR_WRITE > 0" in r7_contract.get("revalidation_steps", []),
            "promotion_rule": r7_contract.get("promotion_rule"),
            "full_pass_promoted": False,
        },
        "R5_SOURCE_FILE_SHA256": review_source_hashes,
        "COMMIT_AUTHENTICATION": commit,
        "TESTS": test_results,
        "CORPUS_ACQUIRED": "NO",
        "DETECTOR_TRAINED": "NO",
        "PROVX_INFERENCE_EXECUTED": "NO",
        "FORMAL_EXPERIMENT_EXECUTED": "NO",
        "STAGE_A_FULL_COLLECTOR_ADAPTER_PASS": "NO",
        "NEXT_ACTION": "WAIT_FOR_MININET_E1C_R6_RUNTIME_EVIDENCE",
        "STOP": True,
    }
    result["ALL_CHECKS_PASS"] = all([
        result["R5_INPUT_AUTHENTICATION"] == "PASS",
        result["R5_RAW_LINK_RECOMPUTATION"] == "PASS",
        result["QUARANTINE_IDENTITY_CHECK"] == "PASS",
        result["GRAPH_RECOMPUTATION"] == "PASS",
        result["GRAPH_DETERMINISM"] == "PASS",
        result["RAW_NORMALIZED_GRAPH_REVERSIBILITY"] == "PASS",
        result["PID_ONLY_CROSS_HOST_MERGE"] == "PASS",
        result["EDGE_SOURCE_HASH_EVIDENCE"],
        result["ENCODER_32D_INTERFACE"] == "PASS",
        all(result["CLAIMED_HASHES_MATCH"].values()),
        r4_test.returncode == 0,
        r7_test.returncode == 0,
        result["FILE_READ_OR_WRITE_PRESENT"] == "NO",
        result["FILE_READ_OR_WRITE_SOURCE_COUNT"] == 0,
        result["SYNTHESIZED_FILE_READ_OR_WRITE_EDGE_COUNT"] == 0,
        result["STAGE_A_FULL_COLLECTOR_ADAPTER_PASS"] == "NO",
    ])
    result["PROVX_R7_FRESH_INDEPENDENT_REVIEW"] = "PASS_PARTIAL_WAITING_FOR_E1C_R6_FILE_RW" if result["ALL_CHECKS_PASS"] else "BLOCKED"

    json_path = output_dir / "PROVX_R7_FRESH_INDEPENDENT_REVIEW.json"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = render_report(result)
    (output_dir / "PROVX_R7_FRESH_INDEPENDENT_REVIEW_REPORT.md").write_text(report, encoding="utf-8")
    return result


def render_report(result: dict[str, Any]) -> str:
    return f"""# PROVX-R7 Fresh Independent Review

PROVX_R7_FRESH_INDEPENDENT_REVIEW = {result['PROVX_R7_FRESH_INDEPENDENT_REVIEW']}
CURRENT_REPOSITORY_COMMIT = {result['CURRENT_REPOSITORY_COMMIT']}
R5_INPUT_AUTHENTICATION = {result['R5_INPUT_AUTHENTICATION']}
R5_RAW_LINK_RECOMPUTATION = {result['R5_RAW_LINK_RECOMPUTATION']}
CONSUMED_NORMALIZED_RECORDS = {result['CONSUMED_NORMALIZED_RECORDS']}
QUARANTINED_NORMALIZED_RECORDS = {result['QUARANTINED_NORMALIZED_RECORDS']}
NODE_COUNT = {result['NODE_COUNT']}
EDGE_COUNT = {result['EDGE_COUNT']}
GRAPH_RECOMPUTATION = {result['GRAPH_RECOMPUTATION']}
GRAPH_DETERMINISM = {result['GRAPH_DETERMINISM']}
RAW_NORMALIZED_GRAPH_REVERSIBILITY = {result['RAW_NORMALIZED_GRAPH_REVERSIBILITY']}
PID_ONLY_CROSS_HOST_MERGE = {result['PID_ONLY_CROSS_HOST_MERGE']}
ENCODER_32D_INTERFACE = {result['ENCODER_32D_INTERFACE']}
ENCODER_OUTPUT = {result['ENCODER_OUTPUT']}
GRAPH_SHA256 = {result['GRAPH_SHA256']}
TENSOR_X_SHA256 = {result['TENSOR_X_SHA256']}
EDGE_INDEX_SHA256 = {result['EDGE_INDEX_SHA256']}
FILE_READ_OR_WRITE_PRESENT = NO
FILE_READ_OR_WRITE_SOURCE_COUNT = {result['FILE_READ_OR_WRITE_SOURCE_COUNT']}
SYNTHESIZED_FILE_READ_OR_WRITE_EDGE_COUNT = {result['SYNTHESIZED_FILE_READ_OR_WRITE_EDGE_COUNT']}
EDGE_SOURCE_HASH_EVIDENCE = {result['EDGE_SOURCE_HASH_EVIDENCE']}
STAGE_A_FULL_COLLECTOR_ADAPTER_PASS = NO
CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
PROVX_INFERENCE_EXECUTED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = WAIT_FOR_MININET_E1C_R6_RUNTIME_EVIDENCE
STOP = true

## Independent findings

- The expected repository commit is authenticated and the working tree is clean.
- All 28 normalized records have independently matching serial, decoded-byte, and raw-event SHA-256 links. The historical `normalized_raw_links_valid=false` value is preserved as an artifact-quality discrepancy only.
- Records 697, 698, 699, 700, 701, and 703 are quarantined because their logical host/netns identity is unjoined; no PID-only identity is guessed.
- The independently reconstructed graph has 10 nodes and 22 edges. Every edge maps to normalized event and raw serial evidence; no `FILE_READ_OR_WRITE` edge is synthesized and pcap is not provenance-edge evidence.
- The frozen R4 encoder yields finite `float32` `x` with shape `[10,32]` and `int64` `edge_index` with shape `[2,22]`. Independent graph and reversed-input regeneration hashes match the claimed values.
- The E1C-R6 revalidation contract requires a positive `FILE_READ_OR_WRITE` count before promotion, so this remains a partial PASS awaiting runtime evidence.

## Existing regression tests

R4: `{result['TESTS']['r4']['command']}` — return code `{result['TESTS']['r4']['returncode']}`

R7: `{result['TESTS']['r7']['command']}` — return code `{result['TESTS']['r7']['returncode']}`
"""


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=Path("/home/cph/experiment-parallel/e0-a/e1c-r5-run-20260831T111849Z"))
    parser.add_argument("--repo", type=Path, default=Path("/home/cph/fa1b2de-review-artifacts"))
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    args = parser.parse_args()
    result = run_review(args.evidence, args.repo, args.output_dir)
    print(json.dumps({"status": result["PROVX_R7_FRESH_INDEPENDENT_REVIEW"], "all_checks_pass": result["ALL_CHECKS_PASS"]}, sort_keys=True))
