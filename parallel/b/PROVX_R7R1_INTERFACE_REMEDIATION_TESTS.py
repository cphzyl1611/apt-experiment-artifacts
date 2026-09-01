"""TDD contract-fixture tests for the bounded R7R1 interface remediation."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from PROVX_R7_NORMALIZED_TO_GRAPH_ADAPTER import (
    AdapterError,
    R5_RUN_ID,
    RuntimeInputDescriptor,
    authenticate_runtime_evidence,
    build_graph,
)


R6_RUN_ID = "e1c-r6-run-20260901T060350Z"
RAW_NAME = "MININET_E1C_R6_RAW_AUDIT_EVIDENCE.jsonl"
NORMALIZED_NAME = "MININET_E1C_R6_NORMALIZED_EVENTS.jsonl"
JOIN_NAME = "MININET_E1C_R6_PID_NETNS_JOIN.jsonl"
COVERAGE_NAME = "MININET_E1C_R6_COVERAGE_AND_LOSS_AUDIT.json"
RESULT_NAME = "MININET_E1C_R6_PRIVILEGED_RUN_RESULT.json"
PCAP_NAME = "MININET_E1C_R6_SMOKE.pcap"


def _fixture(temp: Path, *, event: dict | None = None, join: dict | None = None):
    raw_bytes = b"type=SYSCALL msg=audit(1.001:1): syscall=0 success=yes pid=123 ppid=1"
    raw = {"serial": 1, "raw_bytes_b64": base64.b64encode(raw_bytes).decode(), "raw_sha256": hashlib.sha256(raw_bytes).hexdigest()}
    default_event = {
        "event_id": "event-r6-1",
        "event_type": "FILE_READ_OR_WRITE",
        "evidence_basis": "AUDIT_FILESYSTEM_PERMISSION_FILTER",
        "watched_path": "/tmp/r6-bound-file",
        "requested_access": "rw",
        "underlying_syscall": "openat",
        "run_id": R6_RUN_ID,
        "raw_serial": 1,
        "raw_event_bytes_b64": raw["raw_bytes_b64"],
        "raw_event_sha256": raw["raw_sha256"],
        "timestamp_source": "1.001",
        "pid": 123,
        "ppid": 1,
        "pid_start_time_ticks": 99,
        "logical_host_id": "h1",
        "netns_inode": 4026532669,
        "join_status": "JOINED",
        "path": "/tmp/r6-bound-file",
        "file_identity": {"paths": ["/tmp/r6-bound-file"], "operation": "openat"},
        "executable": {"path": "/usr/bin/python3.10", "proctitle": "python3 -c pass"},
    }
    default_join = {
        "run_id": R6_RUN_ID,
        "pid": 123,
        "start_ticks": 99,
        "netns_inode": 4026532669,
        "logical_host_id": "h1",
        "join_status": "JOINED",
        "process": {"pid": 123, "start_ticks": 99},
    }
    event = {**default_event, **(event or {})}
    join = {**default_join, **(join or {})}
    paths = {
        "raw": temp / RAW_NAME,
        "normalized": temp / NORMALIZED_NAME,
        "join": temp / JOIN_NAME,
        "coverage": temp / COVERAGE_NAME,
        "result": temp / RESULT_NAME,
        "pcap": temp / PCAP_NAME,
    }
    paths["raw"].write_text(json.dumps(raw) + "\n")
    paths["normalized"].write_text(json.dumps(event) + "\n")
    paths["join"].write_text(json.dumps(join) + "\n")
    paths["result"].write_text(json.dumps({
        "run_id": R6_RUN_ID,
        "status": "SYNTHETIC_SCHEMA_FIXTURE_ONLY",
        "classification": "NOT_RUNTIME_EVIDENCE",
        "runtime_evidence_present": False,
    }) + "\n")
    paths["pcap"].write_bytes(b"synthetic-pcap-contract-only")
    paths["coverage"].write_text(json.dumps({"run_id": R6_RUN_ID, "normalized_event_count": 1, "pcap_sha256": hashlib.sha256(paths["pcap"].read_bytes()).hexdigest()}) + "\n")
    expected = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths.values()}
    descriptor = RuntimeInputDescriptor(
        run_id=R6_RUN_ID,
        raw_path=paths["raw"], normalized_path=paths["normalized"], join_path=paths["join"],
        coverage_path=paths["coverage"], runtime_review_path=paths["result"], pcap_path=paths["pcap"],
        pcap_hash_source=paths["coverage"],
        expected_sha256=expected,
    )
    return descriptor, event, join


def _refresh_expected_hashes(descriptor: RuntimeInputDescriptor) -> RuntimeInputDescriptor:
    return replace(
        descriptor,
        expected_sha256={
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in descriptor.selected_paths.values()
        },
    )


class R7R1InterfaceRemediationTests(unittest.TestCase):
    def test_default_r5_descriptor_preserves_historical_route(self):
        descriptor = RuntimeInputDescriptor.for_r5(Path("/home/cph/experiment-parallel/e0-a/e1c-r5-run-20260831T111849Z"))
        self.assertEqual(descriptor.run_id, R5_RUN_ID)
        self.assertEqual(descriptor.raw_path.name, "MININET_E1C_R5_RAW_AUDIT_EVIDENCE.jsonl")

    def test_explicit_r6_descriptor_authenticates_distinct_filenames(self):
        with tempfile.TemporaryDirectory() as temp:
            descriptor, _, _ = _fixture(Path(temp))
            auth = authenticate_runtime_evidence(descriptor)
        self.assertEqual(auth["run_id"], R6_RUN_ID)
        self.assertTrue(auth["all_selected_files_authenticated"])
        self.assertEqual(auth["independent_recomputation"]["consumed_records"], 1)
        self.assertEqual(auth["independent_recomputation"]["raw_event_sha256_matches_raw_sha256"], "1/1")

    def test_file_rw_maps_to_host_scoped_file_write(self):
        with tempfile.TemporaryDirectory() as temp:
            _, event, join = _fixture(Path(temp))
            graph = build_graph([event], [join], run_id=R6_RUN_ID)
        self.assertEqual(graph.manifest["quarantined_event_count"], 0)
        self.assertEqual(graph.edge_map[0]["event_type"], "write")
        self.assertEqual(graph.edge_map[0]["dst_graph_node_id"], "host:h1|path:/tmp/r6-bound-file")
        self.assertEqual(graph.encoder_records[0]["destination"]["type"], "FILE")

    def test_non_r5_same_path_on_distinct_joined_hosts_has_distinct_file_nodes(self):
        """Catches a FILE identity regression that drops the logical-host boundary."""
        with tempfile.TemporaryDirectory() as temp:
            _, first_event, first_join = _fixture(Path(temp))
            second_event = {
                **first_event,
                "event_id": "event-r6-2",
                "raw_serial": 2,
                "logical_host_id": "h2",
                "pid": 456,
                "pid_start_time_ticks": 199,
                "netns_inode": 4026532670,
            }
            second_join = {
                **first_join,
                "logical_host_id": "h2",
                "pid": 456,
                "start_ticks": 199,
                "netns_inode": 4026532670,
                "process": {"pid": 456, "start_ticks": 199},
            }
            graph = build_graph([first_event, second_event], [first_join, second_join], run_id=R6_RUN_ID)

        file_nodes = {
            row["graph_node_id"]
            for row in graph.node_map
            if row["entity_type"] == "file"
        }
        self.assertEqual(graph.manifest["quarantined_event_count"], 0)
        self.assertEqual({edge["event_type"] for edge in graph.edge_map}, {"write"})
        self.assertEqual(
            file_nodes,
            {
                "host:h1|path:/tmp/r6-bound-file",
                "host:h2|path:/tmp/r6-bound-file",
            },
        )

    def test_file_rw_missing_each_permission_evidence_field_fails_closed(self):
        cases = (
            {"evidence_basis": None},
            {"watched_path": None},
            {"requested_access": None},
            {"underlying_syscall": None},
        )
        for event_delta in cases:
            with self.subTest(event_delta=event_delta):
                with tempfile.TemporaryDirectory() as temp:
                    _, event, join = _fixture(Path(temp), event=event_delta)
                    graph = build_graph([event], [join], run_id=R6_RUN_ID)
                self.assertEqual(graph.manifest["quarantined_event_count"], 1)
                self.assertEqual(graph.quarantine[0]["reason"], "missing_file_read_write_permission_evidence")

    def test_file_rw_missing_join_path_or_hash_fails_closed(self):
        cases = (
            ({"join_status": "UNJOINED", "logical_host_id": None, "netns_inode": None, "pid_start_time_ticks": None}, {"logical_host_id": None}),
            ({"path": None, "file_identity": None}, {}),
            ({"raw_event_sha256": None}, {}),
        )
        for event_delta, join_delta in cases:
            with self.subTest(event_delta=event_delta):
                with tempfile.TemporaryDirectory() as temp:
                    _, event, join = _fixture(Path(temp), event=event_delta, join=join_delta)
                    graph = build_graph([event], [join], run_id=R6_RUN_ID)
                self.assertEqual(graph.manifest["quarantined_event_count"], 1)

    def test_file_rw_inconsistent_pid_netns_join_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            _, event, join = _fixture(Path(temp), join={"netns_inode": 4026532670})
            graph = build_graph([event], [join], run_id=R6_RUN_ID)
        self.assertEqual(graph.manifest["quarantined_event_count"], 1)
        self.assertEqual(graph.quarantine[0]["reason"], "pid_netns_join_not_authenticated")

    def test_tampered_raw_file_hash_fails_selected_input_authentication(self):
        with tempfile.TemporaryDirectory() as temp:
            descriptor, _, _ = _fixture(Path(temp))
            descriptor.raw_path.write_text('{"serial":1}\n')
            with self.assertRaisesRegex(AdapterError, "selected runtime evidence file authentication failed"):
                authenticate_runtime_evidence(descriptor)

    def test_tampered_raw_event_hash_link_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            descriptor, event, _ = _fixture(Path(temp))
            event["raw_event_sha256"] = "0" * 64
            descriptor.normalized_path.write_text(json.dumps(event) + "\n")
            descriptor = _refresh_expected_hashes(descriptor)
            with self.assertRaisesRegex(AdapterError, "raw/normalized evidence link authentication failed"):
                authenticate_runtime_evidence(descriptor)

    def test_tampered_pcap_hash_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            descriptor, _, _ = _fixture(Path(temp))
            descriptor.coverage_path.write_text(json.dumps({"run_id": R6_RUN_ID, "pcap_sha256": "0" * 64}) + "\n")
            descriptor = _refresh_expected_hashes(descriptor)
            with self.assertRaisesRegex(AdapterError, "pcap hash source does not authenticate pcap"):
                authenticate_runtime_evidence(descriptor)

    def test_missing_explicit_pcap_hash_binding_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            descriptor, _, _ = _fixture(Path(temp))
            with self.assertRaisesRegex(AdapterError, "pcap_hash_source must be explicitly bound"):
                replace(descriptor, pcap_hash_source=None)

    def test_inconsistent_runtime_run_id_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            descriptor, event, _ = _fixture(Path(temp))
            event["run_id"] = "e1c-r6-run-other"
            descriptor.normalized_path.write_text(json.dumps(event) + "\n")
            descriptor = _refresh_expected_hashes(descriptor)
            with self.assertRaisesRegex(AdapterError, "runtime evidence row run_id does not match descriptor"):
                authenticate_runtime_evidence(descriptor)


if __name__ == "__main__":
    unittest.main()
