#!/usr/bin/env python3
"""R5 RED tests for early-child diagnostics and identity semantics."""

import importlib.util
import json
import tempfile
import unittest
import io
import subprocess
import socket
from unittest import mock
from pathlib import Path


RUN_DIR = Path(__file__).resolve().parent
HARNESS = RUN_DIR / "mininet_e1c_r5_child_bootstrap_hardened_smoke.py"
R4_HARNESS = RUN_DIR.parent / "e1c-r4-run-20260831T105503Z" / "mininet_e1c_r4_delete_argv_fixed_smoke.py"


def load():
    spec = importlib.util.spec_from_file_location("e1c_r5_harness", HARNESS)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {HARNESS}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_r4():
    spec = importlib.util.spec_from_file_location("e1c_r4_harness_for_red", R4_HARNESS)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {R4_HARNESS}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class E1CR5DiagnosticsTests(unittest.TestCase):
    def test_r4_early_finished_before_ready_path_reproduced(self):
        r4 = load_r4()
        stream = io.StringIO('{"event":"FINISHED","logical_host_id":"h2"}\n')
        child = {"h2": {"process": mock.Mock(stdout=stream)}}
        with mock.patch.object(r4.select, "select", return_value=([stream], [], [])):
            with self.assertRaisesRegex(RuntimeError, "h2 emitted FINISHED before READY"):
                r4.read_ready(child, timeout=1)

    def test_read_ready_finished_persists_parent_diagnostics(self):
        r5 = load()
        stream = io.StringIO('{"event":"FINISHED","logical_host_id":"h2","pid":1234}\n')
        proc = mock.Mock(stdout=stream, stderr=io.StringIO("bind traceback"), poll=mock.Mock(return_value=0), communicate=mock.Mock(return_value=("", "")))
        child = {"h2": {"process": proc, "pid": 1234, "popen_pid": 1234,
                         "stdout_history": [], "stderr_history": "", "stage": "READY_WAIT"}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "early.jsonl"
            with mock.patch.object(r5.select, "select", return_value=([stream], [], [])):
                with self.assertRaises(r5.ChildProtocolError):
                    r5.read_ready(child, timeout=1, evidence_path=path)
            evidence = json.loads(path.read_text())
            self.assertEqual(evidence["unexpected_stdout_event"], "FINISHED")
            self.assertIn("child_pid", evidence)

    def test_read_ready_zero_output_exit_persists_parent_diagnostics(self):
        r5 = load()
        stream = io.StringIO("")
        proc = mock.Mock(stdout=stream, stderr=io.StringIO("early failure"), poll=mock.Mock(return_value=1), communicate=mock.Mock(return_value=("", "")))
        child = {"h2": {"process": proc, "pid": 1235, "popen_pid": 1235,
                         "stdout_history": [], "stderr_history": "", "stage": "READY_WAIT"}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "early.jsonl"
            with mock.patch.object(r5.select, "select", return_value=([stream], [], [])):
                with self.assertRaises(r5.ChildProtocolError):
                    r5.read_ready(child, timeout=1, evidence_path=path)
            evidence = json.loads(path.read_text())
            self.assertEqual(evidence["unexpected_stdout_event"], "CHILD_EXIT_BEFORE_READY")
            self.assertEqual(evidence["child_returncode"], 1)
    def test_finished_before_ready_persists_diagnostics_before_raise(self):
        r5 = load()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "early.jsonl"
            with self.assertRaises(r5.ChildProtocolError):
                r5.raise_child_protocol_error(
                    path,
                    logical_host_id="h2",
                    unexpected_event="FINISHED",
                    child_pid=1234,
                    returncode=0,
                    stderr="Traceback: bind failed",
                    stdout_history=[{"event": "FINISHED", "pid": 1234}],
                    process_liveness=False,
                    stage="READY_WAIT",
                    timestamp_utc="2026-08-31T00:00:00+00:00",
                )
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            evidence = rows[0]
            for key in ("logical_host_id", "unexpected_stdout_event", "child_pid",
                        "child_returncode", "complete_stderr", "stdout_history",
                        "process_liveness", "exact_stage", "timestamp_utc"):
                self.assertIn(key, evidence)
            self.assertEqual(evidence["unexpected_stdout_event"], "FINISHED")
            self.assertEqual(evidence["complete_stderr"], "Traceback: bind failed")

    def test_child_exits_before_any_stdout_persists_diagnostics(self):
        r5 = load()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "early.jsonl"
            with self.assertRaises(r5.ChildProtocolError):
                r5.raise_child_protocol_error(
                    path,
                    logical_host_id="h2",
                    unexpected_event="CHILD_EXIT_BEFORE_READY",
                    child_pid=1235,
                    returncode=1,
                    stderr="NameError: socket",
                    stdout_history=[],
                    process_liveness=False,
                    stage="READY_WAIT",
                )
            evidence = json.loads(path.read_text())
            self.assertEqual(evidence["stdout_history"], [])
            self.assertEqual(evidence["child_returncode"], 1)

    def test_child_error_event_contains_required_fields(self):
        r5 = load()
        event = r5.build_child_error_event(
            logical_host_id="h2", pid=42, stage="LISTENER_BIND",
            exc=OSError(98, "Address already in use"), netns="net:[123]",
            traceback_text="traceback",
        )
        self.assertEqual(event["event"], "CHILD_ERROR")
        for key in ("exception_type", "exception_message", "stage",
                    "traceback_sha256", "logical_host_id", "pid", "netns"):
            self.assertIn(key, event)
        self.assertEqual(event["exception_type"], "OSError")

    def test_real_child_bind_failure_emits_child_error_and_state(self):
        harness = str(HARNESS)
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "states.jsonl"
            temp_file = Path(tmp) / "event.txt"
            blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            blocker.bind(("127.0.0.1", 0))
            blocker.listen(1)
            port = blocker.getsockname()[1]
            try:
                proc = subprocess.run(
                    ["/usr/bin/python3", harness, "--child", "--logical-host-id", "h2",
                     "--listen-address", "127.0.0.1", "--listen-port", str(port),
                     "--peer-address", "127.0.0.1", "--temp-file", str(temp_file),
                     "--state-file", str(state), "--role", "server"],
                    text=True, capture_output=True, timeout=5,
                )
            finally:
                blocker.close()
            self.assertNotEqual(proc.returncode, 0)
            events = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
            error = next(event for event in events if event.get("event") == "CHILD_ERROR")
            self.assertEqual(error["logical_host_id"], "h2")
            self.assertEqual(error["stage"], "LISTENER_BIND")
            self.assertTrue(state.exists())
            states = [json.loads(line) for line in state.read_text().splitlines()]
            self.assertTrue(any(row["state"] == "CHILD_ERROR" for row in states))

    def test_namespace_missing_evidence_is_not_observed(self):
        r5 = load()
        result = r5.namespace_assertions(
            {"h1": "net:[1]", "h2": "net:[2]"},
            {"h1": None, "h2": "net:[2]"},
        )
        self.assertEqual(result["checks"]["h1_child_netns == h1_shell_netns"], "NOT_OBSERVED")
        self.assertEqual(result["checks"]["h1_child_netns != h2_shell_netns"], "NOT_OBSERVED")
        self.assertFalse(result["pass"])

    def test_namespace_all_four_assertions_must_pass(self):
        r5 = load()
        result = r5.namespace_assertions(
            {"h1": "net:[1]", "h2": "net:[2]"},
            {"h1": "net:[1]", "h2": "net:[2]"},
        )
        self.assertTrue(result["pass"])
        self.assertTrue(all(value == "PASS" for value in result["checks"].values()))

    def test_post_exec_identity_requires_live_pid_and_netns(self):
        r5 = load()
        passed = r5.validate_post_exec_identity(
            shell={"pid": 10, "netns": "net:[1]"},
            child={"pid": 10, "netns": "net:[1]", "live": True,
                   "start_ticks": 77, "exe": "/usr/bin/python3"},
            popen_pid=10,
        )
        self.assertTrue(passed["pass"])
        failed = r5.validate_post_exec_identity(
            shell={"pid": 10, "netns": "net:[1]"},
            child={"pid": 11, "netns": "net:[1]", "live": False},
            popen_pid=10,
        )
        self.assertFalse(failed["pass"])

    def test_r5_static_boundary_gate_passes(self):
        r5 = load()
        result = r5.static_self_check()
        self.assertTrue(result["pass"], result)
        self.assertTrue(result["clean_root_baseline_fail_closed"])
        self.assertTrue(result["no_mn_cleanup"])
        self.assertTrue(result["no_broad_rule_delete"])

    def test_r5_cli_exit_semantics(self):
        r5 = load()
        self.assertEqual(r5.verdict_exit_code("PASS_READY_FOR_GRAPH_NORMALIZATION"), 0)
        self.assertEqual(r5.verdict_exit_code("PARTIAL_MISSING_REQUIRED_EVENT_CLASS"), 3)
        self.assertEqual(r5.verdict_exit_code("BLOCKED"), 2)
        original = r5.privileged_run
        try:
            r5.privileged_run = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
            self.assertEqual(r5.main([]), 1)
        finally:
            r5.privileged_run = original


if __name__ == "__main__":
    unittest.main()
