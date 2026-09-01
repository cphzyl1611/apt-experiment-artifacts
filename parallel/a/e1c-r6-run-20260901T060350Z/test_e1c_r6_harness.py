#!/usr/bin/env python3
"""Tests for the bounded E1C-R6 file-permission collector."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

RUN_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(RUN_DIR))

import mininet_e1c_r6_file_access_closure_smoke as harness


class FilePermissionRuleTests(unittest.TestCase):
    def test_builds_exact_path_perm_pid_rule(self):
        path = "/tmp/e1c-r6-h1-read-write.txt"
        add = harness.build_file_permission_watch_rule(path, 1234, "e1c6key")
        self.assertEqual(
            add,
            [
                "/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64",
                "-F", f"path={path}", "-F", "perm=rw", "-F", "pid=1234",
                "-k", "e1c6key",
            ],
        )
        self.assertNotIn("-S", add)
        self.assertNotIn("all", add)

    def test_builds_exact_inverse_delete_rule(self):
        add = harness.build_file_permission_watch_rule(
            "/tmp/e1c-r6-h1-read-write.txt", 1234, "e1c6key"
        )
        self.assertEqual(harness.delete_rule_from_add(add)[1], "-d")
        self.assertEqual(
            harness.delete_rule_from_add(add),
            [
                "/usr/sbin/auditctl", "-d", "always,exit", "-F", "arch=b64",
                "-F", "path=/tmp/e1c-r6-h1-read-write.txt", "-F", "perm=rw",
                "-F", "pid=1234", "-k", "e1c6key",
            ],
        )

    def test_rejects_unbounded_or_non_exact_paths(self):
        for path in ("relative.txt", "/tmp/*.txt", "/tmp"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                harness.build_file_permission_watch_rule(path, 1234, "e1c6key")


class MicroProbeTests(unittest.TestCase):
    def test_default_smoke_is_real_reviewed_callable(self):
        self.assertEqual(harness._reviewed_mininet_smoke.__name__, "_reviewed_mininet_smoke")
        self.assertIn("_run_reviewed_mininet_smoke", harness._reviewed_mininet_smoke.__code__.co_names)
        self.assertNotIn("MININET_SMOKE_REQUIRES_HUMAN_REVIEWED_RUNTIME", harness._reviewed_mininet_smoke.__doc__ or "")

    def test_default_path_calls_real_smoke_only_after_probe_pass(self):
        with mock.patch.object(
            harness, "_default_micro_probe",
            return_value={"verdict": "PASS", "states": [
                "CLEAN_BASELINE_VERIFIED", "AUDIT_EVIDENCE_PASS",
                "RULE_REMOVED_BASELINE_RESTORED",
            ]},
        ), mock.patch.object(
            harness, "_run_reviewed_mininet_smoke", return_value=0,
        ) as smoke:
            result = harness.execute_reviewed_r6_path()
        self.assertEqual(result["verdict"], "PASS")
        smoke.assert_called_once_with()

    def test_probe_requires_audit_backed_file_access_event(self):
        self.assertEqual(harness.micro_probe_verdict([]), "BLOCKED")
        event = {
            "event_type": "FILE_READ_OR_WRITE",
            "evidence_basis": "AUDIT_FILESYSTEM_PERMISSION_FILTER",
            "watched_path": "/tmp/e1c-r6-probe.txt",
        }
        self.assertEqual(harness.micro_probe_verdict([event]), "PASS")

    def test_probe_never_accepts_tcpdump_or_strace_as_evidence(self):
        self.assertEqual(
            harness.micro_probe_verdict(
                [{"event_type": "FILE_READ_OR_WRITE", "evidence_basis": "STRACE"}]
            ),
            "BLOCKED",
        )

    def test_probe_state_records_exact_cleanup(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)

        result = harness.run_privileged_micro_probe(
            "/tmp/e1c-r6-probe-state.txt", 4321, runner=runner
        )
        self.assertEqual(result["state"][-1], "RULE_REMOVED_BASELINE_RESTORED")
        self.assertEqual(calls[0][1], "-a")
        self.assertEqual(calls[1][1], "-d")

    def test_static_self_check_is_safe(self):
        checks = harness.static_self_check()
        self.assertTrue(checks["static_safety"])

    def test_probe_state_machine_requires_ordered_gate(self):
        self.assertEqual(
            harness.validate_micro_probe_state(
                ["CLEAN_BASELINE_VERIFIED", "FILE_PRECREATED", "RULE_ADDED",
                 "BENIGN_READ_WRITE_PERFORMED", "AUDIT_EVIDENCE_PASS",
                 "RULE_REMOVED_BASELINE_RESTORED"]
            ),
            "PASS",
        )
        self.assertEqual(
            harness.validate_micro_probe_state(["FILE_PRECREATED", "RULE_ADDED"]),
            "BLOCKED",
        )
        def clean_runner(argv, **kwargs):
            return mock.Mock(stdout="No rules\n" if argv[-1] == "-l" else "lost 0\nbacklog 0\n")
        self.assertTrue(harness._audit_baseline_clean(runner=clean_runner))

        def stale_runner(argv, **kwargs):
            return mock.Mock(stdout="No rules\n" if argv[-1] == "-l" else "lost 0\nbacklog 1\n")
        self.assertFalse(harness._audit_baseline_clean(runner=stale_runner))

    def test_run_privileged_enters_reviewed_path_not_placeholder_gate(self):
        output = io.StringIO()
        with mock.patch.object(harness.os, "geteuid", return_value=0), \
             mock.patch.object(
                 harness, "execute_reviewed_r6_path",
                 return_value={"verdict": "BLOCKED", "states": ["CLEAN_BASELINE_VERIFIED"]},
             ) as execute, contextlib.redirect_stdout(output):
            code = harness.main(["--run-privileged"])
        self.assertEqual(code, harness.verdict_exit_code("BLOCKED"))
        execute.assert_called_once()
        self.assertNotIn("separately reviewed micro-probe/full-run implementation", output.getvalue())

    def test_full_smoke_is_reachable_only_after_probe_pass(self):
        smoke_calls = []
        blocked = harness.execute_reviewed_r6_path(
            probe=lambda: {"verdict": "BLOCKED", "states": ["CLEAN_BASELINE_VERIFIED"]},
            smoke=lambda: smoke_calls.append(True) or {"verdict": "PASS"},
        )
        self.assertEqual(blocked["verdict"], "BLOCKED")
        self.assertEqual(smoke_calls, [])
        passed = harness.execute_reviewed_r6_path(
            probe=lambda: {"verdict": "PASS", "states": [
                "CLEAN_BASELINE_VERIFIED", "AUDIT_EVIDENCE_PASS",
                "RULE_REMOVED_BASELINE_RESTORED",
            ]},
            smoke=lambda: smoke_calls.append(True) or {"verdict": "PASS"},
        )
        self.assertEqual(passed["verdict"], "PASS")
        self.assertEqual(smoke_calls, [True])

    def test_probe_pass_requires_cleanup_before_smoke(self):
        observed = []
        unproven = harness.execute_reviewed_r6_path(
            probe=lambda: {"verdict": "PASS", "states": ["CLEAN_BASELINE_VERIFIED", "AUDIT_EVIDENCE_PASS"]},
            smoke=lambda: observed.append(True) or {"verdict": "PASS"},
        )
        self.assertEqual(unproven["verdict"], "BLOCKED")
        self.assertEqual(observed, [])
        result = harness.execute_reviewed_r6_path(
            probe=lambda: {"verdict": "PASS", "states": [
                "CLEAN_BASELINE_VERIFIED", "AUDIT_EVIDENCE_PASS",
                "RULE_REMOVED_BASELINE_RESTORED",
            ]},
            smoke=lambda: observed.append(True) or {"verdict": "PASS"},
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(observed, [True])
        self.assertLess(result["states"].index("RULE_REMOVED_BASELINE_RESTORED"), result["states"].index("MININET_EXECUTED"))

    def test_smoke_exception_has_cleanup_and_baseline_states(self):
        result = harness.execute_reviewed_r6_path(
            probe=lambda: {"verdict": "PASS", "states": [
                "CLEAN_BASELINE_VERIFIED", "AUDIT_EVIDENCE_PASS",
                "RULE_REMOVED_BASELINE_RESTORED",
            ]},
            smoke=lambda: (_ for _ in ()).throw(RuntimeError("smoke failed")),
        )
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertEqual(result["states"][-2:], ["CLEANUP", "BASELINE_RESTORED"])

    def test_smoke_partial_is_preserved_with_cleanup(self):
        result = harness.execute_reviewed_r6_path(
            probe=lambda: {"verdict": "PASS", "states": [
                "CLEAN_BASELINE_VERIFIED", "AUDIT_EVIDENCE_PASS",
                "RULE_REMOVED_BASELINE_RESTORED",
            ]},
            smoke=lambda: {"verdict": "PARTIAL"},
        )
        self.assertEqual(result["verdict"], "PARTIAL")
        self.assertEqual(result["states"][-2:], ["CLEANUP", "BASELINE_RESTORED"])

    def test_probe_exception_is_blocked_without_smoke(self):
        smoke_calls = []
        result = harness.execute_reviewed_r6_path(
            probe=lambda: (_ for _ in ()).throw(RuntimeError("probe failed")),
            smoke=lambda: smoke_calls.append(True) or {"verdict": "PASS"},
        )
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertEqual(smoke_calls, [])

    def test_all_required_classes_are_runtime_contract(self):
        self.assertEqual(len(harness.REQUIRED_CLASSES), 8)
        self.assertIn("FILE_READ_OR_WRITE", harness.REQUIRED_CLASSES)


class FilesystemNormalizationTests(unittest.TestCase):
    def test_preserves_permission_filter_semantics(self):
        row = harness.normalize_filesystem_permission_event(
            {
                "serial": 77,
                "raw_sha256": "abc",
                "raw_text": 'type=SYSCALL msg=audit(1.2:77): syscall=257 pid=1234',
            },
            "/tmp/e1c-r6-h1-read-write.txt",
            "rw",
            "read",
            "h1",
        )
        self.assertEqual(row["event_type"], "FILE_READ_OR_WRITE")
        self.assertEqual(row["evidence_basis"], "AUDIT_FILESYSTEM_PERMISSION_FILTER")
        self.assertEqual(row["watched_path"], "/tmp/e1c-r6-h1-read-write.txt")
        self.assertEqual(row["requested_access"], "rw")
        self.assertEqual(row["underlying_syscall"], "read")
        self.assertEqual(row["raw_serial"], 77)


def raw(serial=1, text="raw"):
    blob = text.encode()
    return {"serial": serial, "raw_sha256": hashlib.sha256(blob).hexdigest(), "raw_bytes_b64": base64.b64encode(blob).decode()}


def normalized(serial=1, text="raw"):
    blob = text.encode()
    return {"raw_serial": serial, "raw_event_sha256": hashlib.sha256(blob).hexdigest()}


class RawLinkTests(unittest.TestCase):
    def test_valid_link(self):
        self.assertEqual(harness.verify_raw_event_links([raw()], [normalized()]), {"valid": True, "failures": []})

    def test_serial_mismatch(self):
        result = harness.verify_raw_event_links([raw(1)], [normalized(2)])
        self.assertFalse(result["valid"])
        self.assertIn("SERIAL_MISMATCH", result["failures"])

    def test_raw_hash_mismatch(self):
        bad = normalized()
        bad["raw_event_sha256"] = "0" * 64
        result = harness.verify_raw_event_links([raw()], [bad])
        self.assertFalse(result["valid"])
        self.assertIn("RAW_HASH_MISMATCH", result["failures"])

    def test_duplicate_serial(self):
        result = harness.verify_raw_event_links([raw(1), raw(1)], [normalized()])
        self.assertFalse(result["valid"])
        self.assertIn("DUPLICATE_RAW_SERIAL", result["failures"])

    def test_missing_raw_record(self):
        result = harness.verify_raw_event_links([], [normalized()])
        self.assertFalse(result["valid"])
        self.assertIn("MISSING_RAW_RECORD", result["failures"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
