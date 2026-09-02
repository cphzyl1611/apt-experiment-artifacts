#!/usr/bin/env python3
"""Tests for the bounded E1C-R6 file-permission collector."""

from __future__ import annotations

import base64
import ast
import contextlib
import hashlib
import io
import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

RUN_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(RUN_DIR))

import mininet_e1c_r6_file_access_closure_smoke as harness


def raw_file_access_bundle(
    serial=1,
    key="e1c6probe",
    path="/tmp/e1c-r6-probe.txt",
    syscall="257",
    success="yes",
    syscall_serial=None,
    path_serial=None,
    syscall_type="SYSCALL",
    path_type="PATH",
    key_in_syscall=True,
    include_path=True,
    a2="0",
):
    syscall_serial = serial if syscall_serial is None else syscall_serial
    path_serial = serial if path_serial is None else path_serial
    key_field = f' key="{key}"' if key_in_syscall else ""
    rows = [
        f'type={syscall_type} msg=audit(1788264578.381:{syscall_serial}): '
        f'arch=c000003e syscall={syscall} success={success} exit=3 '
        f'a0=ffffff9c a1=7f00 a2={a2} pid=4321{key_field}',
    ]
    if include_path:
        rows.append(
            f'type={path_type} msg=audit(1788264578.381:{path_serial}): '
            f'item=0 name="{path}" inode=1 dev=00:00 mode=0100644 ouid=0 ogid=0'
        )
    return "\n".join(rows) + "\n"


def poll_fixture(fixture, key="e1c6probe", path="/tmp/e1c-r6-probe.txt"):
    now = [0.0]

    def monotonic():
        return now[0]

    def sleep(duration):
        now[0] += duration

    return harness.poll_audit_evidence(
        key,
        path,
        runner=lambda argv, **kwargs: mock.Mock(
            returncode=0, stdout=fixture, stderr=""
        ),
        monotonic=monotonic,
        sleep=sleep,
        max_wait=0.1,
        poll_interval=0.01,
    )


def production_fixture(fixture, key, path):
    return harness.collect_production_audit_records(
        key,
        {},
        [path],
        deadline=12.0,
        runner=lambda argv, **kwargs: mock.Mock(
            returncode=0, stdout=fixture.encode(), stderr=b""
        ),
        monotonic=lambda: 10.0,
    )[1:]


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
    def test_production_collector_routes_ausearch_through_bounded_runner(self):
        source = inspect.getsource(harness._run_reviewed_mininet_smoke)
        self.assertIn("collect_production_audit_records", source)
        collector_source = inspect.getsource(harness.collect_production_audit_evidence)
        self.assertIn("run_bounded_ausearch_bytes", collector_source)
        self.assertIn("failure_reason", collector_source)

        tree = ast.parse(harness.HARNESS_PATH.read_text(encoding="utf-8"))
        unbounded_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name) or node.func.id != "run_command_bytes":
                continue
            if not node.args or not isinstance(node.args[0], (ast.List, ast.Tuple)):
                continue
            values = {
                item.value for item in node.args[0].elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            }
            if "/usr/sbin/ausearch" in values:
                unbounded_calls.append(node.lineno)
        self.assertEqual(unbounded_calls, [])

    def test_production_collector_passes_remaining_deadline_to_ausearch(self):
        key = "e1c6collector-deadline"
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return mock.Mock(returncode=0, stdout=b"raw-audit", stderr=b"")

        result = harness.collect_production_audit_evidence(
            key,
            deadline=12.0,
            runner=runner,
            monotonic=lambda: 10.25,
        )

        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["stdout"], b"raw-audit")
        self.assertEqual(calls[0][0], ["/usr/sbin/ausearch", "-k", key, "--raw"])
        self.assertEqual(calls[0][1]["timeout"], 1.75)
        self.assertLessEqual(calls[0][1]["timeout"], harness.AUDIT_EVIDENCE_MAX_WAIT_SECONDS)

    def test_production_collector_timeout_expiration_fails_closed(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(kwargs)
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"partial", stderr=b"late")

        with self.assertRaisesRegex(TimeoutError, "AUSEARCH_TIMEOUT"):
            harness.collect_production_audit_evidence(
                "e1c6collector-timeout",
                deadline=12.0,
                runner=runner,
                monotonic=lambda: 10.0,
            )

        self.assertEqual(len(calls), 1)
        self.assertGreater(calls[0]["timeout"], 0.0)
        self.assertLessEqual(calls[0]["timeout"], harness.AUDIT_EVIDENCE_MAX_WAIT_SECONDS)

    def test_production_collector_nonzero_returncode_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "returncode=1"):
            harness.collect_production_audit_evidence(
                "e1c6collector-failed",
                deadline=12.0,
                runner=lambda argv, **kwargs: mock.Mock(
                    returncode=1, stdout=b"raw-audit", stderr=b"failed"
                ),
                monotonic=lambda: 10.0,
            )

    def test_production_ausearch_receives_remaining_bounded_timeout(self):
        key = "e1c6production-deadline"
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return mock.Mock(returncode=0, stdout=b"raw-audit", stderr=b"")

        result = harness.run_bounded_ausearch_bytes(
            key,
            deadline=12.0,
            runner=runner,
            monotonic=lambda: 10.25,
        )

        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["stdout"], b"raw-audit")
        self.assertEqual(calls[0][0], ["/usr/sbin/ausearch", "-k", key, "--raw"])
        self.assertEqual(calls[0][1]["timeout"], 1.75)
        self.assertLessEqual(calls[0][1]["timeout"], harness.AUDIT_EVIDENCE_MAX_WAIT_SECONDS)

    def test_production_ausearch_skips_expired_deadline(self):
        calls = []

        def runner(*args, **kwargs):
            calls.append((args, kwargs))
            self.fail("ausearch must not run after the evidence deadline")

        result = harness.run_bounded_ausearch_bytes(
            "e1c6production-expired",
            deadline=12.0,
            runner=runner,
            monotonic=lambda: 12.0,
        )

        self.assertEqual(calls, [])
        self.assertIsNone(result["returncode"])
        self.assertEqual(result["failure_reason"], "AUSEARCH_DEADLINE_EXPIRED")
        self.assertTrue(result["ausearch_timeout"])

    def test_production_ausearch_timeout_expired_fails_closed(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(kwargs)
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"partial", stderr=b"late")

        result = harness.run_bounded_ausearch_bytes(
            "e1c6production-timeout",
            deadline=12.0,
            runner=runner,
            monotonic=lambda: 10.0,
        )

        self.assertEqual(result["failure_reason"], "AUSEARCH_TIMEOUT")
        self.assertTrue(result["ausearch_timeout"])
        self.assertEqual(result["stdout"], b"partial")
        self.assertEqual(result["stderr"], b"late")
        self.assertEqual(len(calls), 1)
        self.assertGreater(calls[0]["timeout"], 0)

    def test_production_ausearch_late_success_fails_closed(self):
        clock = iter([10.0, 12.0])

        def runner(argv, **kwargs):
            return mock.Mock(returncode=0, stdout=b"late-success", stderr=b"")

        result = harness.run_bounded_ausearch_bytes(
            "e1c6production-late",
            deadline=12.0,
            runner=runner,
            monotonic=lambda: next(clock),
        )

        self.assertEqual(result["failure_reason"], "AUSEARCH_DEADLINE_EXPIRED")
        self.assertTrue(result["ausearch_timeout"])

    def test_poll_rejects_successful_evidence_after_deadline(self):
        path = "/tmp/e1c-r6-poller-late-success.txt"
        key = "e1c6poller-late-success"
        fixture = raw_file_access_bundle(serial=120, key=key, path=path)
        now = [0.0]

        def runner(argv, **kwargs):
            now[0] = 0.3
            return mock.Mock(returncode=0, stdout=fixture, stderr="")

        result = harness.poll_audit_evidence(
            key,
            path,
            runner=runner,
            monotonic=lambda: now[0],
            sleep=lambda _: self.fail("late evidence must not be retried as success"),
            max_wait=0.2,
            poll_interval=0.01,
        )

        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertNotIn("AUDIT_EVIDENCE_PASS", result.get("states", []))

    def test_full_smoke_production_normalization_rejects_unrelated_record_type(self):
        path = "/tmp/e1c-r6-production-unrelated.txt"
        key = "e1c6production-unrelated"
        fixture = raw_file_access_bundle(
            serial=121, key=key, path=path,
            syscall_type="UNRELATED", path_type="UNRELATED",
        )

        raw_records, normalized = production_fixture(fixture, key, path)

        self.assertEqual(len(raw_records), 1)
        self.assertEqual(normalized, [])

    def test_full_smoke_production_normalization_rejects_unsuccessful_syscall(self):
        path = "/tmp/e1c-r6-production-unsuccessful.txt"
        key = "e1c6production-unsuccessful"
        fixture = raw_file_access_bundle(serial=122, key=key, path=path, success="no")

        _, normalized = production_fixture(fixture, key, path)

        self.assertNotIn("FILE_READ_OR_WRITE", {
            event["event_type"] for event in normalized
        })
        self.assertEqual(normalized, [])

    def test_full_smoke_production_normalization_rejects_wrong_or_missing_key(self):
        path = "/tmp/e1c-r6-production-key.txt"
        key = "e1c6production-exact-key"
        wrong_key_fixture = raw_file_access_bundle(serial=123, key="other-key", path=path)
        missing_key_fixture = raw_file_access_bundle(
            serial=124, key=key, path=path, key_in_syscall=False
        )

        _, wrong_key_normalized = production_fixture(wrong_key_fixture, key, path)
        _, missing_key_normalized = production_fixture(missing_key_fixture, key, path)

        self.assertEqual(wrong_key_normalized, [])
        self.assertEqual(missing_key_normalized, [])

    def test_full_smoke_production_normalization_rejects_wrong_path(self):
        path = "/tmp/e1c-r6-production-exact-path.txt"
        key = "e1c6production-exact-path"
        fixture = raw_file_access_bundle(serial=125, key=key, path="/tmp/other.txt")

        _, normalized = production_fixture(fixture, key, path)

        self.assertNotIn("FILE_READ_OR_WRITE", {
            event["event_type"] for event in normalized
        })
        self.assertEqual(
            [event["event_type"] for event in normalized],
            ["FILE_CREATE_OR_OPEN"],
        )

    def test_full_smoke_production_normalization_accepts_only_fully_valid_serial(self):
        path = "/tmp/e1c-r6-production-mixed.txt"
        key = "e1c6production-mixed"
        invalid = raw_file_access_bundle(
            serial=126, key=key, path=path, success="no"
        )
        valid = raw_file_access_bundle(serial=127, key=key, path=path)

        raw_records, normalized = production_fixture(invalid + valid, key, path)

        self.assertEqual([record["serial"] for record in raw_records], [126, 127])
        self.assertEqual([event["raw_serial"] for event in normalized], [127])

    def test_full_smoke_production_path_depends_on_strict_raw_acceptance(self):
        smoke_source = inspect.getsource(harness._run_reviewed_mininet_smoke)
        production_source = inspect.getsource(harness.collect_production_audit_records)
        normalization_source = inspect.getsource(harness.normalize_production_audit_records)

        self.assertIn("collect_production_audit_records", smoke_source)
        self.assertIn("normalize_production_audit_records", production_source)
        self.assertIn("_valid_raw_file_access_event", normalization_source)
        self.assertIn("strict_permission_events", normalization_source)

    def test_interpreted_timestamp_with_clock_colons_reproduces_old_parser_failure(self):
        interpreted = (
            'msg=audit(09/01/2026 08:09:38.381:1056): '
            'key="e1c6probeclock" name="/tmp/e1c-r6-probe-clock.txt"'
        )
        self.assertIsNone(harness.parse_audit_serial(interpreted))

    def test_poll_uses_raw_ausearch_mode_and_parses_raw_serial(self):
        path = "/tmp/e1c-r6-probe-raw.txt"
        key = "e1c6proberaw"
        raw = raw_file_access_bundle(serial=1056, key=key, path=path)

        def runner(argv, **kwargs):
            self.assertEqual(argv, ["/usr/sbin/ausearch", "-k", key, "--raw"])
            return mock.Mock(returncode=0, stdout=raw, stderr="")

        result = harness.poll_audit_evidence(
            key, path, runner=runner, monotonic=lambda: 0.0,
            sleep=lambda _: None, max_wait=0.1, poll_interval=0.01,
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["audit_serial"], 1056)
        self.assertEqual(result["evidence_mode"], "RAW")
        self.assertEqual(result["event_type"], "FILE_READ_OR_WRITE")
        self.assertEqual(result["evidence_basis"], "AUDIT_FILESYSTEM_PERMISSION_FILTER")
        self.assertEqual(result["watched_path"], path)
        self.assertEqual(result["raw_serial"], 1056)

    def test_original_immediate_lookup_reproduces_visibility_race(self):
        path = "/tmp/e1c-r6-probe-race.txt"
        key = "e1c6proberace"
        output = raw_file_access_bundle(serial=76, key=key, path=path)
        responses = ["", output]

        def runner(argv, **kwargs):
            return mock.Mock(returncode=0, stdout=responses.pop(0), stderr="")

        immediate_argv = ["/usr/sbin/ausearch", "-k", key, "-i"]
        self.assertIn("-i", immediate_argv)
        immediate = runner(immediate_argv)
        self.assertIsNone(harness.parse_audit_serial(immediate.stdout))
        result = harness.poll_audit_evidence(
            key, path, runner=runner, monotonic=lambda: 0.0,
            sleep=lambda _: None, max_wait=0.1, poll_interval=0.01,
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["poll_attempts"], 1)

    def test_audit_evidence_visible_immediately_passes(self):
        path = "/tmp/e1c-r6-probe-immediate.txt"
        key = "e1c6probeimmediate"
        output = raw_file_access_bundle(serial=77, key=key, path=path)
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return mock.Mock(returncode=0, stdout=output, stderr="")

        result = harness.poll_audit_evidence(
            key, path, runner=runner, monotonic=lambda: 0.0, sleep=lambda _: None,
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["poll_attempts"], 1)
        self.assertTrue(result["key_seen"])
        self.assertTrue(result["path_seen"])
        self.assertEqual(result["audit_serial"], 77)
        self.assertEqual(calls[0], ["/usr/sbin/ausearch", "-k", key, "--raw"])

    def test_audit_evidence_delayed_visibility_passes(self):
        path = "/tmp/e1c-r6-probe-delayed.txt"
        key = "e1c6probedelayed"
        output = raw_file_access_bundle(serial=78, key=key, path=path)
        responses = ["", "", output]
        clock = iter([0.0, 0.01, 0.02, 0.03])
        now = [0.0]

        def monotonic():
            value = now[0]
            now[0] += 0.01
            return value

        def runner(argv, **kwargs):
            return mock.Mock(returncode=0, stdout=responses.pop(0), stderr="")

        result = harness.poll_audit_evidence(
            key, path, runner=runner, monotonic=monotonic, sleep=lambda _: None,
            max_wait=0.2, poll_interval=0.01,
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["poll_attempts"], 3)
        self.assertGreaterEqual(result["elapsed_visibility_latency"], 0.0)

    def test_key_without_exact_path_keeps_polling_then_blocks(self):
        path = "/tmp/e1c-r6-probe-missing-path.txt"
        key = "e1c6probemissingpath"
        output = raw_file_access_bundle(
            serial=79, key=key, path="/tmp/other.txt"
        )
        calls = []
        now = [0.0]

        def monotonic():
            value = now[0]
            now[0] += 0.02
            return value

        def runner(argv, **kwargs):
            calls.append(argv)
            return mock.Mock(returncode=0, stdout=output, stderr="")

        result = harness.poll_audit_evidence(
            key, path, runner=runner, monotonic=monotonic, sleep=lambda _: None,
            max_wait=0.2, poll_interval=0.01,
        )
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertGreaterEqual(result["poll_attempts"], 2)
        self.assertTrue(result["key_seen"])
        self.assertFalse(result["path_seen"])
        self.assertEqual(result["audit_serial"], 79)

    def test_raw_path_without_exact_key_blocks(self):
        path = "/tmp/e1c-r6-probe-missing-key.txt"
        key = "e1c6probemissingkey"
        output = raw_file_access_bundle(serial=80, key="otherkey", path=path)
        now = [-0.05]

        def monotonic():
            value = now[0]
            now[0] += 0.05
            return value

        result = harness.poll_audit_evidence(
            key, path,
            runner=lambda argv, **kwargs: mock.Mock(returncode=0, stdout=output, stderr=""),
            monotonic=monotonic, sleep=lambda _: None, max_wait=0.2, poll_interval=0.01,
        )
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertFalse(result["key_seen"])
        self.assertTrue(result["path_seen"])
        self.assertEqual(result["audit_serial"], 80)

    def test_raw_malformed_or_missing_serial_blocks(self):
        path = "/tmp/e1c-r6-probe-malformed.txt"
        key = "e1c6probemalformed"
        output = f'msg=audit(not-a-serial): key={key} name={path}\n'
        now = [-0.05]

        def monotonic():
            value = now[0]
            now[0] += 0.05
            return value

        result = harness.poll_audit_evidence(
            key, path,
            runner=lambda argv, **kwargs: mock.Mock(returncode=1, stdout=output, stderr="bad"),
            monotonic=monotonic, sleep=lambda _: None, max_wait=0.1,
        )
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertIsNone(result["audit_serial"])
        self.assertTrue(result["key_seen"])
        self.assertTrue(result["path_seen"])

    def test_audit_evidence_timeout_blocks_closed(self):
        key = "e1c6probetimeout"
        path = "/tmp/e1c-r6-probe-timeout.txt"
        now = [0.0]

        def monotonic():
            value = now[0]
            now[0] += 0.11
            return value

        result = harness.poll_audit_evidence(
            key, path,
            runner=lambda argv, **kwargs: mock.Mock(returncode=1, stdout="", stderr="not found"),
            monotonic=monotonic, sleep=lambda _: None, max_wait=0.2, poll_interval=0.01,
        )
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertEqual(result["final_ausearch_returncode"], 1)
        self.assertFalse(result["key_seen"])
        self.assertFalse(result["path_seen"])

    def test_ausearch_receives_finite_timeout_within_remaining_budget(self):
        key = "e1c6probe-deadline"
        path = "/tmp/e1c-r6-probe-deadline.txt"
        now = [0.0]
        timeouts = []

        def runner(argv, **kwargs):
            timeouts.append(kwargs.get("timeout"))
            return mock.Mock(returncode=1, stdout="", stderr="not found")

        def sleep(duration):
            now[0] += duration

        result = harness.poll_audit_evidence(
            key,
            path,
            runner=runner,
            monotonic=lambda: now[0],
            sleep=sleep,
            max_wait=0.2,
            poll_interval=0.05,
        )
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertGreaterEqual(len(timeouts), 2)
        self.assertTrue(all(timeout is not None for timeout in timeouts))
        self.assertTrue(all(0 < timeout <= 0.2 for timeout in timeouts))
        self.assertEqual(timeouts, sorted(timeouts, reverse=True))

    def test_exhausted_evidence_budget_skips_ausearch(self):
        key = "e1c6probe-exhausted"
        path = "/tmp/e1c-r6-probe-exhausted.txt"
        calls = []
        clock = iter([0.0, 0.2, 0.2])

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return mock.Mock(returncode=0, stdout="", stderr="")

        result = harness.poll_audit_evidence(
            key,
            path,
            runner=runner,
            monotonic=lambda: next(clock),
            sleep=lambda _: None,
            max_wait=0.2,
            poll_interval=0.05,
        )
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertEqual(calls, [])
        self.assertEqual(result["poll_attempts"], 0)

    def test_ausearch_timeout_expired_fails_closed_with_distinct_diagnostic(self):
        key = "e1c6probe-timeout-expired"
        path = "/tmp/e1c-r6-probe-timeout-expired.txt"
        calls = []

        def runner(argv, **kwargs):
            calls.append(kwargs)
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        result = harness.poll_audit_evidence(
            key,
            path,
            runner=runner,
            monotonic=lambda: 0.0,
            sleep=lambda _: self.fail("sleep must not retry after timeout"),
            max_wait=0.2,
            poll_interval=0.05,
        )
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertEqual(result["poll_attempts"], 1)
        self.assertEqual(result["failure_reason"], "AUSEARCH_TIMEOUT")
        self.assertTrue(result["ausearch_timeout"])
        self.assertEqual(len(calls), 1)
        self.assertGreater(calls[0]["timeout"], 0)

    def test_timeout_does_not_extend_overall_evidence_window(self):
        key = "e1c6probe-timeout-window"
        path = "/tmp/e1c-r6-probe-timeout-window.txt"
        now = [0.0]

        def monotonic():
            return now[0]

        def runner(argv, **kwargs):
            now[0] = 0.2
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        result = harness.poll_audit_evidence(
            key,
            path,
            runner=runner,
            monotonic=monotonic,
            sleep=lambda _: self.fail("sleep must not extend the deadline"),
            max_wait=0.2,
            poll_interval=0.05,
        )
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertLessEqual(result["elapsed_visibility_latency"], 0.2)

    def test_unrelated_raw_record_with_matching_text_blocks(self):
        key = "e1c6probe-unrelated"
        path = "/tmp/e1c-r6-probe-unrelated.txt"
        fixture = raw_file_access_bundle(
            serial=101, key=key, path=path,
            syscall_type="UNRELATED", path_type="UNRELATED",
        )
        result = poll_fixture(fixture, key, path)
        self.assertEqual(result["verdict"], "BLOCKED")

    def test_syscall_and_path_on_different_serials_block(self):
        key = "e1c6probe-split-serial"
        path = "/tmp/e1c-r6-probe-split-serial.txt"
        fixture = raw_file_access_bundle(
            serial=102, key=key, path=path, path_serial=103,
        )
        result = poll_fixture(fixture, key, path)
        self.assertEqual(result["verdict"], "BLOCKED")

    def test_key_and_path_on_different_serials_block(self):
        key = "e1c6probe-split-key-path"
        path = "/tmp/e1c-r6-probe-split-key-path.txt"
        fixture = raw_file_access_bundle(
            serial=104, key=key, path=path, include_path=False,
        )
        fixture += raw_file_access_bundle(
            serial=105, key="other-key", path=path,
            syscall_type="PATH", path_type="PATH", key_in_syscall=False,
            include_path=True,
        )
        result = poll_fixture(fixture, key, path)
        self.assertEqual(result["verdict"], "BLOCKED")

    def test_missing_syscall_record_blocks(self):
        key = "e1c6probe-missing-syscall"
        path = "/tmp/e1c-r6-probe-missing-syscall.txt"
        fixture = raw_file_access_bundle(
            serial=106, key=key, path=path,
            syscall_type="PATH", path_type="PATH",
        )
        result = poll_fixture(fixture, key, path)
        self.assertEqual(result["verdict"], "BLOCKED")

    def test_missing_same_serial_path_record_blocks(self):
        key = "e1c6probe-missing-path-record"
        path = "/tmp/e1c-r6-probe-missing-path-record.txt"
        fixture = raw_file_access_bundle(
            serial=107, key=key, path=path, include_path=False,
        )
        result = poll_fixture(fixture, key, path)
        self.assertEqual(result["verdict"], "BLOCKED")

    def test_unsuccessful_syscall_blocks(self):
        key = "e1c6probe-unsuccessful"
        path = "/tmp/e1c-r6-probe-unsuccessful.txt"
        fixture = raw_file_access_bundle(
            serial=108, key=key, path=path, success="no",
        )
        result = poll_fixture(fixture, key, path)
        self.assertEqual(result["verdict"], "BLOCKED")

    def test_malformed_or_missing_syscall_identity_blocks(self):
        key = "e1c6probe-bad-syscall"
        path = "/tmp/e1c-r6-probe-bad-syscall.txt"
        for syscall in ("not-a-number", ""):
            with self.subTest(syscall=syscall):
                fixture = raw_file_access_bundle(
                    serial=109, key=key, path=path, syscall=syscall,
                )
                result = poll_fixture(fixture, key, path)
                self.assertEqual(result["verdict"], "BLOCKED")

    def test_wrong_exact_key_blocks(self):
        key = "e1c6probe-exact-key"
        path = "/tmp/e1c-r6-probe-exact-key.txt"
        fixture = raw_file_access_bundle(serial=110, key="different-key", path=path)
        result = poll_fixture(fixture, key, path)
        self.assertEqual(result["verdict"], "BLOCKED")

    def test_wrong_exact_path_blocks(self):
        key = "e1c6probe-exact-path"
        path = "/tmp/e1c-r6-probe-exact-path.txt"
        fixture = raw_file_access_bundle(serial=111, key=key, path="/tmp/other.txt")
        result = poll_fixture(fixture, key, path)
        self.assertEqual(result["verdict"], "BLOCKED")

    def test_timeout_probe_cleanup_and_restoration_still_occurs(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            if argv[0] == "/usr/sbin/auditctl" and argv[1] == "-l":
                return mock.Mock(returncode=0, stdout="No rules\n", stderr="")
            if argv[0] == "/usr/sbin/auditctl" and argv[1] == "-s":
                return mock.Mock(returncode=0, stdout="lost 0\nbacklog 0\n", stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(harness, "_audit_baseline_clean", return_value=True), \
             mock.patch.object(harness.subprocess, "run", side_effect=runner), \
             mock.patch.object(harness.tempfile, "NamedTemporaryFile") as temp_file:
            handle = mock.Mock(name="probe-handle")
            handle.name = "/tmp/e1c-r6-probe-timeout-cleanup.txt"
            temp_file.return_value = handle
            with mock.patch.object(harness.subprocess, "Popen") as popen:
                child = mock.Mock(pid=4321, returncode=0)
                child.poll.return_value = 0
                popen.return_value = child
                with mock.patch.object(harness.os, "unlink") as unlink:
                    result = harness._default_micro_probe()
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertIn("RULE_REMOVED_BASELINE_RESTORED", result["states"])
        self.assertTrue(unlink.called)
        self.assertTrue(any(argv[1] == "-d" for argv in calls if argv and argv[0] == "/usr/sbin/auditctl"))

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
        self.assertTrue(checks["production_ausearch_bounded"])
        self.assertTrue(checks["production_ausearch_fail_closed"])
        self.assertEqual(checks["unbounded_ausearch_calls"], [])

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
