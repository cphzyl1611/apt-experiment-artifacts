#!/usr/bin/env python3
"""Unprivileged TDD tests for the bounded E1C-R2 harness."""

import base64
import hashlib
import importlib.util
import inspect
import unittest
from pathlib import Path


HARNESS_PATH = Path(__file__).with_name("mininet_e1c_r2_corrected_smoke.py")
spec = importlib.util.spec_from_file_location("e1c_r2_harness", HARNESS_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load {HARNESS_PATH}")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class E1CR2HarnessTests(unittest.TestCase):
    def test_static_boundaries_forbid_broad_or_external_actions(self):
        source = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertNotIn("auditctl -D", source)
        self.assertNotIn('"-D"', source)
        self.assertNotIn("mn -c", source)
        self.assertNotIn("addNAT", source)
        self.assertNotIn("iptables", source)
        self.assertNotIn("apt-get", source)
        self.assertNotIn("provx", source.lower())
        self.assertIn("auditctl", source)

    def test_supported_syscalls_are_filtered_individually(self):
        supported = {"openat", "read", "write", "unlink", "bind", "connect", "accept4"}
        specs = harness.build_rule_specs("r2-test-key", 1234, "/tmp/r2", supported)
        self.assertTrue(specs)
        for rule_spec in specs:
            add = rule_spec["add_argv"]
            syscalls = [add[i + 1] for i, value in enumerate(add[:-1]) if value == "-S"]
            self.assertTrue(set(syscalls).issubset(supported))
            self.assertNotIn("pread64", syscalls)
            self.assertIn("-F", add)
            self.assertIn("-k", add)

    def test_blocking_handshake_has_listener_ready_and_accept(self):
        source = inspect.getsource(harness.benign_child)
        self.assertIn('"READY"', source)
        self.assertIn("listener.accept()", source)
        self.assertNotIn("setblocking(False)", source)
        self.assertNotIn("exit=-115", source)

    def test_namespace_assertions_require_all_four_checks(self):
        shells = {"h1": "net:[100]", "h2": "net:[200]"}
        children = {"h1": "net:[100]", "h2": "net:[200]"}
        result = harness.namespace_assertions(shells, children)
        self.assertEqual(result["checks"], {
            "h1_child_netns == h1_shell_netns": True,
            "h2_child_netns == h2_shell_netns": True,
            "h1_child_netns != h2_shell_netns": True,
            "h2_child_netns != h1_shell_netns": True,
        })
        self.assertTrue(result["pass"])

    def test_normalization_keeps_raw_serial_bytes_and_hash(self):
        raw = b'type=SYSCALL msg=audit(1.25:77): syscall=49 success=yes exit=0 ppid=10 pid=11 comm="python3" exe="/usr/bin/python3" key="r2"\n'
        event = harness.normalize_audit_record({
            "serial": 77,
            "timestamp_source": "1.25",
            "raw_bytes": raw,
            "raw_text": raw.decode(),
        }, {11: {"logical_host_id": "h1", "netns_inode": 100}})
        self.assertEqual(event["event_type"], "SOCKET_BIND")
        self.assertEqual(event["raw_serial"], 77)
        self.assertEqual(base64.b64decode(event["raw_event_bytes_b64"]), raw)
        self.assertEqual(event["raw_event_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(event["logical_host_id"], "h1")

    def test_exact_cleanup_only_deletes_successful_specs(self):
        specs = [{"name": "ok", "add_argv": ["/usr/sbin/auditctl", "-a", "always,exit", "-k", "r2"]}]
        calls = []
        result = harness.remove_rules_exact(specs, lambda argv: calls.append(argv) or {"returncode": 0})
        self.assertEqual(result[0]["name"], "ok")
        self.assertEqual(calls, [["/usr/sbin/auditctl", "-d", "always,exit", "-k", "r2"]])


if __name__ == "__main__":
    unittest.main()
