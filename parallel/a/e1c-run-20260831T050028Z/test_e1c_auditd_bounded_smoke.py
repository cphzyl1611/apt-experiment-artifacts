#!/usr/bin/python3
"""Unprivileged contract tests for the E1C auditd smoke harness."""

import importlib.util
import json
import unittest
from pathlib import Path


HARNESS_PATH = Path(__file__).resolve().parent / "mininet_e1c_auditd_bounded_smoke.py"


def load_harness():
    spec = importlib.util.spec_from_file_location("e1c_auditd_smoke", HARNESS_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class E1CAuditdSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = load_harness()

    def test_all_rules_are_bounded_and_names_are_unique(self):
        specs = self.harness.rule_specs("e1c-test", 101, Path("/tmp/e1c-test"), scope="h1_pid")
        specs += self.harness.rule_specs("e1c-test", 101, Path("/tmp/e1c-test"), ppid=101, scope="h1_ppid")
        names = [spec["name"] for spec in specs]
        self.assertEqual(len(names), len(set(names)))
        for spec in specs:
            argv = spec["add"]
            self.assertNotIn("-D", argv)
            self.assertIn("-k", argv)
            if "-S" in argv and ("read" in argv or "write" in argv):
                self.assertIn("-F", argv)
                self.assertTrue(any(item.startswith("dir=") for item in argv))
            self.assertTrue(any(item.startswith("pid=") or item.startswith("ppid=") for item in argv))

    def test_rule_removal_preserves_exact_add_shape(self):
        add = ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", "bind", "-F", "pid=42", "-k", "e1c"]
        self.assertEqual(
            self.harness.remove_argv(add),
            ["/usr/sbin/auditctl", "-d", "always,exit", "-F", "arch=b64", "-S", "bind", "-F", "pid=42", "-k", "e1c"],
        )

    def test_audit_status_parser_keeps_loss_and_backlog_fields(self):
        status = self.harness.parse_audit_status("enabled 1\nbacklog_limit 8192\nbacklog 3\nlost 0\n")
        self.assertEqual(status["enabled"], 1)
        self.assertEqual(status["backlog_limit"], 8192)
        self.assertEqual(status["backlog"], 3)
        self.assertEqual(status["lost"], 0)

    def test_raw_audit_grouping_preserves_serial_and_hash(self):
        raw = (
            b'type=SYSCALL msg=audit(1710000000.100:10): arch=c000003e syscall=59 pid=11 ppid=2 exe="/bin/a"\n'
            b'type=EXECVE msg=audit(1710000000.100:10): argc=1 a0="/bin/a"\n'
            b'type=SYSCALL msg=audit(1710000000.200:11): arch=c000003e syscall=231 pid=11 ppid=2 exe="/bin/a"\n'
        )
        records, malformed = self.harness.parse_audit_groups(raw)
        self.assertEqual(malformed, [])
        self.assertEqual([record["serial"] for record in records], [10, 11])
        self.assertEqual(records[0]["record_types"], ["SYSCALL", "EXECVE"])
        self.assertEqual(records[0]["raw_sha256"], self.harness.sha256_bytes(records[0]["raw_text"].encode()))

    def test_normalization_maps_required_syscall_classes_and_join(self):
        raw = b'type=SYSCALL msg=audit(1710000000.100:10): arch=c000003e syscall=49 pid=11 ppid=2 exe="/bin/a" saddr=0100000A\n'
        records, _ = self.harness.parse_audit_groups(raw)
        event = self.harness.normalize_audit_record(records[0], "e1c-test", {11: {"netns_inode": 99, "logical_host_id": "h1", "join_status": "JOINED"}})
        self.assertEqual(event["event_type"], "SOCKET_BIND")
        self.assertEqual(event["pid"], 11)
        self.assertEqual(event["logical_host_id"], "h1")
        self.assertEqual(event["raw_serial"], 10)
        self.assertEqual(event["raw_event_sha256"], records[0]["raw_sha256"])
        self.assertEqual(event["sockaddr"], "0100000A")

    def test_namespace_assertions_require_owner_and_cross_host_distinction(self):
        result = self.harness.build_namespace_assertions(
            {"h1": {"netns": "net:[1]"}, "h2": {"netns": "net:[2]"}},
            {"h1": {"netns": "net:[1]"}, "h2": {"netns": "net:[2]"}},
        )
        self.assertTrue(result["pass"])
        self.assertEqual(tuple(result["checks"]), self.harness.REQUIRED_NAMESPACE_CHECKS)

    def test_static_self_check_covers_boundaries_and_rule_families(self):
        result = self.harness.static_self_check()
        self.assertTrue(result["pass"], json.dumps(result, indent=2))
        self.assertTrue(result["no_nat_or_external_links"])
        self.assertTrue(result["no_apt_commands"])
        self.assertTrue(result["no_automatic_sudo"])
        self.assertTrue(result["no_mn_c"])
        self.assertTrue(result["transient_audit_rules_only"])
        self.assertTrue(result["bounded_file_rules"])
        self.assertTrue(result["pid_or_ppid_filtered_rules"])
        self.assertTrue(result["required_syscall_families_present"])

    def test_required_normalized_classes_are_explicit(self):
        self.assertEqual(
            self.harness.REQUIRED_CLASSES,
            (
                "PROCESS_START_OR_EXEC",
                "PROCESS_EXIT",
                "FILE_CREATE_OR_OPEN",
                "FILE_READ_OR_WRITE",
                "FILE_DELETE",
                "SOCKET_BIND",
                "SOCKET_CONNECT",
                "SOCKET_ACCEPT",
            ),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
