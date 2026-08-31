#!/usr/bin/env python3
"""R4 RED/GREEN tests for delete argv construction and CLI semantics."""

import importlib.util
import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path


RUN_DIR = Path(__file__).resolve().parent
R3_HARNESS = RUN_DIR.parent / "e1c-r3-run-20260831T075356Z" / "mininet_e1c_r3_auditd_bounded_smoke.py"
R4_HARNESS = RUN_DIR / "mininet_e1c_r4_delete_argv_fixed_smoke.py"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class E1CR4HarnessTests(unittest.TestCase):
    def test_r4_mutation_argv_has_explicit_auditctl_executable(self):
        r4 = load(R4_HARNESS, "e1c_r4_mutation")
        sources = [
            ["-a", "always,exit", "-F", "pid=123", "-k", "r1"],
            ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "ppid=123", "-k", "r2"],
        ]
        for source in sources:
            for action in ("ADD", "DELETE"):
                argv = r4.mutation_argv(source, action)
                self.assertEqual(argv[0], "/usr/sbin/auditctl")
                self.assertIn(argv[1], {"-a", "-d"})

    def test_r4_mutation_accepts_pid_ppid_dir_and_socket_prior_rules(self):
        r4 = load(R4_HARNESS, "e1c_r4_prior_rules")
        rules = [
            ["-a", "always,exit", "-F", "arch=b64", "-S", "bind", "-F", "pid=123", "-F", "key=e1c902f74f583"],
            ["-a", "always,exit", "-F", "arch=b64", "-S", "openat", "-F", "dir=/tmp/r4", "-F", "ppid=123", "-F", "key=e1c30cd510e09357"],
            ["-a", "always,exit", "-F", "arch=b64", "-S", "connect", "-F", "ppid=123", "-F", "key=e1c4prior"],
        ]
        for rule in rules:
            argv = r4.mutation_argv(rule, "DELETE")
            self.assertEqual(argv[:2], ["/usr/sbin/auditctl", "-d"])
            self.assertEqual(r4.canonical_rule(argv), r4.canonical_rule(rule))

    def test_r4_mutation_journal_uses_fixed_argv(self):
        r4 = load(R4_HARNESS, "e1c_r4_journal")
        with tempfile.TemporaryDirectory() as tmp:
            spec = {"name": "r1-residual", "add_argv": ["-a", "always,exit", "-F", "pid=123", "-F", "key=e1c902f74f583"]}
            calls = []

            def runner(argv):
                calls.append(argv)
                return {"argv": argv, "returncode": 0, "stdout": "", "stderr": ""}

            r4.mutation(Path(tmp) / "journal.jsonl", spec, "DELETE", "R1", runner=runner)
            self.assertEqual(calls[0][:2], ["/usr/sbin/auditctl", "-d"])
            entries = [json.loads(line) for line in (Path(tmp) / "journal.jsonl").read_text().splitlines()]
            self.assertEqual([entry["kind"] for entry in entries], ["PLANNED_DELETE", "DELETE_RESULT"])

    def test_r4_builds_bounded_pid_ppid_dir_socket_specs(self):
        r4 = load(R4_HARNESS, "e1c_r4_specs")
        supported = {"openat", "read", "write", "unlink", "bind", "connect", "accept4"}
        for scope, ppid in (("pid", None), ("ppid", 1234)):
            specs = r4.build_rule_specs("r4-key", 1234, "/tmp/r4", supported, ppid=ppid, scope=scope)
            self.assertTrue(specs)
            for spec in specs:
                argv = spec["add_argv"]
                self.assertEqual(argv[:2], ["/usr/sbin/auditctl", "-a"])
                self.assertEqual(sum(value == "-S" for value in argv), 1)
                if ppid is None:
                    self.assertIn("pid=1234", argv)
                else:
                    self.assertIn("ppid=1234", argv)
                if spec["syscall"] in {"read", "write"}:
                    self.assertIn("dir=/tmp/r4", argv)

    def test_cli_exit_semantics(self):
        r4 = load(R4_HARNESS, "e1c_r4_cli")
        self.assertEqual(r4.verdict_exit_code("PASS_READY_FOR_GRAPH_NORMALIZATION"), 0)
        self.assertEqual(r4.verdict_exit_code("PARTIAL_MISSING_REQUIRED_EVENT_CLASS"), 3)
        self.assertEqual(r4.verdict_exit_code("BLOCKED"), 2)
        self.assertEqual(r4.verdict_exit_code("unexpected"), 1)
        original = r4.privileged_run
        try:
            r4.privileged_run = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
            self.assertEqual(r4.main([]), 1)
        finally:
            r4.privileged_run = original

    def test_recursive_json_safe_and_raw_hashes_preserved(self):
        r4 = load(R4_HARNESS, "e1c_r4_json")
        value = {"stdout": b"out\xff", "nested": [b"ok"]}
        safe = r4.json_safe(value)
        json.dumps(safe)
        self.assertEqual(base64.b64decode(safe["stdout"]["base64"]), b"out\xff")
        self.assertEqual(safe["stdout"]["sha256"], hashlib.sha256(b"out\xff").hexdigest())

    def test_static_boundary_gate_passes(self):
        r4 = load(R4_HARNESS, "e1c_r4_static")
        result = r4.static_self_check()
        self.assertTrue(result["pass"], result)
        self.assertTrue(result["no_broad_rule_delete"])
        self.assertTrue(result["no_mn_cleanup"])
        self.assertTrue(result["no_nat_or_external_network"])


if __name__ == "__main__":
    unittest.main()
