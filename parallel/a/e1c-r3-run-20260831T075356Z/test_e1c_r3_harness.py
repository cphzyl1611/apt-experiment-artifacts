#!/usr/bin/env python3
"""RED/GREEN unit tests for the E1C-R3 harness."""

import base64
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


RUN_DIR = Path(__file__).resolve().parent
R2_HARNESS = RUN_DIR.parent / "e1c-r2-run-20260831T061204Z" / "mininet_e1c_r2_corrected_smoke.py"
R3_HARNESS = RUN_DIR / "mininet_e1c_r3_auditd_bounded_smoke.py"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class E1CR3HarnessTests(unittest.TestCase):
    def test_r2_exact_before_probe_bytes_are_json_persistable(self):
        """The exact R2 persistence shape is safe under the R3 writer."""
        r2 = load(R2_HARNESS, "e1c_r2_for_red")
        r3 = load(R3_HARNESS, "e1c_r3_for_green")
        with tempfile.TemporaryDirectory() as tmp:
            value = {
                "before_probe": r2.run_command_bytes(["/bin/printf", "r2"]),
                "nested": {"stdout": b"out\xff", "stderr": b"err\x00"},
            }
            r3.write_json_atomic(Path(tmp) / "r3.json", value)
            persisted = json.loads((Path(tmp) / "r3.json").read_text())
            self.assertEqual(persisted["before_probe"]["stdout"]["encoding"], "base64")
            self.assertEqual(persisted["nested"]["stdout"]["utf8"], None)
            self.assertNotIn("b'", json.dumps(persisted))

    def test_json_safe_is_recursive_for_bytes_and_collections(self):
        r3 = load(R3_HARNESS, "e1c_r3_recursive")
        value = {"a": [b"alpha", {"b": b"\xff"}], "path": Path("/tmp/x")}
        safe = r3.json_safe(value)
        json.dumps(safe)
        self.assertEqual(base64.b64decode(safe["a"][0]["base64"]), b"alpha")
        self.assertIsNone(safe["a"][1]["b"]["utf8"])

    def test_namespace_assertions_require_all_four_checks(self):
        r3 = load(R3_HARNESS, "e1c_r3_namespace")
        result = r3.namespace_assertions({"h1": "net:[100]", "h2": "net:[200]"}, {"h1": "net:[100]", "h2": "net:[200]"})
        self.assertEqual(len(result["checks"]), 4)
        self.assertTrue(result["pass"])

    def test_canonical_rule_and_classification_are_exact(self):
        r3 = load(R3_HARNESS, "e1c_r3_rules")
        line = "-a always,exit -F arch=b64 -S bind -F pid=123 -F key=e1c902f74f583"
        canonical = r3.canonical_rule(__import__("shlex").split(line))
        self.assertEqual(r3.rule_key(line), "e1c902f74f583")
        self.assertIn(("pid", "123"), canonical[2])

    def test_rule_specs_are_single_syscall_and_bounded(self):
        r3 = load(R3_HARNESS, "e1c_r3_specs")
        specs = r3.build_rule_specs("r3-test", 1234, "/tmp/r3", {"openat", "read", "write", "bind", "connect", "accept4"})
        self.assertTrue(specs)
        for spec in specs:
            argv = spec["add_argv"]
            self.assertEqual(sum(value == "-S" for value in argv), 1)
            self.assertIn("pid=1234", argv)
            if spec["syscall"] in {"read", "write"}:
                self.assertIn("-F", argv)
                self.assertIn("dir=/tmp/r3", argv)

    def test_normalization_preserves_raw_serial_and_hash(self):
        r3 = load(R3_HARNESS, "e1c_r3_normalize")
        raw = b'type=SYSCALL msg=audit(1.25:77): syscall=49 success=yes exit=0 ppid=10 pid=11 comm="python3" exe="/usr/bin/python3" key="r3"\n'
        event = r3.normalize_audit_record({"serial": 77, "timestamp_source": "1.25", "raw_bytes": raw, "raw_text": raw.decode(), "raw_sha256": hashlib.sha256(raw).hexdigest()}, {11: {"logical_host_id": "h1", "netns_inode": 100}})
        self.assertEqual(event["event_type"], "SOCKET_BIND")
        self.assertEqual(event["raw_serial"], 77)
        self.assertEqual(base64.b64decode(event["raw_event_bytes_b64"]), raw)
        self.assertEqual(event["logical_host_id"], "h1")

    def test_static_self_check_has_required_boundaries(self):
        r3 = load(R3_HARNESS, "e1c_r3_static")
        result = r3.static_self_check()
        self.assertTrue(result["pass"], result)
        self.assertTrue(result["recursive_json_safe_present"])
        self.assertTrue(result["journal_fsync_present"])

    def test_shell_gate_is_released_before_ready_barrier(self):
        source = R3_HARNESS.read_text(encoding="utf-8")
        self.assertIn('stdin.write("START\\n")', source)
        self.assertLess(source.index('stdin.write("START\\n")'), source.index("ready = read_ready(children)"))


if __name__ == "__main__":
    unittest.main()
