#!/usr/bin/env python3
"""Focused tests for the remediated E0-A R6R4 preflight gates.

Every fixture below is a literal, not a live command.  REAL_AUDITCTL_S_STDOUT is
the exact byte string captured from this host in the failed preflight run
preserved at
failed_preflight_evidence/03_PRE_RUNTIME_PREREQUISITE_MATRIX.RUN2_20260907T115524Z.FAILED.json
(commands.audit_status.stdout, returncode 0, 161 bytes).
"""

import unittest

from preflight_gates import (
    EXPECTED_EMPTY_RULE_HASH, audit_rule_lines, audit_status_gate,
    command_executed, device_absent, empty_rule_baseline_gate,
    ovs_bridge_absent, parse_audit_status_text,
)

REAL_AUDITCTL_S_STDOUT = (
    "enabled 1\nfailure 1\npid 573176\nrate_limit 0\nbacklog_limit 8192\n"
    "lost 0\nbacklog 0\nbacklog_wait_time 60000\nbacklog_wait_time_actual 0\n"
    "loginuid_immutable 0 unlocked\n"
)
LEGACY_KV_STDOUT = (
    "AUDIT_STATUS: enabled=1 flag=1 pid=573176 rate_limit=0 "
    "backlog_limit=8192 lost=0 backlog=0\n"
)
# exact non-execution record produced by the defective run() wrapper
EPERM_RECORD = {
    "argv": ["sudo", "-n", "/usr/sbin/auditctl", "-l"], "returncode": None,
    "stdout": "", "stderr": "PermissionError: [Errno 1] Operation not permitted",
}


def ok(stdout):
    return {"returncode": 0, "stdout": stdout, "stderr": ""}


class TestAuditStatusParser(unittest.TestCase):
    def test_space_delimited_lost_and_backlog_zero(self):
        """DEFECT 1 regression: the real host format must parse."""
        parsed = parse_audit_status_text(REAL_AUDITCTL_S_STDOUT)
        self.assertEqual(parsed["lost"], 0)
        self.assertEqual(parsed["backlog"], 0)
        self.assertEqual(parsed["backlog_limit"], 8192)
        self.assertEqual(audit_status_gate(ok(REAL_AUDITCTL_S_STDOUT))[0], "PASS")

    def test_key_equals_value_form_supported(self):
        parsed = parse_audit_status_text(LEGACY_KV_STDOUT)
        self.assertEqual(parsed["lost"], 0)
        self.assertEqual(parsed["backlog"], 0)
        self.assertEqual(audit_status_gate(ok(LEGACY_KV_STDOUT))[0], "PASS")

    def test_nonzero_lost_blocks(self):
        text = REAL_AUDITCTL_S_STDOUT.replace("lost 0", "lost 7")
        self.assertEqual(parse_audit_status_text(text)["lost"], 7)
        self.assertEqual(audit_status_gate(ok(text))[0], "BLOCKED")

    def test_nonzero_backlog_blocks(self):
        text = REAL_AUDITCTL_S_STDOUT.replace("\nbacklog 0\n", "\nbacklog 12\n")
        self.assertEqual(parse_audit_status_text(text)["backlog"], 12)
        self.assertEqual(audit_status_gate(ok(text))[0], "BLOCKED")

    def test_backlog_limit_never_mistaken_for_backlog(self):
        parsed = parse_audit_status_text("backlog_limit 8192\nbacklog 0\nlost 0\n")
        self.assertEqual(parsed["backlog"], 0)
        self.assertEqual(parsed["backlog_limit"], 8192)

    def test_malformed_status_blocks(self):
        for text in ("", "garbage output\n", "lost\nbacklog\n", "lost x\nbacklog y\n"):
            with self.subTest(text=text):
                self.assertEqual(audit_status_gate(ok(text))[0], "BLOCKED")

    def test_missing_keys_block(self):
        self.assertEqual(audit_status_gate(ok("enabled 1\nlost 0\n"))[0], "BLOCKED")

    def test_conflicting_duplicate_values_block(self):
        self.assertNotIn("lost", parse_audit_status_text("lost 0\nlost 5\n"))
        self.assertEqual(audit_status_gate(ok("lost 0\nlost 5\nbacklog 0\n"))[0], "BLOCKED")

    def test_agreeing_duplicate_values_accepted(self):
        self.assertEqual(parse_audit_status_text("lost 0\nlost 0\nbacklog 0\n")["lost"], 0)

    def test_nonzero_returncode_blocks(self):
        rec = {"returncode": 1, "stdout": REAL_AUDITCTL_S_STDOUT, "stderr": "boom"}
        self.assertEqual(audit_status_gate(rec)[0], "BLOCKED")

    def test_not_executed_blocks(self):
        rec = dict(EPERM_RECORD, stdout=REAL_AUDITCTL_S_STDOUT)
        self.assertFalse(command_executed(rec))
        self.assertEqual(audit_status_gate(rec)[0], "BLOCKED")
        self.assertEqual(audit_status_gate(None)[0], "BLOCKED")


class TestEmptyRuleBaselineGate(unittest.TestCase):
    def test_no_rules_sentinel_is_the_frozen_clean_baseline(self):
        state, ev = empty_rule_baseline_gate(ok("No rules\n"))
        self.assertEqual(state, "PASS")
        self.assertEqual(ev["observed_rule_dump_sha256"], EXPECTED_EMPTY_RULE_HASH)
        self.assertEqual(ev["observed_rule_lines"], [])

    def test_empty_stdout_is_not_the_frozen_clean_baseline(self):
        """Frozen-contract conformance, not a preference.

        The byte-authenticated harness gates on
        sha256(auditctl -l stdout) == sha256(b"No rules\\n") in both
        _audit_baseline_clean() and verify_clean_root_baseline().  Accepting an
        empty dump here would hand a PASS to a preflight whose own smoke would
        then fail closed, so empty stdout stays BLOCKED and the raw hash is
        retained as evidence.
        """
        state, ev = empty_rule_baseline_gate(ok(""))
        self.assertEqual(state, "BLOCKED")
        self.assertEqual(ev["blocked_reason"], "RULE_DUMP_HASH_NOT_FROZEN_EMPTY_BASELINE")
        self.assertEqual(
            ev["observed_rule_dump_sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(ev["observed_rule_lines"], [])

    def test_one_real_rule_blocks(self):
        dump = "-a always,exit -F arch=b64 -S openat -F key=e1c_r6_file_access\n"
        state, ev = empty_rule_baseline_gate(ok(dump))
        self.assertEqual(state, "BLOCKED")
        self.assertEqual(ev["blocked_reason"], "PREEXISTING_AUDIT_RULES_PRESENT")
        self.assertEqual(len(ev["observed_rule_lines"]), 1)

    def test_several_real_rules_block(self):
        dump = ("-a always,exit -F arch=b64 -S execve -F key=k\n"
                "-a always,exit -F arch=b64 -S openat -F key=k\n"
                "-w /etc/passwd -p wa -k identity\n")
        state, ev = empty_rule_baseline_gate(ok(dump))
        self.assertEqual(state, "BLOCKED")
        self.assertEqual(len(ev["observed_rule_lines"]), 3)

    def test_auditctl_nonzero_returncode_blocks(self):
        rec = {"returncode": 1, "stdout": "No rules\n", "stderr": "cannot open netlink"}
        state, ev = empty_rule_baseline_gate(rec)
        self.assertEqual(state, "BLOCKED")
        self.assertEqual(ev["blocked_reason"], "AUDITCTL_LIST_NONZERO_RETURNCODE")

    def test_not_executed_blocks_and_never_reads_as_clean(self):
        """DEFECT 3 regression: the exact record from the failed preflight."""
        state, ev = empty_rule_baseline_gate(EPERM_RECORD)
        self.assertEqual(state, "BLOCKED")
        self.assertEqual(ev["blocked_reason"], "AUDITCTL_LIST_NOT_EXECUTED")
        self.assertFalse(ev["executed"])
        self.assertEqual(empty_rule_baseline_gate(None)[0], "BLOCKED")

    def test_rule_line_helper_ignores_sentinel_and_blank_lines(self):
        self.assertEqual(audit_rule_lines("No rules\n"), [])
        self.assertEqual(audit_rule_lines("\n  \n"), [])
        self.assertEqual(audit_rule_lines("-w /etc/passwd -p wa\n"), ["-w /etc/passwd -p wa"])


class TestExecutionProofPredicates(unittest.TestCase):
    def test_device_absent_requires_execution(self):
        self.assertTrue(device_absent({"returncode": 1, "stdout": "", "stderr": 'Device "s1" does not exist.'}))
        self.assertFalse(device_absent({"returncode": 0, "stdout": "s1 ...", "stderr": ""}))
        self.assertFalse(device_absent(EPERM_RECORD))
        self.assertFalse(device_absent(None))

    def test_ovs_bridge_absent_requires_execution(self):
        self.assertTrue(ovs_bridge_absent({"returncode": 2, "stdout": "", "stderr": ""}))
        self.assertFalse(ovs_bridge_absent({"returncode": 0, "stdout": "", "stderr": ""}))
        self.assertFalse(ovs_bridge_absent(EPERM_RECORD))

    def test_command_executed(self):
        self.assertTrue(command_executed({"returncode": 0}))
        self.assertTrue(command_executed({"returncode": 137}))
        self.assertFalse(command_executed({"returncode": None}))
        self.assertFalse(command_executed({}))
        self.assertFalse(command_executed(None))


class TestFrozenHarnessParity(unittest.TestCase):
    """The remediated parser must agree with the frozen harness on real output."""

    def test_matches_frozen_parse_audit_status(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "frozen_harness",
            "/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/"
            "mininet_e1c_r6_file_access_closure_smoke.py")
        frozen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(frozen)
        frozen_parsed = frozen.parse_audit_status(REAL_AUDITCTL_S_STDOUT)
        ours = parse_audit_status_text(REAL_AUDITCTL_S_STDOUT)
        for key in ("enabled", "backlog_limit", "backlog", "lost",
                    "backlog_wait_time", "backlog_wait_time_actual"):
            self.assertEqual(frozen_parsed[key], ours[key], key)
        self.assertEqual(frozen.HISTORICAL_EMPTY_HASH, EXPECTED_EMPTY_RULE_HASH)


if __name__ == "__main__":
    unittest.main(verbosity=2)
