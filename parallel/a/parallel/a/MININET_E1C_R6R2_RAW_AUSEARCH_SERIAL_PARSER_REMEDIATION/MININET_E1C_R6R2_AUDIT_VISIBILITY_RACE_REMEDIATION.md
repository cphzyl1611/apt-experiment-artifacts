# MININET E1C-R6R2 raw ausearch serial-parser remediation

R6R2 fixes the narrow machine-parsing defect found after R6R1. The interpreted
`ausearch -i` form can emit timestamps such as
`msg=audit(09/01/2026 08:09:38.381:1056)`, which the old serial regex cannot
parse. The exact failure is captured in the RED test and defect-reproduction
artifact.

The bounded R6R1 polling behavior is preserved. Polls now use only
`/usr/sbin/ausearch -k <exact-random-key> --raw`, and `parse_audit_serial()`
accepts only raw epoch/serial syntax such as
`msg=audit(1788264578.381:1056)`. PASS still requires a parseable integer
serial, exact key, exact watched path, and `micro_probe_verdict() == PASS`.
The existing two-second monotonic deadline, 100-ms maximum interval,
fail-closed `AUDIT_EVIDENCE_MISSING` timeout, diagnostics, inverse rule
cleanup, temporary-file deletion, baseline restoration, and downstream real
Mininet smoke are unchanged.

No audit rule was widened; no auditd configuration was changed; no privileged
command, Mininet run, or push was executed.

```text
MININET_E1C_R6R2_RAW_AUSEARCH_SERIAL_PARSER_REMEDIATION = PASS_READY_FOR_TARGETED_FRESH_REVIEW

R6R1_BOUNDED_POLL_PRESERVED = PASS
INTERPRETED_TIMESTAMP_PARSE_DEFECT_REPRODUCED = YES
RAW_AUSEARCH_MODE_IMPLEMENTED = PASS
RAW_SERIAL_PARSE = PASS
EXACT_KEY_REQUIRED = PASS
EXACT_PATH_REQUIRED = PASS
FAIL_CLOSED_TIMEOUT_PRESERVED = PASS
CLEANUP_AND_BASELINE_RESTORATION = PASS
AUDIT_RULE_SCOPE_UNCHANGED = PASS
AUDITD_CONFIG_CHANGED = NO

R6R2_TARGETED_TESTS = 33/33
R3_REGRESSION = 8/8
R4_REGRESSION = 7/7
R5_REGRESSION = 12/12
STATIC_BOUNDARY = PASS

PRIVILEGED_COMMAND_EXECUTED = NO
MININET_EXECUTED = NO
PUSH_EXECUTED = NO

NEXT_ACTION =
TARGETED_FRESH_REVIEW_OF_R6R2

STOP = true
```
