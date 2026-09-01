# MININET E1C-R6R1 audit-evidence visibility-race remediation

This remediation is limited to the R6 micro-probe's audit-evidence visibility
step. The original defect was classified as
`AUDIT_EVIDENCE_VISIBILITY_RACE_AFTER_BENIGN_IO`: an immediate `ausearch`
lookup could be empty even though the exact key/path records became visible
shortly afterward.

The implementation adds `poll_audit_evidence()`, which invokes only
`/usr/sbin/ausearch -k <random_key> -i` until a monotonic deadline (maximum
2.0 seconds, maximum 100 ms interval). It passes only when the current result
contains a parseable audit serial, the exact key, the exact watched path, and
the existing `micro_probe_verdict()` returns `PASS`. Timeout remains
fail-closed as `AUDIT_EVIDENCE_MISSING`; diagnostics record attempts, elapsed
latency, final return code, key visibility, and path visibility.

The exact absolute pre-created file, `perm=rw`, live child PID, random key,
inverse rule deletion, temporary-file deletion, baseline re-verification, and
the downstream real R5-derived Mininet smoke are unchanged. No privileged
command, Mininet run, push, persistent audit rule, broad read/write rule,
`auditctl -D`, `mn -c`, NAT, or external network was used.

Verification artifacts in this directory record the defect reproduction,
bounded-poll contract, static boundary audit, and test reruns.

```text
MININET_E1C_R6R1_AUDIT_VISIBILITY_RACE_REMEDIATION = PASS_READY_FOR_TARGETED_FRESH_REVIEW

ORIGINAL_RUNTIME_DEFECT_REPRODUCED = YES
POST_RUN_AUDIT_RECORDS_CONFIRMED = YES
POST_RUN_EXACT_KEY_CONFIRMED = YES
POST_RUN_EXACT_PATH_CONFIRMED = YES
POST_RUN_AUDIT_LOST = 0
POST_RUN_AUDIT_BACKLOG = 0
POST_RUN_RULE_BASELINE = CLEAN

BOUNDED_VISIBILITY_POLL_IMPLEMENTED = PASS
MAX_VISIBILITY_WAIT_BOUNDED = PASS
EXACT_KEY_AND_PATH_REQUIRED = PASS
FAIL_CLOSED_TIMEOUT = PASS
CLEANUP_AND_BASELINE_RESTORATION = PASS
AUDIT_RULE_SCOPE_UNCHANGED = PASS

R6R1_TARGETED_TESTS = 29/29
R3_REGRESSION = 8/8
R4_REGRESSION = 7/7
R5_REGRESSION = 12/12
STATIC_BOUNDARY = PASS

PRIVILEGED_COMMAND_EXECUTED = NO
MININET_EXECUTED = NO
PUSH_EXECUTED = NO

NEXT_ACTION =
TARGETED_FRESH_REVIEW_OF_R6R1

EXACT_SUDO_COMMAND =
sudo /usr/bin/python3 /home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/mininet_e1c_r6_file_access_closure_smoke.py --run-privileged

STOP = true
```
