# MININET E1C-R6R2 committed-bytes targeted fresh review

Review date: September 1, 2026. This is an independent, non-privileged review of the committed R6R2 candidate at `99f9c0d7fe8b4ecec896837b3991e8d23ebbb608` on `artifact/e0-a`.

Repository authentication passed. The origin is `https://github.com/cphzyl1611/apt-experiment-artifacts.git`; authenticated `origin/main` is the same HEAD. `a471ee6ca09253a381d96a228ab58a1f652bd0b9` and recovery commit `ee28eb41220d080b225f1dbc752c114656ef2299` are ancestors. The R6R2 harness, test, and remediation evidence blobs are identical between `a471ee6` and HEAD. Scoped tree diffs from the materialization commit through recovery and the later Binding-only append are empty, so the evidence package is preserved unchanged.

The original defect was freshly recomputed. `parse_audit_serial()` returns no serial for interpreted `msg=audit(09/01/2026 08:09:38.381:1056)`, while raw `msg=audit(1788264578.381:1056)` returns `1056`. The polling seam observed exactly `/usr/sbin/ausearch -k e1c6probe --raw`, and the committed tests independently cover the interpreted failure, raw serial, delayed visibility, exact key/path, fail-closed timeout, and cleanup gate.

The code-boundary audit found two blockers despite the green tests. The monotonic loop has a 2.0-second deadline, configured 0.05-second interval, and bounded 0.1-second clamp, but the `ausearch` runner has no subprocess timeout; a hung command can exceed the claimed maximum. The PASS path also synthesizes an `AUDIT_FILESYSTEM_PERMISSION_FILTER` event from serial/key/path text without validating raw event type, syscall/access semantics, or same-record association. Exact inverse rule removal, temporary-file cleanup, baseline restoration, and the real R5-derived Mininet smoke path remain intact. Static checks found no `auditctl -D`, persistent `rules.d` edit, auditd configuration change, widened audit scope, automatic sudo, Mininet cleanup command, NAT attachment, or strace/tcpdump substitution. One small duplicated predicate computation in `poll_audit_evidence()` is recorded as non-blocking.

A fresh negative fixture containing only a parseable serial, matching key/path, and `type=UNRELATED` returned `PASS` from the committed poller. That is direct evidence for the audit-evidence-integrity blocker, not historical evidence.

Fresh non-privileged reruns passed: R6R2 `33/33`, R3 `8/8`, R4 `7/7`, and complete R5 `12/12` including the socket test. `py_compile`, JSON validation, static boundary, and `git diff --check` passed. No sudo, Mininet, auditctl mutation, privileged probe, or experiment external-network action was executed. Repository authentication was a required read-only network operation and is distinguished from experiment runtime.

The historical remediation artifacts are explicitly context only; the authentication, defect, boundary, and test records in this directory contain the fresh observations for this review.

```text
MININET_E1C_R6R2_COMMITTED_BYTES_TARGETED_FRESH_REVIEW = BLOCKED

PINNED_R6R2_MATERIALIZATION_COMMIT =
a471ee6ca09253a381d96a228ab58a1f652bd0b9

COMMIT_AUTHENTICATION = PASS
CURRENT_R6R2_BYTES_EQUAL_A471 = PASS
INTERPRETED_TIMESTAMP_DEFECT_RECOMPUTED = PASS
RAW_AUSEARCH_MODE = PASS
RAW_SERIAL_PARSE = PASS

R6R1_BOUNDED_POLL_PRESERVED = BLOCKED
EXACT_KEY_REQUIRED = PASS
EXACT_PATH_REQUIRED = PASS
FAIL_CLOSED_TIMEOUT = BLOCKED
CLEANUP_BASELINE_RESTORATION = PASS
AUDIT_RULE_SCOPE_UNCHANGED = PASS
AUDITD_CONFIG_CHANGED = NO

R6R2_TARGETED_TESTS = 33/33
R3_REGRESSION = 8/8
R4_REGRESSION = 7/7
R5_FULL_REGRESSION = 12/12
R5_SAFE_SUBSET = N/A
R5_SOCKET_TEST = PASS
STATIC_BOUNDARY = PASS

PRIVILEGED_COMMAND_EXECUTED = NO
MININET_EXECUTED = NO

TRACK_BRANCH = artifact/e0-a
MAIN_PUSH_EXECUTED = NO
TRACK_BRANCH_PUSH_EXECUTED = YES

EXACT_HUMAN_COMMAND =
sudo /usr/bin/python3 /home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/mininet_e1c_r6_file_access_closure_smoke.py --run-privileged

NEXT_ACTION =
REMEDIATE_FRESH_REVIEW_BLOCKER

STOP = true
```
