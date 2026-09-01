# MININET E1C-R6 committed-bytes targeted review

Review scope was limited to `MININET_E1C_R6_COMMITTED_BYTES_TARGETED_REVIEW`.
The authenticated checkout is `/home/cph/fa1b2de-review-artifacts`; its remote is
`https://github.com/cphzyl1611/apt-experiment-artifacts.git`.

Current `HEAD` is `f8d62fd36e40f3e0d0f8111022c4e43eb10bfc24`.
`ab0d0161189ee7c98cd4eb2810cd2341de37f341` is an ancestor, and all five reviewed
paths have identical Git blob IDs at the pin and current `HEAD` (no post-pin path
change affecting this review). Exact SHA-256 values are recorded in
`E1C_R6_COMMITTED_INPUT_AUTHENTICATION.json`.

The committed preparation/static artifacts retain their earlier
`UNAVAILABLE_NO_GIT_METADATA` fields; this package supersedes that stale workspace
claim with the authenticated checkout and current-HEAD result above.

The callback-free source trace is:

`main(--run-privileged) -> execute_reviewed_r6_path() -> _default_micro_probe() -> require PASS + AUDIT_EVIDENCE_PASS + RULE_REMOVED_BASELINE_RESTORED -> _reviewed_mininet_smoke() -> _run_reviewed_mininet_smoke()`.

The former placeholder gate is absent. The default smoke is a real R5-derived
Mininet body (imports `Mininet`, creates `s1`, `h1`, and `h2`, performs the bounded
TCP smoke, collects audit evidence, and cleans up in `finally`), not an unconditional
PASS. The full classification requires all eight event classes and also requires
successful rule removal, restored baseline, zero topology/child residue, namespace
assertions, and a packet capture.

Static boundaries preserve exact path+`perm=rw`+PID rules, a separate disposable
delete inode, no NAT/external attachment, no system-wide read/write audit rules,
no `auditctl -D`, and no `mn -c`. The fresh static self-check passed.

Fresh reruns passed: R6 `23/23`, R3 `8/8`, R4 `7/7`, R5 `12/12`; py_compile and
JSON validation also passed. No sudo, Mininet, or push was executed.

```text
MININET_E1C_R6_COMMITTED_BYTES_TARGETED_REVIEW = PASS

CURRENT_HEAD = f8d62fd36e40f3e0d0f8111022c4e43eb10bfc24
AB0D016_IS_ANCESTOR = YES
E0A_PATHS_CHANGED_AFTER_AB0D016 = NO

REAL_DEFAULT_MININET_SMOKE_WIRED = PASS
MICRO_PROBE_RESTORATION_GATE = PASS
ALL_EIGHT_EVENT_CLASS_CONTRACT = PASS
STATIC_BOUNDARY = PASS

R6_TARGETED_TESTS = 23/23
R3_REGRESSION = 8/8
R4_REGRESSION = 7/7
R5_REGRESSION = 12/12

PRIVILEGED_COMMAND_EXECUTED = NO
MININET_EXECUTED = NO
PUSH_EXECUTED = NO

HUMAN_PRIVILEGED_RUN_REQUIRED = YES
EXACT_SUDO_COMMAND =
sudo /usr/bin/python3 /home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/mininet_e1c_r6_file_access_closure_smoke.py --run-privileged

NEXT_ACTION =
HUMAN_RUN_EXACT_SUDO_COMMAND

STOP = true
```
