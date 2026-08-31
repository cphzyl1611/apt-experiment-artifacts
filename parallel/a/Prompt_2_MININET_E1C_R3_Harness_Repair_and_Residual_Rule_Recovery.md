# Mininet E1C-R3 — Harness Serialization Repair and Exact Residual-Rule Recovery

Continue the existing E0-A / Mininet session.

Pinned prior state:

```text
E1C_R1_OLD_AUDIT_KEY = e1c902f74f583
E1C_R2_RUN_ID = e1c-r2-run-20260831T061204Z

E1C_R2_PRIVILEGED_RESULT =
TypeError: Object of type bytes is not JSON serializable

OLD_RUN_RESIDUAL_RULES_FOUND_AT_R2_PRESTATE = 20
CURRENT_RESIDUAL_RULE_COUNT_AFTER_FAILED_R2 = UNKNOWN

AUDITD_PRIMARY_CANDIDATE = PRESERVED
FORMAL_EXPERIMENT_EXECUTED = NO
```

Pinned GitHub review commit:
`90513ab76a2d392398fefd0456ad53a4660a3e8a`

## Goal

Prepare a NEW E1C-R3 privileged harness.

Do not rerun the R2 harness.

The new harness must:

1. fix every bytes-to-JSON serialization path;
2. safely recover/clean exact residual rules owned by prior E1C runs only;
3. journal every mutation before/after it occurs;
4. restore the original audit baseline;
5. only after baseline restoration run a fresh corrected benign collector smoke;
6. finish all cleanup verification while still root.

Do not invoke sudo automatically.

## 1. TDD reproduction of the R2 defect

First write a failing unit test reproducing:

`TypeError: Object of type bytes is not JSON serializable`

against the exact R2 persistence pattern.

Then fix via one explicit JSON-safe conversion policy.

For subprocess byte results:
- stdout bytes -> base64 plus optional UTF-8 decoded view;
- stderr bytes -> base64 plus optional UTF-8 decoded view;
- never silently `str(bytes)`.

Add recursive JSON-safety tests.

Require all persisted evidence structures to pass:
`json.dumps(...)`.

## 2. New run namespace

Create a brand-new R3 run directory.

Do not overwrite:
- R1 artifacts;
- R2 artifacts.

Pin R1/R2 harness hashes and failure result into R3 lineage.

## 3. Exact current audit-rule inventory

At root harness start:
- `auditctl -l`;
- persist raw bytes safely;
- canonicalize rules;
- classify each as:
  - exact R1 old-key rule (`e1c902f74f583`);
  - exact known R2/probe key rule, if any;
  - unrelated rule.

Do not assume only the 20 R1 rules remain.

If an unrelated rule exists and was not part of the historical empty baseline:
fail closed before any smoke execution.

## 4. Transactional rule-remediation journal

Before each rule deletion, append a JSON-safe journal record:

```text
PLANNED_DELETE
rule canonical identity
source run/key
timestamp
```

After the command, append:

```text
DELETE_RESULT
returncode
stdout/stderr safe encoding
post-rule-set hash
```

Flush/fsync each journal record before proceeding to the next deletion.

Only delete rules whose canonical identity is proven to belong to:
- R1 key `e1c902f74f583`, or
- an R2 probe/run key created by the known failed R2 harness.

Never:
- `auditctl -D`;
- delete by broad key wildcard;
- delete unrelated rules.

## 5. Baseline restoration gate

Historical baseline = `No rules`, with pinned historical baseline hash from R1.

After exact residual deletion:
- run `auditctl -l`;
- require canonical empty rule set;
- record fresh hash;
- prove `AUDIT_BASELINE_RESTORED_BEFORE_R3 = YES`.

If NO:
STOP.
Do not start Mininet.

## 6. Fresh R3 smoke

Once baseline is clean, perform a fresh benign s1/h1/h2 smoke.

Required improvements from R2:
- supported syscall probing remains per-syscall;
- no unsupported compound rule;
- deterministic blocking TCP handshake;
- listener READY barrier;
- bind/connect/accept must complete;
- persist PID/netns/cgroup/socket evidence while children are alive;
- all four namespace assertions;
- only bounded audit rules;
- no NAT/external network.

Use a new R3 audit key, not the R1 key.

## 7. Required event classes

Attempt and normalize:

```text
PROCESS_START_OR_EXEC
PROCESS_EXIT
FILE_CREATE_OR_OPEN
FILE_READ_OR_WRITE
FILE_DELETE
SOCKET_BIND
SOCKET_CONNECT
SOCKET_ACCEPT
```

If FILE_READ_OR_WRITE cannot be safely collected with bounded rules:
record PARTIAL with exact reason.

Do not infer audit evidence from strace/tcpdump.

## 8. Cleanup journal and root-lifetime post-state

Every R3 rule add/delete must be journaled.

In `finally`:
- remove exact R3 rules;
- remove exact probe rules;
- `auditctl -l`;
- prove historical empty baseline;
- audit lost/backlog;
- run-owned child residue;
- reserved interfaces;
- OVS objects;
- tcpdump/process residue.

No `mn -c`.

Persist post-state before root exits.

## 9. Static gate before human run

Require:
- defect reproduction test RED before fix;
- all new tests PASS after fix;
- py_compile;
- static no `auditctl -D`;
- static no `mn -c`;
- static no NAT/external;
- static no APT action;
- static no PROVX inference;
- harness SHA256.

Then STOP and print exactly one human command:

```text
sudo /usr/bin/python3 <absolute R3 harness>
```

Do not execute it.

## Outputs

Before sudo:
- R3 corrected harness;
- tests;
- `MININET_E1C_R3_LINEAGE.json`;
- `MININET_E1C_R3_STATIC_AUDIT.json`;
- `MININET_E1C_R3_PRE_RUN_CONTRACT.json`.

After one human sudo run:
- `MININET_E1C_R3_RULE_REMEDIATION_JOURNAL.jsonl`;
- `MININET_E1C_R3_PRE_STATE.json`;
- `MININET_E1C_R3_RESIDUAL_REMEDIATION.json`;
- `MININET_E1C_R3_TRANSIENT_RULE_CONTRACT.json`;
- `MININET_E1C_R3_RAW_AUDIT_EVIDENCE.jsonl`;
- `MININET_E1C_R3_NORMALIZED_EVENTS.jsonl`;
- `MININET_E1C_R3_PID_NETNS_JOIN.jsonl`;
- `MININET_E1C_R3_COVERAGE_AND_LOSS.json`;
- `MININET_E1C_R3_POST_CLEANUP.json`;
- `MININET_E1C_R3_REPORT.md`.

## Pre-run terminal

```text
MININET_E1C_R3_PREPARATION = PASS | BLOCKED
R2_SERIALIZATION_DEFECT_REPRODUCED = YES | NO
R2_SERIALIZATION_DEFECT_FIXED = YES | NO
HUMAN_PRIVILEGED_RUN_REQUIRED = YES | NO
NEXT_ACTION = HUMAN_RUN_EXACT_SUDO_COMMAND
STOP = true
```

## Post-run terminal

```text
MININET_E1C_R3_AUDITD_COLLECTOR =
PASS_READY_FOR_GRAPH_NORMALIZATION
|
PARTIAL_MISSING_REQUIRED_EVENT_CLASS
|
BLOCKED

R1_RESIDUAL_RULES_FOUND = <n>
R2_RESIDUAL_RULES_FOUND = <n>
EXACT_RESIDUAL_RULES_REMOVED = <n>
AUDIT_BASELINE_RESTORED_BEFORE_R3 = YES | NO
AUDIT_BASELINE_RESTORED_AFTER_R3 = YES | NO

AUDIT_LOST_EVENTS = <n>
NORMALIZED_EVENT_COUNT = <n>
LOGICAL_HOST_JOIN_SUCCESS_COUNT = <n>
LOGICAL_HOST_JOIN_FAILURE_COUNT = <n>

FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_MININET_E1C_R3
STOP = true
```
