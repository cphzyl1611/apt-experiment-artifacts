# MININET E1C-R2 — Exact Residual-Rule Cleanup and Corrected Auditd Smoke

Continue in the existing E0-A / Mininet session.

Fresh-reviewed prior run: `e1c-run-20260831T050028Z`  
Old audit key: `e1c902f74f583`

Fresh review verdict:

```text
MININET_E1C_R1 = BLOCKED_HARNESS_AND_PRIVILEGED_POSTSTATE_NOT_COLLECTOR_REJECTION
AUDITD_PRIMARY_CANDIDATE = PRESERVED
```

## Goal
Prepare one corrected privileged R2 harness that first sanitizes/verifies ONLY residual state owned by the exact old E1C run, proves the audit baseline is restored, then runs a corrected benign auditd smoke, and performs all privileged post-cleanup verification inside the same root lifetime. Do not invoke sudo automatically.

## 1. Old-run cleanup gate inside future root harness
At privileged start, run `auditctl -l`, compare with the recorded R1 baseline (`No rules`), and identify rules containing exact key `e1c902f74f583`.

Allowed cleanup: remove only exact rules attributable to the prior run key and matching the recorded old rule contract.

Prohibited: `auditctl -D`, deleting unrelated rules, modifying persistent `/etc/audit/rules.d/*`.

If unrelated rules exist that were absent from the recorded baseline, fail closed and stop. After exact old-rule removal, require current rule state to equal the recorded baseline before continuing. Record `MININET_E1C_R2_R1_RESIDUAL_STATE_REMEDIATION.json`.

## 2. Fix rule portability
Before privileged execution, query supported audit syscall names mechanically. Do not submit one compound rule containing an unsupported syscall. For file read/write coverage, determine supported exact syscalls on this auditctl/kernel combination; build only supported bounded rules; keep them scoped to the unique run temp directory and run-owned PID/PPID where permitted. If precise read/write auditing cannot be safely bounded, explicitly mark that class PARTIAL rather than enabling broad system-wide auditing.

## 3. Fix benign TCP exchange
Use a deterministic blocking handshake: listeners signal READY; persist child PIDs/netns/socket state while alive; client connect waits until listener readiness; accept must complete; small fixed benign message exchange; retain exact bind/connect/accept evidence. Avoid the R1 nonblocking `-115` failure mode.

## 4. Persist netns evidence before process exit
Persist atomically while children are alive: host shell PID/netns, child PID/netns, cgroup, listener socket evidence, `/proc/<pid>/net/tcp`, `ss` ownership, logical_host_id.

Require all four assertions:
```text
h1_child_netns == h1_shell_netns
h2_child_netns == h2_shell_netns
h1_child_netns != h2_shell_netns
h2_child_netns != h1_shell_netns
```

## 5. Correct transient rule lifecycle
Record every successful add rule immediately. Use `try/finally` so every installed run rule has a corresponding exact delete attempt even on worker failure.

Before root harness exits: delete all run-owned rules exactly; `auditctl -l`; compare to baseline; query audit lost/backlog; check OVS objects; check Mininet interfaces; check run-owned children; check tcpdump/process residue. All privileged cleanup evidence must be persisted before dropping root.

## 6. Required event classes
Attempt and independently normalize:
`PROCESS_START_OR_EXEC`, `PROCESS_EXIT`, `FILE_CREATE_OR_OPEN`, `FILE_READ_OR_WRITE`, `FILE_DELETE`, `SOCKET_BIND`, `SOCKET_CONNECT`, `SOCKET_ACCEPT`.

Do not infer a missing primary audit event from strace or tcpdump.

## 7. Pre-run static gate
Before asking the human to run: TDD tests; `py_compile`; static no-NAT/no-external-network check; static no-APT/no-PROVX check; static prohibition of `auditctl -D` and `mn -c`; harness SHA256.

Then STOP with exactly one command:
`sudo /usr/bin/python3 <absolute corrected R2 harness>`

Do not invoke sudo.

## Outputs
Before privileged run: corrected R2 harness; `MININET_E1C_R2_PRE_RUN_CONTRACT.json`; `MININET_E1C_R2_STATIC_AUDIT.json`.

After the human runs exactly once: `MININET_E1C_R2_R1_RESIDUAL_STATE_REMEDIATION.json`; `MININET_E1C_R2_RAW_AUDIT_EVIDENCE.jsonl`; `MININET_E1C_R2_NORMALIZED_EVENTS.jsonl`; `MININET_E1C_R2_PID_NETNS_JOIN.jsonl`; `MININET_E1C_R2_COVERAGE_AND_LOSS.json`; `MININET_E1C_R2_POST_CLEANUP.json`; `MININET_E1C_R2_REPORT.md`.

## Terminal before human run
```text
MININET_E1C_R2_PREPARATION = PASS | BLOCKED
HUMAN_PRIVILEGED_RUN_REQUIRED = YES | NO
NEXT_ACTION = HUMAN_RUN_EXACT_SUDO_COMMAND
STOP = true
```

## Terminal after human run
```text
MININET_E1C_R2_AUDITD_COLLECTOR = PASS_READY_FOR_GRAPH_NORMALIZATION | PARTIAL_MISSING_REQUIRED_EVENT_CLASS | BLOCKED
OLD_RUN_RESIDUAL_RULES_FOUND = <n>
OLD_RUN_RESIDUAL_RULES_REMOVED = <n>
AUDIT_BASELINE_RESTORED_BEFORE_R2 = YES | NO
AUDIT_BASELINE_RESTORED_AFTER_R2 = YES | NO
AUDIT_LOST_EVENTS = <n>
NORMALIZED_EVENT_COUNT = <n>
LOGICAL_HOST_JOIN_SUCCESS_COUNT = <n>
LOGICAL_HOST_JOIN_FAILURE_COUNT = <n>
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_MININET_E1C_R2
STOP = true
```
