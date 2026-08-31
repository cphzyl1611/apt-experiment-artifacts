# Mininet E1C-R4 — Residual-Rule Delete argv Defect Fix and Fresh Smoke Preparation

Continue the existing E0-A / Mininet session.

Pinned prior state:

E1C_R3_RUN_ID = e1c-r3-run-20260831T075356Z
MININET_E1C_R3_AUDITD_COLLECTOR = BLOCKED
R1_RESIDUAL_RULES_FOUND = 10
R2_RESIDUAL_RULES_FOUND = 0
EXACT_RESIDUAL_RULES_REMOVED = 0
AUDIT_BASELINE_RESTORED_BEFORE_R3 = NO
AUDIT_BASELINE_RESTORED_AFTER_R3 = NO
AUDIT_LOST_EVENTS = 0
BACKLOG = 0

Exact R3 defect:

intended:
`/usr/sbin/auditctl -d ...`

actual:
`-d ...`

failure:
`FileNotFoundError: [Errno 2] No such file or directory: '-d'`

The R3 shell exit code was 0 despite collector verdict BLOCKED.

## Goal

Prepare a NEW E1C-R4 harness.
Do not rerun R1/R2/R3 harnesses.
Do not invoke sudo automatically.

## Mandatory work

1. TDD-reproduce the exact R3 argv bug.
2. Fix the mutation builder so every mutation argv satisfies:
   - argv[0] == "/usr/sbin/auditctl"
   - argv[1] in {"-a", "-d"}
3. Add tests for pid, ppid, dir-scoped, socket, R1 residual, and known prior-run rules.
4. Preserve the recursive JSON-safe bytes/base64/hash persistence and fsync journals from R3.
5. Fix CLI exit semantics:
   - PASS_READY_FOR_GRAPH_NORMALIZATION -> 0
   - PARTIAL_MISSING_REQUIRED_EVENT_CLASS -> 3
   - BLOCKED -> 2
   - unexpected exception -> 1
6. Create a brand-new R4 run directory; never overwrite R1/R2/R3.
7. At future privileged start, inventory current audit rules and classify exact-known prior-run vs unrelated.
8. Fail closed on unrelated rules.
9. Delete only exact proven run-owned rules; journal PLANNED_DELETE and DELETE_RESULT with fsync.
10. Never use `auditctl -D`, wildcard key deletion, `mn -c`, or persistent rule-file edits.
11. Require historical empty baseline:
   `61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87`
   before Mininet starts.
12. Only after baseline PASS, run a fresh bounded benign s1/h1/h2 smoke:
   - no NAT/external
   - per-syscall support probes
   - deterministic READY barrier
   - blocking connect/accept
   - fixed benign message
   - live PID/netns/cgroup/socket persistence
   - all four namespace assertions
13. Required audit classes:
   PROCESS_START_OR_EXEC
   PROCESS_EXIT
   FILE_CREATE_OR_OPEN
   FILE_READ_OR_WRITE
   FILE_DELETE
   SOCKET_BIND
   SOCKET_CONNECT
   SOCKET_ACCEPT
14. Missing audit classes remain missing; do not infer them from tcpdump/strace.
15. In finally, remove every R4/probe rule exactly and prove the empty baseline again.
16. Verify lost/backlog and zero child/interface/OVS/tcpdump residue.
17. Pre-run static gate: RED reproduction, tests PASS, CLI exit tests PASS, py_compile, no broad delete, no mn -c, no NAT/external, no APT, no PROVX.
18. STOP and print exactly one new sudo command. Do not execute it.

## Pre-run terminal

MININET_E1C_R4_PREPARATION = PASS | BLOCKED
R3_DELETE_ARGV_DEFECT_REPRODUCED = YES | NO
R3_DELETE_ARGV_DEFECT_FIXED = YES | NO
CLI_EXIT_SEMANTICS_FIXED = YES | NO

HUMAN_PRIVILEGED_RUN_REQUIRED = YES | NO
NEXT_ACTION = HUMAN_RUN_EXACT_SUDO_COMMAND
STOP = true
