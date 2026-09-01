# Mininet E1C-R6 — Bounded File-Access Audit Strategy and Full Collector Closure Preparation

Continue the existing E0-A / Mininet session.

Pinned latest fixed commit:
`107ef9f69a734a10b320d552cfe18a6cb9a2ac0c`

Pinned R5 runtime facts:

MININET_E1C_R5_AUDITD_COLLECTOR =
PARTIAL_MISSING_REQUIRED_EVENT_CLASS

AUDIT_BASELINE_CLEAN_AT_START = YES
AUDIT_BASELINE_RESTORED_AFTER_R5 = YES
AUDIT_LOST_EVENTS = 0

PROCESS_START_OR_EXEC = 10
PROCESS_EXIT = 4
FILE_CREATE_OR_OPEN = 6
FILE_READ_OR_WRITE = 0
FILE_DELETE = 2
SOCKET_BIND = 4
SOCKET_CONNECT = 1
SOCKET_ACCEPT = 1

LOGICAL_HOST_JOIN_SUCCESS_COUNT = 4
LOGICAL_HOST_JOIN_FAILURE_COUNT = 0
ALL_FOUR_NAMESPACE_ASSERTIONS = PASS
TCP_HANDSHAKE_COMPLETED = true
R5_CHILD_ERROR_COUNT = 0
R5_EARLY_CHILD_FAILURE_COUNT = 0

R5 independent review also found:
- raw records = 108
- normalized events = 28
- independently recomputed serial links = 28/28
- independently recomputed decoded-byte hash links = 28/28
- historical R5 `normalized_raw_links_valid` boolean was false despite those recomputations.

## Goal

Close the single missing class FILE_READ_OR_WRITE using a bounded,
auditd-native filesystem-access strategy.

Do NOT broaden to whole-system read/write syscall logging.

Prepare a NEW E1C-R6 harness and STOP before sudo.

## 1. Diagnose R5 correctly

Authenticate R5 evidence:
- pread64 and pwrite64 names were rejected by installed audit userspace;
- read/write/readv/writev/pwritev2 rules were accepted;
- nevertheless zero FILE_READ_OR_WRITE normalized events were observed.

Review the installed local auditctl/audit.rules documentation.

The design must explicitly account for Linux Audit filesystem permission-watch
semantics:
- prefer syscall-form filesystem watches using path or dir + perm;
- perm=r/w is the bounded filesystem-audit mechanism for requested read/write access;
- do not require global direct read/write syscall auditing.

If local installed docs disagree, STOP and report the conflict.

## 2. Exact bounded watched-file design

Preferred candidate to validate:

-a always,exit
-F arch=b64
-F path=<exact pre-created R6 benign file>
-F perm=rw
-F pid=<exact live child pid>
-k <R6 key>

Derive exact syntax from locally supported auditctl semantics.

Requirements:
- exact pre-created file per logical host;
- file exists before rule insertion;
- exact live post-exec child PID;
- no wildcard;
- no system-wide directory watch;
- no -S all;
- no unbounded read/write rules;
- no persistent rule-file edits.

Use a separate disposable file for FILE_DELETE so deleting a watched inode
does not invalidate the read/write watch.

## 3. Honest evidence semantics

If perm=rw is used, normalized evidence must retain:

FILE_READ_OR_WRITE
evidence_basis = AUDIT_FILESYSTEM_PERMISSION_FILTER
watched_path = exact path
requested_access = evidence-supported r/w
underlying_syscall = observed syscall

Do not falsely claim that the event was necessarily a raw read(2)/write(2)
syscall if it was generated from filesystem access/open flags.

## 4. Bounded root micro-probe gate

The future single privileged R6 run must first:

1. verify exact clean No-rules baseline;
2. pre-create isolated benign probe file;
3. add only exact candidate path+perm rule;
4. perform bounded benign read and write from exact process;
5. collect audit evidence;
6. require evidence-backed FILE_READ_OR_WRITE;
7. remove exact probe rule;
8. prove clean baseline again.

If micro-probe fails:
STOP before Mininet.
Do not try broader rules in the same run.

## 5. Full R6 Mininet smoke only after probe PASS

Reuse R5 controls:
- s1/h1/h2
- TCP 18080
- distinct namespaces
- child state protocol
- post-exec identity validation
- listener evidence
- exact transient rules
- no NAT/external
- same-root cleanup

Replace only R5 file-read/write collection strategy.

Require all eight classes > 0.

## 6. Fix R5 normalized/raw-link checker defect

Do NOT rewrite R5 evidence.

TDD-reproduce the discrepancy:
- normalized field = raw_event_sha256
- raw field = raw_sha256
- independent serial/hash recomputation was 28/28
- R5 boolean reported false.

Implement R6 verifier joining by exact audit serial and comparing correct hash fields.

Test:
- valid link
- serial mismatch
- raw hash mismatch
- duplicate serial
- missing raw record.

## 7. Cleanup / exit semantics

Preserve:
PASS -> 0
PARTIAL -> 3
BLOCKED -> 2
unexpected exception -> 1

In all paths:
- exact R6 rule cleanup
- baseline restored
- lost/backlog recorded
- zero run-owned child/interface/OVS/tcpdump residue
- no auditctl -D
- no mn -c.

## 8. TDD/static gate

Require:
- R5 missing-class diagnosis report
- local audit documentation evidence
- watched-file rule-builder tests PASS
- micro-probe state-machine tests PASS
- filesystem-permission normalization tests PASS
- R5 raw-link defect reproduced and R6 checker fixed
- R3/R4/R5 regression tests PASS
- py_compile PASS
- static no broad read/write auditing
- no auditctl -D / mn -c / NAT / external / APT / PROVX

Then STOP and emit exactly one sudo command.
Do not execute it.

## Outputs before sudo

- MININET_E1C_R6_R5_FILE_RW_ROOT_CAUSE.md
- MININET_E1C_R6_AUDIT_FILE_ACCESS_SEMANTICS.json
- MININET_E1C_R6_PRE_RUN_CONTRACT.json
- MININET_E1C_R6_STATIC_AUDIT.json
- R6 harness
- R6 tests
- raw-link RED evidence.

## Terminal

MININET_E1C_R6_PREPARATION = PASS | BLOCKED

R5_FILE_RW_ROOT_CAUSE =
DIRECT_READ_WRITE_SYSCALL_RULE_STRATEGY_INSUFFICIENT_FOR_BOUNDED_FILE_ACCESS
| <evidence-backed alternative>

BOUNDED_FILE_ACCESS_RULE_DESIGN = PASS | BLOCKED
R5_RAW_LINK_BOOLEAN_DEFECT_REPRODUCED = YES | NO
R6_RAW_LINK_VERIFIER_FIXED = YES | NO

HUMAN_PRIVILEGED_RUN_REQUIRED = YES | NO
NEXT_ACTION = HUMAN_RUN_EXACT_SUDO_COMMAND
STOP = true
