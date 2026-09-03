# MININET E1C R6R4 Targeted Fresh Review

Reviewed 2026-09-03. This is an independent, non-privileged review of
`df21b485b10aefd90ac522f5192c72b5aff74d50` on `artifact/e0-a`, with required
parent `e88e664fd0c9927323845427f88e85cea7ccb5d4` and exact message
`materialize e0-a: MININET_E1C_R6R4_PRODUCTION_PATH_AND_EVIDENCE_REMEDIATION`.

Commit scope authentication found exactly ten additions in the R6R4
remediation package and two materialized R6 source/test modifications. There
were no unrelated E0-A artifacts. The package file list has ten files and
matches the payload exactly; all nine SHA256SUMS entries recomputed `OK` from
the package root. The candidate harness and tests are byte-identical to the
committed materialized production inputs, respectively hashing to
`8b0db6eab7c2a9d720a9a9d0624ebbe4ba93859f2151fc338f0e0303321e78cc` and
`4392694ab6505548fa07d3e6a3f802b105ce065c80619aa955026ce7b6e9e058`.

## A1: Deadline and late-success acceptance

The micro-probe poller and full production collector share the relevant
monotonic deadline discipline. Every actual `ausearch` invocation receives
only a finite positive remaining time. Expired deadlines skip invocation,
completion at the deadline is rejected, subprocess timeout does not extend
the window, nonzero returns are rejected, and execution errors fail closed.
A controlled late-success double returned `BLOCKED`, not `PASS`.

## A2: Production raw acceptance

The actual full-smoke path reaches `collect_production_audit_records()`, not a
permissive acceptance route. Raw records group only by exact audit serial, and
`FILE_READ_OR_WRITE` requires a same-serial raw `SYSCALL` plus `PATH`, a
supported file-access syscall, `success=yes`, the exact key on the syscall,
and the exact watched path on the PATH record. Controlled parser fixtures
rejected unrelated record types, failed syscalls, wrong key/path, and mixed
serials; a fully valid same-serial bundle passed. The permissive parser
remains convenience-only and cannot authorize this event class.

## A3: Package self-authentication

No listed path escapes the package. There are no omissions, duplicate entries,
`.pyc`, cache, transient, swap, or unrelated manifest files. Source/test
candidate bytes agree with both committed materialized files and the primary
source workspace.

## A4: Call-chain trace freshness

Code independently reconstructs the trace as:

```text
main -> execute_reviewed_r6_path -> reviewed smoke -> real smoke
-> production audit records -> bounded raw ausearch
-> strict raw normalization/acceptance
```

The historical trace's statement that remediation was uncommitted was accurate
when written and does not claim a future materialization SHA. Its two declared
source hashes match the now-pinned committed materialized source/test bytes.

## A5: Evidence truthfulness

`git diff --check e88e664f df21b485` is clean. Re-running the predecessor
diagnostic reproduces six blank-line-at-EOF warnings in immutable R6R3
evidence. The R6R4 package does not claim a generic historical diff-check
PASS; it labels that condition `NOT_CLAIMED_AS_PASS` and documents the
historical warnings. This is truthful and not a blocker.

## Regression and safety

Non-privileged reruns passed: R6 `61/61`, pinned R6R2 subset `33/33`, R3
`8/8`, R4 `7/7`, and R5 `12/12`. Python parse/compile and the static boundary
audit passed. No sudo, Mininet execution, auditctl mutation, persistent rule
modification, `mn -c`, NAT/external-network mutation, formal experiment,
commit, or push was performed.

```text
MININET_E1C_R6R4_TARGETED_FRESH_REVIEW = PASS_READY_FOR_PRIVILEGED_RUNTIME_SMOKE_PREPARATION

A1 = CLOSED
A2 = CLOSED
A3 = CLOSED
A4 = CLOSED
A5 = CLOSED
PRIVILEGED_RUNTIME_SMOKE_EXECUTED = NO
FILE_READ_OR_WRITE_RUNTIME_CLOSURE = NOT_PROVEN
FORMAL_1796_EXPERIMENT_EXECUTED = NO
NEXT_PHASE = PRIVILEGED_RUNTIME_SMOKE_PREPARATION
```
