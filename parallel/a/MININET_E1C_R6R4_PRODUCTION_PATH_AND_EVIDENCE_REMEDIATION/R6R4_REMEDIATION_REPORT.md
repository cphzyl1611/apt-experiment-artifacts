# MININET E1C-R6R4 Production-Path and Evidence-Authentication Remediation

Review date: 2026-09-02

This package records the smallest remediation of the blockers found in the
committed R6R3 materialization. The reviewed predecessor artifact is
`e88e664fd0c9927323845427f88e85cea7ccb5d4`, whose parent is
`415c84edf39acd618b5c4e05cc09b17dd43129ef`. The remediation source in this
workspace is intentionally uncommitted; no future commit SHA is claimed.

## Closure Status

```text
A1_LATE_SUCCESS_ACCEPTANCE = CLOSED
A2_PERMISSIVE_FULL_SMOKE_AUDIT_PATH = CLOSED
A3_SELF_AUTHENTICATING_EVIDENCE_PACKAGE = CLOSED
A4_PRODUCTION_CALL_CHAIN_TRACE = CLOSED
A5_DIFF_CHECK_CLAIM_ACCURACY = CLOSED
```

A1 is closed by checking the monotonic clock immediately before accepting a
successful poll result and by checking subprocess completion against the same
bounded deadline in `run_bounded_ausearch_bytes()`. The full collector raises
on deadline expiry, subprocess timeout, execution error, or nonzero
`ausearch` return code.

A2 is closed by routing the actual full-smoke path through
`collect_production_audit_records()`, which parses raw records by serial and
passes only strictly validated file-access bundles to normalization. A valid
bundle requires raw `SYSCALL` and `PATH` records on one serial, a supported
file-access syscall, `success=yes`, the exact audit key on the syscall record,
and the exact watched path on a PATH record.

A3 is closed by placing exact source copies under `candidate/`, listing every
package path in `FILE_LIST.txt`, and generating `SHA256SUMS.txt` from this
package root. The documented verification command is:

```text
cd MININET_E1C_R6R4_PRODUCTION_PATH_AND_EVIDENCE_REMEDIATION
sha256sum -c SHA256SUMS.txt
```

A4 is closed by the companion trace naming the committed predecessor and
separately identifying the uncommitted remediation source and its hashes. No
future materialization commit is represented as already existing.

A5 is closed by not claiming a clean generic `git diff --check` result. The
old committed R6R3 package's exact diagnostic reported six blank-line-at-EOF
warnings in immutable evidence files. This new package reports that fact and
uses checksum, syntax, targeted-test, and static-boundary evidence instead.

## Verification

All verification was non-privileged. No sudo, Mininet execution, auditd
configuration change, privileged smoke, artifact commit, artifact push, or
formal 1796 evaluation was performed.

```text
R6R4_TARGETED_R6_TESTS = 61/61 PASS
PINNED_R6R2_SUBSET = 33/33 PASS
R3_REGRESSION = 8/8 PASS
R4_REGRESSION = 7/7 PASS
R5_REGRESSION = 12/12 PASS
PY_COMPILE = PASS
STATIC_SELF_CHECK = PASS
```

The R6 tests exercise late successful evidence, bounded production
`ausearch`, expired deadlines, subprocess timeout, nonzero return code, raw
same-serial validation, unrelated record type, failed syscall, exact key,
exact path, mixed serials, historical `-i` handling, and actual full-smoke
collector wiring. The R6R2 subset preserves the prior timeout, raw-mode,
cleanup, rule-scope, link-integrity, and state-machine coverage.

This package is ready for targeted fresh review only. It does not establish
privileged runtime closure or FILE_READ_OR_WRITE runtime closure.

```text
MININET_E1C_R6R4_PRODUCTION_PATH_AND_EVIDENCE_REMEDIATION = PASS_READY_FOR_TARGETED_FRESH_REVIEW
```
