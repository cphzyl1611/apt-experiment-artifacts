# MININET E1C R6R3 Committed Targeted Fresh Review

Reviewed on 2026-09-02. This review is limited to committed candidate
`6aec9e0ed113c17fd729f8ae359fd6d2c30fff0a` against parent fresh-review
blocker commit `73bbe957846ca7f4ad84abb417f488af22f74f8a`.

## Authentication

- `HEAD` resolves to the pinned R6R3 commit and its sole parent resolves to
  the pinned R6R2 fresh-review blocker commit.
- The committed blobs and clean working-tree files both hash to the supplied
  values:
  - harness: `4202d3144974355881a398ffb58b28cb016d3add73e8fe7752012d1c76d06428`
  - test: `510a4339830a1641737fbefa152d231a45c98f2bca0f185e1e13d1cf473be14d`
- `git diff --check 73bbe957846ca7f4ad84abb417f488af22f74f8a...6aec9e0ed113c17fd729f8ae359fd6d2c30fff0a`
  passed. The candidate diff is limited to the remediation artifacts, the R6
  harness, and the R6 harness test.

## Standards

No repository coding-standard source was present in the review scope. The
targeted implementation is otherwise consistent with the local rule,
cleanup, baseline, and R5-derived smoke patterns. One high-severity boundary
violation remains: the later production collector calls `ausearch --raw`
through `run_command_bytes` at
`parallel/a/e1c-r6-run-20260901T060350Z/mininet_e1c_r6_file_access_closure_smoke.py:1754`.
That helper has a default `timeout=30` at line 639, has no monotonic
remaining-budget calculation, and catches `TimeoutExpired` generically.

## Spec

The R6R3 requirement applies before every production raw `ausearch` call: a
finite timeout must be no greater than the remaining 2.0-second monotonic
budget, and `TimeoutExpired` must fail closed without extending that budget.
`poll_audit_evidence` satisfies the contract at lines 339-402. The full
collector bypasses it at line 1754, so it can block for 30 seconds and does
not emit the required fail-closed timeout result. The candidate tests cover
the helper only; they do not exercise this collector path.

The same-serial raw bundle checks are correctly present in
`_valid_raw_file_access_event` at lines 270-305: one `SYSCALL` and one `PATH`
with the same serial, an exact audit key, exact path, a mapped supported file
syscall, `success=yes`, and permission-filter provenance. Fresh R6R3 tests
also closed the unrelated-type, split-serial, wrong-key, wrong-path, and
failed-syscall fixtures. Historical `-i` is restricted to the historical
fixture in `test_e1c_r6_harness.py:149`; production calls use `--raw`.

The exact syscall-form path plus `perm=rw` plus PID rule, exact inverse
cleanup, baseline re-verification, R5-derived Mininet smoke path, and the
eight-event-class contract remain unchanged. The harness's built-in static
self-check passes those bounded-scope checks, but the independent static
review is blocked by the unbounded production raw collector above.

## Verification

- R6R3 targeted: `46/46` passed.
- R6R2 non-regression, extracted directly from the pinned parent: `33/33`
  passed.
- R3 regression: `8/8` passed.
- R4 regression: `7/7` passed.
- R5 regression: `11/12` passed. The remaining fixture creates an IPv4 TCP
  socket and is denied by this sandbox with `PermissionError: [Errno 1]
  Operation not permitted`; the other eleven tests passed independently.
- `py_compile`, candidate-remediation JSON parsing, and diff checks passed.
- No privileged command, sudo, Mininet, audit mutation, or runtime experiment
  was executed.

## Required Remediation

Route the full-smoke collector's raw `ausearch` invocation through an
equivalent remaining-budget helper (or share `poll_audit_evidence`'s deadline
logic), and add a collector-path test proving finite remaining timeout plus
immediate `TimeoutExpired` fail-closed behavior. Re-run this exact review
after materialization.

## Required Terminal

```text
MININET_E1C_R6R3_COMMITTED_TARGETED_FRESH_REVIEW = BLOCKED
PINNED_R6R3_COMMIT = 6aec9e0ed113c17fd729f8ae359fd6d2c30fff0a
COMMIT_AUTHENTICATION = PASS
CANDIDATE_HASH_AUTHENTICATION = PASS
SUBPROCESS_DEADLINE_CLOSED = BLOCKED
TIMEOUT_FAIL_CLOSED = BLOCKED
SAME_SERIAL_AUDIT_BUNDLE = PASS
SUCCESSFUL_SYSCALL_REQUIRED = PASS
EXACT_KEY_PATH_REQUIRED = PASS
UNRELATED_FALSE_PASS_CLOSED = PASS
RAW_MODE_PRESERVED = PASS
AUDIT_RULE_SCOPE_UNCHANGED = PASS
CLEANUP_BASELINE_RESTORATION = PASS
R6R3_TARGETED_TESTS = 46/46
R6R2_NON_REGRESSION = 33/33
R3_REGRESSION = 8/8
R4_REGRESSION = 7/7
R5_REGRESSION = 11/12 | SANDBOX_PARTIAL
STATIC_BOUNDARY = BLOCKED
PRIVILEGED_COMMAND_EXECUTED = NO
MININET_EXECUTED = NO
TRACK_BRANCH = artifact/e0-a
MAIN_PUSH_EXECUTED = NO
TRACK_BRANCH_PUSH_EXECUTED = YES
NEXT_ACTION = REMEDIATE_R6R3_FRESH_REVIEW_BLOCKER
STOP = true
```
