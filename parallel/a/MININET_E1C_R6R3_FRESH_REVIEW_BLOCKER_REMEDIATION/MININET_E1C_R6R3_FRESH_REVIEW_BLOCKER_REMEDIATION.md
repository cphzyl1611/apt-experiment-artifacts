# MININET E1C-R6R3 fresh-review blocker remediation

R6R3 remediates the two blockers identified by the fresh R6R2 review. The
pre-remediation artifact bytes reproduce both defects: `ausearch --raw` was
invoked without a subprocess timeout, allowing a simulated 3.0-second child
to exceed the claimed 2.0-second evidence window; and a raw `UNRELATED` record
with a parseable serial plus matching key/path text incorrectly returned
`PASS`.

The source harness now recomputes the remaining monotonic budget before every
`ausearch` call, passes a finite timeout no greater than that budget, skips an
exhausted budget, and fails closed with a distinct `AUSEARCH_TIMEOUT` result
on `subprocess.TimeoutExpired`. The 2.0-second maximum and 0.05-second poll
interval remain unchanged.

Raw output is parsed into bundles grouped by audit serial. PASS requires the
same serial to contain raw `SYSCALL` and `PATH` records, a supported numeric
file-access syscall, `success=yes`, the exact audit key, and the exact watched
path. The historical interpreted fixture explicitly asserts `-i`; current
production polling remains `--raw`.

Cleanup, baseline re-verification, exact path+`perm=rw`+live-pid+random-key
rule scope, the real R5-derived Mininet smoke, and the eight-event-class
contract are preserved. No privileged command, Mininet execution, artifact
repository mutation, or push occurred. This is local candidate evidence only.

```text
MININET_E1C_R6R3_FRESH_REVIEW_BLOCKER_REMEDIATION_TDD = PASS_READY_FOR_EXACT_ARTIFACT_MATERIALIZATION

R6R2_BOUND_001_REPRODUCED = YES
R6R2_EVIDENCE_002_REPRODUCED = YES

AUSEARCH_SUBPROCESS_TIMEOUT_IMPLEMENTED = PASS
PER_CALL_TIMEOUT_WITHIN_REMAINING_BUDGET = PASS
TIMEOUT_EXPIRED_FAIL_CLOSED = PASS
MAX_EVIDENCE_WINDOW_UNCHANGED = PASS

RAW_EVENT_BUNDLE_PARSER = PASS
SAME_SERIAL_SYSCALL_PATH_ASSOCIATION = PASS
EXACT_KEY_SAME_EVENT_REQUIRED = PASS
EXACT_PATH_SAME_EVENT_REQUIRED = PASS
SUCCESSFUL_SYSCALL_REQUIRED = PASS
UNRELATED_TYPE_FALSE_PASS_CLOSED = PASS
INTERPRETED_I_FIXTURE_ARGV_ASSERTED = PASS

RAW_AUSEARCH_MODE_PRESERVED = PASS
AUDIT_RULE_SCOPE_UNCHANGED = PASS
AUDITD_CONFIG_CHANGED = NO
CLEANUP_BASELINE_RESTORATION = PASS

R6R3_TARGETED_TESTS = 46/46
R6R2_NON_REGRESSION = 33/33
R3_REGRESSION = 8/8
R4_REGRESSION = 7/7
R5_REGRESSION = 12/12
STATIC_BOUNDARY = PASS

PRIVILEGED_COMMAND_EXECUTED = NO
MININET_EXECUTED = NO
PUSH_EXECUTED = NO
ARTIFACT_REPOSITORY_MUTATED = NO

HARNESS_SHA256 = 4202d3144974355881a398ffb58b28cb016d3add73e8fe7752012d1c76d06428
TEST_SHA256 = 510a4339830a1641737fbefa152d231a45c98f2bca0f185e1e13d1cf473be14d

NEXT_ACTION =
EXACT_MATERIALIZATION_TO_ARTIFACT_E0A_BRANCH

STOP = true
```
