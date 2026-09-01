# Mininet E1C-R6 Privileged-Path Fresh Review and Wiring Closure

Run configuration:
- Tool: Codex
- Model: GPT-5.6 Sol
- Reasoning effort: xhigh
- New session: YES

Repository:
https://github.com/cphzyl1611/apt-experiment-artifacts.git

Expected current main:
2ff2b21cd313c5b91567adfe05691d3e25aabb87

Harness:
parallel/a/e1c-r6-run-20260901T060350Z/mininet_e1c_r6_file_access_closure_smoke.py

Tests:
parallel/a/e1c-r6-run-20260901T060350Z/test_e1c_r6_harness.py

Historical R5 stable baseline:
107ef9f69a734a10b320d552cfe18a6cb9a2ac0c

Pinned R5 collector:
PARTIAL_MISSING_REQUIRED_EVENT_CLASS

R5 counts:
PROCESS_START_OR_EXEC = 10
PROCESS_EXIT = 4
FILE_CREATE_OR_OPEN = 6
FILE_READ_OR_WRITE = 0
FILE_DELETE = 2
SOCKET_BIND = 4
SOCKET_CONNECT = 1
SOCKET_ACCEPT = 1

The first R6 privileged invocation exited 2 before micro-probe or Mininet.
The subsequent session claimed PASS_READY_FOR_HUMAN_PRIVILEGED_RUN with
16/16 R6, 8/8 R3, 7/7 R4, 12/12 R5 tests and STATIC_BOUNDARY=PASS.

Perform:
MININET_E1C_R6_PRIVILEGED_PATH_FRESH_REVIEW_AND_WIRING_CLOSURE

Important:
Do not trust the claimed readiness. Inspect the exact pushed harness.

Phase A — read-only review:
1. Authenticate exact current commit and harness/test hashes.
2. Trace main(["--run-privileged"]) end to end.
3. Trace root gate -> clean baseline -> bounded micro-probe -> cleanup/baseline restore
   -> actual DEFAULT Mininet smoke callable -> verdict mapping.
4. Determine whether `_reviewed_mininet_smoke()` or equivalent default runtime path
   is still a placeholder/blocker rather than the real reviewed Mininet smoke.
5. Inspect whether tests prove only mocked/injected smoke reachability.
6. Report exact discrepancy between claimed readiness and pushed implementation.

If already fully wired, do not redesign; verify and STOP before sudo.

If placeholder/unwired path is confirmed:
Phase B — bounded remediation only.
- Preserve exact pre-created file + path + perm=rw + exact PID strategy.
- Preserve micro-probe before Mininet.
- Preserve permission-filter-aware normalization and exact serial/hash linking.
- No system-wide read/write audit.
- No persistent audit rules.
- No NAT/external network.
- No APT action.
- No PROVX.
- No formal experiment.
- Reuse the already reviewed R5 Mininet smoke logic and change only what is necessary
  for the R6 file-access collector.

Required runtime order:
clean audit baseline
-> bounded micro-probe
-> evidence-backed FILE_READ_OR_WRITE
-> exact probe-rule cleanup
-> prove baseline restoration
-> REAL reviewed Mininet smoke
-> collect all 8 required classes
-> exact cleanup
-> prove audit baseline restoration

TDD must prove:
1. default --run-privileged path does not terminate at a placeholder smoke function;
2. micro-probe failure prevents Mininet;
3. micro-probe PASS reaches the real default reviewed Mininet smoke;
4. default smoke is not a fake/mocked PASS;
5. all 8 counters exist in runtime contract;
6. cleanup occurs on PASS/PARTIAL/BLOCKED/exception;
7. prohibited broadening remains absent.

Re-run R6/R3/R4/R5 tests, py_compile, JSON validation and static checks.

Hard stop:
DO NOT execute sudo.
DO NOT run Mininet during this task.
DO NOT use auditctl -D.
DO NOT use mn -c.

Terminal:
MININET_E1C_R6_PRIVILEGED_PATH_FRESH_REVIEW = PASS | BLOCKED
PUSHED_HARNESS_DEFAULT_FULL_SMOKE_WAS_PLACEHOLDER = YES | NO
CLAIMED_READINESS_CONSISTENT_WITH_PUSHED_CODE = YES | NO
R6_PRIVILEGED_PATH_IMPLEMENTATION =
PASS_READY_FOR_HUMAN_PRIVILEGED_RUN | BLOCKED
MICRO_PROBE_GATE_WIRED = PASS | BLOCKED
REAL_DEFAULT_MININET_SMOKE_WIRED = PASS | BLOCKED
FULL_SMOKE_REACHABLE_ONLY_AFTER_PROBE_PASS = PASS | BLOCKED
R6_TARGETED_TESTS = <passed>/<total>
R3_REGRESSION = <passed>/<total>
R4_REGRESSION = <passed>/<total>
R5_REGRESSION = <passed>/<total>
STATIC_BOUNDARY = PASS | BLOCKED
PRIVILEGED_COMMAND_EXECUTED = NO
NEXT_ACTION =
HUMAN_RUN_EXACT_SUDO_COMMAND | REMEDIATE_R6_PRIVILEGED_PATH
EXACT_SUDO_COMMAND = <command or NONE>
STOP = true
