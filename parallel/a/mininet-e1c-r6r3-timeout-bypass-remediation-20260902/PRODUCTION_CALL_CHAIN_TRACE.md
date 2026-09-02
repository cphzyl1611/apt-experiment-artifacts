# MININET E1C-R6R3 Production Timeout Bypass Remediation

Review date: 2026-09-02

This trace covers the local candidate source at
`parallel/a/e1c-r6-run-20260901T060350Z/mininet_e1c_r6_file_access_closure_smoke.py`.
The candidate is intentionally uncommitted and is based on worktree `HEAD`
`415c84edf39acd618b5c4e05cc09b17dd43129ef`.

## Complete production chain

1. `main(argv)` parses `--run-privileged` and calls
   `execute_reviewed_r6_path()` (`mininet_e1c_r6_file_access_closure_smoke.py:2031-2045`).
2. `execute_reviewed_r6_path()` runs the bounded micro-probe, requires
   `AUDIT_EVIDENCE_PASS`, and requires the terminal
   `RULE_REMOVED_BASELINE_RESTORED` state before calling the smoke wrapper
   (`:2000-2028`).
3. `_reviewed_mininet_smoke()` invokes the real
   `_run_reviewed_mininet_smoke()` and maps its exit code to a verdict
   (`:1989-1997`).
4. `_run_reviewed_mininet_smoke()` performs the existing clean-baseline gate,
   exact transient rule setup, R5-derived topology/child workflow, cleanup,
   and baseline restoration. Its production audit collection at `:1855` now
   calls `collect_production_audit_evidence(key)`.
5. `collect_production_audit_evidence()` establishes or accepts the absolute
   audit evidence deadline and delegates only to
   `run_bounded_ausearch_bytes()` (`:714-728`). Any failure reason raises
   `TimeoutError`, which is captured by the smoke body and still enters its
   cleanup `finally` block (`:1864-1900`).
6. `run_bounded_ausearch_bytes()` validates the exact audit key, constructs
   `/usr/sbin/ausearch -k <key> --raw`, computes the bounded remaining
   monotonic budget, and invokes the runner with `timeout=remaining`
   (`:657-711`). It never delegates production `ausearch` to
   `run_command_bytes(argv, timeout=30)`.

## Boundary result

The former production path was `_run_reviewed_mininet_smoke()` ->
`run_command_bytes()` -> fixed `timeout=30`. The candidate path is now
`_run_reviewed_mininet_smoke()` -> `collect_production_audit_evidence()` ->
`run_bounded_ausearch_bytes()` -> `runner(..., timeout=remaining)`.

The existing R6R1 `poll_audit_evidence()` path remains separate and continues
to recompute `remaining` before each raw `ausearch` invocation. The R6R2 raw
bundle parser, same-serial validation, exact key/path checks, cleanup, and
baseline restoration code were not replaced by this remediation.

