# MININET E1C-R6R3 Timeout Bypass Remediation

Review date: 2026-09-02

## Result

```text
R6R3_TIMEOUT_BYPASS_REMEDIATION = PASS_READY_FOR_TARGETED_FRESH_REVIEW
```

The production full-smoke collector no longer invokes raw `ausearch` through
`run_command_bytes(..., timeout=30)`. It routes through
`run_bounded_ausearch_bytes()`, which computes the remaining monotonic budget,
passes that finite value as the subprocess timeout, skips an expired deadline,
and marks timeout or late completion as a fail-closed condition. The collector
raises `TimeoutError`; `_run_reviewed_mininet_smoke()` records the runtime
failure and still executes its existing cleanup and baseline-restoration
`finally` block.

## Fresh verification

- R6R3 collector-path tests: `7/7`.
- Full current R6 harness: `53/53`.
- Historical R6R2 subset from parent `73bbe957846ca7f4ad84abb417f488af22f74f8a`: `33/33`.
- R3 regression: `8/8`.
- R4 regression: `7/7`.
- R5 regression: `12/12` in the approved non-privileged escalated rerun; the sandbox-only run was blocked before the socket fixture by `EPERM`.
- Static self-check: `PASS`.
- Independent AST boundary check: `PASS`.
- `py_compile`: `PASS`.
- `git diff --check`: `PASS`.

## Preserved boundaries

R6R1 bounded polling remains unchanged. R6R2 raw `ausearch --raw` parsing,
same-serial `SYSCALL`/`PATH` association, exact audit key, exact watched path,
successful supported file-access syscall validation, serial-based links, exact
inverse rule cleanup, child cleanup, and baseline restoration remain covered by
the passing regression suites.

No sudo, Mininet, auditd configuration mutation, privileged probe, artifact
repository mutation, or push was performed. This directory is a local
candidate evidence package only.

