# MININET-E1C-R5 child bootstrap hardening

## Goal

Prepare a new, unprivileged-to-run E1C-R5 harness that diagnoses early child
bootstrap failures before any formal smoke logic and preserves the bounded R4
audit/topology controls.

## Constraints

- Do not rerun R1/R2/R3/R4, execute sudo, mutate audit rules, use `auditctl -D`,
  or use `mn -c`.
- Preserve the clean historical audit baseline and fail closed if the root
  preflight is not clean.
- No NAT/external links, APT, PROVX, or formal benchmark execution.

## Work sequence

1. Forensically review the pinned R4 evidence and record what is and is not
   recoverable about h2 startup.
2. Write and run RED tests for early `FINISHED`, zero-output child exit,
   `CHILD_ERROR` persistence, namespace `NOT_OBSERVED`, and post-exec PID/netns
   identity validation.
3. Harden the child protocol with persisted state transitions and explicit
   `CHILD_ERROR` diagnostics, and harden the parent READY gate to persist a
   complete diagnostic record before raising.
4. Add bounded listener diagnostics, live post-exec identity evidence, and
   strict three-state namespace assertions.
5. Preserve R4 audit rule probing, exact transient-rule cleanup, deterministic
   handshake, attribution joins, cleanup invariants, and exit semantics.
6. Run regression tests, static boundary checks, and `py_compile`; materialize
   the R5 lineage, static audit, pre-run contract, and forensic report.
7. Stop before privileged execution and provide only the exact human sudo
   command.

## R4 forensic conclusion

`R4_CHILD_FAILURE_EXACT_EXCEPTION = NOT_RECOVERABLE_FROM_R4_EVIDENCE`.
R4 persisted only the parent-side `FINISHED` observation. It did not retain
child stderr, stdout history, return code, stage, temp-file operations, bind
diagnostics, or live child PID/netns identity.
