# MININET E1C-R6R4 Production Call-Chain Trace

Review date: 2026-09-02

## Authentication and Lineage

The exact previously reviewed artifact commit is
`e88e664fd0c9927323845427f88e85cea7ccb5d4`; its sole parent is
`415c84edf39acd618b5c4e05cc09b17dd43129ef`. The current remediation is a
separate uncommitted source state at:

```text
/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/
```

The final source hashes are recorded in `SHA256SUMS.txt` and are repeated
here for review convenience:

```text
mininet_e1c_r6_file_access_closure_smoke.py
  8b0db6eab7c2a9d720a9a9d0624ebbe4ba93859f2151fc338f0e0303321e78cc
test_e1c_r6_harness.py
  4392694ab6505548fa07d3e6a3f802b105ce065c80619aa955026ce7b6e9e058
```

No remediation commit SHA is claimed before materialization.

## Production Chain

1. `main(argv)` accepts `--run-privileged` and calls
   `execute_reviewed_r6_path()`.
2. `execute_reviewed_r6_path()` requires a passing micro-probe, the
   `AUDIT_EVIDENCE_PASS` state, and terminal
   `RULE_REMOVED_BASELINE_RESTORED` before invoking the smoke wrapper.
3. `_reviewed_mininet_smoke()` invokes the real
   `_run_reviewed_mininet_smoke()` and maps its exit code.
4. `_run_reviewed_mininet_smoke()` performs the existing baseline, transient
   rule, R5-derived topology, cleanup, and restoration workflow. Its actual
   production collector calls `collect_production_audit_records()` at source
   lines 1939-1941.
5. `collect_production_audit_records()` calls
   `collect_production_audit_evidence()`. The latter delegates only to
   `run_bounded_ausearch_bytes()` and raises on any bounded-collection failure
   or nonzero command result.
6. `run_bounded_ausearch_bytes()` constructs
   `/usr/sbin/ausearch -k <exact-key> --raw`, computes remaining time from the
   injected or default monotonic clock, clamps the effective deadline to the
   two-second evidence maximum, and passes only that finite remaining time as
   the subprocess timeout.
7. After the subprocess returns, completion is checked against the same
   monotonic deadline. A completion at or after the deadline is rejected.
8. `normalize_production_audit_records()` parses raw serial bundles and uses
   `_strict_raw_file_access_event()` before permitting `FILE_READ_OR_WRITE`
   normalization. The permissive parser is not an acceptance gate.

## Boundary Result

The former bypass was:

```text
_run_reviewed_mininet_smoke()
  -> run_command_bytes(..., timeout=30)
  -> ausearch --raw
```

The remediation chain is:

```text
_run_reviewed_mininet_smoke()
  -> collect_production_audit_records()
  -> collect_production_audit_evidence()
  -> run_bounded_ausearch_bytes()
  -> runner(..., timeout=remaining)
  -> normalize_production_audit_records()
  -> strict same-serial raw acceptance
```

The separate micro-probe poller also checks acceptance time immediately before
returning `PASS`; late successful evidence returns `BLOCKED`.
