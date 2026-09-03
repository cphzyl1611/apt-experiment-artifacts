# A4 Production Call-Chain Recalculation

Reviewed 2026-09-03 against pinned commit
`df21b485b10aefd90ac522f5192c72b5aff74d50`.

The materialized production source is
`parallel/a/e1c-r6-run-20260901T060350Z/mininet_e1c_r6_file_access_closure_smoke.py`.
The independently reconstructed privileged path is:

```text
main --run-privileged
  -> execute_reviewed_r6_path
  -> _reviewed_mininet_smoke
  -> _run_reviewed_mininet_smoke
  -> collect_production_audit_records
  -> collect_production_audit_evidence
  -> run_bounded_ausearch_bytes
  -> normalize_production_audit_records
  -> _strict_raw_file_access_event
```

`main()` sends `--run-privileged` to `execute_reviewed_r6_path()` at source
lines 2111-2132. That entry refuses a non-PASS probe and requires its
`AUDIT_EVIDENCE_PASS` plus `RULE_REMOVED_BASELINE_RESTORED` state before the
real smoke wrapper at lines 2080-2108. `_reviewed_mininet_smoke()` calls the
actual `_run_reviewed_mininet_smoke()` at lines 2069-2077. The full-smoke body
calls `collect_production_audit_records()` at lines 1939-1941.

The collector delegates to `collect_production_audit_evidence()` and then
`run_bounded_ausearch_bytes()` at lines 1159-1170 and 739-757. The latter
uses raw `ausearch`, gives the subprocess only finite remaining deadline time,
and rejects completion at or after the bounded deadline (lines 682-736).
Production normalization parses raw bundles and admits `FILE_READ_OR_WRITE`
only through `_strict_raw_file_access_event()` (lines 1132-1156 and 270-307).

The supplied `PRODUCTION_CALL_CHAIN_TRACE.md` names the same chain and has a
historical statement that its remediation source was uncommitted. That was not
a false prospective claim: it expressly states that no remediation commit was
claimed. Independently, this review authenticated the later materialization
commit and confirmed that both trace hashes match the committed production
source and tests:

```text
harness  8b0db6eab7c2a9d720a9a9d0624ebbe4ba93859f2151fc338f0e0303321e78cc
tests    4392694ab6505548fa07d3e6a3f802b105ce065c80619aa955026ce7b6e9e058
```

`A4 = CLOSED`
