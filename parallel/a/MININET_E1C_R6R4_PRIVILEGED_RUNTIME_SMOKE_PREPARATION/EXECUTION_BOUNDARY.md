# Privileged Runtime Smoke Execution Boundary

This package is preparation only. It defines contracts, validates static
package completeness, and produces a materialization manifest only after that
static validation succeeds.

## Authorized Work In This Phase

- Read the named R6R4, R6 pre-run, and R7R1 review artifacts.
- Validate the contracts and package hash closure without external side
  effects.
- Produce `MATERIALIZATION_MANIFEST.json` only after the validator returns
  `PASS`.
- Conduct an independent review of this static preparation package.

## Prohibited Work In This Phase

- No privileged command, elevated interpreter, Mininet topology, or network
  workload is run.
- No audit rule, audit daemon, kernel, namespace, process, interface, route,
  or filesystem state is modified.
- No audit search, packet capture, runtime receipt, raw audit JSONL,
  normalized JSONL, PID/netns join, coverage/loss output, or cleanup proof is
  generated.
- No R6R4 artifact is edited.
- No PROVX-R7R1 adapter or frozen encoder source is edited or invoked.
- No formal experiment, corpus acquisition, model training, inference, commit,
  or push is performed.

## Handoff Boundary

A later human-authorized runtime operator may begin only from a separately
reviewed immutable copy of this package. That operator must create a new
receipt root and satisfy every field in
`EXPECTED_RUNTIME_RECEIPT_SCHEMA.json`. The future runtime evidence must not
be written into this preparation package.

This package does not provide an execution command, operational runbook, or
permission to cross that boundary.

```text
PRIVILEGED_RUNTIME_SMOKE_EXECUTED = NO
FILE_READ_OR_WRITE_RUNTIME_CLOSURE = NOT_PROVEN
FORMAL_1796_EXPERIMENT_EXECUTED = NO
STOP = true
```
