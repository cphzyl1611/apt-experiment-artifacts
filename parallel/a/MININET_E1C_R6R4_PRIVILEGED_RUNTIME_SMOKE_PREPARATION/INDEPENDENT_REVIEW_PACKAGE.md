# Independent Review Package

## Review Object

This is a static preparation package for a possible later privileged runtime
smoke. It is not an execution package, an authorization, or runtime evidence.
The review subject is limited to the files in this directory and the six
read-only, SHA-256-pinned upstream inputs declared in
`RUNTIME_SMOKE_PREPARATION_CONTRACT.json`.

The reviewer must keep the following terminal statements intact:

```text
PRIVILEGED_RUNTIME_SMOKE_EXECUTED = NO
FILE_READ_OR_WRITE_RUNTIME_CLOSURE = NOT_PROVEN
FORMAL_1796_EXPERIMENT_EXECUTED = NO
STOP = true
```

## Required Static Checks

1. Recompute each pinned upstream SHA-256 and compare it with the contract.
2. Confirm that the package contains exactly the declared static artifacts,
   validator, and tests, plus `MATERIALIZATION_MANIFEST.json` only after a
   passing validation.
3. Confirm that the execution boundary prohibits privileged execution, audit
   modification, Mininet execution, PROVX adapter invocation, runtime evidence
   generation, formal experiment work, commits, and pushes.
4. Confirm that the receipt schema requires a single immutable `run_id`,
   separately authenticated PCAP bytes, exact raw-to-normalized byte links,
   and one exact `JOINED` PID/netns/logical-host record for every normalized
   event.
5. Confirm that `FILE_READ_OR_WRITE` requires an
   `AUDIT_FILESYSTEM_PERMISSION_FILTER` basis, same-serial `SYSCALL` and
   `PATH` records, a successful supported syscall, exact key and watched path,
   authenticated raw bytes, and positive coverage.
6. Confirm that every condition in `FAIL_CLOSED_CONDITIONS.json` blocks the
   receipt rather than accepting partial, inferred, synthetic, or repaired
   evidence.

## Review Decision

The reviewer may record only one of these preparation decisions:

- `PASS_STATIC_PREPARATION_ONLY`: all static package checks pass and the
  materialization manifest exists.
- `BLOCKED`: any package file, pinned hash, required field, boundary,
  fail-closed condition, or manifest rule fails.

`PASS_STATIC_PREPARATION_ONLY` does not establish a runtime result. It merely
states that a future, independently authorized operator has a precise receipt
contract to satisfy outside this directory.

## Review Evidence

The static review record must contain the validator result, the recomputed
upstream hashes, a package file listing, and the reviewer decision. It must
not contain a runtime receipt, audit output, PCAP, namespace observation,
cleanup proof, or any claim that file read/write closure has been observed.

## Stop Boundary

After the independent static review, stop. A future runtime smoke requires a
separate authorization and a new receipt root outside this package. Nothing
in this package authorizes crossing that boundary.
