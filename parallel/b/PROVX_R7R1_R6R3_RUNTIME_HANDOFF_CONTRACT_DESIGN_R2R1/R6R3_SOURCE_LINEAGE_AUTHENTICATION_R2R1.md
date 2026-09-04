# R6R3 Source Lineage Authentication R2R1

## Required Disposition

The runtime handoff may report `AUTHENTICATED_COMMITTED_SOURCE` only when the
producer source state is independently resolvable and exact source bytes from
that state match every declared source hash. Otherwise the only valid
disposition is:

```text
SOURCE_LINEAGE_NOT_AUTHENTICATED
```

This is a prerequisite failure. It is not repaired by a source filename, a
human assertion, a stale commit pin, an adjacent review document, or a hash
copied from another run.

## Three Provenance Domains

1. **Design-source provenance** identifies the R2R1 package documents and their
   exact hashes. This establishes what contract was reviewed.
2. **Committed artifact provenance** identifies an independently resolvable
   committed producer/source state and exact source-file hashes. This is
   required before a future runtime handoff can pass.
3. **Future runtime producer provenance** identifies the producer invocation,
   exact runtime root, exact run ID, and the dedicated execution receipt. This
   is evidence about one future run, not proof that the source is committed.

These domains are recorded separately and cannot be merged by inference.

## Current Snapshot Finding

The local `/home/cph/experiment-parallel/e0-b/.git` directory is empty and is
not a source repository. It cannot resolve a commit, prove reachability, or
authenticate a committed producer state. Repeated reads during the September
2, 2026 review also observed changing E0-A working-copy hashes, while adjacent
materialization metadata records still other before/after hashes for a
different worktree. None of those working-copy values is accepted as committed
provenance or silently substituted for the current source snapshot.

The earlier R1 package also names source commits that are not independently
resolvable from this snapshot and contains conflicting source-lineage
references. R2R1 deliberately does not pin or invent a replacement commit. Its
contract-level state is therefore `SOURCE_LINEAGE_NOT_AUTHENTICATED` until a
future producer package supplies a resolvable committed state whose exact
source hashes match.

## Verification Procedure

An independent implementation must:

1. Require a full lowercase commit identifier and an explicit resolution
   method.
2. Resolve that exact state from an authenticated repository or equivalent
   committed artifact source.
3. Read the declared producer harness, tests, and contract inputs from that
   state, not from a convenient working-tree path.
4. Recompute exact SHA-256 values and compare them with both the committed
   state and the handoff manifest.
5. Reject empty, missing, conflicting, stale, or unreachable provenance with
   `SOURCE_LINEAGE_NOT_AUTHENTICATED`.

No future runtime evidence can pass the handoff gate while this prerequisite
is unresolved, even if the runtime files themselves are internally coherent.
