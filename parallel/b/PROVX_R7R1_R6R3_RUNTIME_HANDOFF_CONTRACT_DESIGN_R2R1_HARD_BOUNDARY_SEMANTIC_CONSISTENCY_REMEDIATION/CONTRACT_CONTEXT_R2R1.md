# PROVX R7R1 R6R3 Authenticated Runtime Handoff Contract Design R2R1

## Decision

R2R1 defines the future authenticated handoff from an E0-A R6R3 runtime run to
the already-completed PROVX-R7R1 graph adapter. It is a contract and verifier
design package. It is not runtime evidence, does not create runtime evidence,
and does not authorize Stage A execution.

The R2R1 terminal is:

```text
PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2R1 = PASS_READY_FOR_INDEPENDENT_R2R1_REVIEW
```

That terminal means the design package is ready for another independent design
review. It does not mean that an authenticated R6R3 run exists.

## Evidence Classes

The contract distinguishes these classes and never substitutes one for
another:

- **Design/template artifacts:** this R2R1 package and the prior minimum package.
  They define shape and semantics only. `NOT_RUNTIME_EVIDENCE` is rejected.
- **Future authenticated runtime artifacts:** the exact twenty required paths
  selected by the producer manifest under one exact runtime root.
- **Execution receipt:** one dedicated
  `r6_privileged_execution_receipt`, bound to the package manifest, run ID,
  runtime root, producer source, authorization reference, command, UID/EUID,
  process identity, and exit/result facts.
- **Collection provenance:** producer/source identity, pre-run contract,
  static audit, lineage, and source hashes.
- **Audit evidence:** raw audit JSONL, normalized events, same-serial raw-byte
  links, and the PID/start-time/netns/role join.
- **Network evidence:** exact PCAP bytes and cross-file hashes. PCAP is
  provenance/authentication only and is never a graph-edge source.
- **Cleanup/baseline-restoration evidence:** authenticated pre-state, transient
  rule contract, remediation journal, residual evidence, and post-cleanup
  revalidation. A cleanup claim without these inputs is insufficient.

## Contract Architecture

`R6R3_RUNTIME_HANDOFF_OPERATOR_SEMANTICS_R2R1.json` is the single authoritative
registry for custom operators. Every operator has an input shape, exact
procedure, canonicalization, success/failure disposition, ambiguity behavior,
duplicate behavior, ordering, and error propagation. Unknown operators and
duplicate definitions are blocking failures.

`R6R3_RUNTIME_HANDOFF_SCHEMA_R2R1.json` defines the strict handoff envelope.
`R6R3_RUNTIME_ARTIFACT_CONTENT_SCHEMAS_R2R1.json` defines every parsed runtime
artifact or JSONL row shape, and the path-binding registry points to those
definitions by exact JSON pointer. The receipt remains a dedicated standalone
schema. All object boundaries reject undeclared properties. Cross-file
equalities are named in the ordered authentication rules and recomputed by the
safe validator model.

## Authentication Contract

The verifier must:

1. Strictly parse the handoff and all selected JSON/JSONL artifacts. Duplicate
   keys, non-finite numbers, BOMs, invalid UTF-8, blank JSONL records, and
   malformed values block.
2. Validate the exact 20-ID artifact set. Each ID has exactly one absolute
   canonical path under one exact runtime root. No directory discovery,
   basename fallback, glob, latest-run selection, cross-run path, cross-root
   path, symlink, alias, or object replacement is permitted.
3. Hash exact opened bytes and lengths, with stable device/inode/regular-file
   identity checks before and after reads.
4. Recompute the manifest hash using the R2R1 canonical JSON profile after
   removing only `package_manifest.manifest_sha256`.
5. Require an independently resolvable committed producer/source state. If it
   cannot be established, the disposition is
   `SOURCE_LINEAGE_NOT_AUTHENTICATED`; no commit is invented or selected from
   an empty local `.git` directory.
6. Validate one dedicated privileged receipt and compare it field-for-field
   with `privileged_execution`. Current E0-A does not emit this receipt, so
   `PRODUCER_RECEIPT_EMISSION_NOT_IMPLEMENTED` is a future producer
   prerequisite, not a satisfied runtime fact.
7. Authenticate raw serials, normalized event IDs, decoded byte hashes, and
   same-serial raw/normalized byte equality.
8. Require exact file-access evidence from a same-serial successful syscall
   and PATH record with exact audit key and watched path. A permission filter
   or report alone cannot infer a syscall.
9. Join process-bearing rows using the round-trippable tuple:

   ```text
   (run_id, logical_host_id, pid, pid_start_time_ticks, netns_inode, role)
   ```

   The role is present and authenticated on both sides. Exactly one `JOINED`
   candidate is required; zero, duplicate, or ambiguous candidates block.
10. Recompute the exact ordered eight-class closure, zero loss/backlog, and
    zero duplicates.
11. Hash the PCAP exactly and compare its hash with coverage and post-cleanup
    evidence. Never derive graph data from PCAP or strace.
12. Recompute cleanup from evidence. Successful transient adds must equal
    successful deletes, all must belong to the transient contract, residual
    rules must be empty, baseline and persistent-rule hashes must be restored,
    global delete must be false, and post-cleanup revalidation must occur
    after all reads with zero residue and zero audit loss/backlog.
13. Re-read and revalidate all selected objects before returning a decision.

Any missing, duplicate, malformed, inconsistent, stale, unavailable, or
unverifiable condition blocks. There is no warning-only or best-effort pass.

## Producer Compatibility State

The currently available E0-A R6 directory at
`/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z` contains the
producer and test source files only. It contains no accepted runtime evidence
and no R2R1 receipt. The R2R1 contract therefore requires a future E0-A producer
implementation that emits the dedicated receipt and all twenty bound runtime
artifacts. R2R1 does not modify E0-A and does not claim that the producer already
supports this boundary.

## Unchanged Downstream Boundaries

The completed `PROVX_R7_NORMALIZED_TO_GRAPH_ADAPTER.py` and frozen
`PROVX_R4_ENCODER_IMPLEMENTATION.py` remain outside this remediation. R2R1
defines an authenticated eligibility boundary before later consumption; it
does not redesign, patch, invoke, or reinterpret either component.

Detector training, PROVX inference, Mininet, privileged commands, auditd
mutation, and formal 1796 evaluation are outside this design task.

## Review Result

The R2R1 package is ready for independent design review only when all safe local
tests pass, all schemas meta-validate, every operator reference resolves once,
the 20-ID set is exact, the negative fixtures remain blocked, the minimum
package remains rejected, and the adapter/encoder boundary hashes are
unchanged.
