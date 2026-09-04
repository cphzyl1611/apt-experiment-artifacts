# R2R1 Independent Remediation Report

## Decision

```text
PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2R1 = PASS_READY_FOR_INDEPENDENT_R2R1_REVIEW
```

This is a contract and safe-validator result only. It is not authenticated R6
runtime evidence, does not permit runtime execution, and does not permit
PROVX training, inference, or formal evaluation.

## Baseline Reconciliation

The R2 independent review compared a primary-workspace adapter copy
(`d467359b...`) with a pinned artifact worktree adapter
(`7e33886b...`). The pinned commit `11a5692effd70ab5fbcf75b4574c7c27338e49af`
is the design object. Its parent is
`e3458d64ec94cf4b7b3e246103ce1c1c65b02261`, its message is
`materialize e0-b: PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2`,
and it does not modify the adapter or frozen encoder.

The recomputed frozen boundaries are:

- `parallel/b/PROVX_R7_NORMALIZED_TO_GRAPH_ADAPTER.py`:
  `7e33886b9ac628e8c4f312317127d95c181e40bebc2c5059cc9022ed4555ad6e`
- `parallel/b/PROVX_R4_ENCODER_IMPLEMENTATION.py`:
  `013d9b77297308843144ccfce4c3eec4b03dc3cc5172dabd6eb3320e7bc46547`

The same values are hard-bound by the R2R1 boundary test. The original
independent-review record is preserved; this package's
`ADAPTER_ENCODER_NON_MUTATION_AUTHENTICATION_R2R1.json` supersedes only its
incorrect baseline selection.

## Contract Recomputations

- `B1_CONTRACT = CLOSED`: the single operator registry requires complete
  semantics; unknown, duplicate, and incomplete operators fail closed. The
  handoff and every parsed runtime artifact use strict schemas and strict
  JSON/JSONL parsing.
- `B2_CONTRACT = CLOSED`: the required set is exactly 20 IDs, each with one
  role, one content-schema binding, one root-bound exact path, and no
  discovery, basename, glob, latest-run, cross-root, duplicate-path, symlink,
  hard-link alias, or replacement fallback.
- `B3_CONTRACT = CLOSED`: H015 derives cleanup exclusively from the five
  authenticated evidence artifacts. It checks authorized rule hashes,
  operation IDs, equal successful add/delete sets, empty transient residue,
  restored baseline and persistent hashes, no global delete, post-read
  revalidation, zero loss/backlog, and zero residual process/interface/OVS/
  tcpdump state.
- `B4_CONTRACT = CLOSED`: the dedicated receipt schema binds the package
  manifest, run identity, exact runtime root, producer/source identity,
  authorization, command, UID/EUID, PID/start ticks/netns, and result facts.
  The receipt must be singular and must exactly equal the privileged summary.
- `B5_CONTRACT = CLOSED`: both sides carry the complete ordered tuple
  `(run_id, logical_host_id, pid, pid_start_time_ticks, netns_inode, role)`;
  zero, duplicate, stale, role-mismatched, compact-only, and coercive joins
  fail closed.
- `B6_CONTRACT = CLOSED_FAIL_CLOSED`: committed source lineage needs a
  resolvable Git commit, safe repository-relative paths, exact committed bytes,
  exact hashes, and exact manifest-source entries. Empty or mutable snapshots
  cannot authenticate provenance.
- `B7_CONTRACT = CLOSED`: exact paths must be absolute and canonical with no
  dot segments or double-leading-slash ambiguity. The validator
  component-walks using no-follow descriptors, requires regular files, checks
  device/inode identity around reads, rejects aliases and containment
  violations, and performs deterministic root/object rechecks.

The ordered H001-H017 rules retain every prerequisite. PCAP remains exact-byte
provenance/authentication only and cannot create graph edges; strace cannot
substitute for audit evidence. The minimum/placeholder package remains
rejected as non-runtime evidence.

## Safe Verification

- `python -m unittest test_r2r1_contract.py`: `47/47` passed, including the
  double-leading-slash path regression.
- Draft 2020-12 meta-validation: `9/9` R2R1 JSON documents declaring
  `$schema` passed.
- Negative fixtures and direct adversarial cases reject for their intended
  error conditions, including unknown operator, duplicate operator,
  cross-root/generic/duplicate-path/hard-link/symlink/traversal artifact,
  false cleanup, malformed or mismatched receipt, ambiguous/zero/role-mismatch
  join, fabricated lineage, malformed JSON/JSONL, and PCAP mismatch.
- The adapter and frozen 32D encoder hashes above are unchanged from the
  pinned commit bytes.
- No privileged command, Mininet execution, training, inference, or formal
  experiment was performed. No runtime evidence was created.

## Remaining Producer Prerequisites

The current E0-A R6 directory contains only the producer and test source files:
`mininet_e1c_r6_file_access_closure_smoke.py` and
`test_e1c_r6_harness.py`. It contains no R2R1 receipt, JSON/JSONL, or PCAP
runtime evidence.

```text
AUTHENTICATED_R6_RUNTIME_INPUT = ABSENT
R2_PRIVILEGED_EXECUTION_RECEIPT = ABSENT
SOURCE_LINEAGE_AUTHENTICATED = NO
PROVX_TRAINING = NO
PROVX_INFERENCE = NO
FORMAL_1796_EXPERIMENT = NO

EXACT_REMAINING_BLOCKERS =
- PRODUCER_RECEIPT_EMISSION_NOT_IMPLEMENTED
- SOURCE_LINEAGE_NOT_AUTHENTICATED

NEXT_PHASE = INDEPENDENT_R2R1_REVIEW
```
