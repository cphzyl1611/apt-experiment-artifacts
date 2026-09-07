# E0-C Exact12 Governed Decision Design

## Purpose

This package defines the decision transaction that may be used later to
resolve the twelve frozen Exact12 subjects. It is a design and validation
package only. It does not apply a split, materialize a human decision, mutate
scoring or binding status, change denominator membership, execute runtime, or
run the formal 1796 experiment.

The package is anchored to the authenticated R2R2 review state:

- reviewed R2R2 materialization commit:
  `ce5c43d344b42c38d88b0503160228312a5cf9ea`;
- reviewed R2R2 parent:
  `86dfd43c96303d6e74504706d5f7cc68744e15a1`;
- independent-review materialization commit:
  `dc870e0506bd3d83ccb73dad73d817d01ea9089f`;
- independent-review task:
  `E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2_INDEPENDENT_REVIEW`;
- independent-review verdict:
  `PASS_READY_FOR_GOVERNED_SPLIT_RESOLUTION_NEXT_PHASE`.

The local artifact ref, cached remote-tracking ref, and live remote ref were
equal at the independent-review materialization commit before this design was
prepared.

## Authority Boundary

The design package is non-authoritative. Its schemas describe what a later
governed transaction must contain; its validator accepts or rejects records;
neither creates authority.

There are four intentionally separate operations:

1. `GOVERNED DECISION DESIGN` defines the record and gates.
2. `HUMAN DECISION MATERIALIZATION` records an owner decision in a separate
   authorized process.
3. `SPLIT EXECUTION` applies an independently approved transaction.
4. `STATUS MUTATION` changes operational state only through its own explicit
   authority.

This package performs only the first operation. The synthetic approved fixture
is a structural validator witness, not an operative human decision. It carries
authority and evidence references so the approval gate can be tested while
`decision_materialized` remains false and all mutation counters remain zero.

## Decision Granularity

`DECISION_GRANULARITY = TEMPLATE_LEVEL_DECISION_WITH_PROPOSAL_LEVEL_PARTITION_AND_TRANSACTION_BUNDLE_AUTHORITY`

R2R2 is template-level: every Exact12 crosswalk row has one frozen template
identity, one frozen member set, and one future-resolution slot. The governed
record therefore has exactly one Exact12 template subject. Raw members are the
conserved membership units inside that subject, not independent decision
subjects.

A proposed child split is subordinate to its parent template and must carry a
complete child partition. A later approval for a specific split transaction
also carries a transaction-bundle reference. That reference scopes a future
operation; it does not authorize execution in this package.

The twelve subjects are independent. A caller must create one separately
validated record per template or an explicitly defined future transaction
bundle. No disposition is inferred or copied from another subject.

## Authenticated Subject Scope

`EXACT12_SUBJECT_MANIFEST.json` is the exact inventory copied from the
authenticated R2R2 crosswalk. It contains:

- 12 templates in frozen order `1..12`;
- 203 unique raw members;
- zero cross-template overlap;
- zero overlap with Blocked31;
- union hash
  `ffeb2704a1c971b89129e1959ae721bbc9ef159153a5f0a20f8abda13edb441a`;
- byte-identical R2 and R2R2 crosswalks.

Every subject record must repeat its complete member list, count, member-set
hash, and source reference. The validator compares those fields to the
manifest in exact order. A subject may not add, remove, rename, reorder, or
reassign a raw member.

The carried current state is frozen for every subject:

```text
source_human_decision = REQUEST_SPLIT_OR_MORE_EVIDENCE
resolution_state = REQUEST_MORE_EVIDENCE
planning_status = MANUAL_DESIGN_REQUIRED
current_split_status = NO_CURRENT_SPLIT
applied_split = false
status_mutations = 0
denominator_change = NO
formal_execution_authorized = false
```

## Decision Dispositions

Each future record carries exactly one disposition, except `DESIGN_ONLY`,
which intentionally carries no disposition. The vocabulary is:

| Disposition | Meaning | Required state | Execution effect |
| --- | --- | --- | --- |
| `KEEP_UNSPLIT_REQUEST_MORE_EVIDENCE` | Preserve the frozen parent while enumerating missing evidence. | Pending, deferred, or rejected only when explicitly recorded. | None. |
| `APPROVE_SPLIT_DESIGN_ONLY` | Accept the structure for further governance review, not as an operative split. | `PROPOSAL_PREPARED` or `PENDING_GOVERNANCE`. | None. |
| `APPROVE_SPECIFIC_SPLIT_TRANSACTION` | Identify one exact proposed partition and future transaction bundle for governance approval. | `PENDING_GOVERNANCE` or `APPROVED_FOR_FUTURE_TRANSACTION`. | Never execution. |
| `REJECT_PROPOSED_SPLIT` | Reject the proposed partition while retaining the frozen parent and denominator. | `REJECTED`. | None. |
| `DEFER_TO_OWNER_ADJUDICATION` | Hold the subject for an explicit owner decision. | `DEFERRED`. | None. |

`APPROVED_FOR_FUTURE_TRANSACTION` means only that the structurally validated
proposal has sufficient referenced authority and evidence to be handed to a
later transaction phase. It is not a split-applied state, an execution
authorization, or a status mutation.

## Evidence Prerequisites

Evidence references are required by class and must use the R2R2 canonical
reference grammar. The schema and semantic validator use the same pattern:

```text
^(?:[A-Za-z][A-Za-z0-9+.-]*://[^\s]+|[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.:/#-]+)*(?:#[A-Za-z0-9_.:/-]+)?)$
```

Required classes are:

- `identity_provenance`: exact parent and member identity;
- `source_semantics`: source-visible meaning and raw-specific parameters;
- `partition`: deterministic, source-grounded child assignment;
- `safety_reset`: bounded, inert, reversible conditions;
- `governance`: decision authority and rationale;
- `independent_review`: independent recomputation and review;
- `evidence_manifest`: a traceable manifest for the evidence set.

An approved future transaction requires a non-empty reference in every class,
an authority reference, an owner reference, an independent-review reference,
an approval reference, and a transaction-bundle reference. An incomplete or
malformed reference fails closed.

`UNKNOWN` remains unknown. It cannot be normalized into a partition predicate,
and it cannot satisfy a missing evidence prerequisite.

## Split-Transaction Boundary

`SPLIT_PROPOSAL_ENVELOPE_SCHEMA.json` defines the child partition nested in a
decision record. It requires:

- one exact frozen parent subject;
- at least two non-empty children;
- ordered and unique child identifiers;
- a complete member list for every child;
- exclusive membership with no duplicates;
- deterministic, source-grounded partition rationale;
- recomputed child counts and member-set hashes;
- exact parent/child union equality;
- zero unassigned members and zero members outside the parent;
- zero Blocked31 overlap;
- denominator delta `0` and denominator mutation `NO`;
- crosswalk byte drift `0`;
- unapplied and unauthorized zero-mutation assertions.

The semantic validator recomputes these conditions from the member lists. A
submitted claim cannot override a recomputed count, hash, overlap, or union.
The proposal remains a proposal even when its future decision status is
`APPROVED_FOR_FUTURE_TRANSACTION`.

## State Machine

The allowed states are defined in `DECISION_STATE_MACHINE.json`:

```text
DESIGN_ONLY
  -> PROPOSAL_PREPARED
  -> PENDING_GOVERNANCE
  -> APPROVED_FOR_FUTURE_TRANSACTION
  -> REJECTED
  -> DEFERRED
```

The legal path requires a prepared proposal and evidence before governance
review. Approval additionally requires full authority, full evidence,
independent review, and zero-mutation assertions. Rejection and deferral
require an explicit rationale and owner-bound reference.

`SPLIT_APPLIED` is deliberately absent from the state enum and is listed as a
forbidden state. A record that attempts to represent an applied split is
rejected even if its other fields appear valid.

## Human and Owner Boundary

This package can refer to a human or owner authority, but it cannot materialize
one. An authority object is a reference bundle with `decision_materialized:
false`. The owner reference identifies the authority boundary; the approval
and transaction-bundle references identify the future transaction scope.

The following are separate and cannot be implied:

- evidence acquisition and evidence acceptance;
- independent review and owner adjudication;
- approval of a design and authorization of execution;
- approval of a transaction and mutation of scoring, binding, or denominator
  state.

No automatic recommendation is treated as a human decision. No disposition is
created for all twelve subjects by default.

## Denominator and Crosswalk Invariants

The validator fails closed if any of these change:

1. Exact12 template count is not `12`.
2. Unique raw member count is not `203`.
3. The union hash differs from the frozen commitment.
4. Any member occurs in more than one template.
5. Any child member is outside its authenticated parent.
6. A child member is duplicated, omitted, or overlaps another child.
7. Blocked31 overlap is non-zero.
8. A denominator delta is non-zero.
9. Crosswalk bytes drift from the authenticated R2 baseline.
10. Any current state, status, or execution flag is changed implicitly.

These checks apply regardless of disposition. Rejection does not remove a
member, deferral does not suspend a member, and approval does not add a child
to the denominator.

## Audit and Provenance

Each record repeats the exact review identity and frozen baseline commitments.
The subject manifest records the source crosswalk path and hash. The package
manifest records every design and fixture payload with SHA-256 hashes, excludes
itself from the payload list, and uses the canonical-v1 materialization shape.

The validation evidence records:

- local, cached, and live artifact refs;
- the reviewed commit and its required parent;
- the independent-review materialization commit and verdict;
- schema meta-validation and grammar alignment;
- exact baseline counts and hashes;
- every positive and negative fixture result;
- zero operational effect.

Validation output is evidence, not authority. It must be independently
reviewed before any later human decision or split-transaction work.

## Fail-Closed Rules

The validator rejects on:

- duplicate JSON object keys or non-finite numbers;
- missing or malformed governance/evidence references;
- unknown schema fields;
- unknown decision states or the fake applied-split state;
- approval without authority, evidence, owner, review, or transaction-bundle
  references;
- any conservation, hash, overlap, denominator, crosswalk, or current-state
  mismatch;
- any non-zero mutation counter or execution flag;
- any attempt to use `UNKNOWN` as a partition boundary.

The validator does not repair a record. The caller must produce a new record
that satisfies the full contract while preserving the frozen subject.

## Zero Operational Effect

This package is design-only. Its terminal boundary is:

```text
APPLIED_SPLITS = 0
STATUS_MUTATIONS = 0
DENOMINATOR_MUTATIONS = 0
HUMAN_DECISIONS_CREATED = 0
FORMAL_1796_EXPERIMENT_EXECUTED = NO
ZERO_OPERATIONAL_EFFECT = PASS
```

The next phase is:

```text
E0C_EXACT12_SPLIT_RESOLUTION_GOVERNED_DECISION_DESIGN_INDEPENDENT_REVIEW
```
