# E0C Exact12 Resolution Evidence-Class Policy

## Scope

This policy defines a future, governed path for the twelve frozen Exact12
templates that currently carry `REQUEST_SPLIT_OR_MORE_EVIDENCE`. It is a
design contract only. It does not select an outcome, create an execution
authority, apply a split, mutate a status, change the denominator, or run an
experiment.

The frozen reviewed-state anchors are:

- materialization commit: `f10c874513071345ddc2411004f81ee5c57f4065`
- independent review commit: `38468ed7968d4030b2c070f381c35bae52452dbb`
- exact template count: `12`
- frozen raw coverage: `203`
- current resolution state for every template: `REQUEST_MORE_EVIDENCE`

The commits above are carried as task-pinned provenance anchors. This design
does not re-materialize or rewrite either reviewed state.

## Evidence classes

| Class | Purpose | Minimum admissible content | Not sufficient by itself |
| --- | --- | --- | --- |
| `IDENTITY_PROVENANCE` | Protect frozen identity and source traceability | Exact template ID/order, member-set hash/count/reference, source locator coverage, immutable input references | A renamed template, inferred membership, or an unreferenced summary |
| `SOURCE_SEMANTICS` | Establish what must be preserved | Exact source-visible action semantics, raw-specific parameters, explicit unknowns, and unresolved questions | Free-text interpretation, ATT&CK inference, or guessed command behavior |
| `CONTROLLED_ENVIRONMENT` | Establish a safe, bounded replay context | Platform/service prerequisites, fixture ownership, isolation, reset plan, and feasibility evidence | A claim that an environment exists without a bounded fixture and reset proof |
| `DEFENSIVE_EQUIVALENCE` | Show that a candidate preserves the relevant decision point | Source-grounded invariants for process, file, socket, network, timing, causality, and required side effects | Payload similarity, a generic command, or a convenient but semantically different action |
| `OBSERVABILITY` | Show that required behavior can be distinguished and localized | Expected telemetry surfaces, correlation IDs, event ordering, and known limitations | A detector score, unlocalized event, or unobserved assertion |
| `SAFETY_RESET` | Prevent uncontrolled or irreversible effects | Inert fixtures, secret isolation, deny-by-default egress, cleanup/reset proof, and rollback conditions | Real malware, real credentials, destructive effects, or public endpoints |
| `PARTITION` | Justify a split without losing or duplicating members | A deterministic, source-grounded predicate and complete child membership lists with conservation checks | A cluster label, similarity score, or an UNKNOWN value used as a boundary |
| `GOVERNANCE` | Make a future disposition authoritative | Explicit reviewer identity/role, evidence manifest, decision rationale, independent check, and approval record | This design package, an automatic recommendation, or an unapproved draft |

## Admissibility rules

1. Evidence must be traceable to an exact raw member or an explicitly scoped
   template-level claim. A template-level claim cannot erase raw-specific
   parameters.
2. `UNKNOWN` remains unknown. It cannot be converted into a known value by
   normalization, semantic interpretation, or a proposed fixture.
3. Evidence may support a future decision only when it is internally
   consistent, reproducible from its references, and reviewed against the
   frozen identity commitment.
4. Review aids such as complexity, cohesion, or candidate-split counts are
   non-authoritative. They can focus review but cannot satisfy an outcome gate.
5. Evidence collection is not authorized by this policy. A future acquisition
   request must pass the separate `MORE_EVIDENCE_ACQUISITION_CONTRACT` gate.
6. No evidence record may contain real secrets, uncontrolled external
   destinations, destructive actions, or unbounded service changes.

## Mutually exclusive future outcomes

Each future template-level decision must set exactly one outcome. Until a
separate decision record exists, `resolution_outcome` remains null and the
template remains `REQUEST_MORE_EVIDENCE`.

### `APPROVE`

Use only when the evidence gate is complete for every member in the frozen
member set. The decision record must show source-semantic equivalence,
controlled-environment feasibility, safety/reset sufficiency, required
observability, raw-specific parameter binding, and an independent review. An
approval is not execution authorization; any later execution requires its own
separate authorization and run binding.

### `REJECT_KEEP_MANUAL`

Use when an explicit review concludes that the member set cannot be supported
by a safe, source-faithful governed contract, or that the evidence is
contradictory or insufficient for a safe reusable disposition. The rationale
must identify the blocking evidence and preserve every member as manual. A
rejection must not be used as an automatic fallback for an incomplete review.

### `JUSTIFIED_SPLIT_PROPOSAL`

Use only when a deterministic, source-grounded partition is demonstrated.
The proposal must satisfy the split justification contract, including
non-empty children, pairwise zero overlap, exact union equality with the
parent, count conservation, recomputed child hashes, and raw-level evidence
for the partition predicate. A split proposal is a proposal only: it remains
unapplied, creates no child authority, and does not change the denominator or
any member status.

### `KEEP_REQUEST_MORE_EVIDENCE`

Use when the current evidence gate remains incomplete and no authoritative
reject or justified split has been approved. This is the conservative holding
state. It records the missing evidence questions and may request bounded future
acquisition without selecting a disposition.

## Outcome gate matrix

| Outcome | Required evidence | Required governance | Forbidden consequence |
| --- | --- | --- | --- |
| `APPROVE` | All required classes except `PARTITION`, plus member-complete equivalence and safety evidence | Independent review and explicit approval | No automatic execution or status mutation |
| `REJECT_KEEP_MANUAL` | Contradiction or infeasibility record tied to source and safety constraints | Explicit decision rationale and review | No member removal or denominator reduction |
| `JUSTIFIED_SPLIT_PROPOSAL` | `IDENTITY_PROVENANCE`, `SOURCE_SEMANTICS`, `PARTITION`, `SAFETY_RESET`, and `GOVERNANCE` | Independent partition recomputation and separate approval | No applied split or child authorization |
| `KEEP_REQUEST_MORE_EVIDENCE` | A complete missing-evidence register | Review acknowledgement; no disposition approval | No implied approval, rejection, or split |

## Transition rules

The only legal future transition sequence is:

`REQUEST_MORE_EVIDENCE` -> evidence request or review -> exactly one governed
outcome -> separate implementation/authority phase, if later approved.

`JUSTIFIED_SPLIT_PROPOSAL` cannot transition directly to execution. It must
first pass an independent partition review and an explicit approval that
creates the child records. The parent remains frozen until that approval.

No transition may expand a member set, reuse a stale hash, reinterpret an
UNKNOWN field as a split boundary, mutate the R3 planning status, or alter the
203-row denominator.
