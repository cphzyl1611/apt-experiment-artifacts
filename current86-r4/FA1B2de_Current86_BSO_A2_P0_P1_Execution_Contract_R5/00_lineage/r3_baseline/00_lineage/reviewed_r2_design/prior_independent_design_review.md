# Independent Design Review — FA-1B2de Current86 B-SO-A2 Human-Light Execution P0–P4

**Review mode:** `FRESH / READ_ONLY / DESIGN_ONLY`  
**Reviewed artifact:** `Design_FA1B2de_Current86_BSO_A2_HumanLight_Execution_P0_P4.md`  
**Expected SHA-256:** `50bb2e17b2a3e71f3015125d20ce7b10381d9dec1cef9465b722171a9f467dd2`  
**Observed SHA-256:** `50bb2e17b2a3e71f3015125d20ce7b10381d9dec1cef9465b722171a9f467dd2`  
**Authentication:** `PASS`

No reviewed source file was modified. No P0/P1/P2/P3/P4 runtime action, proposer/verifier
materialization, raw-level human decision, adjudication ledger write, B-SO-V/P action, scoring/binding
authority mutation, publication, replay, experiment, or paper modification was performed.

---

## 1. Review verdict

```text
REVIEW_VERDICT = BLOCKED

CONSOLIDATED_EXECUTION_DESIGN =
BLOCKED_PENDING_TWO_NARROW_DESIGN_CORRECTIONS

READY_FOR_P0_P1_EXECUTION_CONTRACT_MATERIALIZATION = NO
```

The accepted five-layer architecture itself is not challenged:

```text
P0 → P1 → P2 → P3 → P4 → B-SO-V handoff
```

No P5/P6 or new authority layer is required.

The design is substantially coherent and preserves the activated Human-Light authority direction.
Two narrow defects remain genuinely blocking because they affect the mechanical identity/state
semantics that P0/P1 schemas would otherwise have to guess.

---

# 2. A — FACT / EXISTING AUTHORITY / PROPOSED EXECUTION RULE

**Result: PASS**

The three-way classification is internally coherent.

The proposed execution rules do not introduce a new owner-selection authority and do not mutate:

```text
PROJECT_SCORING_AUTHORITY
PROJECT_BINDING_AUTHORITY_BASELINE
PROJECT_ACCEPTED_BINDINGS
1796 denominator
```

The design preserves inherited rules that the complete candidate universe is normative input,
machine proposals are non-authoritative, hidden pruning/top-k/rank authority is prohibited, the human
normative unit is one raw, and owner/escalation terminal semantics remain distinct.

The P3 scheduling/checkpoint/resume rules are subordinate operational execution semantics rather than
new scoring/binding/owner semantics.

No blocker under A.

---

# 3. B — canonicalization and hashing

**Result: PASS WITH DEFERRED-MATERIALIZATION REQUIREMENT — NOT A BLOCKER**

`RAW_FILE_SHA256` is mechanically exact-byte based.

`PROJECT_CANONICAL_JSON_V1` is sufficiently constrained to avoid filesystem order, locale, JSON
insertion order, pretty-print formatting, and platform newline dependence. The ban on floating-point
values in normative identity objects and NFC validation also reduce cross-implementation ambiguity.

The design does not enumerate a concrete ordering rule for every mathematical-set field. It instead
requires each schema-declared set to define a field-specific ordering rule before canonicalization.

That is acceptable as a **P0 execution-contract materialization detail**, not a design blocker,
provided the P0/P1 contract freezes a `SET_ORDERING_REGISTRY` (or equivalent exact schema rules)
before any runtime identity is computed.

At minimum the materialized schemas must mechanically define deterministic ordering for:

```text
Current86 raw set
relation set
per-raw candidate universe
evidence fact set
owner terminal raw set
escalation terminal raw set
each P3 state-partition raw set
```

Recommended deterministic keys, without changing architecture:

```text
raw set:
  canonical_raw_key by BYTEWISE_ASCENDING_UTF8

relation set:
  canonical relation identity by BYTEWISE_ASCENDING_UTF8

candidate-universe entries:
  a schema-frozen canonical candidate-entry identity
  (or an exact tuple ordering such as candidate_scoring_id then relation_identity)

evidence fact set:
  source_fact_id / canonical_fact_id by BYTEWISE_ASCENDING_UTF8

terminal raw sets and P3 partition sets:
  canonical_raw_key by BYTEWISE_ASCENDING_UTF8
```

The exact choice for the subordinate sets may be frozen during materialization; it must not be
selected dynamically from runtime content.

---

# 4. C — proposer/verifier computational contract identity and isolation

**Result: PASS WITH MANDATORY MATERIALIZATION ENFORCEMENT — NOT A BLOCKER**

The computational contract identity binds the required semantic inputs:

```text
implementation identity
prompt/template identity
model/runtime identity where exposed
tool-permission boundary
input/output schema identities
normative source profile
source registry
historical-output denylist
isolation contract
canonicalization contract
```

Private chain-of-thought is correctly excluded from normative artifacts.

However:

```text
PRIMARY.context_identity != VERIFIER.context_identity
PRIMARY.run_identity != VERIFIER.run_identity
```

is **necessary but not sufficient** proof of isolation.

The design itself already states the stronger normative requirement: before verifier commitment
freeze, the verifier SHALL NOT receive primary owner, relation, rationale, evidence selection,
scores/ranks/shortlists/pruning state, or mutable primary derivation artifacts.

Therefore P0 execution-contract materialization MUST mechanically bind an enforcement mechanism.
The materialized isolation contract must make the visibility boundary independently auditable, for
example through exact read roots / separate immutable input workspace / primary-output exclusion /
tool ACLs or an equivalent mechanism.

The P0 contract must be capable of proving:

```text
VERIFIER_PRECOMMIT_READABLE_INPUT_SET
==
FROZEN_COMMON_VERIFIER_INPUT_SET

and

VERIFIER_PRECOMMIT_READABLE_INPUT_SET
∩
PRIMARY_PRIVATE_OR_COMMITMENT_OUTPUT_SET
=
∅
```

This is a required runtime-contract detail, but the current design already normatively requires the
result and provides `tool_permission_boundary` plus `isolation_contract_identity` to bind it.
Therefore no architectural redesign is required.

---

# 5. D — complete candidate universe / pruning / ranking

**Result: PASS**

The design preserves exact complete-candidate-universe consideration and prevents proposal ranking,
top-k truncation, hidden pruning, candidate popularity, historical EQ output, or model confidence
from becoming normative owner-selection authority.

Primary and verifier bind the same complete-universe hash.

Pilot selection and P3 scheduling are independent of candidate semantics.

No hidden rank/pruning return path is identified.

---

# 6. E — human authority and workload shape

**Result: PASS**

The design preserves:

```text
HUMAN_NORMATIVE_UNIT = ONE_RAW

CONFIRM_PROPOSED_OWNER
REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE
NOT_SURE_ESCALATE
```

and does not reintroduce relation-level adjudication.

Human-selected alternatives remain normative human choices but must still pass structural/evidence
validation before owner freeze; failure becomes a legal unresolved escalation rather than a silent
fallback to the original machine proposal.

The reviewer is not required to copy candidate IDs, relation IDs, evidence IDs, or hashes.

No blocker under E.

---

# 7. F — P1/P2 pilot semantics

**Result: PASS**

The pilot-selection rule is deterministic, bytewise, positional, and non-semantic.

The pilot is real A2 adjudication but only becomes an **accepted** terminal after P2 PASS.

The design correctly separates:

```text
PILOT_RECORD_VALIDITY
PILOT_SCALE_OUT_ELIGIBILITY
```

A legitimate pre-human semantic escalation may be a valid terminal but does not qualify the
Human-Light human path for scale-out.

Technical / integrity / software defects are explicitly not legitimate semantic escalation
terminals.

No blocker under F.

---

# 8. G — P3 exact state partition / exactly-once / resume

**Result: BLOCKED**

The intended five-state partition is correct in concept:

```text
S_ACCEPTED_TERMINAL
S_PENDING_REVIEW
S_IN_PROGRESS_OR_INCOMPLETE
S_BLOCKED_ATTEMPT
S_NOT_STARTED_FOR_ADJUDICATION
```

and the design explicitly requires pairwise disjointness and exact union with Current86.

However the current append-only ledger/state semantics do not mechanically guarantee that invariant
after a blocked checkpoint or remediation.

## BLOCKER_ID

```text
BLOCKER_ID = P3_CURRENT_STATE_DISPOSITION_AND_PENDING_INVALIDATION_UNDERSPECIFIED
```

### Exact affected sections

```text
§5.4  P3 — Scale-out execution / checkpoint BLOCK behavior
§6.1  State definitions
§6.4  State transitions
§6.5  Resume token
§7.2  Pending terminal ledger
§7.4  Promotion
§15.2 Raw-level state machine
```

### Why this is actually blocking

The pending ledger is append-only and contains terminal candidates awaiting review. The design says
a checkpoint BLOCK quarantines the unaccepted batch and the raw may transition:

```text
PENDING_REVIEW → BLOCKED_ATTEMPT
```

but it does not define the mechanical disposition record that makes the previous pending terminal no
longer **current pending state**.

Therefore a fresh implementation could legitimately derive both:

```text
raw ∈ S_PENDING_REVIEW
```

from the historical pending entry and:

```text
raw ∈ S_BLOCKED_ATTEMPT
```

from the later blocked review.

There is a second ambiguity in the current definition of `BLOCKED_ATTEMPT`:

> “At least one execution attempt is blocked ...”

Taken literally, a raw with a historical failed attempt could remain eligible for
`S_BLOCKED_ATTEMPT` even after controlled remediation and later acceptance, conflicting with the
required pairwise-disjoint current-state partition.

This ambiguity affects:

```text
exactly-once human decision behavior
orphan pending detection
duplicate terminal prevention
checkpoint quarantine
resume-token reconstruction
P4 entry condition
```

and must not be left for runtime code to guess.

### Minimal required correction

Do not redesign P3. Add one explicit append-only **current-disposition/state-transition contract**.

The correction must establish all of the following:

1. State membership is determined by the **current authoritative disposition**, not by the mere
   historical existence of an attempt/ledger row.
2. A pending terminal receives an immutable identity.
3. If independent review substantively rejects that candidate terminal, append a disposition such
   as:

```text
PENDING_TERMINAL_INVALIDATED
  raw_key
  pending_terminal_id
  blocking_review_id
  invalidation_reason_class
  next_state = BLOCKED_ATTEMPT
```

   The historical pending record remains byte-preserved but is excluded from the current
   `S_PENDING_REVIEW`.
4. If the independent review cannot complete because of reviewer/infrastructure failure **without
   invalidating the terminal candidate**, the raw remains `PENDING_REVIEW` under global pause; it
   must not be silently converted to `BLOCKED_ATTEMPT`.
5. `BLOCKED_ATTEMPT` must mean **current raw execution state is blocked and no current reviewable
   terminal exists**, not “a historical blocked attempt exists somewhere.”
6. Controlled remediation appends a state transition from the current blocked state to
   `IN_PROGRESS_OR_INCOMPLETE`; old failures remain audit history only.
7. `ACCEPTED_TERMINAL` supersedes all historical attempt/pending/blocked states for current-state
   membership.
8. The resume token must bind the exact disposition/state-transition head(s) used to reconstruct the
   five current-state sets.

This is a narrow state-schema correction. It does not add a new architecture layer or new human
workload.

---

# 9. H — normative identity versus non-authoritative workload telemetry

**Result: BLOCKED**

The workload section correctly declares:

```text
NON_AUTHORITATIVE_WORKLOAD_EVIDENCE
```

and explicitly prohibits workload telemetry from affecting owner selection, terminal semantics, or
scoring/binding semantics.

However the P4 packaging/identity rule is ambiguous.

## BLOCKER_ID

```text
BLOCKER_ID = P4_NONAUTHORITATIVE_WORKLOAD_MAY_CONTAMINATE_NORMATIVE_FINAL_FREEZE_ID
```

### Exact affected sections

```text
§9.4  Final freeze artifacts / CURRENT86_A2_FINAL_FREEZE_ID
§11   Human workload boundary
§13   Artifact / hash / ID registry
§10   B-SO-V boundary, because B-SO-V pins the verified final freeze
```

### Why this is actually blocking

`workload_summary.json` is placed inside the P4 final-freeze package, while
`CURRENT86_A2_FINAL_FREEZE_ID` is defined from `FINAL_FREEZE_MANIFEST`.

The design does not explicitly state whether:

```text
FINAL_FREEZE_MANIFEST
```

contains the workload-summary hash, workload-derived fields, or a whole-package inventory hash.

If it does, changing purely non-authoritative telemetry — for example corrected idle-time metadata —
could change:

```text
CURRENT86_A2_FINAL_FREEZE_ID
```

even when the exact 86 terminal results, owner/escalation partition, authority lineage, provenance,
and normative execution semantics are unchanged.

That would allow non-authoritative workload evidence to alter the normative identity handed to
B-SO-V, contradicting the declared workload boundary.

### Minimal required correction

Do not remove workload evidence from the package.

Instead split the two identities explicitly:

```text
CURRENT86_A2_FINAL_FREEZE_ID
=
hash of FINAL_FREEZE_NORMATIVE_MANIFEST only
```

where the normative manifest MUST exclude:

```text
decision-time telemetry
idle/session interruption telemetry
workload_summary hash
workload-derived aggregates
non-authoritative presentation/performance metrics
```

Define a separate delivery/package identity, for example:

```text
FINAL_FREEZE_PACKAGE_INTEGRITY_SHA256
or
FINAL_FREEZE_PACKAGE_MANIFEST_ID
```

which MAY bind the complete package including `workload_summary.json`.

Required principle:

```text
changing only NON_AUTHORITATIVE_WORKLOAD_EVIDENCE
MAY change package-integrity identity

but MUST NOT change
CURRENT86_A2_FINAL_FREEZE_ID
```

B-SO-V may authenticate both identities for transport/integrity, but the normative Current86 A2
result identity must be the workload-independent `CURRENT86_A2_FINAL_FREEZE_ID`.

This is a narrow identity-separation correction, not a new authority layer.

---

# 10. I — P4 terminal/freeze semantics

**Result: PASS SUBJECT TO BLOCKER H CORRECTION**

The design correctly requires:

```text
EXACTLY_ONE_ACCEPTED_A2_TERMINAL_PER_CURRENT86_RAW = YES

OWNER_TERMINAL_SET ∩ ESCALATION_TERMINAL_SET = ∅

OWNER_COUNT + ESCALATION_COUNT = 86

A2_PROCESS_COMPLETE != OWNER_RESOLUTION_COMPLETE

P4_FREEZE != BINDING_PUBLICATION
```

It also clearly distinguishes technical execution defects from legitimate semantic escalation.

Technical defects cannot become final accepted escalation terminals.

No additional P4 blocker exists beyond the final-freeze identity contamination issue already
identified under H.

---

# 11. J — B-SO-V boundary

**Result: PASS**

The handoff boundary is correctly constrained:

```text
BSO_V_CURRENT86_A2_INPUT =
VERIFIED_CURRENT86_A2_FINAL_FREEZE_ONLY

BSO_V_MUST_NOT_RE_ADJUDICATE_OWNER = YES
```

The design does not authorize P4 to modify:

```text
PROJECT_ACCEPTED_BINDINGS
binding authority
scoring authority
1796 denominator
```

Escalation terminals remain unresolved and non-publishable as owner bindings.

No blocker under J.

---

# 12. Narrow blocker registry

Only the following defects block P0/P1 execution-contract materialization:

| BLOCKER_ID | Affected area | Minimal correction |
|---|---|---|
| `P3_CURRENT_STATE_DISPOSITION_AND_PENDING_INVALIDATION_UNDERSPECIFIED` | P3 state/ledger/checkpoint/resume | Freeze append-only disposition/invalidation semantics so exactly one current state is mechanically derivable after checkpoint BLOCK/remediation. |
| `P4_NONAUTHORITATIVE_WORKLOAD_MAY_CONTAMINATE_NORMATIVE_FINAL_FREEZE_ID` | P4 manifest/freeze identity/workload package | Separate workload-independent normative final-freeze ID from full package-integrity identity. |

No other architecture expansion is required.

---

# 13. Human workload boundary as reviewed

```text
HUMAN_WORKLOAD_BOUNDARY_AS_REVIEWED
```

The design preserves the Human-Light division of labor.

The human reviewer remains responsible only for necessary normative human governance / raw-level
semantic decisions, principally:

```text
CONFIRM_PROPOSED_OWNER

REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE

NOT_SURE_ESCALATE
```

plus the already-designed one-time scale-out release after a successful independently reviewed pilot.

The human is **not** required to:

```text
reconstruct candidate universes
perform 4,161 relation-level outcomes
extract source facts
copy candidate/relation/evidence IDs
copy hashes
calculate canonical IDs
run proposer/verifier comparison
capture provenance identifiers manually
maintain ledgers
perform checkpoint accounting
construct resume tokens
perform conservation calculations
```

Those remain machine responsibilities:

```text
source extraction
hashing/canonicalization
complete candidate reconstruction
primary proposal
isolated verifier derivation
provenance packaging/verification
packet rendering
ledger/state maintenance
checkpoint review inputs
resume/conservation accounting
P4 freeze construction
```

Workload timing remains observational only:

```text
NON_AUTHORITATIVE_WORKLOAD_EVIDENCE
```

and uncontrolled session idle time may be reported only as wall-clock latency with idle-risk, not
reviewer cognitive effort.

The two blockers above do not require any increase in relation-level or raw-level human workload.

---

# 14. Review terminal

```text
REVIEW_VERDICT = BLOCKED

CONSOLIDATED_EXECUTION_DESIGN =
BLOCKED_PENDING_TWO_NARROW_DESIGN_CORRECTIONS

READY_FOR_P0_P1_EXECUTION_CONTRACT_MATERIALIZATION = NO

BLOCKER_COUNT = 2

BLOCKER_1 =
P3_CURRENT_STATE_DISPOSITION_AND_PENDING_INVALIDATION_UNDERSPECIFIED

BLOCKER_2 =
P4_NONAUTHORITATIVE_WORKLOAD_MAY_CONTAMINATE_NORMATIVE_FINAL_FREEZE_ID

P0_EXECUTED = NO
P1_EXECUTED = NO
RAW_LEVEL_HUMAN_DECISIONS = 0
BINDING_PUBLICATION = NO

RETURN_TO_4161_RELATION_EQ = NO
CONTINUE_OLD_44_RELATION_EQ_PILOT = NO

NEXT_ACTION =
PATCH_ONLY_THE_TWO_NARROW_CONSOLIDATED_DESIGN_BLOCKERS_THEN_TARGETED_INDEPENDENT_DESIGN_REVIEW
```
