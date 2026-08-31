# E0C-R6 — Blocked31 Source-Detail Recovery and Exact89 Template Evidence Enrichment

Continue from fresh-reviewed E0C-R5.

Pinned state:

```text
EXACT_MANUAL_RAW_COUNT = 589

SHARED_TEMPLATE_COUNT = 89
SHARED_TEMPLATE_COVERED_ROWS = 494
REVIEW_BATCH_COUNT = 9

RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED = 64
BLOCKED_NEED_MORE_SOURCE_DETAIL = 31

HUMAN_DECISIONS_CREATED = 0
FORMAL_EXPERIMENT_EXECUTED = NO
```

Pinned GitHub review commit:
`90513ab76a2d392398fefd0456ad53a4660a3e8a`

## Goal

Without making any human decision:

1. attempt evidence-only recovery for the exact 31 rows blocked on missing source detail;
2. enrich the 89 template review packets with exact source evidence and environment prerequisites;
3. produce a more efficient first human-review tranche.

Do not mutate R3/R4/R5 manual status.

## 1. Authenticate exact sets

Authenticate:
- exact589 manual set;
- exact89 shared templates;
- exact494 member union;
- 64 raw-specific set;
- exact31 blocked set;
- 9 presentation batches;
- all member-set commitments.

Require:
- overlap = 0;
- missing = 0;
- no status mutation.

## 2. Recover source detail for exact31

Search only existing authenticated project sources:
- authoritative raw playbook corpus;
- verified raw registry;
- E0C R1/R2/R3/R4/R5 artifacts;
- already-authenticated source excerpts/manifests;
- other immutable local project evidence already part of the project.

For each of 31:
- exact raw key;
- missing field(s);
- exact searched source identities;
- exact source locators;
- recovered source text/field if present;
- evidence hash;
- recovery status.

Allowed recovery status:

```text
RECOVERED_FROM_AUTHENTICATED_EXISTING_SOURCE
NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE
CONFLICTING_EXISTING_SOURCE_DETAIL
```

Do not use LLM inference to fill a missing protocol/service/command.

## 3. Recovery effect is advisory only

Even if detail is recovered, do NOT automatically convert the row from:
`BLOCKED_NEED_MORE_SOURCE_DETAIL`.

Instead produce:
`CANDIDATE_FOR_HUMAN_RECLASSIFICATION_AFTER_SOURCE_RECOVERY`.

No R3 global planning status changes.

## 4. Enrich exact89 template packets

For each shared template attach:
- exact source evidence references;
- exact representative raw source snippets/fields;
- exact environment prerequisites supported by evidence;
- known protocol/service/platform;
- unresolved UNKNOWN fields;
- defensive-equivalence invariants;
- telemetry-equivalence invariants;
- cleanup/reset requirements;
- negative cases;
- member count and member-set SHA256.

Do not add guessed semantics.

## 5. Human-review leverage analysis

Compute a deterministic first-review tranche using only:
1. highest raw coverage;
2. highest playbook reuse;
3. most complete source detail;
4. controlled environment feasibility;
5. lower reset/safety complexity.

Prefer a first tranche of 10-15 templates.

Do not decide them.

## 6. Prepare human decision sheets

For each first-tranche template show compactly:
- template ID;
- exact covered raw count;
- exact member SHA;
- 1-3 representative raw keys;
- source evidence;
- proposed reusable design contract;
- unresolved questions;
- consequences of approval.

Allowed human actions:

```text
APPROVE_TEMPLATE_FOR_MEMBER_SET
REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL
REQUEST_SPLIT_OR_MORE_EVIDENCE
```

Decision remains null.

## 7. Raw-specific 64 support

For the top-priority raw-specific rows, determine whether a shared environment/fixture can be reused even though semantic design remains raw-specific.

Do not turn them into shared templates automatically.

## Outputs

- `E0C_R6_INPUT_AUTHENTICATION.json`
- `E0C_R6_BLOCKED31_SOURCE_RECOVERY_RESULTS.json`
- `E0C_R6_BLOCKED31_RECOVERED_EVIDENCE.jsonl`
- `E0C_R6_EXACT89_ENRICHED_TEMPLATE_PACKETS.jsonl`
- `E0C_R6_FIRST_HUMAN_REVIEW_TRANCHE.json`
- `E0C_R6_FIRST_HUMAN_REVIEW_SHEETS.md`
- `E0C_R6_RAW_SPECIFIC64_FIXTURE_REUSE_ANALYSIS.json`
- `E0C_R6_SOURCE_RECOVERY_AND_ENRICHMENT_REPORT.md`

## Hard boundaries

NO:
- human decisions;
- automatic row reclassification;
- manual-to-contract status mutation;
- action implementation/execution;
- formal outcomes;
- PROVX detection claims;
- denominator mutation;
- binding/scoring mutation.

## Terminal

```text
E0C_R6_SOURCE_RECOVERY_AND_TEMPLATE_ENRICHMENT =
READY_FOR_HUMAN_REVIEW | BLOCKED

EXACT31_CONSERVATION = PASS | BLOCKED
RECOVERED_FROM_AUTHENTICATED_EXISTING_SOURCE = <n>
NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE = <n>
CONFLICTING_EXISTING_SOURCE_DETAIL = <n>

EXACT89_TEMPLATE_ENRICHMENT = PASS | BLOCKED
FIRST_HUMAN_REVIEW_TRANCHE_TEMPLATE_COUNT = <n>
FIRST_HUMAN_REVIEW_TRANCHE_RAW_COVERAGE = <n>

HUMAN_DECISIONS_CREATED = 0
STATUS_MUTATIONS = 0
FORMAL_EXPERIMENT_EXECUTED = NO
DENOMINATOR_CHANGE = NO

NEXT_ACTION =
FRESH_REVIEW_OF_E0C_R6_SOURCE_RECOVERY_AND_TEMPLATE_ENRICHMENT

STOP = true
```
