# EXP-E0C-R4 Manual-Design Workload Compression

Evidence-bound compression of the exact R3 manual-design set into human-reviewable template candidates. No row is automatically resolved and no action is executed.

## Terminal State

- `E0C_R4_MANUAL_DESIGN_COMPRESSION = READY_FOR_HUMAN_TEMPLATE_REVIEW`
- `EXACT_MANUAL_RAW_COUNT = 589`
- `MANUAL_SET_CONSERVATION = PASS`
- `SHARED_TEMPLATE_COUNT = 89`
- `SHARED_TEMPLATE_COVERED_ROWS = 494`
- `RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED = 64`
- `BLOCKED_NEED_MORE_SOURCE_DETAIL = 31`
- `HUMAN_DECISIONS_CREATED = 0`
- `FORMAL_EXPERIMENT_EXECUTED = NO`
- `DENOMINATOR_CHANGE = NO`
- `NEXT_ACTION = FRESH_REVIEW_OF_E0C_R4_MANUAL_DESIGN_COMPRESSION`
- `STOP = true`

## Compression Policy

Clustering uses only exact R1 fields and R2 blocker labels. Embeddings, semantic guesses, guessed command syntax, credentials, target behavior, destructive effects, and human decisions are excluded. Shared templates remain review candidates; no member changes its R3 global status.

## Classification

The 589 manual rows are classified into 494 candidate shared-template rows, 64 raw-specific rows, and 31 rows blocked on missing source detail. The counts sum to 589 with overlap 0 and missing 0.

| Classification | Rows |
|---|---:|
| `CANDIDATE_FOR_SHARED_HUMAN_TEMPLATE` | 494 |
| `RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED` | 64 |
| `BLOCKED_NEED_MORE_SOURCE_DETAIL` | 31 |

## Review Decisions

Each JSONL review packet exposes only `APPROVE_TEMPLATE_FOR_MEMBER_SET`, `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`, or `REQUEST_SPLIT_OR_MORE_EVIDENCE`. The decision field is null and `HUMAN_DECISIONS_CREATED = 0`.

## Boundaries

R1 candidate fidelity and R3 global statuses are preserved. PROVX observability/localization remains UNKNOWN and all result state remains UNEXECUTED_NOT_OBSERVED. No authority, denominator, or formal experiment state changed.

STOP = true
