# E0C-R5 — Exact89 Human Template Review Batching

Continue from fresh-reviewed E0C-R4.

Frozen manual set:
```text
EXACT_MANUAL_RAW_COUNT = 589
SHARED_TEMPLATE_COUNT = 89
SHARED_TEMPLATE_COVERED_ROWS = 494
RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED = 64
BLOCKED_NEED_MORE_SOURCE_DETAIL = 31
```

No R3/R4 status may be mutated in this task.

## Goal
Convert the 89 shared-template review candidates into compact, coverage-ranked human review batches while preserving exact member commitments and without making any human decision.

## 1. Authenticate exact89
Pin `E0C_R4_SHARED_MANUAL_DESIGN_TEMPLATES.json`, raw-to-template map, exact589 manual set, R4 review packets, and R4 workload audit. Require exactly 89 shared templates; union exactly 494 rows; expected zero shared-member overlap; every member remains R3 `MANUAL_DESIGN_REQUIRED`.

## 2. Coverage ranking
For each shared template compute member count, playbook count, archetype, OS/platform, dominant blockers, telemetry surfaces, environment availability, reset/safety complexity.

Rank by member coverage, playbook reuse, defensive/telemetry equivalence confidence from existing evidence, environment availability, and lower reset complexity. No scoring weight.

## 3. Review batches
Create deterministic batches, preferably 8-12 templates each, maximizing human review efficiency while keeping conceptually similar templates together. Do not merge template authority/member sets. Each batch is only a presentation layer.

## 4. Compact human review sheet
For each template include template ID, member count, member-set SHA256, representative 1-3 raw keys, archetype/platform/service, blocker summary, defensive-equivalence summary, telemetry-equivalence summary, raw-specific parameters, unresolved human questions, negative cases.

Allowed human actions remain:
```text
APPROVE_TEMPLATE_FOR_MEMBER_SET
REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL
REQUEST_SPLIT_OR_MORE_EVIDENCE
```
Do not prefill any action.

## 5. Source-detail recovery plan for 31
For the 31 `BLOCKED_NEED_MORE_SOURCE_DETAIL` raws, enumerate exact missing fields/detail; group mechanically where the same missing evidence source is implicated; identify whether recovery could come from existing source playbook text, an authenticated artifact, or requires human clarification. Do not guess missing semantics.

## 6. Raw-specific 64 prioritization
Rank the 64 raw-specific rows for later one-by-one review by playbook dependency criticality, environment availability, shared-fixture reuse, and reset/safety complexity. Do not resolve them.

## Outputs
- `E0C_R5_EXACT89_TEMPLATE_AUDIT.json`
- `E0C_R5_TEMPLATE_PRIORITY.json`
- `E0C_R5_REVIEW_BATCHES.json`
- `E0C_R5_HUMAN_REVIEW_SHEETS.md`
- `E0C_R5_BLOCKED31_SOURCE_DETAIL_RECOVERY.json`
- `E0C_R5_RAW_SPECIFIC64_PRIORITY.json`
- `E0C_R5_REVIEW_BATCHING_REPORT.md`

## Hard boundaries
NO human decisions, manual-row resolution, action implementation/execution, formal outcomes, PROVX detection claims, denominator/status mutation, or authority mutation.

## Terminal
```text
E0C_R5_TEMPLATE_REVIEW_BATCHING = READY_FOR_HUMAN_REVIEW | BLOCKED
SHARED_TEMPLATE_COUNT = 89
SHARED_TEMPLATE_COVERED_ROWS = 494
TEMPLATE_MEMBER_OVERLAP = 0 | <n>
TEMPLATE_MEMBER_MISSING = 0 | <n>
REVIEW_BATCH_COUNT = <n>
BLOCKED31_RECOVERY_PLAN_READY = YES | NO
RAW_SPECIFIC64_PRIORITY_READY = YES | NO
HUMAN_DECISIONS_CREATED = 0
FORMAL_EXPERIMENT_EXECUTED = NO
DENOMINATOR_CHANGE = NO
NEXT_ACTION = FRESH_REVIEW_OF_E0C_R5_TEMPLATE_REVIEW_BATCHING
STOP = true
```
