# E0C-R8 — Exact12 Structured Cohesion and Candidate-Split Evidence for Human Review

Continue the existing E0C session.

Pinned latest fixed commit:
`107ef9f69a734a10b320d552cfe18a6cb9a2ac0c`

Pinned R7 state:
- first tranche templates = exactly 12
- exact raw coverage = 203
- all members remain MANUAL_DESIGN_REQUIRED
- human decisions created = 0
- status mutations = 0
- blocked31 overlap = 0

## Goal

Improve HUMAN review quality for exact12.

Do not approve, reject, or split any template.

Perform only an evidence-only structured cohesion / heterogeneity audit and
prepare candidate split evidence where exact authenticated structured fields justify it.

## Requirements

1. Authenticate exact 12 template IDs, member-set SHA256s, union=203,
   no overlap, no drift, all member statuses still MANUAL_DESIGN_REQUIRED.
2. Use only authenticated structured evidence from R4/R5/R6/R7.
3. For every template compute distinct values / coverage for fields such as:
   - source action type
   - OS/platform
   - explicit protocol/service
   - telemetry surface flags
   - host-process/file/socket/network requirements
   - destructive-state flag only if explicitly recorded
   - reset/safety complexity
   - environment blocker
   - explicit required protocol/service
   - source-detail completeness
   - controlled-environment feasibility.
4. Do NOT derive semantic categories from embeddings, LLM interpretation of
   free text, nearest-neighbor similarity, or undocumented ATT&CK guesses.
5. Produce structured heterogeneity matrix:
   member count, distinct values per field, UNKNOWN burden,
   members per value, exact hashes.
6. Deterministic review-complexity metrics are allowed, but they are review aids,
   not APPROVE/REJECT recommendations.
7. A candidate split may be presented ONLY when an exact structured field
   creates >=2 non-empty member groups.
8. For each candidate split record:
   split_basis_field, exact values, exact member keys/group hashes,
   union conservation, overlap=0, status=EVIDENCE_ONLY_NOT_APPLIED.
9. If no structured split evidence exists:
   NO_STRUCTURED_SPLIT_EVIDENCE.
10. Produce compact human decision support sheets for all 12:
    strongest cohesion evidence, strongest structured heterogeneity evidence,
    UNKNOWN burden, candidate splits, consequences of keeping/splitting,
    representative source evidence.
11. Allowed human actions remain exactly:
    APPROVE_TEMPLATE_FOR_MEMBER_SET
    REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL
    REQUEST_SPLIT_OR_MORE_EVIDENCE
    Decision remains null.
12. Do not change member sets, statuses, authority, implementation, execution or outcomes.

## Outputs

- E0C_R8_INPUT_AUTHENTICATION.json
- E0C_R8_EXACT12_STRUCTURED_HETEROGENEITY.json
- E0C_R8_EXACT12_CANDIDATE_SPLIT_EVIDENCE.jsonl
- E0C_R8_EXACT12_REVIEW_COMPLEXITY.json
- E0C_R8_HUMAN_DECISION_SUPPORT_SHEETS.md
- E0C_R8_HUMAN_DECISION_PACKET.json
- E0C_R8_STRUCTURED_COHESION_REVIEW_REPORT.md

## Hard boundaries

NO autonomous human decisions.
NO applied split.
NO status mutation.
NO action implementation/execution.
NO formal experiment.
NO denominator change.
NO binding/scoring mutation.

## Terminal

E0C_R8_STRUCTURED_HUMAN_REVIEW_SUPPORT =
READY_FOR_EXPLICIT_HUMAN_TEMPLATE_DECISIONS | BLOCKED

EXACT12_AUTHENTICATION = PASS | BLOCKED
TEMPLATE_COUNT = 12
RAW_COVERAGE = 203

TEMPLATES_WITH_STRUCTURED_SPLIT_EVIDENCE = <n>
TEMPLATES_WITH_NO_STRUCTURED_SPLIT_EVIDENCE = <n>

HUMAN_DECISIONS_CREATED = 0
APPLIED_SPLITS = 0
STATUS_MUTATIONS = 0
FORMAL_EXPERIMENT_EXECUTED = NO

NEXT_ACTION =
FRESH_REVIEW_OF_E0C_R8_STRUCTURED_HUMAN_REVIEW_SUPPORT

STOP = true
