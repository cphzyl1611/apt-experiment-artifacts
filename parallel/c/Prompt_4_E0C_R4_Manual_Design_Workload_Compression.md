# EXP-E0C-R4 — Exact589 Manual-Design Workload Compression

Continue from fresh-reviewed E0C-R3:
- denominator 1796
- contract-designed 1196
- manual-design 589
- blocked prerequisite 11
- overlap 0, missing 0

Goal: compress the 589 manual-design rows into the smallest defensible set of reusable human-reviewed execution-design templates. Do not automatically resolve any row and do not execute actions.

1. Extract exactly the 589 raw keys with global status MANUAL_DESIGN_REQUIRED. Require 589 unique, all from frozen 1796 authority, zero non-manual included.

2. Cluster only by mechanically available evidence:
primary archetype, OS/platform, protocol/service, privilege requirement, credential sensitivity, destructive-state risk, persistence, Windows-specific semantics, blocker taxonomy, source action type, explicit tooling/service.
No embeddings/model semantic guesses.

3. For each proposed shared template define:
- template ID/version
- exact member-key commitment
- common blockers/environment
- allowed candidate fidelity classes
- defensive-equivalence invariants
- telemetry-equivalence invariants
- PROVX process/file/socket/network surfaces
- cleanup/reset
- per-raw parameters
- raw-specific human questions
- negative cases

Template is a design aid, not authority.

4. Classify every manual row exactly:
CANDIDATE_FOR_SHARED_HUMAN_TEMPLATE
RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED
BLOCKED_NEED_MORE_SOURCE_DETAIL

5. Rank templates by raw coverage, playbook reuse, equivalence quality, environment availability, safety/reset complexity. Never scoring weight.

6. Generate one human review packet per template with exact member keys/count, representative source fields, proposed contract, unresolved questions, and:
APPROVE_TEMPLATE_FOR_MEMBER_SET
REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL
REQUEST_SPLIT_OR_MORE_EVIDENCE
No default; no actual human decision.

If a template requires guessed command semantics, credentials, target service behavior, destructive effect, or platform behavior, split/block instead.

Outputs:
E0C_R4_EXACT589_MANUAL_SET.json
E0C_R4_MANUAL_CLUSTERING_DIMENSIONS.json
E0C_R4_SHARED_MANUAL_DESIGN_TEMPLATES.json
E0C_R4_RAW_TO_TEMPLATE_MAP.jsonl
E0C_R4_MANUAL_OUTLIERS.json
E0C_R4_HUMAN_TEMPLATE_REVIEW_PACKETS.jsonl
E0C_R4_MANUAL_WORKLOAD_AUDIT.json
E0C_R4_MANUAL_DESIGN_COMPRESSION_REPORT.md

No action execution, automatic manual-row resolution, formal outcomes, PROVX detection claims, authority mutation, denominator/status mutation, or human decisions.

Terminal:
E0C_R4_MANUAL_DESIGN_COMPRESSION = READY_FOR_HUMAN_TEMPLATE_REVIEW | BLOCKED
EXACT_MANUAL_RAW_COUNT = 589
MANUAL_SET_CONSERVATION = PASS | BLOCKED
SHARED_TEMPLATE_COUNT = <n>
SHARED_TEMPLATE_COVERED_ROWS = <n>
RAW_SPECIFIC_HUMAN_DESIGN_REQUIRED = <n>
BLOCKED_NEED_MORE_SOURCE_DETAIL = <n>
HUMAN_DECISIONS_CREATED = 0
FORMAL_EXPERIMENT_EXECUTED = NO
DENOMINATOR_CHANGE = NO
NEXT_ACTION = FRESH_REVIEW_OF_E0C_R4_MANUAL_DESIGN_COMPRESSION
STOP = true
