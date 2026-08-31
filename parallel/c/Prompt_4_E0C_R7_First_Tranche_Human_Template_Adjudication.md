# E0C-R7 — First-Tranche Human Template Adjudication

Continue from fresh-reviewed E0C-R6.

Pinned state:

EXACT_MANUAL_RAW_COUNT = 589
SHARED_TEMPLATE_COUNT = 89
SHARED_TEMPLATE_COVERED_ROWS = 494
FIRST_HUMAN_REVIEW_TRANCHE_TEMPLATE_COUNT = 12
FIRST_HUMAN_REVIEW_TRANCHE_RAW_COVERAGE = 203
RECOVERED_FROM_AUTHENTICATED_EXISTING_SOURCE = 0
NOT_PRESENT_IN_AUTHENTICATED_EXISTING_SOURCE = 31
HUMAN_DECISIONS_CREATED = 0
STATUS_MUTATIONS = 0
FORMAL_EXPERIMENT_EXECUTED = NO

Pinned GitHub commit:
`ef9cc3cf7566cbe2280c29fcc1dde958cebf12d9`

## Goal

Run the first real human template-review tranche over exactly the 12 R6-selected templates covering exactly 203 raws.

The model/agent must NOT impersonate the human reviewer.
No decision may be created without an explicit user-origin choice.

## Mandatory work

1. Authenticate exact 12 template IDs, each member-set SHA256, union raw count 203, zero overlap, and no member-set drift.
2. Confirm all members remain MANUAL_DESIGN_REQUIRED before adjudication.
3. Present one compact review table for all 12 templates with:
   - template ID
   - member count
   - playbook count
   - representative raw keys
   - archetype/platform
   - exact source evidence summary
   - proposed reusable design contract
   - defensive-equivalence requirements
   - telemetry-equivalence requirements
   - environment prerequisites
   - unresolved UNKNOWN fields
   - cleanup/reset obligations
   - negative cases
   - member-set SHA256
4. Allowed human actions per template only:
   - APPROVE_TEMPLATE_FOR_MEMBER_SET
   - REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL
   - REQUEST_SPLIT_OR_MORE_EVIDENCE
5. No default, timeout, or model-created decision.
6. If the human has not supplied decisions, STOP at the review gate.
7. For every later explicit human decision, record human origin, exact template ID, exact member-set SHA256, decision, evidence packet hash, and no member expansion.
8. Approval means only the shared manual-design contract is accepted for the exact member set. It does NOT authorize action execution or formal experiment.
9. Rejection keeps all members manual.
10. Split/more-evidence keeps all members manual and creates a bounded follow-up request.
11. Do not force the 31 missing-source-detail rows into these templates.

## Outputs before human decisions

- E0C_R7_FIRST_TRANCHE_INPUT_AUTHENTICATION.json
- E0C_R7_FIRST_TRANCHE_REVIEW_TABLE.md
- E0C_R7_FIRST_TRANCHE_DECISION_PACKET.json

## Outputs after explicit decisions, if later supplied

- E0C_R7_HUMAN_TEMPLATE_DECISIONS.jsonl
- E0C_R7_APPROVED_TEMPLATE_MEMBER_MAP.json
- E0C_R7_REJECTED_TEMPLATE_MAP.json
- E0C_R7_SPLIT_OR_MORE_EVIDENCE_QUEUE.json
- E0C_R7_FIRST_TRANCHE_CONSERVATION.json
- E0C_R7_FIRST_TRANCHE_ADJUDICATION_REPORT.md

## Terminal before human decisions

E0C_R7_FIRST_TRANCHE_HUMAN_REVIEW =
AWAITING_EXPLICIT_HUMAN_TEMPLATE_DECISIONS | BLOCKED

TEMPLATE_COUNT = 12
RAW_COVERAGE = 203
HUMAN_DECISIONS_CREATED = 0
STATUS_MUTATIONS = 0
FORMAL_EXPERIMENT_EXECUTED = NO

NEXT_ACTION = HUMAN_REVIEW_OF_EXACT12_TEMPLATE_PACKETS
STOP = true
