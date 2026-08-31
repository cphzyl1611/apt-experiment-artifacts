# Binding R5 Wrapper Materialization

This package materializes the three explicitly approved R4 deterministic wrapper specifications and performs only a non-authoritative dry run. The RAW legacy route preserves the absence of historical producer identity; the C0 route preserves its historical evidence identity; and the scoring route does not mutate scoring authority.

- Exact317: 317 targets = 86 RAW + 231 CANDIDATE
- Dry-run route counts: RAW legacy 26/26, C0 60/60, scoring 231/231
- Union: Exact317; duplicates: 0; cross-route substitution: 0
- Output class: `CANDIDATE_WRAPPER_OBJECTS_ONLY`
- Active canonical source authority: no
- Source-auth execution: no
- Field pins: 0
- P0/P1: not executed
- Binding publication: no
- EXEC-R4/GOV-R4 mutation: no

The four files under `06_non_active_candidates/` are candidates only and are not registered or active.

## Required Terminal

```text
BINDING_R5_WRAPPER_MATERIALIZATION = PASS_READY_FOR_FRESH_REVIEW
HUMAN_APPROVAL_AUTHENTICATED = YES
TARGETS_TOTAL = 317
DRY_RUN_EXACT317_CONSERVATION = PASS
ACTIVE_SOURCE_AUTHORITY_CREATED = NO
SOURCE_AUTH_EXECUTED = NO
FIELD_PINS_CREATED = 0
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO
NEXT_ACTION = FRESH_INDEPENDENT_REVIEW_OF_BINDING_R5_WRAPPER_MATERIALIZATION
STOP = true
```
