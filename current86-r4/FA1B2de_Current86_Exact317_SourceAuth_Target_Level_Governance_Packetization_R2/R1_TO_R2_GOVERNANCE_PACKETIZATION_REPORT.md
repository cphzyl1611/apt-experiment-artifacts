# Exact317 Target-Level Governance Packetization R2

Status: design/preparation only. The R1 group packets were replaced by one
unified target packet per manifest target, with sequential Stage A admission and
gated Stage B field pin. No human decision, source fact, binding, or authority
root was created.

## Frozen conservation

- Targets: **317** (RAW 86, CANDIDATE 231)
- Manifest SHA256: `d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac`
- Target IDs and manifest order are copied byte-for-byte from EXEC-R4.

## Readiness

Every target has mechanically located source rows and a parsed-object hash. The
rows are authenticated only for their existing RAW/scoring/evidence classes.
No canonical source manifest entry, provenance identity, pinned identity, or
canonical candidate object ID is available. Therefore every Stage A record is
`ADMISSION_BLOCKED_MISSING_PROVENANCE` / `ADMISSION_NOT_READY_MISSING_PROVENANCE`.
Stage B is disabled for all targets and exposes no pointer or semantics action.

Scalar RFC6901 leaves are enumerated in the inventory as
`NON_AUTHORITATIVE_EVIDENCE_ONLY`; no leaf is ranked or selected.

## Counts

```text
TARGETS_TOTAL = 317
ADMISSION_HUMAN_READY = 0
ADMISSION_BLOCKED_NOT_DECISION_READY = 317
FIELD_PIN_HUMAN_READY_PRE_ADMISSION = 0
FIELD_PIN_BLOCKED_PENDING_ADMISSION = 317
SCALAR_LEAF_INVENTORY_AVAILABLE = 317
SCALAR_LEAF_TOTAL = 7911
SEMANTICS_CHOICE_AVAILABLE = 0
SEMANTICS_SELECTION_REQUIRES_HUMAN = 317
HUMAN_DECISIONS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
BINDING_PUBLICATION = NO
```

The future workload is 317 Stage A admissions and, only after approval, 317
Stage B field pins. These are obligations, not currently actionable decisions.

## Terminal

```text
TARGET_LEVEL_GOVERNANCE_PACKETIZATION_R2 = READY_FOR_FRESH_REVIEW
TARGETS_TOTAL = 317
TARGET_CONSERVATION = PASS
ADMISSION_HUMAN_READY = 0
ADMISSION_BLOCKED_NOT_DECISION_READY = 317
FIELD_PIN_BLOCKED_PENDING_ADMISSION = 317
HUMAN_DECISIONS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO
NEXT_ACTION = FRESH_INDEPENDENT_REVIEW_OF_TARGET_LEVEL_GOVERNANCE_PACKETIZATION_R2
STOP = true
```
