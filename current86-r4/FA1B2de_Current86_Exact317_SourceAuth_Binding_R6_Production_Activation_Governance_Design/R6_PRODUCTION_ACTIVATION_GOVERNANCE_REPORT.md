# Binding R6 Production Activation Governance Design

This package is a design-only, hash-bound production source-authority activation transaction. It authenticates the pinned R5 package and exact317, but it does not activate source authority, execute source-auth, select or pin fields, run P0/P1, publish bindings, mutate scoring/binding authority, modify GOV-R4/EXEC-R4, or mutate Git refs.

## Authenticated inputs

- R5 review commit: `90513ab76a2d392398fefd0456ad53a4660a3e8a`; tree: `fc67b7dcc66284ea2b8be4bb52d2fc3f3d1ebef5`.
- R5 package envelope: `5f1746499c2ca5ba966b3f716e6b8ca87844cf4cd0a1316ec215b25cc092fdc1`; all 31 committed files match the review commit.
- Exact317 manifest: `d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac`; 86 RAW + 231 CANDIDATE = 317.
- R4 wrapper rules: RAW 26, C0 60, scoring 231; all approved rule IDs are exact.
- R5 dry-run: union `Exact317`, duplicates 0, cross-route substitution 0, candidate-only objects.

## Activation design

The transaction is `e8a0a97a33d47ac68c8ded4af1af109fa010d979acf9736fd5dffdebf96c5208`. It stages four immutable candidate roots (registry, corpus/schema rules, common-input freeze/runtime whitelist additions, and EXEC-R4 dispatch integration), verifies their exact content hashes under an activation lock, then atomically replaces one consumer pointer. Production sees either the complete pre-state or complete post-state; partial roots are never visible. Any failed precondition yields `FAIL_CLOSED_NO_ACTIVATION`. Rollback before commit leaves the pre-state untouched; after commit, rollback requires a separately reviewed compensating transaction.

The human activation decision remains null in `R6_HUMAN_ACTIVATION_DECISION_PACKET.json`; prior R5 wrapper approval is not activation approval.

## Field-pin bridge

`R6_EXACT317_FIELD_PIN_PACKET_SKELETONS.jsonl` contains exactly 317 evidence-only packet skeletons. Each retains its target ID, source side, wrapper rule, candidate wrapper object ID, exact locator, and available scalar leaves. No canonical pointer or field is selected. The only future human actions are `APPROVE_EXACT_FIELD_PIN`, `REJECT_FIELD_CANDIDATES_KEEP_BLOCKED`, and `REQUEST_MORE_EVIDENCE`.

## Current boundary

- Active source authority: no
- Source-auth executed: no
- Field pins: 0
- P0/P1: not executed
- Binding publication: no
- GOV-R4/EXEC-R4 and Git refs: unchanged

## Required terminal

```text
BINDING_R6_PRODUCTION_ACTIVATION_GOVERNANCE_DESIGN = READY_FOR_EXPLICIT_HUMAN_ACTIVATION_REVIEW
R5_INPUT_AUTHENTICATION = PASS
EXACT317_CONSERVATION = PASS
ACTIVATION_TRANSACTION_MATERIALIZED = DESIGN_ONLY
FIELD_PIN_PACKET_SKELETON_COUNT = 317

ACTIVE_SOURCE_AUTHORITY_CREATED = NO
SOURCE_AUTH_EXECUTED = NO
FIELD_PINS_CREATED = 0
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO

NEXT_ACTION = FRESH_INDEPENDENT_REVIEW_OF_BINDING_R6_PRODUCTION_ACTIVATION_GOVERNANCE_DESIGN
STOP = true
```
