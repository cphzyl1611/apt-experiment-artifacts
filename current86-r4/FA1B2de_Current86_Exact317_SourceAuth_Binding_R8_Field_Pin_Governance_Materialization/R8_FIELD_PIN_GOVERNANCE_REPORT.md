# Binding R8 Exact317 Field-Pin Governance Materialization

This package is a non-authoritative, evidence-only preparation step over the active R7 source-authority route. It preserves the R7 consumer pointer and immutable roots and does not execute source-auth or choose a field pointer.

## Authenticated inputs

- R8 review commit/tree: `107ef9f69a734a10b320d552cfe18a6cb9a2ac0c` / `26b5c3a56e86fb5c11d50fc86bd99d6b940239fc`.
- R7 transaction: `e8a0a97a33d47ac68c8ded4af1af109fa010d979acf9736fd5dffdebf96c5208`; consumer pointer SHA-256: `02394a7fc7c5f337dfbfff521467759f80e14f8d5d27ca9e01653eec3f0d592c`.
- Active roots: registry `8f9596729361f8c6620c98c18344c8cf31073e35085b3eb408fc5212ebd41d6a`, corpus/schema `f88d911080e97e8e1e58010fd5e551f91127ec6b1ae77d2a3d28af07f71ef52f`, common freeze/runtime `5d868125294dcd4d5f643f2fef820b89b056925a925d0b0f98fcf7408c41009d`, EXEC-R4 `3f1f169c1ada9fbddd381727114b5b4a0a422b1bd4016c6ec5ff5b6461a02aa8`.
- Exact317 manifest: `d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac`; R6 skeletons: `d55bc015d21b3fb4a6edc7ef9aa0caf5abca1da177da2df232f1dd97bd6f8573`; count 317.

## Materialized evidence

Each packet carries the target identity and side, active wrapper rule, active source object and canonical hash, source-byte hash and exact locator, wrapper identity/hash, every scalar RFC6901 pointer permitted by the R6 design with value type/hash, and an evidence-completeness result. Classification is descriptive only. Human decisions and selected pointers remain null.

The 317 independent governance units are presented in 23 presentation-only batches. The first review tranche contains 24 targets and is ordered only by candidate-set presence, candidate count, evidence completeness, and target-ID tie break.

## Terminal

```text
BINDING_R8_FIELD_PIN_GOVERNANCE_MATERIALIZATION = READY_FOR_EXPLICIT_HUMAN_FIELD_PIN_REVIEW
ACTIVE_R7_AUTHORITY_AUTHENTICATION = PASS
EXACT317_CONSERVATION = PASS
FIELD_PIN_PACKET_COUNT = 317
SINGLE_CANDIDATE_POINTER = 0
MULTIPLE_CANDIDATE_POINTERS = 317
NO_CANDIDATE_POINTER = 0
FIRST_HUMAN_REVIEW_TRANCHE_COUNT = 24

FIELD_PINS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO

NEXT_ACTION =
FRESH_REVIEW_OF_BINDING_R8_FIELD_PIN_GOVERNANCE_MATERIALIZATION

STOP = true
```
