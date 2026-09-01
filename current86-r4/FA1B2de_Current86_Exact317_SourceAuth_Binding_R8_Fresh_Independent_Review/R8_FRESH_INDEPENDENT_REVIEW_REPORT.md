# Binding R8 Fresh Independent Review

This is a new, read-only review context. It did not mutate the reviewed R8 package, select a field pointer, create a human decision, execute source-auth, run P0/P1, publish bindings, or mutate a Git ref. The independent implementation in `tools/independent_verify_r8.py` does not import the supplied R8 materializer or verifier.

## Review result

```text
BINDING_R8_FRESH_INDEPENDENT_REVIEW = BLOCKED
CURRENT_REPOSITORY_COMMIT = 2ff2b21cd313c5b91567adfe05691d3e25aabb87
R8_PACKAGE_AUTHENTICATION = BLOCKED
R7_ACTIVE_AUTHORITY_AUTHENTICATION = PASS
EXACT317_CONSERVATION = PASS
FIELD_PIN_PACKET_COUNT = 317
SINGLE_CANDIDATE_POINTER = 0
MULTIPLE_CANDIDATE_POINTERS = 317
NO_CANDIDATE_POINTER = 0
FIRST_HUMAN_REVIEW_TRANCHE_COUNT = 24
NO_PRESELECTED_POINTERS = PASS
FIELD_PINS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO
NEXT_ACTION =
REMEDIATE_R8_MATERIALIZATION
STOP = true
```

## Evidence gates

- Repository identity and exact current commit: `PASS`. Origin is `https://github.com/cphzyl1611/apt-experiment-artifacts.git`; the tracked tree resolves to the expected `2ff2b21cd313c5b91567adfe05691d3e25aabb87` and its parent is the historical stable baseline `107ef9f69a734a10b320d552cfe18a6cb9a2ac0c`. Untracked bytecode present in the checkout is recorded in the authentication JSON and does not alter the authenticated commit.
- R7 active authority: `PASS`. The committed consumer pointer, transaction `e8a0a97a33d47ac68c8ded4af1af109fa010d979acf9736fd5dffdebf96c5208`, pointer hash `02394a7fc7c5f337dfbfff521467759f80e14f8d5d27ca9e01653eec3f0d592c`, four active root IDs/hashes, Exact317 manifest, and R7 envelope were independently recomputed. The R7 package tree and shared project-authority paths are unchanged from the baseline.
- Exact317 conservation: `PASS` — 86 RAW + 231 CANDIDATE = 317, route counts 26/60/231, duplicates 0, missing 0, and cross-route substitution 0. R6 skeleton population is 317 and remains decision-null.
- Candidate packet review: `PASS`. All `317` packets were independently checked for target identity, active route, source object/hash/locator, wrapper identity/hash, RFC6901 syntax and resolution, scalar type, canonical value hash, completeness, null decisions, and blocked state. Detailed rows are in `R8_FRESH_REVIEW_CANDIDATE_RECOMPUTATION.jsonl`.
- Classification: `PASS`. Counts independently recompute to 0 SINGLE, 317 MULTIPLE, and 0 NONE; this is descriptive only and no pointer is selected.
- Presentation batches: `PASS`. The 23 batches cover indices 1–317 exactly once, preserve one governance unit per target, and carry no decisions.
- First tranche: `PASS`. It contains 24 targets in the deterministic non-empty/smallest-count/complete-evidence/target-ID order, with no semantic ranking or selection.
- Readiness bridge/boundary: `PASS`. The bridge is design-only/not executed; every unapproved target remains blocked and all downstream flags remain zero/false.
- Required clean reruns: `PASS` for the packaged R8 tests and supplied independent verifier.

## Blocking finding

`R8_PACKAGE_AUTHENTICATION = BLOCKED` because the reviewed R8 `FILE_LIST.txt` contains 11 payload paths while `SHA256SUMS.txt` contains those paths plus `FILE_LIST.txt`. All checksum bytes and all payload bytes match the expected current Git commit, but the two inventory path sets are not equal. R6/R5/R7 envelopes are internally consistent. The reviewed package was not modified to repair this mismatch.

The substantive Exact317 and field-pin evidence gates pass, but the requested terminal is blocked until the R8 producer emits a self-consistent FILE_LIST/SHA256SUMS envelope and a fresh review repeats the authentication gate.
