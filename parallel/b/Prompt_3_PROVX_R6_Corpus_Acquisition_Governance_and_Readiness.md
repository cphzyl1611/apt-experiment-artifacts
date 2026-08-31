# PROVX-R6 — Track-L Corpus Acquisition Governance and Readiness

Continue from fresh-reviewed PROVX-R5.

Pinned state:
TRACK_L_ENCODER = provx-adapted-live-v1
TRACK_L_DIMENSION = 32
STAGED_CORPUS_STRATEGY = FROZEN
SPLIT_PROTOCOL = FROZEN
TRAINING_SEARCH_POLICY = FROZEN
CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
FORMAL_EXPERIMENT_EXECUTED = NO

Pinned GitHub commit:
`ef9cc3cf7566cbe2280c29fcc1dde958cebf12d9`

## Goal

Materialize an exact, human-reviewable acquisition plan and release contract for Track-L training data.

Do NOT download external datasets.
Do NOT train.
Do NOT execute FA1B2de actions.

## Mandatory work

1. Authenticate all R5 corpus/split/leakage/search/release-gate artifacts and R4 encoder identities.
2. Preserve local-first sequence:
   - Stage A: reserved non-scored Mininet/benign traces for adapter round-trip only; blocked until Mininet E1C passes.
   - Stage B: controlled benign background, at least 24 whole run groups.
   - Stage C: positive/adversary source from authorized non-FA1B2de emulation, with bounded OpTC/TC-E3 as predeclared fallback/diversity sources.
3. No formal 1796 FA1B2de action may enter training/tuning/calibration.
4. Build exact pre-acquisition manifest schemas for bounded OpTC and TC-E3:
   - official source URL/revision
   - deterministic group selection
   - expected provider object identity
   - checksum method
   - size caps
   - target group count
   - label expectations
   - release/terms evidence
   - stop conditions
5. Unknown provider checksums/object IDs remain null and block actual acquisition.
6. Design Stage-B benign-generation contract with workload families, fixed seeds, run durations, process/file/socket coverage, loss threshold, and raw→normalized→graph→feature hash chain.
7. Prepare Stage-C decision alternatives:
   OPTION_A_AUTHORIZED_NON_FA1B2DE_EMULATION
   OPTION_B_BOUNDED_OPTC_SUBSET
   OPTION_C_BOUNDED_TC_E3_SUBSET
   OPTION_D_COMBINATION_WITH_FIXED_CAPS
8. For each alternative record scientific value, preprocessing/storage burden, label quality, leakage risk, compatibility risk, and Mininet dependency.
9. Create a human acquisition decision packet with only:
   APPROVE_BOUNDED_TRAINING_CORPUS_ACQUISITION
   REJECT_CORPUS_ROUTE
   REQUEST_SMALLER_OR_DIFFERENT_SUBSET
   Decision must remain null.
10. Approval of acquisition must not imply training authorization.
11. Keep acquisition/training release gates separate.

## Outputs

- PROVX_R6_INPUT_AUTHENTICATION.json
- PROVX_R6_STAGE_A_LOCAL_VALIDATION_DEPENDENCY.json
- PROVX_R6_STAGE_B_BENIGN_GENERATION_CONTRACT.json
- PROVX_R6_STAGE_C_POSITIVE_CORPUS_OPTIONS.json
- PROVX_R6_OPTC_PRE_ACQUISITION_MANIFEST_SCHEMA.json
- PROVX_R6_TC_E3_PRE_ACQUISITION_MANIFEST_SCHEMA.json
- PROVX_R6_ACQUISITION_DECISION_PACKET.json
- PROVX_R6_ACQUISITION_AND_TRAINING_RELEASE_GATES.json
- PROVX_R6_CORPUS_ACQUISITION_GOVERNANCE_REPORT.md

## Terminal

PROVX_R6_CORPUS_ACQUISITION_GOVERNANCE =
READY_FOR_EXPLICIT_HUMAN_ACQUISITION_REVIEW | BLOCKED

R5_INPUT_AUTHENTICATION = PASS | BLOCKED
STAGE_A_DEPENDENCY = WAIT_MININET_E1C | READY
STAGE_B_GENERATION_CONTRACT = FROZEN | BLOCKED
STAGE_C_OPTIONS = FROZEN | BLOCKED

CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
FORMAL_EXPERIMENT_EXECUTED = NO

NEXT_ACTION =
FRESH_REVIEW_OF_PROVX_R6_CORPUS_ACQUISITION_GOVERNANCE

STOP = true
