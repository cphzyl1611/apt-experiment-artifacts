# PROVX-R4 — Adapted Live Encoder Implementation and Training-Corpus Preflight

Continue from fresh-reviewed PROVX-R3.

Frozen methodology:
```text
TRACK_O = EXACT_OFFICIAL_ARTIFACT_REPRODUCTION_BASELINE
TRACK_L = PROVX_ADAPTED_LIVE_DEPLOYMENT
OFFICIAL_21_FEATURE_VOCABULARY = NOT_AVAILABLE
PACKAGED_CHECKPOINT_DIRECT_LIVE_MININET_USE = NOT_VALIDATED
TRACK_L_ENCODER_ID = provx-adapted-live-v1
TRACK_L_OUTPUT_DIMENSION = 32
PRIMARY_PHASE2_SEED = 314159
```

## Goal
Implement and verify the versioned 32-feature Track-L encoder against non-scored fixtures, and perform a training-corpus feasibility/preflight. Do not train a detector yet.

## 1. Freeze R3 schema
Authenticate `PROVX_R3_ADAPTED_LIVE_FEATURE_SCHEMA.json`, encoder SHA256, train/eval separation contract, seed policy, and R2 structural graph contract. Do not alter the 32-feature ordering/definitions during this task. Any schema change requires a new design version and fresh review.

## 2. TDD encoder implementation
Implement a pure deterministic converter from normalized provenance records to `x` float32 `[N,32]`, `edge_index` int64 `[2,E]`, `node_map`, `edge_map`, `normalization_map`, and run manifest.

Use only synthetic/benign non-scored fixture records. Tests must cover process/file/socket/other nodes, all declared event classes, unknown handling, missing optional fields, invalid/non-finite rejection, deterministic node/edge ordering, duplicate coalescing, self-loop policy, raw-key reversibility, and repeat generation stability. No formal benchmark raw may be used as a fixture.

## 3. Feature identity verification
Compute implementation SHA256, schema SHA256, canonical encoder identity, and golden-fixture tensor hashes. Require two independent regenerations to match.

## 4. Graph-interface compatibility
Using a new untrained GCN model configured for `input_dim=32`, verify tensor/device/dtype compatibility only. A bounded forward pass with random/untrained weights is allowed for interface validation. Do not report detector accuracy/detection/Phase-II results. Do not load the packaged 21-input checkpoint into the 32-input model.

## 5. Training-corpus preflight
Without downloading a large corpus unless already local, inventory feasible non-FA1B2de training sources, including official OpTC, DARPA TC E3, reserved non-scored Mininet traces, separately generated benign traces, and separately authorized non-FA1B2de adversary/emulation traces.

For each record: provenance/event-schema compatibility with the 32-feature encoder; preprocessing burden; download/storage size if known; labels; split feasibility; leakage risk; licensing/access constraints. No 1796 benchmark raw/action may enter training/tuning/calibration.

## 6. Training protocol design
Design but do not execute detector architecture for 32 inputs, loss/optimizer candidates, model-selection metric, grouped train/validation split, class imbalance handling, fixed seeds, checkpoint identity, early stopping if any, calibration policy, and frozen final-test boundary. Keep Track O parameters separate.

## Outputs
- `PROVX_R4_ENCODER_IMPLEMENTATION.py`
- `PROVX_R4_ENCODER_TESTS.py`
- `PROVX_R4_GOLDEN_FIXTURES.jsonl`
- `PROVX_R4_GOLDEN_TENSOR_HASHES.json`
- `PROVX_R4_ENCODER_VERIFICATION.json`
- `PROVX_R4_32D_MODEL_INTERFACE_CHECK.json`
- `PROVX_R4_TRAINING_CORPUS_PREFLIGHT.json`
- `PROVX_R4_TRAINING_PROTOCOL_DESIGN.json`
- `PROVX_R4_ADAPTED_ENCODER_REPORT.md`

## Hard boundaries
NO detector training, formal 1796 benchmark, benchmark leakage, packaged checkpoint misuse, APT action execution, or authority mutation.

## Terminal
```text
PROVX_R4_ADAPTED_ENCODER = PASS_READY_FOR_TRAINING_REVIEW | BLOCKED
ENCODER_SCHEMA_ID = provx-adapted-live-v1
ENCODER_DIMENSION = 32
GOLDEN_FIXTURE_DETERMINISM = PASS | BLOCKED
MODEL_INTERFACE_32D = PASS | BLOCKED
TRAINING_CORPUS_ROUTE = READY_FOR_SELECTION | BLOCKED
DETECTOR_TRAINED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_PROVX_R4_ADAPTED_ENCODER_AND_TRAINING_PREFLIGHT
STOP = true
```
