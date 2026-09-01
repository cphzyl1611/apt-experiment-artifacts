# PROVX R4 Adapted Encoder and Training Preflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for the encoder and superpowers:verification-before-completion before the final claims. Steps use checkbox syntax for tracking.

**Goal:** Implement and verify the frozen 32-feature Track-L encoder on synthetic non-scored fixtures, validate an untrained 32D GCN interface, and produce a training-corpus/protocol preflight without training.

**Architecture:** `PROVX_R4_ENCODER_IMPLEMENTATION.py` is a dependency-light pure converter from normalized provenance records to deterministic tensors and reversible maps. Golden JSONL fixtures exercise all declared event/entity and error paths; verification hashes regenerated outputs. A separate interface check constructs an untrained GCN with `input_dim=32` and checks only tensor/device compatibility.

**Tech Stack:** Python 3.10+, standard library, NumPy, PyTorch, PyTorch Geometric where available; JSONL fixtures and SHA-256 manifests.

**Spec:** `Prompt_PROVX_R4_Adapted_Encoder_and_Training_Preflight.md`

## Global Constraints

- Frozen encoder ID is `provx-adapted-live-v1` and output dimension is 32.
- Do not alter R3 feature ordering or definitions; schema changes require a new design version and fresh review.
- Use only synthetic/benign non-scored fixtures; no FA1B2de raw/action may enter training, tuning, calibration, or fixtures.
- Do not train a detector, execute formal benchmarks, acquire raw DARPA data, execute APT actions, misuse the packaged 21-input checkpoint, or mutate authority.
- Interface validation may use random/untrained 32-input GCN weights but must not report accuracy, detection, or Phase-II results.

### Task 1: Red tests

**Files:** Create `PROVX_R4_ENCODER_TESTS.py` and `PROVX_R4_GOLDEN_FIXTURES.jsonl`.

- [ ] Define tests for entity/event coverage, unknown/missing handling, invalid/non-finite rejection, deterministic ordering, duplicate coalescing, self-loop mapping, raw-key reversibility, and repeat stability.
- [ ] Run the tests before implementation and confirm the expected import failure.

### Task 2: Pure encoder implementation

**Files:** Create `PROVX_R4_ENCODER_IMPLEMENTATION.py`.

- [ ] Implement the exact R3 32-column order, fixed transforms, canonicalization, stable node/edge ordering, duplicate/self-loop policies, and run manifest without external data access.
- [ ] Run the tests and correct implementation defects only.

### Task 3: Hashes and verification

**Files:** Create `PROVX_R4_GOLDEN_TENSOR_HASHES.json` and `PROVX_R4_ENCODER_VERIFICATION.json`.

- [ ] Regenerate every golden fixture twice in independent processes.
- [ ] Record implementation/schema hashes, canonical encoder hash, tensor hashes, and map/manifest hashes; require equality across regenerations.

### Task 4: 32D interface check

**Files:** Create `PROVX_R4_32D_MODEL_INTERFACE_CHECK.json`.

- [ ] Instantiate a new untrained `GCNConv` detector with input dimension 32.
- [ ] Run a bounded forward pass on fixture tensors and verify shapes/dtypes/device only.
- [ ] Prove the packaged 21-input checkpoint was not loaded.

### Task 5: Training preflight and protocol

**Files:** Create `PROVX_R4_TRAINING_CORPUS_PREFLIGHT.json`, `PROVX_R4_TRAINING_PROTOCOL_DESIGN.json`, and `PROVX_R4_ADAPTED_ENCODER_REPORT.md`.

- [ ] Inventory feasible non-FA1B2de sources without downloading large corpora, including official OpTC, official TC E3, reserved Mininet, benign traces, and authorized non-formal adversary/emulation traces.
- [ ] Freeze a conceptual 32-input detector training/model-selection/calibration protocol separate from Track O.
- [ ] Record terminal values and the remaining fresh-review gate.
