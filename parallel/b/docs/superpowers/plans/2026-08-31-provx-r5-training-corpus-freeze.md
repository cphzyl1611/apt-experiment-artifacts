# PROVX R5 Training Corpus Freeze Design Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:verification-before-completion before reporting the freeze outcome. Steps use checkbox syntax for tracking.

**Goal:** Select and freeze a defensible, bounded Track-L corpus acquisition, split, leakage-control, and training-search strategy without acquiring data or training.

**Architecture:** Authenticate the frozen R3/R4 contracts, then separate corpus roles into Stage A collector validation, Stage B controlled benign training, and Stage C positive/adversary training. Express group assignment through deterministic pre-acquisition hash rules, keep labels outside the encoder, bound official-source subsets, and require distinct human acquisition and training release gates.

**Tech Stack:** JSON and Markdown contracts, SHA-256, official GitHub/DARPA dataset metadata, deterministic canonical-JSON identities.

**Spec:** `Prompt_3_PROVX_R5_Training_Corpus_Selection_and_Freeze_Design.md`

## Global Constraints

- Track L encoder is `provx-adapted-live-v1`, dimension 32; do not edit the R3 schema or R4 encoder.
- Do not download large external data, train a detector, execute FA1B2de actions, use the 1796 benchmark for fitting/tuning/calibration, load the packaged 21D checkpoint, or mutate authority.
- Primary Phase-II seed remains `314159` and is separate from training seeds.
- External corpus acquisition requires a later human choice among the three prompt-authorized decisions; no approval occurs in R5.
- Detector training requires a separate later release after corpus hashes, split manifest, encoder compatibility, contamination/class audits, and train/eval exclusion checks.

### Task 1: Input authentication

**Files:** Create `PROVX_R5_INPUT_AUTHENTICATION.json`.

- [ ] Recompute hashes for the R3 schema/separation/seed contracts and all required R4 implementation/verification artifacts.
- [ ] Record the pinned review commit `90513ab76a2d392398fefd0456ad53a4660a3e8a` as prompt authority, without inventing a local Git association.

### Task 2: Corpus route and bounded official subsets

**Files:** Create `PROVX_R5_STAGED_TRAINING_CORPUS_STRATEGY.json` and `PROVX_R5_OFFICIAL_CORPUS_SUBSET_ACQUISITION_DESIGN.json`.

- [ ] Freeze Stage A reserved collector validation, Stage B controlled benign traces, and Stage C authorized positive traces plus a bounded official subset fallback.
- [ ] Pin official URLs/revisions, host/day/run selection criteria, checksum methods, access/release terms, label availability, and schema-normalization requirements without downloading data.

### Task 3: Splits and contamination

**Files:** Create `PROVX_R5_TRAIN_VALIDATION_SPLIT_CONTRACT.json` and `PROVX_R5_LABEL_LEAKAGE_AND_CONTAMINATION_CONTRACT.json`.

- [ ] Define source-specific group IDs and deterministic pre-acquisition assignment rules.
- [ ] Freeze exclusions, duplicate/cross-group detection, path/host de-identification, label separation, and explicit FA1B2de denial.

### Task 4: Search policy and release gates

**Files:** Create `PROVX_R5_TRAINING_SEARCH_POLICY.json`, `PROVX_R5_CORPUS_ACQUISITION_DECISION_PACKET.json`, and `PROVX_R5_TRAINING_RELEASE_GATES.json`.

- [ ] Freeze a bounded architecture/optimizer/loss/LR/epoch/seed grid and validation-only selection/calibration rules.
- [ ] Define the later human corpus decision packet and separate training release gate.

### Task 5: Report and verification

**Files:** Create `PROVX_R5_TRAINING_CORPUS_FREEZE_REPORT.md`.

- [ ] Write the terminal block and evidence summary.
- [ ] Parse every JSON, validate referenced hashes and cross-file values, scan for contradictory terminal values, and confirm no corpus/training/formal execution occurred.
