# PROVX R6 Corpus Acquisition Governance and Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Materialize an exact, human-reviewable Track-L acquisition plan and release contract without downloading external corpora, training, or executing formal actions.

**Architecture:** Authenticate the frozen R5 contracts and R4 encoder identities, then keep the local-first Stage A/B/C route explicit. Define bounded provider-manifest schemas for OpTC and TC E3, a fixed benign-generation contract, positive-source alternatives, and independent acquisition/training gates. Finish with a governance report and fresh cross-file verification.

**Tech Stack:** JSON/Markdown contracts, SHA-256, canonical JSON identities, official repository metadata already authenticated in R5, read-only HTTP metadata checks.

**Spec:** `Prompt_3_PROVX_R6_Corpus_Acquisition_Governance_and_Readiness.md`

## Global Constraints

- Track-L encoder remains `provx-adapted-live-v1`, dimension 32; R5 staged strategy, split protocol, and search policy remain frozen.
- Do not download external datasets, train a detector, execute FA1B2de actions, use the 53 playbooks/1796 raw actions for training/tuning/calibration, or mutate authority.
- Stage A is reserved non-scored Mininet/benign round-trip validation and remains blocked until Mininet E1C passes.
- Stage B requires at least 24 whole run groups with fixed seeds, workload diversity, coverage, loss threshold, and raw→normalized→graph→feature hashes.
- Stage C alternatives are limited to authorized non-FA1B2de emulation, bounded OpTC, bounded TC E3, or a fixed-cap combination.
- Unknown provider object IDs/checksums remain null and block acquisition; acquisition approval never authorizes training.
- Primary Phase-II seed `314159` remains separate from training seeds.

### Task 1: Authenticate R5/R4 inputs

**Files:** Create `PROVX_R6_INPUT_AUTHENTICATION.json`.

- [ ] Hash all R5 outputs and required R4 identity artifacts; record pinned commit `ef9cc3cf7566cbe2280c29fcc1dde958cebf12d9` as review authority and compare available remote bytes read-only.

### Task 2: Freeze local-first dependencies and generation

**Files:** Create `PROVX_R6_STAGE_A_LOCAL_VALIDATION_DEPENDENCY.json`, `PROVX_R6_STAGE_B_BENIGN_GENERATION_CONTRACT.json`.

- [ ] Encode Stage A E1C dependency and explicit smoke-only boundary.
- [ ] Encode Stage B workload families, fixed generation seeds, run duration/count, process/file/socket coverage, loss threshold, manifests, and hash-chain requirements.

### Task 3: Freeze positive-source options and provider manifest schemas

**Files:** Create `PROVX_R6_STAGE_C_POSITIVE_CORPUS_OPTIONS.json`, `PROVX_R6_OPTC_PRE_ACQUISITION_MANIFEST_SCHEMA.json`, `PROVX_R6_TC_E3_PRE_ACQUISITION_MANIFEST_SCHEMA.json`.

- [ ] Define exactly four Stage-C alternatives with scientific value, burden, label quality, leakage/compatibility risk, and Mininet dependency.
- [ ] Define pre-acquisition schemas with URLs/revisions, deterministic selection, expected provider object identity/checksum nulls, caps, target groups, labels/terms, normalization, and stop conditions.

### Task 4: Freeze decisions and independent gates

**Files:** Create `PROVX_R6_ACQUISITION_DECISION_PACKET.json`, `PROVX_R6_ACQUISITION_AND_TRAINING_RELEASE_GATES.json`.

- [ ] Offer only the three permitted human acquisition decisions with null decision state.
- [ ] Keep acquisition, training, and formal-evaluation gates independent and closed.

### Task 5: Report and verify

**Files:** Create `PROVX_R6_CORPUS_ACQUISITION_GOVERNANCE_REPORT.md`.

- [ ] Include the required terminal block and evidence summary.
- [ ] Parse JSON, validate hashes and cross-file invariants, scan for forbidden true/yes states, and rerun inherited R4 tests before claiming completion.
