# EXP-E0C-R4 Manual-Design Workload Compression Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compress the exact 589 R3 manual-design rows into mechanically derived shared human-review template candidates while preserving every row's authority, status, and unexecuted boundaries.

**Architecture:** A deterministic Python builder authenticates the existing R1/R2/R3 artifacts, extracts the exact R3 manual set, clusters rows by explicit source fields and blocker taxonomy, emits template contracts and review packets, and writes a workload audit/report. It never executes actions, makes human decisions, resolves statuses, or uses embeddings/semantic guesses.

**Tech Stack:** Python 3 standard library, `unittest`, JSON/JSONL, SHA-256 commitments.

**Spec:** `Prompt_4_E0C_R4_Manual_Design_Workload_Compression.md`

## Global Constraints

- Exact manual set is `589` unique raw keys from R3 `MANUAL_DESIGN_REQUIRED`.
- Cluster only by mechanically available evidence; no embeddings or semantic model guesses.
- No automatic row resolution, human decision, action execution, formal outcome, PROVX detection claim, authority mutation, denominator mutation, or status mutation.
- Every template exposes the three human decision options with no default decision.

### Task 1: Define extraction, clustering, and packet tests

**Files:**
- Create: `test_exp_e0c_r4_manual_design_compression.py`
- Create: `build_exp_e0c_r4_manual_design_compression.py`

- [x] Write failing tests for exact manual extraction, mechanical dimensions, commitments, one-row classification, packets, and terminal audit boundaries.
- [x] Run the focused test command and confirm failure before the builder exists.
- [x] Implement deterministic R1/R2/R3 authentication, evidence-only clustering, template contracts, outlier classification, and review packets.
- [x] Run focused tests and confirm they pass.

### Task 2: Generate and verify R4 artifacts

**Files:**
- Generate: `E0C_R4_EXACT589_MANUAL_SET.json`
- Generate: `E0C_R4_MANUAL_CLUSTERING_DIMENSIONS.json`
- Generate: `E0C_R4_SHARED_MANUAL_DESIGN_TEMPLATES.json`
- Generate: `E0C_R4_RAW_TO_TEMPLATE_MAP.jsonl`
- Generate: `E0C_R4_MANUAL_OUTLIERS.json`
- Generate: `E0C_R4_HUMAN_TEMPLATE_REVIEW_PACKETS.jsonl`
- Generate: `E0C_R4_MANUAL_WORKLOAD_AUDIT.json`
- Generate: `E0C_R4_MANUAL_DESIGN_COMPRESSION_REPORT.md`

- [x] Run the builder against existing R1/R2/R3 artifacts.
- [x] Run all E0-C, R1, R2, and R4 tests.
- [x] Verify exact 589-set conservation, classification sum/overlap/missing, template commitments, packet decision nulls, and unchanged R3 boundaries.
- [x] Re-run the builder and verify deterministic output hashes.

