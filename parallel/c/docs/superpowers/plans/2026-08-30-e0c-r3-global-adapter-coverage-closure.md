# EXP-E0C-R3 Global Adapter Coverage Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconcile R2's overlapping accounting, design non-executable contracts for the remaining eight R1 archetypes, and assign every one of 1,796 raws exactly one mutually-exclusive global planning status.

**Architecture:** A deterministic Python builder consumes the existing R1 enriched JSONL and R2 JSON artifacts, authenticates their counts and commitments, adds equivalent contracts for the eight remaining families, and emits a row-level global status JSONL plus coverage, priority, reconciliation, and report artifacts. No R1 candidate-fidelity fields are overwritten.

**Tech Stack:** Python 3 standard library, `unittest`, JSON/JSONL, SHA-256 commitments.

**Spec:** `Prompt_4_E0C_R3_Global_Adapter_Coverage_Closure.md`

## Global Constraints

- Frozen archetype denominator is exactly `1796`.
- No action execution, command implementation, formal results, PROVX detection claims, authority mutation, or denominator change.
- Preserve R1 candidate fidelity separately.
- Every raw receives exactly one of `CONTRACT_DESIGNED_READY_FOR_IMPLEMENTATION_PLANNING`, `MANUAL_DESIGN_REQUIRED`, or `BLOCKED_UNRESOLVED_PREREQUISITE`.
- `GLOBAL_STATUS_OVERLAP = 0` and `GLOBAL_STATUS_MISSING = 0`.

### Task 1: Reconciliation and global-status tests

**Files:**
- Create: `test_exp_e0c_r3_global_adapter_coverage.py`
- Create: `build_exp_e0c_r3_global_adapter_coverage.py`

- [ ] Write failing tests for R1/R2 authentication, exact remaining-eight counts, R2 945/589/4 non-disjoint explanation, complete global status partition, preserved R1 candidate modes, and terminal metadata.
- [ ] Run `python3 -m unittest -v test_exp_e0c_r3_global_adapter_coverage.py` and confirm the expected missing-module failure.
- [ ] Implement R1/R2 loaders, commitment validation, reconciliation, and mutually-exclusive status assignment.
- [ ] Run focused tests and confirm they pass.

### Task 2: Remaining-family contracts and priority

**Files:**
- Modify: `build_exp_e0c_r3_global_adapter_coverage.py`
- Modify: `test_exp_e0c_r3_global_adapter_coverage.py`

- [ ] Extend tests for all eight remaining families, exact member commitments, contract layers, dependency classifications, PROVX boundaries, and implementation-priority rationale.
- [ ] Run tests to observe the new assertions fail.
- [ ] Implement conservative family contracts, dependency labels, blocker/prerequisite logic, and priority ordering.
- [ ] Run focused tests and confirm they pass.

### Task 3: Generate and verify R3 artifacts

**Files:**
- Generate: `E0C_R3_R2_ACCOUNTING_RECONCILIATION.json`
- Generate: `E0C_R3_REMAINING_8_FAMILY_CONTRACTS.json`
- Generate: `E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl`
- Generate: `E0C_R3_GLOBAL_COVERAGE_AUDIT.json`
- Generate: `E0C_R3_IMPLEMENTATION_PRIORITY.json`
- Generate: `E0C_R3_GLOBAL_ADAPTER_COVERAGE_REPORT.md`

- [ ] Run the builder from existing R1/R2 artifacts and inspect terminal output.
- [ ] Run all E0-C, R1, and R3 tests.
- [ ] Verify all 1,796 rows have one status, status counts sum to 1,796, overlap/missing are zero, and R1/PROVX boundaries are unchanged.
- [ ] Re-run the builder and verify deterministic hashes.

