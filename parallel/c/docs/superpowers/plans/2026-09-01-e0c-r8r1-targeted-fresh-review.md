# E0C-R8R1 Targeted Fresh Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Independently validate the completed R8R1 UNKNOWN normalization remediation without repeating Exact12 reconstruction unless authenticated non-UNKNOWN inputs drift.

**Architecture:** A read-only targeted reviewer authenticates the local R8R1 package, current remote HEAD, historical fresh-review blobs, and frozen R6/R7/R3 input commitments. It compares current corrected R8 distributions against the preserved prior independent recomputation and writes a new addendum directory only.

**Tech Stack:** Python 3, `unittest`, JSON/JSONL, SHA-256 and Git blob SHA-1 commitments, GitHub read-only APIs.

**Spec:** User-provided `E0C_R8R1_TARGETED_FRESH_REVIEW` prompt.

## Global Constraints

- Do not repeat the full 203-member reconstruction unless a substantive non-UNKNOWN input/member artifact changed.
- Do not modify the historical `E0C_R8_FRESH_INDEPENDENT_REVIEW.*` artifacts.
- Do not make decisions, create splits, mutate statuses, change denominator/binding/scoring, or push.

### Task 1: Add a failing targeted-review contract test

**Files:**
- Create: `test_exp_e0c_r8r1_targeted_fresh_review.py`

- [ ] Assert the future reviewer returns PASS with Exact12, corrected UNKNOWN audit, no split evidence, null decisions, and 59-test suite.
- [ ] Run it before the reviewer exists and record the expected import failure.

### Task 2: Implement the read-only targeted reviewer

**Files:**
- Create: `review_exp_e0c_r8r1_targeted_fresh_review.py`

- [ ] Authenticate current remote HEAD, package files, frozen input Git blobs, and historical fresh-review blobs.
- [ ] Independently check scalar/empty/all-UNKNOWN/mixed normalization semantics.
- [ ] Compare corrected outputs to the preserved prior fresh recomputation for all affected distribution fields and complexity values.
- [ ] Set escalation flags and stop if any non-UNKNOWN source/member commitment drifts.

### Task 3: Materialize and verify the addendum

**Files:**
- Create: `E0C_R8R1_TARGETED_FRESH_REVIEW/` with the six requested artifacts.

- [ ] Run targeted and available E0C tests.
- [ ] Verify boundary metadata and historical report immutability.
- [ ] Write a new Markdown addendum with terminal fields and STOP=true.
