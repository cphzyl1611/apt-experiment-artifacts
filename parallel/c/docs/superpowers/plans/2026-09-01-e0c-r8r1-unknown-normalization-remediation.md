# E0C-R8R1 UNKNOWN Normalization Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Correct R8 UNKNOWN collection canonicalization, rebuild outputs, and produce an independently verified remediation package without mutating decisions or exact12 membership.

**Architecture:** Keep the fix confined to the R8 builder's value canonicalization/accounting helpers. Add a focused regression test and a separate remediation verifier that authenticates the materialized inputs, recomputes corrected heterogeneity and complexity independently, audits non-regression invariants, and writes only the requested package.

**Tech Stack:** Python 3, `unittest`, JSON/JSONL artifacts, SHA-256 commitments, subprocess test execution.

**Spec:** `Prompt_4_E0C_R8_Unknown_Normalization_Targeted_Remediation` (user-provided task in this session)

## Global Constraints

- Do not push while Binding is active.
- Do not modify the historical `E0C_R8_FRESH_INDEPENDENT_REVIEW.*` report.
- Do not alter human decisions, membership, statuses, denominator, binding, scoring, or execute actions.
- Preserve exact12 / 203 raws / overlap 0 / drift 0 / blocked31 overlap 0.

### Task 1: Reproduce the Defect With a Red Test

**Files:**
- Create: `test_exp_e0c_r8r1_unknown_normalization.py`
- Create: `E0C_R8R1_UNKNOWN_NORMALIZATION_REMEDIATION/` (later)

- [ ] Add tests proving scalar UNKNOWN, empty collections, all-UNKNOWN collections, and conservative mixed collection behavior. The all-UNKNOWN assertion must fail against the current builder.
- [ ] Run the focused test and record the expected failure before editing production code.

### Task 2: Patch Canonicalization/Accounting

**Files:**
- Modify: `build_exp_e0c_r8_structured_human_review_support.py` `_json_value` / `_is_unknown`

- [ ] Normalize all-UNKNOWN collections to the scalar UNKNOWN sentinel.
- [ ] Make UNKNOWN accounting recognize canonical serialized collections containing UNKNOWN members, preserving the serialized source evidence for mixed collections.
- [ ] Keep candidate split eligibility restricted to at least two known non-empty groups with zero UNKNOWN members.
- [ ] Run the focused regression and existing builder tests.

### Task 3: Deterministic Rebuild and Independent Verification

**Files:**
- Create: `remediate_exp_e0c_r8_unknown_normalization.py`
- Create: `E0C_R8R1_UNKNOWN_NORMALIZATION_REMEDIATION/E0C_R8R1_*.json`
- Create: `E0C_R8R1_UNKNOWN_NORMALIZATION_REMEDIATION/E0C_R8R1_REMEDIATION_REPORT.md`

- [ ] Authenticate remote main and the relevant local input/output hashes plus historical defect evidence.
- [ ] Rebuild the seven R8 output files deterministically using the corrected builder.
- [ ] Recompute corrected heterogeneity and complexity with independent logic and compare all fields, counts, fractions, and commitments.
- [ ] Audit exact12, null decisions, no mutations, no split evidence, and forbidden inference.
- [ ] Run the full available E0C suite plus the targeted regression and emit test results.

### Task 4: Final Verification

- [ ] Confirm historical fresh-review files are byte-for-byte unchanged.
- [ ] Confirm no push command was executed and report `PASS_READY_FOR_TARGETED_FRESH_REVIEW` only with fresh test evidence.
