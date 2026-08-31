# EXP-E0C-R2 Adapter Contract Design Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate reproducible, non-executable adapter-family manifests and contracts for the highest-coverage R1 archetypes while conserving the exact 1,796 raw keys.

**Architecture:** A single deterministic Python builder will consume the authenticated R1 enriched JSONL, select the five requested archetype families, and derive manifests, contracts, equivalence/telemetry specifications, blocker taxonomy, coverage audit, and report. Tests will exercise the builder in memory and verify exact key conservation, schema fields, candidate/manual separation, and hard execution/PROVX boundaries.

**Tech Stack:** Python 3 standard library, `unittest`, JSON/JSONL parsing.

**Spec:** `Prompt_4_E0C_R2_High_Coverage_Adapter_Contract_Design.md`

## Global Constraints

- Frozen denominator is exactly `1796`.
- No attack execution, command implementation, formal benchmark outcome, PROVX detectability claim, authority mutation, or denominator change.
- R2 artifacts are design contracts only; contract-covered rows are not executable.
- Preserve R1 formal authorization and PROVX/result boundary values.
- Target family manifests must conserve exact R1 member keys and separate manual-design members.

### Task 1: Define R2 schemas and conservation tests

**Files:**
- Create: `test_exp_e0c_r2_adapter_contracts.py`
- Create: `build_exp_e0c_r2_adapter_contracts.py`

**Interfaces:**
- `load_r1_rows(path: Path) -> list[dict[str, Any]]`
- `build_r2_outputs(rows: list[dict[str, Any]]) -> dict[str, Any]`
- `write_outputs(output_dir: Path, outputs: Mapping[str, Any]) -> None`

- [x] **Step 1: Write failing tests** for five target family manifests, exact key/count conservation, required contract sections, blocker totals, unresolved prerequisite accounting, and terminal boundaries.
- [x] **Step 2: Run `python3 -m unittest -v test_exp_e0c_r2_adapter_contracts.py` and confirm failure because the builder/output interfaces do not exist.**
- [x] **Step 3: Implement deterministic loading, target-family selection, exact manifests, and schema-rich contracts with no execution behavior.**
- [x] **Step 4: Run the focused tests and confirm they pass.**

### Task 2: Add equivalence, telemetry, compatibility, and blocker derivation

**Files:**
- Modify: `build_exp_e0c_r2_adapter_contracts.py`
- Modify: `test_exp_e0c_r2_adapter_contracts.py`

**Interfaces:**
- `derive_manual_blockers(row: Mapping[str, Any]) -> list[str]`
- `build_defensive_equivalence_contracts(...) -> dict[str, Any]`
- `build_provx_telemetry_contracts(...) -> dict[str, Any]`

- [x] **Step 1: Extend failing tests** for mode-specific defensive equivalence, PROVX interface fields, Mininet compatibility classes, and all 589 manual rows receiving source-supported blocker labels.
- [x] **Step 2: Run the focused tests and confirm the new assertions fail.**
- [x] **Step 3: Implement conservative derivations; route ambiguous or unsupported equivalence to `MANUAL_DESIGN`; never set PROVX observations/results.**
- [x] **Step 4: Run focused tests and confirm they pass.**

### Task 3: Generate and verify all R2 artifacts

**Files:**
- Generate: `E0C_R2_ADAPTER_FAMILY_MANIFESTS.json`
- Generate: `E0C_R2_ADAPTER_CONTRACTS.json`
- Generate: `E0C_R2_DEFENSIVE_EQUIVALENCE_CONTRACTS.json`
- Generate: `E0C_R2_PROVX_TELEMETRY_CONTRACTS.json`
- Generate: `E0C_R2_MANUAL_DESIGN_BLOCKERS.json`
- Generate: `E0C_R2_COVERAGE_AUDIT.json`
- Generate: `E0C_R2_ADAPTER_DESIGN_REPORT.md`

- [x] **Step 1: Run the builder against the existing R1 JSONL and inspect terminal output.**
- [x] **Step 2: Run baseline R1/E0-C tests plus R2 tests.**
- [x] **Step 3: Verify JSON/manifest/contract counts, unique keys, blocker totals, unresolved prerequisites, and all hard-boundary values.**
- [x] **Step 4: Re-run the builder and verify deterministic output hashes.**
