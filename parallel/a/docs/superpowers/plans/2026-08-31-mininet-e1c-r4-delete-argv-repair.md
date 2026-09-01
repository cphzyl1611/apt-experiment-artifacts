# Mininet E1C-R4 Delete argv Repair and Smoke Preparation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare a new R4 harness that repairs the R3 delete-argv defect, preserves bounded audit/remediation behavior, and stops before privileged execution.

**Architecture:** R4 copies the validated R3 bounded collector into a fresh run directory, fixes mutation argv construction at one boundary, and adds explicit CLI verdict exit mapping. The existing recursive JSON-safe evidence policy, exact residual classification, fsync journal, historical-baseline gate, gated Mininet smoke, and cleanup checks remain intact.

**Tech Stack:** Python 3 standard library, auditctl/ausearch, Mininet/OVS, unittest, py_compile, AST/static checks.

**Spec:** `Prompt_2_MININET_E1C_R4_Delete_Argv_Defect_Fix_and_Preparation.md`

## Global Constraints

- Do not execute R1/R2/R3/R4 privileged harnesses, sudo, APT, PROVX, formal scoring, `mn -c`, or broad audit deletion.
- Never edit persistent audit rule files, attach NAT/external links, or treat pre-existing OVS daemons as run-owned.
- Use a brand-new `e1c-r4-run-<UTC>` directory and preserve all earlier runs.
- Delete only exact proven prior-run rules and journal each mutation before/after with fsync.
- Require the historical empty baseline hash before Mininet and after cleanup.
- Missing audit classes remain explicit; no strace/tcpdump inference.

### Task 1: R3 delete argv defect RED

**Files:**
- Create: `e1c-r4-run-<UTC>/test_e1c_r4_harness.py`
- Create: `e1c-r4-run-<UTC>/r3_delete_argv_red.txt`

- [ ] Write a focused test invoking the unchanged R3 `mutation()` with a fake runner that asserts argv[0] is `/usr/sbin/auditctl`.
- [ ] Run it and record the expected `FileNotFoundError`/argv failure before any R4 production edit.

### Task 2: R4 harness repair and tests

**Files:**
- Create: `e1c-r4-run-<UTC>/mininet_e1c_r4_delete_argv_fixed_smoke.py`
- Modify: `e1c-r4-run-<UTC>/test_e1c_r4_harness.py`

- [ ] Add a mutation argv builder guaranteeing executable plus `-a`/`-d` for pid, ppid, dir, socket, R1 residual, and prior-run rules.
- [ ] Preserve R3 recursive JSON-safe byte encoding, hashes, atomic persistence, fsync journal, exact classification, baseline gate, bounded smoke, and cleanup.
- [ ] Add CLI verdict mapping: PASS=0, PARTIAL=3, BLOCKED=2, unexpected exception=1.
- [ ] Run all R4 tests and py_compile.

### Task 3: Pre-run artifacts and static gate

**Files:**
- Create: `MININET_E1C_R4_LINEAGE.json`
- Create: `MININET_E1C_R4_STATIC_AUDIT.json`
- Create: `MININET_E1C_R4_PRE_RUN_CONTRACT.json`

- [ ] Pin R1/R2/R3 hashes and R3 failure evidence without overwriting earlier artifacts.
- [ ] Record RED reproduction, final tests, CLI exit tests, py_compile, and static boundary results.
- [ ] Materialize the pre-run contract and stop with exactly one new sudo command.
