# Mininet E1C-R3 Harness Repair and Residual Rule Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a corrected, bounded E1C-R3 harness that repairs only exact residual R1/R2-owned audit rules, safely persists byte-valued command evidence, performs a fresh benign Mininet/auditd smoke, and stops before privileged execution.

**Architecture:** The R3 harness runs as a root-owned, run-isolated transaction. It snapshots and classifies current audit rules, journals every exact mutation with fsync, restores the historical empty baseline before the smoke, then collects raw audit records and normalized evidence with mechanical namespace joins. A recursive JSON-safe encoder converts bytes to base64 plus an optional UTF-8 view and rejects unsafe implicit stringification.

**Tech Stack:** Python 3 standard library, auditctl/ausearch/aureport, Mininet/OVS, iproute2/ss, JSONL/JSON artifacts, py_compile and unittest.

**Spec:** `Prompt_2_MININET_E1C_R3_Harness_Repair_and_Residual_Rule_Recovery.md`

## Global Constraints

- Do not rerun R1/R2, invoke sudo, execute APT/PROVX/formal scoring, or run `mn -c`.
- No external network, NAT, or pre-existing OVS daemon mutation.
- Use a brand-new `e1c-r3-run-<UTC>` directory and preserve R1/R2 artifacts.
- Delete only exact canonical R1/R2/probe rules after fail-closed classification.
- Journal every add/delete before and after mutation; restore the historical `No rules` baseline.
- Missing audit classes are reported as missing; never infer them from strace or tcpdump.

### Task 1: Reproduce the R2 serialization defect (RED)

**Files:**
- Create: `e1c-r3-run-<UTC>/test_e1c_r3_harness.py`
- Create: `e1c-r3-run-<UTC>/r2_serialization_red.txt`

- [ ] **Step 1: Write a failing test** that constructs the exact R2 `before_probe` persistence shape containing byte-valued stdout/stderr and calls the R2 `write_json_atomic` implementation without an exception expectation.
- [ ] **Step 2: Run the focused test** and capture the expected `TypeError: Object of type bytes is not JSON serializable` as the RED record.

### Task 2: Implement the JSON-safe persistence and rule transaction

**Files:**
- Create: `e1c-r3-run-<UTC>/mininet_e1c_r3_auditd_smoke.py`
- Modify: `e1c-r3-run-<UTC>/test_e1c_r3_harness.py`

- [ ] **Step 1:** Add recursive `json_safe` and atomic JSON/JSONL writers; encode every bytes value as base64 with a decoded UTF-8 view when valid, never `str(bytes)`.
- [ ] **Step 2:** Add root audit snapshots, canonicalization, exact R1/R2/probe classification, fail-closed unrelated-rule handling, and fsync-backed PLANNED/RESULT remediation journaling.
- [ ] **Step 3:** Add per-syscall bounded probing, gated child smoke, live PID/netns/socket/cgroup evidence, raw/normalized collection, joins and four namespace assertions.
- [ ] **Step 4:** Add finally-path exact-rule cleanup, loss/backlog and residue checks, and all required pre/post artifacts.
- [ ] **Step 5:** Update tests to target the R3 writer and recursive safety policy using the same R2 input; run GREEN focused tests.

### Task 3: Static/pre-run gate

**Files:**
- Create: `e1c-r3-run-<UTC>/MININET_E1C_R3_LINEAGE.json`
- Create: `e1c-r3-run-<UTC>/MININET_E1C_R3_STATIC_AUDIT.json`
- Create: `e1c-r3-run-<UTC>/MININET_E1C_R3_PRE_RUN_CONTRACT.json`

- [ ] **Step 1:** Record R1/R2 paths, hashes, pinned R2 failure, and the new harness/test hashes.
- [ ] **Step 2:** Run all tests, `py_compile`, and static boundary scans; fail if sudo/mn-c/APT/PROVX/NAT/external-network violations appear.
- [ ] **Step 3:** Write the pre-run contract and print the exact single human command, then stop without executing it.
