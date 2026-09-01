# Mininet E1C-R6 File-Access Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare a bounded auditd-native R6 harness that closes FILE_READ_OR_WRITE, verifies raw/normalized links correctly, and stops before sudo.

**Architecture:** Pure, unit-tested helpers model exact path/permission/PID rules, inverse cleanup, permission-filter normalization, micro-probe gating, and serial/hash evidence joins. Required JSON/Markdown contracts document the R5 diagnosis, local audit semantics, static safety checks, and the exact human command; no privileged execution occurs.

**Tech Stack:** Python 3, unittest, JSON, Markdown, auditctl command-vector contracts.

**Spec:** `Prompt_2_MININET_E1C_R6_File_Access_Collector_Closure_Preparation.md`

## Global Constraints

- Use exact pre-created watched files, exact live child PIDs, and `perm=rw` filesystem permission filters.
- Do not use broad read/write syscall rules, `-S all`, wildcard paths, persistent rule files, `auditctl -D`, `mn -c`, NAT, external links, APT, or automatic sudo.
- Preserve cleanup and exit semantics: PASS 0, PARTIAL 3, BLOCKED 2, unexpected exception 1.
- Stop with exactly one sudo command for the human privileged run.

### Task 1: Implement pure R6 helper behaviors

**Files:**
- Modify: `e1c-r6-run-20260901T060350Z/mininet_e1c_r6_file_access_closure_smoke.py`
- Test: `e1c-r6-run-20260901T060350Z/test_e1c_r6_harness.py`

- [ ] Run the focused tests and confirm RED against the stubs.
- [ ] Implement validation, rule construction/inversion, probe verdict, normalization, and exact serial/hash link verification.
- [ ] Run the focused tests and the full R6 test module.

### Task 2: Emit R6 preparation artifacts and static checks

**Files:**
- Create: `MININET_E1C_R6_R5_FILE_RW_ROOT_CAUSE.md`
- Create: `MININET_E1C_R6_AUDIT_FILE_ACCESS_SEMANTICS.json`
- Create: `MININET_E1C_R6_PRE_RUN_CONTRACT.json`
- Create: `MININET_E1C_R6_STATIC_AUDIT.json`
- Create: `MININET_E1C_R6_RAW_LINK_RED_EVIDENCE.json`

- [ ] Encode the pinned R5 facts and local audit permission-watch semantics.
- [ ] Record the exact bounded rule and micro-probe/full-run state machine.
- [ ] Compute harness/test hashes and static safety results.
- [ ] Reproduce the R5 boolean defect with RED evidence and record the corrected verifier.

### Task 3: Verification gate

- [ ] Run `py_compile` and all R6 tests.
- [ ] Run static scans for prohibited broad auditing, destructive cleanup, NAT/external links, and automatic sudo.
- [ ] Confirm no privileged command was executed and report the exact sudo command only.
