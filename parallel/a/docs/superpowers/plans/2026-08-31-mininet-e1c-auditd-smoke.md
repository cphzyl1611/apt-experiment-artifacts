# MININET-E1C Auditd Bounded Benign Smoke Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove or disprove that the installed Ubuntu auditd can provide a bounded process/file/socket event substrate joined to Mininet logical hosts.

**Architecture:** Prepare a single privileged harness that snapshots auditd state, adds only transient per-PID and unique-directory rules, runs benign two-host Mininet activity, collects raw records by a unique key, normalizes them, joins event PIDs to live network namespaces, removes only its rules, and verifies baseline/topology/process restoration. The harness is static-tested and compiled unprivileged, then the human runs one exact sudo command.

**Tech Stack:** Python 3.10, auditd/auditctl/ausearch, Mininet 2.3.0, Open vSwitch, `/proc` namespace metadata, JSONL evidence, optional strace oracle.

**Spec:** `Prompt_3_MININET_E1C_Auditd_Bounded_Benign_Smoke.md`

## Global Constraints

- No APT actions, automatic sudo, persistent `/etc/audit/rules.d/*` edits, PROVX inference, formal experiment, authority mutation, or `mn -c`.
- Add only run-scoped transient audit rules and remove only rules whose unique run key was added by this harness.
- Never enable broad unfiltered system-wide read/write auditing; file rules must be limited to the unique run directory and process rules to exact PIDs/PPIDs.
- Preserve raw audit serial, timestamp, PID/PPID, syscall, executable/proctitle, path, sockaddr, result, and raw bytes/hash.
- Terminal state must include `FORMAL_EXPERIMENT_EXECUTED = NO` and `STOP = true`.

### Task 1: Build bounded harness and contracts

**Files:**
- Create: `e1c-run-<timestamp>/mininet_e1c_auditd_bounded_smoke.py`
- Create: `e1c-run-<timestamp>/test_e1c_auditd_bounded_smoke.py`

- [ ] Implement root-only runtime mode, unprivileged child/static-check modes, baseline audit snapshots, bounded transient rules, benign two-host topology, raw collection, normalization, PID/netns joins, and scoped cleanup.
- [ ] Add tests for rule boundedness, audit grouping/normalization, namespace joins, and static boundary checks.

### Task 2: Verify unprivileged and static gates

**Files:**
- Create: `MININET_E1C_HARNESS_STATIC_AUDIT.json`
- Create: `MININET_E1C_PRE_RUN_CONTRACT.json`

- [ ] Run py_compile, unit tests, and static self-check without sudo.
- [ ] Record current auditd package/daemon/kernel evidence and the exact human command.

### Task 3: Human privileged smoke gate

**Files:**
- Create at runtime: `MININET_E1C_AUDIT_PRE_STATE.json`, `MININET_E1C_TRANSIENT_RULE_CONTRACT.json`, `MININET_E1C_RAW_AUDIT_EVIDENCE.jsonl`, `MININET_E1C_NORMALIZED_EVENTS.jsonl`, `MININET_E1C_PID_NETNS_JOIN.jsonl`, `MININET_E1C_STRACE_ORACLE_COMPARISON.json`, `MININET_E1C_COVERAGE_AND_LOSS_AUDIT.json`, `MININET_E1C_POST_CLEANUP_AUDIT.json`, `MININET_E1C_AUDITD_SMOKE_REPORT.md`

- [ ] Stop before privileged execution and print exactly one human sudo command.
- [ ] After human completion, independently review runtime evidence and classify auditd as pass-ready, partial, or blocked.
