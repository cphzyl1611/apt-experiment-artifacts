# MININET-E1B Collector Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Select the smallest defensible host provenance collector for the Mininet-based PROVX extension and define a benign event and graph-conversion contract.

**Architecture:** Use read-only local availability checks and the verified E1A-R2 runtime artifacts to compare auditd, eBPF/BCC/bpftrace/libbpf tooling, CamFlow, strace, and existing telemetry. Treat strace as a development/validation oracle unless evidence supports a formal collector; preserve raw events and explicit PID/netns/logical-host joins for a future causal graph.

**Tech Stack:** Ubuntu command/package metadata, Python JSON artifacts, Mininet E1A-R2 evidence, auditd/eBPF/CamFlow/strace capability probes.

**Spec:** `Prompt_3_MININET_E1B_Provenance_Collector_Selection.md`

## Global Constraints

- No APT actions, formal scoring, PROVX inference on Mininet data, automatic sudo installation, system-wide audit-rule mutation, or authority mutation.
- Pin the verified E1A-R2 corrected harness, runtime evidence, attribution report, pcap hash, and four zero-residue cleanup assertions.
- Selection must be one allowed value: `AUDITD_PRIMARY_CANDIDATE`, `EBPF_PRIMARY_CANDIDATE`, `CAMFLOW_PRIMARY_CANDIDATE`, `OTHER_EXACT_CANDIDATE`, or `BLOCKED_NEED_MORE_EVIDENCE`.
- Strace is a validation oracle unless separately justified as a formal collector.
- Terminal state must include `FORMAL_EXPERIMENT_EXECUTED = NO` and `STOP = true`.

### Task 1: Inventory local collector availability

**Files:**
- Create: `MININET_E1B_COLLECTOR_INVENTORY.json`
- Read: `EXP_E0_A_ENVIRONMENT_PRECHECK.json`, `EXP_E0_A_EXISTING_ASSET_INVENTORY.json`, E1A-R2 runtime artifacts

- [ ] Probe command binaries, package metadata, kernel tracing support, and existing endpoint telemetry with read-only commands.
- [ ] Record exact paths, versions, probe return codes, and whether each collector is installed and ready without mutating the system.

### Task 2: Compare candidates and select one

**Files:**
- Create: `MININET_E1B_COLLECTOR_COMPARISON.json`
- Create: `MININET_E1B_PRIMARY_COLLECTOR_DECISION.md`

- [ ] Pin E1A-R2 hashes and runtime facts.
- [ ] Evaluate every required capability for auditd, eBPF, CamFlow, strace, and existing telemetry.
- [ ] Select only an evidence-backed allowed decision; provide an exact package/version and human install command if the selected collector is unavailable.

### Task 3: Define benign event and graph contracts

**Files:**
- Create: `MININET_E1B_BENIGN_EVENT_CONTRACT.json`
- Create: `MININET_E1B_GRAPH_CONVERSION_PREREQUISITES.json`

- [ ] Define PROCESS_START, PROCESS_EXEC, PROCESS_EXIT, FILE_CREATE_OR_OPEN, FILE_READ_OR_WRITE, FILE_DELETE, SOCKET_BIND, SOCKET_CONNECT_OR_ACCEPT, and NETWORK_CORRELATION fields.
- [ ] Require event_id, timestamp, PID/PPID, executable, file/socket identity, netns inode, logical_host_id, run_id, and raw bytes/hash on each event.
- [ ] Define PROCESS/FILE/SOCKET nodes and causal edges without constructing PROVX tensors.

### Task 4: Verify artifacts and terminal state

**Files:**
- Create if required: `MININET_E1B_HUMAN_INSTALL_COMMAND.txt`

- [ ] Parse all generated JSON, verify E1A-R2 hashes and cleanup assertions, and ensure no APT/sudo/PROVX/formal experiment action ran.
- [ ] Run a final read-only validation and record `NEXT_ACTION = HUMAN_INSTALL_APPROVAL`, `BENIGN_COLLECTOR_SMOKE_DESIGN`, or `FRESH_REVIEW` with `STOP = true`.
