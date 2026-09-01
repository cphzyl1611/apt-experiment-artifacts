# MININET-E1C-R6 bounded file-access collector closure implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare a new E1C-R6 privileged harness whose exact per-file audit permission watch closes R5's missing `FILE_READ_OR_WRITE` class without broadening system-wide syscall logging.

**Architecture:** Copy the proven R5 bounded topology and child protocol into a new timestamped R6 run directory only after RED tests exist. Add a root-only micro-probe state machine that pre-creates one exact file, installs one `-F path=... -F perm=rw -F pid=...` rule, performs bounded read/write, and fails closed unless an audit-backed event is observed. Reuse R5 event normalization and cleanup while adding an honest filesystem-permission evidence basis and a serial/hash-correct raw-link verifier.

**Tech Stack:** Python 3, `unittest`, `ast`, `py_compile`, Linux auditd/auditctl/ausearch, Mininet/OVS, tcpdump, SHA256 manifests.

**Spec:** `Prompt_2_MININET_E1C_R6_File_Access_Collector_Closure_Preparation.md`

## Global Constraints

- Do not execute sudo, mutate audit rules, use `auditctl -D`, use `mn -c`, run APT/PROVX, attach NAT/external links, or execute a formal benchmark.
- Preserve R5 controls, clean baseline fail-closed behavior, exact transient cleanup, same-root residue checks, and exit semantics PASS=0/PARTIAL=3/BLOCKED=2/exception=1.
- Use exact pre-created per-host files and exact live child PIDs; no wildcard, whole-system directory watch, `-S all`, persistent rule-file edits, or broad read/write rules.
- Missing `FILE_READ_OR_WRITE` must remain missing unless the audit evidence itself proves it; never infer from tcpdump or strace.

### Task 1: Establish R6 run skeleton and RED tests

**Files:**
- Create: `e1c-r6-run-20260901T060256Z/test_e1c_r6_harness.py`
- Create: `e1c-r6-run-20260901T060256Z/MININET_E1C_R6_R5_FILE_RW_ROOT_CAUSE.md`
- Create: `e1c-r6-run-20260901T060256Z/MININET_E1C_R6_AUDIT_FILE_ACCESS_SEMANTICS.json`

- [ ] Write tests first for exact path+perm rule construction, micro-probe gate failure, filesystem-permission normalization, and the five raw-link defects (valid, serial mismatch, hash mismatch, duplicate serial, missing raw record).
- [ ] Run `python3 -m unittest -v e1c-r6-run-20260901T060256Z/test_e1c_r6_harness.py`; confirm the new tests fail because the R6 module/helpers do not yet exist.
- [ ] Record the R5 diagnosis and local `auditctl(8)` evidence: `path` is an exit-list exact file filter; `perm` accepts `r/w`; without `-S`, the kernel selects permission-relevant syscalls; read/write syscalls are omitted from filesystem permission watches and open flags represent requested access.

### Task 2: Implement minimal bounded helpers

**Files:**
- Create: `e1c-r6-run-20260901T060256Z/mininet_e1c_r6_file_access_closure_smoke.py`
- Modify: `e1c-r6-run-20260901T060256Z/test_e1c_r6_harness.py`

- [ ] Implement `build_file_permission_watch_rule(path, pid, key)` returning `auditctl -a always,exit -F arch=b64 -F path=<exact> -F perm=rw -F pid=<pid> -k <key>` and an exact `-d` inverse; reject wildcards, directories, missing absolute paths, `-S`, and broad subjects.
- [ ] Implement three-state micro-probe helpers that require clean baseline, pre-create the file, add exactly the candidate rule, perform read/write, collect keyed audit records, require an audit-backed event, remove exactly the rule, and re-prove the baseline; any failure returns BLOCKED without trying a broader rule.
- [ ] Implement `normalize_filesystem_permission_event` preserving `event_type=FILE_READ_OR_WRITE`, `evidence_basis=AUDIT_FILESYSTEM_PERMISSION_FILTER`, `watched_path`, `requested_access`, and observed `underlying_syscall`.
- [ ] Implement raw-link verification keyed by exact serial and comparing normalized `raw_event_sha256` to raw `raw_sha256`, with explicit duplicate/missing/mismatch failures.
- [ ] Run the focused tests and make them green, then run the R3/R4/R5 regression suites.

### Task 3: Build the bounded R6 harness

**Files:**
- Modify: `e1c-r6-run-20260901T060256Z/mininet_e1c_r6_file_access_closure_smoke.py`
- Create: `e1c-r6-run-20260901T060256Z/MININET_E1C_R6_PRE_RUN_CONTRACT.json`
- Create: `e1c-r6-run-20260901T060256Z/MININET_E1C_R6_STATIC_AUDIT.json`

- [ ] Reuse R5 child states, PID/netns identity, listener/socket evidence, TCP 18080, tcpdump lifetime, raw audit capture, cleanup invariants, and exit classification.
- [ ] At root start require auditd `1:3.0.7-1build1` and exact clean `No rules` hash; do not perform legacy cleanup.
- [ ] Run the exact root micro-probe before Mininet; proceed to h1/h2 only on audit-backed FILE_READ_OR_WRITE PASS.
- [ ] For full smoke, create separate read/write files and a disposable delete file per host; install exact path+perm rules bound to each live child PID; require all eight classes >0.
- [ ] Ensure normalized filesystem events carry logical host joins and raw serial/byte links; preserve auxiliary unjoined events explicitly rather than fabricating joins.
- [ ] Encode static checks that reject `-S all`, broad read/write syscall rules, `auditctl -D`, `mn -c`, NAT/external links, APT, PROVX, persistent rule edits, and strace as primary collector.

### Task 4: Static/TDD gate and pre-run artifacts

**Files:**
- Create: `e1c-r6-run-20260901T060256Z/MININET_E1C_R6_LINEAGE.json`
- Create: `e1c-r6-run-20260901T060256Z/MININET_E1C_R6_TDD_GATE.json`
- Create: `e1c-r6-run-20260901T060256Z/MININET_E1C_R6_RAW_LINK_RED_REPRODUCTION.txt`

- [ ] Run all R6 tests, R3/R4/R5 regressions, `python3 -m py_compile` on the harness/tests, and the harness static self-check.
- [ ] Materialize test counts, local documentation hashes/quotes, rule design, raw-link RED evidence, clean-baseline contract, and boundary audit.
- [ ] Verify no privileged command has been run and emit exactly one absolute human sudo command for fresh review.
