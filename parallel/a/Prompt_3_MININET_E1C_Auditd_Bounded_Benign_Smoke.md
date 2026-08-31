# MININET-E1C — Auditd Bounded Benign Collector Smoke

Continue from fresh-reviewed E1B:
MININET_E1B_COLLECTOR_DECISION = AUDITD_PRIMARY_CANDIDATE

Human prerequisite:
sudo apt-get install auditd=1:3.0.7-1build1

The user must run installation manually. Codex must not run apt/sudo automatically.

Goal: prove or disprove that auditd provides the bounded process/file/socket event substrate needed for Mininet logical-host provenance.

1. Verify installed package version, auditctl/ausearch, kernel audit support, daemon status, current rules, backlog/lost status. If missing, stop HUMAN_INSTALL_REQUIRED.

2. Preserve baseline:
- auditctl -l
- daemon status/config
- baseline rule-dump hash
Do not edit persistent /etc/audit/rules.d/*.

3. Build one bounded privileged smoke harness over the validated s1/h1/h2 topology:
- no NAT/external links
- capture shell PIDs/netns
- add only run-scoped transient audit rules
- spawn long-lived benign children after rules are active
- perform exec/process creation, unique temp file create/write/read/delete, socket bind/listen, h1<->h2 TCP connect/accept/exchange
- collect by unique audit key
- snapshot PID->netns while alive
- optionally use strace as validation oracle only
- remove only run-owned audit rules
- stop topology and prove baseline restoration

4. Rule design must be bounded. Attempt coverage of execve/execveat, openat/openat2, safely filterable read/write, unlink/unlinkat, bind, connect, accept/accept4, and process exit. Never enable broad unfiltered system-wide read/write auditing. If an event family cannot be safely filtered, state it.

5. Normalize raw audit records to:
PROCESS_START_OR_EXEC
PROCESS_EXIT
FILE_CREATE_OR_OPEN
FILE_READ_OR_WRITE
FILE_DELETE
SOCKET_BIND
SOCKET_CONNECT
SOCKET_ACCEPT

Preserve raw serial, timestamp, pid/ppid, syscall, exe/proctitle, path, sockaddr, result, raw bytes/hash.

6. Prove PID -> live netns -> h1/h2 shell netns -> logical_host_id. Quantify join failures.

7. Record expected benign actions, raw records, normalized class counts, joined/unjoined events, lost/backlog count, duplicates/malformed records.

8. Cleanup:
- run rules removed
- baseline rule hash restored
- topology residue 0
- child residue 0
- no mn -c
Audit service may remain installed/running.

Outputs:
MININET_E1C_AUDIT_PRE_STATE.json
MININET_E1C_TRANSIENT_RULE_CONTRACT.json
MININET_E1C_RAW_AUDIT_EVIDENCE.jsonl
MININET_E1C_NORMALIZED_EVENTS.jsonl
MININET_E1C_PID_NETNS_JOIN.jsonl
MININET_E1C_STRACE_ORACLE_COMPARISON.json
MININET_E1C_COVERAGE_AND_LOSS_AUDIT.json
MININET_E1C_POST_CLEANUP_AUDIT.json
MININET_E1C_AUDITD_SMOKE_REPORT.md

If a privileged run is required, prepare/static-audit the harness and STOP with exactly one human sudo command. Do not invoke sudo.

Pre-human terminal:
MININET_E1C_HARNESS_PREPARATION = PASS | BLOCKED
HUMAN_PRIVILEGED_RUN_REQUIRED = YES | NO
NEXT_ACTION = HUMAN_RUN_EXACT_SUDO_COMMAND | FIX_SMOKE_DESIGN
STOP = true

Post-run terminal:
MININET_E1C_AUDITD_COLLECTOR = PASS_READY_FOR_GRAPH_NORMALIZATION | PARTIAL_MISSING_REQUIRED_EVENT_CLASS | BLOCKED
AUDIT_LOST_EVENTS = <n>
NORMALIZED_EVENT_COUNT = <n>
LOGICAL_HOST_JOIN_SUCCESS_COUNT = <n>
LOGICAL_HOST_JOIN_FAILURE_COUNT = <n>
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_MININET_E1C_AUDITD_SMOKE
STOP = true
