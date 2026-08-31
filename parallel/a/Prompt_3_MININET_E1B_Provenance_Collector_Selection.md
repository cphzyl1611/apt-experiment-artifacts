# MININET-E1B — Provenance Collector Selection and Benign Event Contract

Continue from verified:
`PLAIN_MININET_ATTRIBUTION_FEASIBLE`

Plain Mininet remains preferred unless later evidence disproves it.

## Goal

Select the smallest defensible host provenance collector for the Mininet-based PROVX extension and define a benign event-capture contract.

## Required work

1. Pin E1A-R2 corrected harness, runtime evidence, attribution report, PCAP hash, and four zero-residue cleanup assertions.

2. Inventory local availability of:
   - auditd/auditctl
   - CamFlow
   - eBPF/BCC/bpftrace/libbpf tooling
   - strace as a development/validation oracle
   - relevant existing endpoint telemetry

3. For each viable collector evaluate:
   - process exec/create/exit
   - parent/child IDs
   - file open/read/write/create/delete
   - socket bind/connect/accept/send/receive
   - timestamp/order
   - PID/netns mapping
   - event loss/drop reporting
   - raw-event preservation
   - privileges/overhead
   - Mininet compatibility
   - logical_host_id correlation
   - deterministic parsing
   - process/file/socket causal-graph suitability

4. Select only with evidence:
   AUDITD_PRIMARY_CANDIDATE
   EBPF_PRIMARY_CANDIDATE
   CAMFLOW_PRIMARY_CANDIDATE
   OTHER_EXACT_CANDIDATE
   BLOCKED_NEED_MORE_EVIDENCE

   Treat strace as validation oracle unless separately justified as formal collector.

5. If selected collector is not installed, output the exact Ubuntu package/version and one exact human install command. Do NOT run sudo/apt automatically.

6. Define the future benign event contract for h1/h2:
   PROCESS_START, PROCESS_EXEC, PROCESS_EXIT,
   FILE_CREATE_OR_OPEN, FILE_READ_OR_WRITE, FILE_DELETE,
   SOCKET_BIND, SOCKET_CONNECT_OR_ACCEPT, NETWORK_CORRELATION.

   Each event contract must include:
   event_id, timestamp, PID/PPID, executable, file/socket identity,
   netns inode, logical_host_id, run_id, raw bytes/hash.

7. Define graph-conversion prerequisites for PROCESS/FILE/SOCKET nodes and causal edges. Do not construct PROVX tensors yet.

## Outputs

- MININET_E1B_COLLECTOR_INVENTORY.json
- MININET_E1B_COLLECTOR_COMPARISON.json
- MININET_E1B_PRIMARY_COLLECTOR_DECISION.md
- MININET_E1B_BENIGN_EVENT_CONTRACT.json
- MININET_E1B_GRAPH_CONVERSION_PREREQUISITES.json
- MININET_E1B_HUMAN_INSTALL_COMMAND.txt if needed

## Boundaries

No APT actions, formal scoring, PROVX inference on Mininet data, automatic sudo installation, system-wide audit-rule mutation, or authority mutation.

## Terminal

MININET_E1B_COLLECTOR_DECISION = <allowed value>
COLLECTOR_INSTALLED_AND_READY = YES | NO
NEXT_ACTION = HUMAN_INSTALL_APPROVAL | BENIGN_COLLECTOR_SMOKE_DESIGN | FRESH_REVIEW
FORMAL_EXPERIMENT_EXECUTED = NO
STOP = true
