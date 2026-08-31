# MININET-E1C Auditd Bounded Benign Smoke

Run: `e1c-run-20260831T050028Z`  
Audit key: `e1c902f74f583`  
Audit log SHA-256: `777a9c397de1f4cd6e861b56697df52176fe96c94a9cf18c9be77ab463903c52`  

## Terminal

`MININET_E1C_AUDITD_COLLECTOR = BLOCKED`

`AUDIT_LOST_EVENTS = 0 (pre-run counter; post-run auditctl probe denied)`

`NORMALIZED_EVENT_COUNT = 22`

`LOGICAL_HOST_JOIN_SUCCESS_COUNT = 0`

`LOGICAL_HOST_JOIN_FAILURE_COUNT = 4`

`FORMAL_EXPERIMENT_EXECUTED = NO`

`NEXT_ACTION = FRESH_REVIEW_OF_MININET_E1C_AUDITD_SMOKE`

`STOP = true`

## Independent Findings

- auditd package remains `auditd=1:3.0.7-1build1`; auditd is active and enabled; kernel audit support is present.
- The pre-run rule baseline is recorded (`No rules`, hash `61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87`).
- 42 keyed audit serial groups were recovered (serials 104 through 145); raw bytes and SHA-256 hashes are retained.
- Required classes observed: PROCESS_START_OR_EXEC, PROCESS_EXIT, FILE_CREATE_OR_OPEN, FILE_DELETE, SOCKET_BIND, SOCKET_CONNECT.
- Required classes missing: FILE_READ_OR_WRITE (bounded rule rejected `pread64`) and SOCKET_ACCEPT (connect failed with `exit=-115`; no accept record).
- h1/h2 child namespace snapshots were captured in memory by the harness control flow but not persisted; worker capture failed after PID 575829 exited. All four PID joins are therefore UNJOINED and the four namespace assertions are not validated.
- Both hosts issued bind attempts for port 18080 (`10.0.0.1` and `10.0.0.2`), but both connects failed; successful same-port exchange is not established.
- No transient-rule deletion records exist, the rule contract remains ACTIVE, and post-run auditctl/rules.d probes are unavailable without root; baseline restoration is not proven.
- Reserved interfaces are absent and run-owned child/tcpdump process counts are zero. OVS object residue cannot be checked due permission denial; pre-existing OVS daemons are explicitly excluded from run-owned state.
- Static/source evidence shows no NAT or external link, no APT/PROVX/formal experiment, and no `mn -c`; no such actions were executed during independent review.
- Strace is marked NOT_RUN and is not used to fill missing audit classes.

## Namespace Assertions

- h1_child_netns == h1_shell_netns: NOT_VALIDATED (child snapshot was not persisted).
- h2_child_netns == h2_shell_netns: NOT_VALIDATED (child snapshot was not persisted).
- h1_child_netns != h2_shell_netns: NOT_VALIDATED (no persisted shell/child netns inodes).
- h2_child_netns != h1_shell_netns: NOT_VALIDATED (no persisted shell/child netns inodes).
- Child PID/netns evidence while alive: capture attempted for both wrappers in memory, but no JSONL persistence survived the exception; independent join validation fails.
- Socket evidence while listener alive: bind syscalls are present before process exit; no direct ss or /proc/<pid>/net/tcp snapshot was persisted.

## Normalized Class Counts

- PROCESS_START_OR_EXEC: 6
- PROCESS_EXIT: 4
- FILE_CREATE_OR_OPEN: 6
- FILE_READ_OR_WRITE: 0
- FILE_DELETE: 2
- SOCKET_BIND: 2
- SOCKET_CONNECT: 2
- SOCKET_ACCEPT: 0

## Cleanup Invariants

- RUN_OWNED_CHILDREN_REMAINING: 0
- RESERVED_TEST_INTERFACES_REMAINING: 0
- RESERVED_TEST_OVS_OBJECTS_REMAINING: UNKNOWN (permission denied)
- TCPDUMP_PROCESS_REMAINING: 0
- transient audit rules removed: NOT PROVEN
- post-run audit rule baseline restored: NOT PROVEN

## Artifact SHA-256

- `MININET_E1C_AUDIT_PRE_STATE.json`: `49bea36b12bd06f9fa51554483167f4bfe77d2ce602d1000b146179f50058e20`
- `MININET_E1C_COVERAGE_AND_LOSS_AUDIT.json`: `6cdb35bde8a341607be42b0323c9894c6e635a85fe6419a727a26b6fb12e0f5c`
- `MININET_E1C_NORMALIZED_EVENTS.jsonl`: `d8cea0f171e58b6a5b4ec25c4f98929b8f6191c5ce61c9b7cf842517aed7017d`
- `MININET_E1C_PID_NETNS_JOIN.jsonl`: `f815fdc2ee84c8c383a1dc531f0aaa3a33594b0fc6fb39d6cdf97b7d3207f301`
- `MININET_E1C_POST_CLEANUP_AUDIT.json`: `7781d1aa460d4c80468ad1e3c74ff0bb401da528bfeb5cf19ad3eaaa42d2a9d6`
- `MININET_E1C_RAW_AUDIT_EVIDENCE.jsonl`: `2d93590c62e89374b7be13353cc13405894fbc683913c892cef24ad90ceb1e46`
- `MININET_E1C_STRACE_ORACLE_COMPARISON.json`: `630ee799b21e67417d860c89ed172ec10d4e310e47f0bc77e001590113421a54`
- `MININET_E1C_TRANSIENT_RULE_CONTRACT.json`: `c9cb8820046114d4b17b6cf814e93f79eced2d1722faf1b10e9d96a254ff4e8b`
