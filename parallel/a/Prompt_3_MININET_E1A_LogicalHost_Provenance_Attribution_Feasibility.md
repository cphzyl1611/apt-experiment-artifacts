# Prompt 3 — MININET-E1A Benign Logical-Host Provenance Attribution Feasibility

Continue from EXP-E0-A.

The previous environment preflight is accepted as a correct inventory, but its VM-per-node recommendation is **not frozen**.

Supervisor constraint: the experiment must remain Mininet-centered.

## Goal

Determine, with a **benign non-scored smoke test**, whether plain Mininet logical hosts can be deterministically attributed in host-level provenance using Linux namespace/process metadata.

Do not install new packages.
Do not execute any APT action.

## 1. Preserve existing state

Before mutation record:
- boot ID;
- active interfaces;
- active net namespaces;
- Mininet/OVS processes;
- OVS bridge state;
- relevant repo Git status.

Use a dedicated new run directory.

Do not use historical stale run markers as live evidence.

## 2. Build a minimal benign topology

Use exactly:
- one OVS switch;
- two Mininet hosts;
- stable host names/IPs/MACs;
- no Internet/NAT/external attachment.

Use only benign actions such as:
- `echo`;
- local temporary-file create/read/delete;
- ping between the two hosts;
- optionally a local loopback/TCP echo or simple HTTP transfer if it requires no install.

No attack commands.

## 3. Logical-host identity capture

For each Mininet host:
- capture Mininet shell PID;
- capture process descendants used by benign actions;
- capture `/proc/<pid>/ns/net` identity;
- capture any mount/cgroup identity available without new tooling;
- capture interface/IP/MAC mapping;
- capture namespace inode before/during/after the run.

Test whether host h1 and h2 remain distinct under:
- simultaneous commands;
- descendant processes;
- PID changes/reuse where practical;
- socket creation.

The security property is:

`event process -> exact logical Mininet host`

must be mechanically derivable without relying only on timestamp guessing.

## 4. File-event attribution design

Because plain Mininet may share filesystem/mount context, determine whether a process-owned file event can still be attributed to a logical host through its process/netns identity.

Do not claim filesystem isolation if it is not present.

If Mininet supports an already-installed `privateDirs`/bind-mount mechanism without external packages, inspect its suitability but do not broaden the test beyond benign temp files.

## 5. Packet correlation

If existing `tcpdump` can be used with approved sudo/root access, capture only this benign topology traffic.

Bind:
- logical host;
- interface;
- IP/MAC;
- socket tuple if available;
- packet timestamp.

Do not install tshark.

If root interaction is required and cannot be automated safely, print the exact command for the human user and stop at that subgate rather than fabricating capture evidence.

## 6. Decision

Preferred outcomes:

A. `PLAIN_MININET_ATTRIBUTION_FEASIBLE`
- logical host attribution can be mechanically derived using netns/process identities;
- continue with a host-level collector design on plain Mininet.

B. `MININET_CONTAINER_SUBSTRATE_REQUIRED`
- plain Mininet attribution/isolation is insufficient;
- recommend a Mininet-compatible container/cgroup substrate (e.g. a Containernet-style design) for later review.

C. `BLOCKED`
- evidence insufficient.

Do **not** jump directly to VM-per-node unless a later explicit review approves it.

## 7. Cleanup

After the benign test:
- stop only processes created by this run;
- clean only topology state created by this run;
- record post-cleanup interfaces/namespaces/OVS state;
- prove no stale run state remains.

Any use of `mn -c` must be explicitly recorded because it is broad cleanup.

## Outputs

- `MININET_E1A_PRE_STATE.json`
- `MININET_E1A_TOPOLOGY_AND_RUN_MANIFEST.json`
- `MININET_E1A_PROCESS_NETNS_ATTRIBUTION.jsonl`
- `MININET_E1A_PACKET_CORRELATION.json` if capture is available
- `MININET_E1A_POST_CLEANUP_AUDIT.json`
- `MININET_E1A_ATTRIBUTION_FEASIBILITY_REPORT.md`

## Hard boundaries

DO NOT:
- install packages;
- connect Mininet to external networks;
- execute APT actions;
- run PROVX;
- produce benchmark scores;
- mutate binding/scoring authority;
- mutate Git refs.

## Terminal

```text
MININET_E1A_ATTRIBUTION_VERDICT =
PLAIN_MININET_ATTRIBUTION_FEASIBLE
|
MININET_CONTAINER_SUBSTRATE_REQUIRED
|
BLOCKED

ATTACK_ACTIONS_EXECUTED = 0
PROVX_EXECUTED = NO
FORMAL_EXPERIMENT_EXECUTED = NO

NEXT_ACTION =
FRESH_REVIEW_OF_MININET_E1A_ATTRIBUTION_FEASIBILITY

STOP = true
```
