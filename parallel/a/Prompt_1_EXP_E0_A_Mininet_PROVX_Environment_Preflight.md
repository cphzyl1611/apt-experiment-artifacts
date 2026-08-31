# Prompt 1 — EXP-E0-A Mininet + PROVX Environment Preflight

You are working on the FA1B2de APT defense benchmark experiment preparation.

This task is **experiment infrastructure preparation only**.

The supervisor-selected defense system is fixed as:

**PROVX — "Cutting the Fuse: Actionable APT Attack Blocking in Provenance-based IDS"**

Do NOT compare or select other defense systems.

Primary local experiment scope:

`/home/cph/experiment`

Also inspect, if present:

- `~/apt-defense-mininet`
- other existing Mininet / provenance / experiment directories under the user's home directory

## Goal

Establish the exact current machine/lab state required to later reproduce PROVX and connect it to a Mininet-centered controlled APT experiment.

Do this before installing or mutating anything.

## A. System/runtime inventory

Record:

- OS distribution/version
- kernel
- CPU / RAM / free disk
- Python versions and virtual environments
- Mininet version/status
- Open vSwitch version/status
- iproute2 / network namespace support
- Docker / Podman availability
- Git repositories already present
- relevant existing experiment scripts/topologies

Also record whether root/sudo privileges will later be required.

## B. Network experiment inventory

Inspect read-only for:

- existing Mininet topologies
- node naming/address conventions
- existing switches/controllers
- host network namespaces
- VMware / NAT / bridge dependencies
- packet capture scripts
- reset / teardown scripts
- stale Mininet namespaces/interfaces/processes
- existing pcap/log directories

Do NOT execute `mn -c`, delete namespaces, stop processes, or mutate network state in this E0 task.

## C. PROVX provenance-input readiness

PROVX is provenance-based, not packet-only.

Inspect whether the current machine already has any of:

- Linux auditd / auditctl
- CamFlow
- eBPF/BPF provenance/event tooling
- process execution telemetry
- file-access telemetry
- socket/network connection telemetry
- Sysmon/ETW-related assets for any Windows experiment node
- provenance graph conversion scripts
- DARPA TC / OpTC preprocessing code
- PROVX/ProvX source or artifact files

Determine:

1. whether plain Mininet hosts are only network namespaces;
2. whether logical Mininet hosts can be uniquely distinguished in host-level process/file/socket audit telemetry;
3. whether all Mininet nodes share host kernel/process context in a way that would make provenance attribution ambiguous;
4. whether existing container-backed or VM-backed host mechanisms are present;
5. what smallest later host-isolation design would preserve:
   - logical node identity
   - process provenance
   - file provenance
   - socket provenance
   - packet-to-host correlation.

Do not implement the host-isolation solution yet.

## D. Telemetry/time correlation readiness

Inspect whether a future run can deterministically bind:

`run_id`
→ `raw_key`
→ `logical_host_id`
→ host audit event
→ socket/network event
→ packet capture
→ provenance graph node/edge
→ PROVX input subgraph

Check existing:

- timestamp sources
- clock synchronization
- stable run markers
- pcap capture
- audit-log persistence
- structured log formats.

## E. Storage and repeatability

Estimate available capacity for simultaneously retaining:

- raw PCAP
- host audit/provenance telemetry
- generated provenance graphs
- PROVX model outputs
- experiment run manifests.

Identify existing snapshot/reset/cleanup mechanisms.

## Required outputs

Create in the current task output directory:

- `EXP_E0_A_ENVIRONMENT_PRECHECK.md`
- `EXP_E0_A_ENVIRONMENT_PRECHECK.json`
- `EXP_E0_A_EXISTING_ASSET_INVENTORY.json`
- `EXP_E0_A_PROVX_MININET_HOST_SUBSTRATE_RECOMMENDATION.md`

The recommendation must distinguish:

- what already exists;
- what is missing;
- what should be installed/configured later;
- what must be validated before formal experiment execution.

## Hard boundaries

DO NOT:

- install apt/pip/conda packages;
- download repositories or datasets;
- modify Git refs;
- modify network namespaces/interfaces;
- run attack replay;
- run PROVX training/inference;
- execute any formal benchmark action;
- modify binding authority;
- modify scoring authority;
- change the 1796 denominator.

## Required terminal

```text
EXP_E0_A_VERDICT =
READY_FOR_E1_DESIGN | BLOCKED_MISSING_BASE_CAPABILITY

PROVX_LIVE_PROVENANCE_INPUT_READY =
YES | NO | UNKNOWN

PLAIN_MININET_SUFFICIENT_FOR_PROVX =
YES | NO | UNKNOWN

FORMAL_EXPERIMENT_EXECUTED = NO
BINDING_AUTHORITY_MUTATION = NO
SCORING_AUTHORITY_MUTATION = NO

STOP = true
```
