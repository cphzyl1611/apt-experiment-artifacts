# EXP-E0-A Environment Preflight

Preflight scope: read-only environment and asset inventory for the fixed PROVX
defense system, "Cutting the Fuse: Actionable APT Attack Blocking in
Provenance-based IDS". No packages, Git refs, network namespaces, interfaces,
processes, scoring authority, or binding authority were changed.

Observed: 2026-08-29 (America/New_York), host `UBU-MONITOR01`, current boot ID
`b5116b9e-9bef-4c8b-a02a-be618de984de`.

## A. System and Runtime

| Item | Observation |
|---|---|
| OS | Ubuntu 22.04.5 LTS (Jammy) |
| Kernel | Linux 6.8.0-138-generic x86_64, VMware full virtualization |
| CPU | 4 online CPUs, Intel Core Ultra 5 230F, 2 sockets x 2 cores |
| Memory | 7.7 GiB RAM; 3.5 GiB available at capture; 3.1 GiB swap, 1.7 GiB free |
| Disk | Root ext4 78.1 GiB; 18.2 GiB available (about 76% used) |
| Identity/privilege | `cph` UID 1000, member of `sudo` and `lxd`; `sudo -n` fails because a password is required |
| Python on PATH | Conda base Python 3.13.13 (`/home/cph/miniconda3/bin/python3`) |
| System Python | `/usr/bin/python3` 3.10.12 |
| Additional Python | `/home/cph/miniconda3/envs/dd37/bin/python` 3.7.16 |
| Virtual environments | Conda `base` (active) and `dd37`; no project `.venv`/`venv` found under `/home/cph` (the `miniconda3/lib/python3.13/venv` directory is the stdlib) |
| Mininet | Installed package `mininet 2.3.0-1ubuntu1`; `mn --version` = 2.3.0; imports with system Python, not Conda Python |
| Open vSwitch | `openvswitch-switch 2.17.9-0ubuntu0.22.04.2`; `ovs-vsctl`/`ovs-ofctl` 2.17.9; daemons `ovsdb-server` and `ovs-vswitchd` running; systemd unit active (exited after successful start). Unprivileged `ovs-vsctl` cannot open `/var/run/openvswitch/db.sock` (permission denied). |
| Java/build | OpenJDK 8 package installed (`javac 1.8.0_502`); `java` defaults to OpenJDK 11.0.32. Ant 1.10.12 and Maven 3.6.3 installed. |
| iproute2 | iproute2 5.15.0, libbpf 0.5.0; `ip` available |
| Packet tools | `tcpdump 4.99.1` installed; `tshark` absent |
| Containers/VMs | Docker, Podman, LXC, libvirt/virsh, and VirtualBox CLI absent. VMware guest tools (`open-vm-tools`, `vmtoolsd`) active. |
| Network namespace capability | `ip netns list` is empty; `/run/netns` and `/var/run/netns` contain no named namespaces. `unshare -n` is not permitted for this unprivileged shell. |
| Root later required | Yes. Mininet/OVS bridge creation, namespace setup/teardown, packet capture on protected interfaces, and audit/provenance collectors require root or delegated capabilities. |

Current host interfaces are only `lo` and VMware NAT interface `ens33` (IPv4
`192.168.93.128/24`, default gateway `192.168.93.2`). No Mininet bridge or veth
is visible now. The current OVS database is readable only with root; passwordless
sudo is not configured in this session.

## Existing Git repositories

Read-only repository discovery found:

- `/home/cph/experiment` (branch `feature/s1-empirical-subset-protocol`, local modifications/untracked prompt and generated files).
- `/home/cph/apt-defense-mininet` (branch `main`, local untracked controller/upstream worktree content; remote `cphzyl1611/apt-defense-mininet`).
- `/home/cph/APT-Taxonomy-recovery`, `/home/cph/APT-Taxonomy-v35-authority`, `/home/cph/tmr1_recovery_inputs`, and `/home/cph/fa1b2de-review-artifacts`.
- Additional worktrees under `/home/cph/experiment-worktrees` and `/home/cph/APT-Taxonomy-worktrees`.

No repository containing PROVX source, model, or released artifact was found.
The Mininet repository contains released FRESCO/Floodlight source and build
outputs, not PROVX.

## B. Network Experiment Inventory

The existing `/home/cph/apt-defense-mininet` repository contains:

- `topology/g3_minimal_topology.py`: one remote controller at
  `127.0.0.1:6653`, one OVS switch `s1`, hosts `h1=10.0.0.1/24` and
  `h2=10.0.0.2/24`, deterministic MACs ending in `:01` and `:02`,
  OpenFlow10 and secure fail mode. It explicitly attaches no NAT or external
  interface.
- `topology/g4_blacklist_topology.py`: the same one-switch/two-host layout for
  FRESCO blacklist states A/B/C.
- Controller start/stop and evidence scripts under `scripts/g2_*`,
  `scripts/g3_*`, and `scripts/g4_*`; teardown scripts call destructive
  commands such as `sudo mn -c`, but none were executed in this preflight.
- Historical evidence directories for G1-G4 (text logs, flow dumps, REST JSON,
  and manifests). They contain no `.pcap` or `.pcapng` files.

No Mininet topology, controller, or packet-capture orchestration exists in the
primary `/home/cph/experiment` repository; its scripts are dataset parsing,
feasibility, audit, and run-plan generation utilities.

VMware NAT is the only observed virtualization dependency. No bridge/NAT
attachment for Mininet is configured in the existing topologies. There are no
active `mnexec`, `floodlight.jar`, Mininet host processes, named namespaces,
or veth remnants in the current snapshot. Existing `.active_g2_run`,
`.active_g3_run`, and `.active_g4_run` marker files are historical. The G4
boot marker is `9b3a0d12-...`, which does not match the current boot ID, so it
must be treated as stale and cannot establish a live run.

## C. PROVX Provenance-Input Readiness

| Input capability | Current status |
|---|---|
| Linux auditd/auditctl | Missing: `auditctl` absent, `auditd` inactive, no `/var/log/audit` inventory accessible |
| CamFlow | Missing (`camflow` not found) |
| eBPF/BPF event tooling | `bpftool 7.4.0` binary exists, but no event collector/provenance pipeline found; `bpftrace` absent and trace/BPF mounts are not readable by this user |
| Process execution telemetry | No PROVX collector. Wazuh manager is active, but its protected configuration cannot be read as `cph` and no evidence shows a provenance graph feed |
| File-access telemetry | No auditd/CamFlow/eBPF collector or graph converter found |
| Socket/network connection telemetry | `ss` provides a point-in-time inventory only; no persistent per-event socket telemetry found |
| Windows Sysmon/ETW assets | None found for an experiment node |
| DARPA TC/OpTC preprocessing | No local DARPA TC/OpTC preprocessing or PROVX conversion code found |
| PROVX source/model/artifacts | None found |
| Existing provenance graphs | No graph outputs tied to Mininet runs found. Other FA1B2de artifact trees contain governance/provenance JSON, not PROVX input graphs. |

Plain Mininet hosts are network namespaces for interfaces and network state;
their processes normally remain in the host PID/mount/IPC/UTS context and use
the host kernel. Therefore multiple logical hosts can generate audit/file
events with indistinguishable host-level process context. IP/MAC and veth
names alone are not a sufficient identity for process, file, and socket
provenance, especially after process reuse or file sharing.

The smallest later substrate that preserves all required identities is
VM-backed logical hosts (one small VM per provenance-bearing node, or an
equivalent microVM), connected through a controlled OVS/Mininet fabric. A
collector inside each VM can observe process, file, and socket events in one
kernel context; the VM UUID plus `logical_host_id` is stable. Capture on each
VM vNIC and/or the OVS bridge supplies packet evidence. A lower-cost
container-backed alternative is possible only if a validation proves that
PID, mount, network, cgroup/container ID, and collector records remain
unambiguous; shared-kernel containers are not accepted by default.

## D. Telemetry and Time Correlation

The host clock reports synchronized system time with active
`systemd-timesyncd`/NTP and an UTC RTC. Existing FRESCO evidence uses
run-specific directories, `metadata.env`, timestamps, process lists, and
boot IDs. This is useful for a future manifest but does not bind a
`run_id -> raw_key -> logical_host_id -> audit event -> socket event -> pcap
packet -> provenance graph -> PROVX subgraph` chain today.

Observed gaps:

- no stable run marker or host-agent event schema shared with the primary
  experiment repository;
- no persistent audit-log capture and no packet captures;
- no cross-source event IDs linking sockets to packets or graph nodes;
- no verified clock policy for multiple future VMs beyond the current host's
  NTP state;
- current FRESCO manifests and flow/REST logs are structured, but they do not
  contain provenance graph identifiers or PROVX input schemas.

Before a formal run, the design must register a run manifest containing
`run_id`, `raw_key`, `logical_host_id`, VM/container identity, interface/MAC/IP,
collector boot/session marker, timestamp origin/precision, pcap path, audit
path, graph path, and PROVX subgraph path, with hashes for every artifact.

## E. Storage and Repeatability

Current sizes: `/home/cph/experiment` about 1.3 GiB; `/home/cph/apt-defense-mininet`
about 235 MiB; root filesystem has about 18.2 GiB free. No pcap directory,
retention quota, graph store, or automated rotation policy exists. This is
adequate for small smoke captures but is not yet capacity-planned for
simultaneous raw PCAP, host audit/provenance, graphs, model outputs, and
manifests. A later run must budget space per trial, reserve headroom, hash and
compress artifacts, and enforce a retention policy before execution.

Repeatability assets already present are Git repositories, pinned FRESCO source
trees/build artifacts, deterministic h1/h2 names and addresses, evidence
manifests, and safe controller/topology scripts. Snapshot/reset support is
limited to those scripts and historical evidence; cleanup scripts include
destructive `mn -c` and process stopping and require explicit privileged use.
There is no VM snapshot or host-provenance reset workflow.

## Verdict

The Mininet/OVS network base capability is present and has historical FRESCO
interoperability evidence. PROVX live provenance input readiness is **NO**.
Plain Mininet is **not sufficient** for PROVX provenance attribution. The
overall preflight is therefore blocked on missing base provenance/isolation
capabilities, not on the network switch substrate.

```text
EXP_E0_A_VERDICT = BLOCKED_MISSING_BASE_CAPABILITY
PROVX_LIVE_PROVENANCE_INPUT_READY = NO
PLAIN_MININET_SUFFICIENT_FOR_PROVX = NO
FORMAL_EXPERIMENT_EXECUTED = NO
BINDING_AUTHORITY_MUTATION = NO
SCORING_AUTHORITY_MUTATION = NO
STOP = true
```
