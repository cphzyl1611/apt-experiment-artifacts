# PROVX and Mininet Host Substrate Recommendation

## What exists

The machine has a usable network substrate: Mininet 2.3.0, Open vSwitch
2.17.9, iproute2 5.15.0, tcpdump 4.99.1, Java 8/11, Ant, and Maven. The
FRESCO reproduction repository has deterministic two-host topologies, remote
controller wiring, historical flow/REST evidence, and cleanup scripts. VMware
NAT and guest tools are present. The primary experiment repository has dataset
and run-plan assets.

## What is missing

No PROVX source or model artifact is present. There is no live provenance input
pipeline: auditd/auditctl, CamFlow, bpftrace, persistent eBPF event collector,
or DARPA TC/OpTC conversion code. There are no PCAPs or packet-capture
orchestration scripts. Existing Wazuh services are endpoint monitoring, not a
validated PROVX graph source. The current FRESCO run markers are stale after a
VM reboot, and no host-isolated logical-node substrate exists.

Plain Mininet is not sufficient. Its normal host abstraction isolates network
interfaces in a network namespace but shares the host PID/mount/IPC/UTS
context and kernel. Host-level process, file, and socket events therefore do
not carry a unique logical Mininet host identity. IP/MAC/veth correlation can
help packet attribution, but cannot by itself make process and file
provenance unambiguous.

## Install/configure later

1. Select a small VM or microVM per provenance-bearing logical node. Keep the
   Mininet/OVS fabric in a dedicated controller/host VM or a clearly separated
   management context. Record immutable VM UUIDs and map them to
   `logical_host_id`.
2. Inside each node VM, install and configure one supported provenance source
   (auditd/CamFlow/eBPF collector as required by the PROVX implementation) for
   process execution, file access, and socket lifecycle/connection events.
   Preserve raw events before any graph conversion.
3. Add deterministic packet capture on VM vNICs and the OVS/Mininet links with
   synchronized clocks. Use `tcpdump` initially; add a parser only after the
   capture format is fixed.
4. Obtain and pin the PROVX source/model/runtime and its documented input
   schema. Add a conversion step from raw host events to the exact PROVX
   provenance subgraph format; do not substitute packet-only features.
5. Add a run manifest and validator that binds `run_id`, `raw_key`,
   `logical_host_id`, VM UUID, collector session/boot marker, event IDs,
   socket tuple, packet five-tuple/sequence or capture timestamp, graph node
   IDs, and PROVX subgraph IDs. Hash every raw and derived artifact.
6. Reserve disk headroom, compress immutable raw data, and implement per-run
   rotation plus VM snapshot/reset. Retain enough raw data to independently
   recompute the graph and model input.

## Minimum validation before formal execution

- Demonstrate two logical nodes produce disjoint, stable process/file/socket
  identities under the chosen isolation mechanism, including PID reuse and
  simultaneous events.
- Demonstrate a known socket event appears in the node collector, the OVS/VM
  packet capture, the graph conversion output, and the PROVX input subgraph
  with deterministic ordering and bounded timestamp skew.
- Verify all node clocks and record synchronization status in the manifest.
- Verify a complete baseline/defense-on/recovery-style dry run can be reset
  from snapshots without stale namespaces, bridges, processes, or telemetry
  offsets. Do not rely on `mn -c` alone for host provenance reset.
- Validate that the PROVX runtime accepts the generated graph and that its
  output is retained with model/version/configuration hashes. This is a design
  readiness check, not a benchmark execution.
- Obtain explicit privileged execution approval and verify root/sudo access in
  the terminal that will run Mininet, OVS inspection, collectors, and capture.

## Recommended decision

Proceed to E1 design only after the VM-backed (or equivalently validated)
isolation and provenance-input plan is accepted. The current Mininet/OVS base
is reusable, but the environment is presently blocked for a PROVX live-input
experiment.
