# MININET-E1A Logical-Host Provenance Attribution Feasibility

## Scope and safety

This was a benign, non-scored feasibility attempt continuing from E0-A. The
requested topology was one OVS switch (`s1`) and two stable Mininet hosts
(`h1=10.0.0.1/24`, `h2=10.0.0.2/24`, deterministic MACs), with no controller,
NAT, Internet, or external interface. The harness actions were limited to
process PID markers, temporary-file create/read/delete, `pingAll`, and a
one-second loopback TCP listener. No APT action, PROVX execution, benchmark
score, binding-authority mutation, scoring-authority mutation, package
installation, Git-ref mutation, or broad cleanup occurred.

## Fresh pre-state

Pre-state is recorded in `MININET_E1A_PRE_STATE.json` and the raw run copy
`e1a-run-20260829/MININET_E1A_PRE_STATE.json`. The host is
`UBU-MONITOR01`, boot ID `b5116b9e-9bef-4c8b-a02a-be618de984de`, with only
`lo` and VMware-NAT `ens33` active. Named network namespaces are empty. OVS
daemons are pre-existing (`ovsdb-server` PID 841 and `ovs-vswitchd` PID 907),
but unprivileged `ovs-vsctl` cannot read the OVS database socket. The relevant
Git repositories were inspected read-only; existing local changes were
preserved.

## Smoke-test result

The exact harness command was attempted as the current user:

```text
/usr/bin/python3 /home/cph/experiment-parallel/e0-a/e1a-run-20260829/e1a_benign_topology.py
```

It exited before constructing any Mininet object with:

```text
*** Mininet must run as root.
```

The installed Mininet source confirms the cause: `Mininet.__init__` calls
`Mininet.init()`, which calls `ensureRoot()` and exits for any UID other than
0. Therefore no host shell PID, descendant process, netns inode, interface
mapping, socket tuple, ping result, or benign file-event observation exists
for this run. The run result is `not_started`, not a failed attack or network
experiment.

## What the installed implementation can and cannot establish

The source inspection provides a conditional attribution design, but not a
smoke-test proof:

- `Host` defaults to `inNamespace=True`.
- `Node.startShell()` appends `-n` to `mnexec` and records the shell PID in
  `self.pid`.
- `Node.popen()` uses `mnexec -da <host.pid>` for descendants. A collector
  that records the event PID and `/proc/<pid>/ns/net` inode while the process
  exists could map the event to the host shell's netns inode and then to
  `h1` or `h2`.
- `privateDirs` is already supported, but it performs privileged
  `mount --bind` or `mount -n -t tmpfs` operations. It can change a directory
  view for benign temp files; it does not provide a new kernel/process context
  and filesystem isolation is not claimed here.
- A file path alone cannot identify a logical host. Process PID plus netns
  metadata, a persistent PID/namespace observation, or an equivalent cgroup
  record is required. PID reuse and post-exit attribution must be explicitly
  validated.

Thus the property `event process -> exact logical Mininet host` is
conditionally plausible for a collector that captures process/netns metadata,
but it was not established by this run. No host-level auditd/CamFlow/eBPF
collector is installed, so there is also no provenance event to compare with
the process metadata.

## Packet-correlation subgate

No capture was attempted because the topology could not start and passwordless
sudo is unavailable. The exact commands for a human terminal are recorded in
`MININET_E1A_PACKET_CORRELATION.json`:

```text
sudo /usr/bin/python3 /home/cph/experiment-parallel/e0-a/e1a-run-20260829/e1a_benign_topology.py
sudo timeout 20s tcpdump -i any -nn -tttt -w /home/cph/experiment-parallel/e0-a/e1a-run-20260829/benign-topology.pcap '(net 10.0.0.0/24 or (host 127.0.0.1 and tcp))'
```

The second command is a capture recipe only; no `.pcap` was created in E1A.
It must be run in a controlled terminal during a human-approved benign run,
with the resulting interface, socket tuple, timestamp, and run ID recorded.

## Cleanup audit

Because the harness exited before topology creation, no run process or network
object required cleanup. Post-state is recorded in
`MININET_E1A_POST_CLEANUP_AUDIT.json` and the raw
`e1a-run-20260829/post_cleanup_state.json`: only the pre-existing `lo` and
`ens33` interfaces remain, named namespaces remain empty, and no Mininet/test
process remains. `mn -c` was not executed, and no stale run state was created.

## Decision

The correct E1A outcome is **`BLOCKED`**. Evidence is insufficient to choose
either plain-Mininet feasibility or a container substrate requirement: the
required benign topology, descendant, socket, file, and packet observations
could not run without root, and no live provenance collector is available.
Do not jump directly to VM-per-node or container adoption from this result.
First obtain approved privileged execution and repeat this exact benign
subgate, then review whether process-PID plus netns-inode attribution remains
stable under simultaneous commands, PID reuse, socket creation, and file
events.

```text
MININET_E1A_ATTRIBUTION_VERDICT = BLOCKED
ATTACK_ACTIONS_EXECUTED = 0
PROVX_EXECUTED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_MININET_E1A_ATTRIBUTION_FEASIBILITY
STOP = true
```
