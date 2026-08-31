# MININET-E1A-R2 Attribution Feasibility Report

## Decision

`PLAIN_MININET_ATTRIBUTION_FEASIBLE`

The R2 runtime evidence independently supports the mapping:

`event process -> process netns -> logical Mininet host netns -> logical_host_id`

The privileged harness was not rerun during this review. No PROVX, APT, formal benchmark, external/NAT attachment, or `mn -c` action was performed.

## Exact Host Attribution

| Logical host | Host shell PID | Child PID | Host shell netns | Child netns | Interface | Listener |
|---|---:|---:|---|---|---|---|
| `h1` | 554185 | 554254 | `net:[4026532665]` | `net:[4026532665]` | `h1-eth0`, `10.0.0.1` | `10.0.0.1:18080` |
| `h2` | 554187 | 554255 | `net:[4026532826]` | `net:[4026532826]` | `h2-eth0`, `10.0.0.2` | `10.0.0.2:18080` |

All four mandatory namespace relations evaluate true. The two child netns values are distinct.

For each host, evidence capture occurred after the child's `READY` event and before its `FINISHED` event. The child PID is consistent across the ready event, `/proc` status, socket evidence, file evidence, and finished event.

## Socket And Packet Evidence

Both children simultaneously listened on TCP port `18080` in their distinct network namespaces:

- `h1`: `/proc/554254/net/tcp` recorded LISTEN state `0A`, inode `2305693`; fd 5 targets that inode, and `ss` identifies the exact PID, fd, address, and port.
- `h2`: `/proc/554255/net/tcp` recorded LISTEN state `0A`, inode `2308281`; fd 5 targets that inode, and `ss` identifies the exact PID, fd, address, and port.

Both TCP exchanges succeeded. The pcap independently decodes to 58 bounded records containing bidirectional ICMP and TCP flows to port `18080` at both `10.0.0.1` and `10.0.0.2`. Negative BPF decoding finds zero packets outside `10.0.0.0/24` and zero packets outside the exact bounded capture filter.

The pcap exists at `e1a-r2-run-20260830T060231Z/MININET_E1A_R2_BENIGN_TRAFFIC.pcap`. Its recorded and recomputed SHA-256 values both equal:

`184b030eb86881bd7e0b08fce1e2d2a22731af85e806cc66f0951dd9592b7e50`

Harness source order and runtime process start ticks place tcpdump after topology creation, before the child traffic, and before `net.stop()` at shutdown. The capture exited with status 0 and reported 58 captured, 0 dropped.

The two live-attribution JSONL rows exactly reproduce each host's shell, socket/process, and file-event evidence under the matching `logical_host_id`. Packet endpoints correlate to the recorded logical interfaces and listener addresses.

## Cleanup Verification

The recorded cleanup values are:

```text
RUN_OWNED_CHILDREN_REMAINING = 0
RESERVED_TEST_INTERFACES_REMAINING = 0
RESERVED_TEST_OVS_OBJECTS_REMAINING = 0
TCPDUMP_PROCESS_REMAINING = 0
```

Independent current-state queries also found none of the known run PIDs, no matching run process, no reserved test interface, and no reserved OVS bridge, Interface, or Port row. Pre-existing OVS daemon PIDs 841 and 907 were correctly excluded from run-owned state.

The topology contract and static command inventory show no NAT or external attachment. The pcap contains only test-network endpoints. `broad_cleanup_executed` is false, and neither the harness source nor its command inventory contains `mn -c`.

## Scope Limits

The child cgroups are identical, so cgroup identity does not distinguish `h1` from `h2`; network namespace identity does. File operations are PID-attributed but do not prove filesystem isolation. Capture on `any` uses Linux cooked capture and duplicates some records, but the endpoint, namespace, interface, and socket ownership correlation remains intact.

Machine-readable validation is in `MININET_E1A_R2_RUNTIME_EVIDENCE_VALIDATION.json`.

`NEXT_ACTION = FRESH_INDEPENDENT_REVIEW`

`STOP = true`
