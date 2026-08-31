# MININET-E1B Primary Collector Decision

## Decision

`MININET_E1B_COLLECTOR_DECISION = AUDITD_PRIMARY_CANDIDATE`

`COLLECTOR_INSTALLED_AND_READY = NO`

Auditd is the smallest defensible primary candidate for the Mininet-based PROVX extension. The decision is conditional on human-approved installation and a bounded benign smoke run; it is not a claim that a collector is currently ready.

## Evidence Basis

E1A-R2 is pinned to the corrected harness SHA-256 `129bc1b10486e3f23c37d7b3386f7dfeebc108a7b29a25f493809391fd070e90`, runtime result SHA-256 `43c769bdf1c074c9456aeba7d3d2d6737b592891234cc541de2a4907345c58e1`, runtime-validation SHA-256 `f50a771931e51b9bb37980a5e2619069da2ff92c374e311aaab0c0fb41e83c2c`, attribution-report SHA-256 `e265a6a3dab4ee0dc41ecbcfb479448e31ec4c51ebdbc5f21281274a01f19a44`, and PCAP SHA-256 `184b030eb86881bd7e0b08fce1e2d2a22731af85e806cc66f0951dd9592b7e50`.

The verified cleanup assertions are:

```text
RUN_OWNED_CHILDREN_REMAINING = 0
RESERVED_TEST_INTERFACES_REMAINING = 0
RESERVED_TEST_OVS_OBJECTS_REMAINING = 0
TCPDUMP_PROCESS_REMAINING = 0
```

The R2 run demonstrated that the exact child PID can be joined to `/proc/<pid>/ns/net`, the owning Mininet shell namespace, the logical interface, live `/proc/net/tcp` and `ss` socket ownership, file-event PID, and bounded packet endpoints. That join is the required foundation for collector normalization.

## Local Collector Inventory

- `auditd`, `auditctl`, `ausearch`, and `aureport` are absent; the `auditd` service is inactive; `/etc/audit` and `/var/log/audit` are absent.
- The local Ubuntu Jammy package index provides `auditd=1:3.0.7-1build1`, and the running kernel has `CONFIG_AUDIT=y` and `CONFIG_AUDITSYSCALL=y`.
- `bpftool v7.4.0`, `perf`, `libbpf0`, tracefs, and BPF kernel support are present, but no bpftrace/BCC collector or BPF program is installed. Unprivileged BPF is disabled and `perf_event_paranoid=4`.
- CamFlow is absent with no local package record or event schema.
- `strace 5.16` is installed and will remain a development/validation oracle, not the formal collector.
- Wazuh services are active, but no persistent process/file/socket provenance stream or netns/logical-host binding is available. Filebeat's auditd module is disabled and `/var/log/audit` is missing.

## Why Auditd

Auditd is the smallest standard Ubuntu component that can cover the required process lifecycle and configured file/socket syscall families, preserve raw kernel audit records, expose loss/backlog status, and provide deterministic timestamps/serials. It still requires an explicit bounded rule set and a synchronized `/proc/<pid>/ns/net` join; those are prerequisites for the smoke design, not assumptions.

eBPF could ultimately provide lower-overhead, richer semantics, but selecting it now would mean selecting an unimplemented collector rather than an installed capability. CamFlow has no local evidence. Strace is scoped and high-overhead. Wazuh is not a unified provenance stream.

## Human Installation Gate

The exact package/version is:

`auditd=1:3.0.7-1build1`

The exact human command is stored in [MININET_E1B_HUMAN_INSTALL_COMMAND.txt](/home/cph/experiment-parallel/e0-a/MININET_E1B_HUMAN_INSTALL_COMMAND.txt). It has not been run automatically.

After installation, the next bounded step is a human-approved benign collector smoke design. No audit rules were changed in this selection step.

`NEXT_ACTION = HUMAN_INSTALL_APPROVAL`

`FORMAL_EXPERIMENT_EXECUTED = NO`

`STOP = true`
