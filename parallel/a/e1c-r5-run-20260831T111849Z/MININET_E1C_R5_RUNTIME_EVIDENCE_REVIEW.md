# MININET-E1C-R5 independent runtime evidence review

Run `e1c-r5-run-20260831T111849Z` completed (`runtime_error = null`, formal experiment not executed); the observed human shell exit code was 3.

`MININET_E1C_R5_AUDITD_COLLECTOR = PARTIAL_MISSING_REQUIRED_EVENT_CLASS`

The exact runtime cause is a collector limitation: `FILE_READ_OR_WRITE` remained absent. The bounded syscall probe records `pread64` and `pwrite64` as unsupported (`Syscall name unknown`); no `FILE_READ_OR_WRITE` event was normalized. This missing class is not inferred from tcpdump or strace (`STRACE_ORACLE_COMPARISON = NOT_RUN`).

Audit state was clean at start and restored after R5. The pinned auditd package remained `auditd=1:3.0.7-1build1`; start and end rule-dump SHA256 are both `61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87`. No old residual rules were found or removed, legacy cleanup was false, transient rules were removed (80 successful adds and 80 successful removals), and lost/backlog counters were both zero.

Normalized class counts were: `PROCESS_START_OR_EXEC=10`, `PROCESS_EXIT=4`, `FILE_CREATE_OR_OPEN=6`, `FILE_READ_OR_WRITE=0`, `FILE_DELETE=2`, `SOCKET_BIND=4`, `SOCKET_CONNECT=1`, and `SOCKET_ACCEPT=1`. There were 108 raw records and 28 normalized events, all raw serials unique and all raw hashes independently recomputed.

All namespace assertions are `PASS`:

- `h1_child_netns == h1_shell_netns`
- `h2_child_netns == h2_shell_netns`
- `h1_child_netns != h2_shell_netns`
- `h2_child_netns != h1_shell_netns`

The four PID/netns joins succeeded with zero recorded join failures. Post-exec identity and child/netns evidence were captured while each child was alive. Listener `/proc/<pid>/net/tcp` and `ss` ownership evidence were captured while both listeners were alive. Both children completed all eight protocol states through `FINISHED`, returned 0, emitted no `CHILD_ERROR`, and had zero early-child failures.

The intended same TCP port was used in both distinct namespaces (`18080`), and the handshake completed. tcpdump ran within the bounded topology lifetime. The PCAP exists with SHA256 `78f32b500600739b5a67111b6f7566f76139d6bb491c4105b887ea17f9951e86`.

Post-cleanup invariants are all zero: `RUN_OWNED_CHILDREN_REMAINING=0`, `RESERVED_TEST_INTERFACES_REMAINING=0`, `RESERVED_TEST_OVS_OBJECTS_REMAINING=0`, and `TCPDUMP_PROCESS_REMAINING=0`. External/NAT attachment, APT, PROVX, formal benchmark execution, and `mn -c` are all recorded false; pre-existing OVS daemons were excluded.

One artifact-quality discrepancy is preserved without modifying runtime evidence: coverage declares `normalized_raw_links_valid=false`, while independent checks match all 28 normalized `raw_serial` values and all 28 decoded `raw_event_bytes_b64` SHA256 values to the raw records (`raw_event_sha256` versus raw `raw_sha256`).

The machine-readable recomputation and SHA256 manifest are in `MININET_E1C_R5_RUNTIME_EVIDENCE_REVIEW.json`.
