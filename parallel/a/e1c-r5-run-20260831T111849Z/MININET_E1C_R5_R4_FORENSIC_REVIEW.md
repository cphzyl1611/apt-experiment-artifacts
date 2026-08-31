# MININET-E1C-R5 R4 forensic review

## Pinned source and result

- Fixed review commit: `64854aeb8ad688b4423d600193fa6be5c2cbc390`.
- R4 privileged result is `FAILED` / `BLOCKED` with `RuntimeError: h2 emitted FINISHED before READY`.
- Formal experiment did not execute. R4 raw audit, normalized event, and PID/netns join JSONL files are zero bytes.
- The R4 PCAP is the 24-byte header-only file with SHA256 `704e5e5b3234433c01fcfd1b20a306e77e985038120492dc53965c3edd38a4ea`.

## What is known

- The h2 shell/Popen PID was `598904` in the R4 rule contract and journal.
- Parent `read_ready()` observed a JSON `FINISHED` event before `READY` and raised the generic runtime error.
- In the R4 child source, `FINISHED` is emitted from an unconditional `finally` block. No `CHILD_ERROR` event was implemented.
- The R4 source calls `socket.socket`/`socket.create_connection` without importing `socket`; this is a code-level candidate for the failure, but it is not promoted to the exact runtime exception because R4 did not persist stderr or a traceback.
- R4 cleanup removed all run rules and restored the historical empty audit baseline; child, topology, OVS-delta, and tcpdump residue were zero. Pre-existing OVS daemons were excluded from run-owned state.
- R4 audit loss and backlog were both zero.

## What is unknown

- h2 stderr, complete stdout history, return code, exact failing stage, and exception are absent from R4 artifacts.
- Temp-file create/write/read success cannot be established: the child unlinks the temp file in `finally`, and no operation log was persisted.
- No `READY` event means there is no evidence of a successful h2 bind/listen, getsockname, or interface-address snapshot.
- No live post-exec child PID/netns identity or logical-host join was persisted.

Therefore:

`R4_CHILD_FAILURE_EXACT_EXCEPTION = NOT_RECOVERABLE_FROM_R4_EVIDENCE`

R5 adds durable parent failure diagnostics, explicit child states, `CHILD_ERROR`, listener diagnostics, and live post-exec identity validation before formal smoke logic.
