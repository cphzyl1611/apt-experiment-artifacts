# PROVX R7R1 / R6 Interface Remediation Continuation

This local-only remediation closes the deterministic non-R5 FILE-identity gap found after the partial R7R1 implementation at `d304a8dbbe41a0f4aae8d9cf3047a5fec7044b13` was authenticated as both local `HEAD` and `origin/main` on September 1, 2026.

The regression reproduced two valid synthetic `FILE_READ_OR_WRITE` events with the same path on joined hosts `h1` and `h2`. Before this change both produced `path:/tmp/r6-bound-file`, which merged two hosts into one FILE node. The adapter now applies one explicit compatibility split:

- Historical R5 retains `path:<canonical-path>` exactly.
- Every non-R5 route uses `host:<logical-host>|path:<canonical-path>`.

The R6 mapping remains `PROCESS -> FILE` with the unchanged frozen encoder class `write`. It requires joined host/PID/netns identity, exact file identity matching the watched path, raw serial and raw-event-hash evidence, and `AUDIT_FILESYSTEM_PERMISSION_FILTER`; absent or inconsistent evidence quarantines or rejects input.

## Verification

- The new R7R1 fixture suite passed 12 tests, including the formerly failing same-path/different-host regression.
- Existing R7 adapter tests passed 5 tests; frozen R4 encoder tests passed 7 tests.
- Static compilation and `git diff --check` passed.
- Fresh R5 regeneration remained byte-identical: 28 consumed, 6 quarantined, 10 nodes, 22 edges; graph, tensor-X, and edge-index hashes all match the pinned values.

The historical fresh-review test harness was executed but is not applicable to this continuation: it is intentionally pinned to commit `2ff2b21cd313c5b91567adfe05691d3e25aabb87`, not authenticated current main `d304a8dbbe41a0f4aae8d9cf3047a5fec7044b13`. Its R5 constants were independently rechecked here; the harness itself was not rewritten.

No Mininet or privileged R6 command was run. The R6 records are temporary schema-only fixtures explicitly marked `NOT_RUNTIME_EVIDENCE`; no R6 runtime pass, graph, tensor, inference, detector training, corpus acquisition, or formal experiment was produced.

```text
PROVX_R7R1_R6_INTERFACE_REMEDIATION =
PASS_READY_FOR_TARGETED_FRESH_REVIEW

CURRENT_HEAD = d304a8dbbe41a0f4aae8d9cf3047a5fec7044b13
D304_PARTIAL_IMPLEMENTATION_AUTHENTICATION = PASS

R5_COMPATIBILITY_ROUTE = PASS
R5_GRAPH_HASH_NON_REGRESSION = PASS
R5_TENSOR_HASH_NON_REGRESSION = PASS
R5_EDGE_INDEX_HASH_NON_REGRESSION = PASS

R6_EXPLICIT_RUNTIME_DESCRIPTOR = PASS
R6_FILE_READ_OR_WRITE_MAPPING = PASS
R6_HOST_SCOPED_FILE_IDENTITY = PASS
CROSS_HOST_SAME_PATH_COLLISION_TEST = PASS
RAW_LINK_FAIL_CLOSED = PASS
PCAP_AUTH_FAIL_CLOSED = PASS
PID_NETNS_JOIN_FAIL_CLOSED = PASS

FROZEN_32D_ENCODER_CHANGED = NO
RUNTIME_EVIDENCE_PRESENT = NO
DETECTOR_TRAINED = NO
PROVX_INFERENCE_EXECUTED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
PUSH_EXECUTED = NO

NEXT_ACTION = TARGETED_FRESH_REVIEW_OF_PROVX_R7R1

STOP = true
```
