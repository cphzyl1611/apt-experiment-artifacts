# PROVX R7R1 R6 Interface Remediation Targeted Fresh Review

Review date: September 1, 2026. This is a read-only independent review of committed remediation bytes at `cde75a82e7938db6d5903d16885bf35ceb17aa68`, with historical base `d304a8dbbe41a0f4aae8d9cf3047a5fec7044b13`.

The authenticated repository origin is `https://github.com/cphzyl1611/apt-experiment-artifacts.git`. The pinned commit is current `main` HEAD, exists, and has the historical base as its parent. The delta contains fifteen files: nine E0-B files listed in `R7R1_FRESH_INPUT_AUTHENTICATION.json` and six unrelated Binding fresh-review files. No frozen encoder source or committed `__pycache__`/`.pyc` was introduced by the cde E0-B delta.

The original defect was recomputed from the two commit trees. At `d304`, valid joined non-R5 `FILE_READ_OR_WRITE` events for `/tmp/r6-bound-file` on `h1` and `h2` produced one `path:/tmp/r6-bound-file` FILE node. At `cde`, the same inputs produced distinct `host:h1|path:/tmp/r6-bound-file` and `host:h2|path:/tmp/r6-bound-file` nodes, with `PROCESS -> FILE` edges classified as `write`. R5 remains path-scoped.

Fresh R5 regeneration matched the required counts and hashes: 28 consumed, 6 quarantined, 10 nodes, 22 edges; graph `b24b424d0e530a9d03c2bf01ed6a193447e3fa75b9725b978d7c27a0998b9acd`, tensor-X `605d1e2133589f9ae68d104ac62c2092d1d7238becf2a4cd99f9e7d34b9b621d`, and edge-index `f29e051b027b7fd5eb20b995cf82f5906b2eaceda75dd12c76ebae24c0dabd21`. Reversed-input regeneration was hash-identical.

Synthetic schema-only fixtures independently passed explicit descriptor binding, selected-file authentication, raw-to-normalized linkage, PCAP fail-closed behavior, run-ID and PID/netns/logical-host joins, exact permission-filter evidence, exact watched path, `PROCESS -> FILE`/`write` mapping, host-scoped non-R5 identity, and quarantine/rejection of missing or inconsistent evidence. These fixtures are explicitly `NOT_RUNTIME_EVIDENCE`.

The frozen 32D encoder implementation bytes are unchanged. No detector checkpoint was loaded, no training or PROVX inference was executed, no Mininet or sudo was run, and no formal experiment was executed. The historical reviewer pinned to `2ff2b21cd313c5b91567adfe05691d3e25aabb87` is not applicable to this continuation and was not rewritten.

Fresh committed suites passed: R7R1 fixture tests `12/12`, existing R7 adapter tests `5/5`, frozen encoder tests `7/7`, combined `24/24`; `py_compile`, whitespace checking, and JSON validation passed. No push was executed.

```text
PROVX_R7R1_R6_INTERFACE_REMEDIATION_TARGETED_FRESH_REVIEW =
PASS_READY_FOR_AUTHENTICATED_R6_RUNTIME_INPUT

PINNED_REMEDIATION_COMMIT = cde75a82e7938db6d5903d16885bf35ceb17aa68
COMMIT_AUTHENTICATION = PASS
E0B_SCOPE_ISOLATION = PASS

ORIGINAL_CROSS_HOST_COLLISION_REPRODUCED = YES
R5_LEGACY_FILE_IDENTITY_PRESERVED = PASS
R6_HOST_SCOPED_FILE_IDENTITY = PASS
CROSS_HOST_SAME_PATH_COLLISION_CLOSED = PASS

R5_COUNTS_NON_REGRESSION = PASS
R5_GRAPH_HASH_NON_REGRESSION = PASS
R5_TENSOR_HASH_NON_REGRESSION = PASS
R5_EDGE_INDEX_HASH_NON_REGRESSION = PASS

R6_EXPLICIT_RUNTIME_DESCRIPTOR = PASS
R6_FILE_READ_OR_WRITE_MAPPING = PASS
RAW_LINK_FAIL_CLOSED = PASS
PCAP_AUTH_FAIL_CLOSED = PASS
PID_NETNS_JOIN_FAIL_CLOSED = PASS

FROZEN_32D_ENCODER_CHANGED = NO
RUNTIME_EVIDENCE_PRESENT = NO
DETECTOR_TRAINED = NO
PROVX_INFERENCE_EXECUTED = NO
FORMAL_EXPERIMENT_EXECUTED = NO

PUSH_EXECUTED = NO

NEXT_ACTION =
WAIT_FOR_AUTHENTICATED_MININET_R6_RUNTIME_EVIDENCE

STOP = true
```
