# PROVX-R7 Stage-A Partial Adapter Fresh Independent Review

Run configuration:
- Tool: Codex
- Model: GPT-5.6 Sol
- Reasoning effort: xhigh
- New session: YES

Repository:
https://github.com/cphzyl1611/apt-experiment-artifacts.git

Expected current main:
2ff2b21cd313c5b91567adfe05691d3e25aabb87

Review directory:
parallel/b/

Claimed terminal:
PROVX_R7_STAGE_A_PARTIAL_ADAPTER = PASS_PARTIAL_WAITING_FOR_E1C_R6_FILE_RW
R5_CONSUMED_NORMALIZED_RECORDS = 28
R5_RAW_LINK_RECOMPUTATION = PASS
GRAPH_DETERMINISM = PASS
GRAPH_TO_32D_TENSOR = PASS
FILE_READ_OR_WRITE_PRESENT = NO
STAGE_A_FULL_COLLECTOR_ADAPTER_PASS = NO
Nodes = 10
Edges = 22
Quarantined normalized records = 6
CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
FORMAL_EXPERIMENT_EXECUTED = NO

Claimed hashes:
Graph = b24b424d0e530a9d03c2bf01ed6a193447e3fa75b9725b978d7c27a0998b9acd
Tensor x = 605d1e2133589f9ae68d104ac62c2092d1d7238becf2a4cd99f9e7d34b9b621d
Edge index = f29e051b027b7fd5eb20b995cf82f5906b2eaceda75dd12c76ebae24c0dabd21

Perform only:
PROVX_R7_STAGE_A_PARTIAL_ADAPTER_FRESH_INDEPENDENT_REVIEW

Requirements:
1. Authenticate current commit and all R5 evidence consumed by R7.
2. Independently recompute all 28 normalized-to-raw serial/hash links.
3. Verify six quarantined records are legitimately excluded under frozen identity requirements.
4. Independently reconstruct canonical entities/edges without calling builder decision functions.
5. Verify no PID-only cross-host merge and every edge has reversible source evidence.
6. Verify no FILE_READ_OR_WRITE edge is synthesized and pcap is not provenance-edge evidence.
7. Recompute node, edge and quarantine counts.
8. Independently recompute graph hash and deterministic regeneration.
9. Re-run frozen 32D encoder interface; verify x [N,32] float32 finite and edge_index [2,E] int64.
10. Independently recompute graph/tensor/edge-index hashes.
11. Preserve historical normalized_raw_links_valid=false as an artifact-quality discrepancy only.
12. Verify E1C-R6 revalidation contract does not promote R7 to full PASS while FILE_READ_OR_WRITE is absent.
13. Re-run existing R4/R7 tests.

Do not:
- train detector;
- acquire corpus;
- run inference;
- run formal experiment;
- synthesize FILE_READ_OR_WRITE;
- load original 21D checkpoint;
- modify R7 outputs.

Create separate fresh-review artifacts.

Terminal:
PROVX_R7_FRESH_INDEPENDENT_REVIEW =
PASS_PARTIAL_WAITING_FOR_E1C_R6_FILE_RW | BLOCKED
CURRENT_REPOSITORY_COMMIT = <sha>
R5_INPUT_AUTHENTICATION = PASS | BLOCKED
R5_RAW_LINK_RECOMPUTATION = PASS | BLOCKED
CONSUMED_NORMALIZED_RECORDS = <n>
QUARANTINED_NORMALIZED_RECORDS = <n>
NODE_COUNT = <n>
EDGE_COUNT = <n>
GRAPH_RECOMPUTATION = PASS | BLOCKED
GRAPH_DETERMINISM = PASS | BLOCKED
RAW_NORMALIZED_GRAPH_REVERSIBILITY = PASS | BLOCKED
ENCODER_32D_INTERFACE = PASS | BLOCKED
GRAPH_SHA256 = <sha>
TENSOR_X_SHA256 = <sha>
EDGE_INDEX_SHA256 = <sha>
FILE_READ_OR_WRITE_PRESENT = NO
STAGE_A_FULL_COLLECTOR_ADAPTER_PASS = NO
CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
PROVX_INFERENCE_EXECUTED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION =
WAIT_FOR_MININET_E1C_R6_RUNTIME_EVIDENCE | REMEDIATE_PROVX_R7
STOP = true
