# PROVX-R7 Fresh Independent Review

PROVX_R7_FRESH_INDEPENDENT_REVIEW = PASS_PARTIAL_WAITING_FOR_E1C_R6_FILE_RW
CURRENT_REPOSITORY_COMMIT = 2ff2b21cd313c5b91567adfe05691d3e25aabb87
R5_INPUT_AUTHENTICATION = PASS
R5_RAW_LINK_RECOMPUTATION = PASS
CONSUMED_NORMALIZED_RECORDS = 28
QUARANTINED_NORMALIZED_RECORDS = 6
NODE_COUNT = 10
EDGE_COUNT = 22
GRAPH_RECOMPUTATION = PASS
GRAPH_DETERMINISM = PASS
RAW_NORMALIZED_GRAPH_REVERSIBILITY = PASS
PID_ONLY_CROSS_HOST_MERGE = PASS
ENCODER_32D_INTERFACE = PASS
ENCODER_OUTPUT = {'x_shape': [10, 32], 'x_dtype': 'float32', 'x_finite': True, 'edge_index_shape': [2, 22], 'edge_index_dtype': 'int64'}
GRAPH_SHA256 = b24b424d0e530a9d03c2bf01ed6a193447e3fa75b9725b978d7c27a0998b9acd
TENSOR_X_SHA256 = 605d1e2133589f9ae68d104ac62c2092d1d7238becf2a4cd99f9e7d34b9b621d
EDGE_INDEX_SHA256 = f29e051b027b7fd5eb20b995cf82f5906b2eaceda75dd12c76ebae24c0dabd21
FILE_READ_OR_WRITE_PRESENT = NO
FILE_READ_OR_WRITE_SOURCE_COUNT = 0
SYNTHESIZED_FILE_READ_OR_WRITE_EDGE_COUNT = 0
EDGE_SOURCE_HASH_EVIDENCE = True
STAGE_A_FULL_COLLECTOR_ADAPTER_PASS = NO
CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
PROVX_INFERENCE_EXECUTED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = WAIT_FOR_MININET_E1C_R6_RUNTIME_EVIDENCE
STOP = true

## Independent findings

- The expected repository commit is authenticated and the working tree is clean.
- All 28 normalized records have independently matching serial, decoded-byte, and raw-event SHA-256 links. The historical `normalized_raw_links_valid=false` value is preserved as an artifact-quality discrepancy only.
- Records 697, 698, 699, 700, 701, and 703 are quarantined because their logical host/netns identity is unjoined; no PID-only identity is guessed.
- The independently reconstructed graph has 10 nodes and 22 edges. Every edge maps to normalized event and raw serial evidence; no `FILE_READ_OR_WRITE` edge is synthesized and pcap is not provenance-edge evidence.
- The frozen R4 encoder yields finite `float32` `x` with shape `[10,32]` and `int64` `edge_index` with shape `[2,22]`. Independent graph and reversed-input regeneration hashes match the claimed values.
- The E1C-R6 revalidation contract requires a positive `FILE_READ_OR_WRITE` count before promotion, so this remains a partial PASS awaiting runtime evidence.

## Existing regression tests

R4: `python PROVX_R4_ENCODER_TESTS.py` — return code `0`

R7: `python PROVX_R7_GRAPH_ADAPTER_TESTS.py` — return code `0`
