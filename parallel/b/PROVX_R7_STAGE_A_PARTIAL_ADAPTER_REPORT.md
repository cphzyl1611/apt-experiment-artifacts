# PROVX-R7 Stage-A Partial Adapter Report

PROVX_R7_STAGE_A_PARTIAL_ADAPTER = PASS_PARTIAL_WAITING_FOR_E1C_R6_FILE_RW

R5_CONSUMED_NORMALIZED_RECORDS = 28
R5_RAW_LINK_RECOMPUTATION = PASS
GRAPH_DETERMINISM = PASS
GRAPH_TO_32D_TENSOR = PASS

FILE_READ_OR_WRITE_PRESENT = NO
STAGE_A_FULL_COLLECTOR_ADAPTER_PASS = NO

Nodes: 10
Edges: 22
Quarantined normalized records: 6
Graph SHA-256: `b24b424d0e530a9d03c2bf01ed6a193447e3fa75b9725b978d7c27a0998b9acd`
Tensor x SHA-256: `605d1e2133589f9ae68d104ac62c2092d1d7238becf2a4cd99f9e7d34b9b621d`
Edge index SHA-256: `f29e051b027b7fd5eb20b995cf82f5906b2eaceda75dd12c76ebae24c0dabd21`

The historical R5 `normalized_raw_links_valid=false` declaration is retained as an artifact-quality discrepancy. Independent serial, decoded-byte, and raw-hash recomputation passed for every consumed record. Unjoined `ip` helper records and records missing mandatory identity are quarantined; no identity is guessed. FILE_READ_OR_WRITE edges are not synthesized, and pcap is not used as provenance edge evidence.

CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
FORMAL_EXPERIMENT_EXECUTED = NO

NEXT_ACTION = FRESH_REVIEW_OF_PROVX_R7_STAGE_A_PARTIAL_ADAPTER
