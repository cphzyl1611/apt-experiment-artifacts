# PROVX-R7 — Stage-A Partial Provenance Graph Adapter Validation on R5 Benign Evidence

Continue the existing PROVX session.

Pinned latest fixed commit:
`107ef9f69a734a10b320d552cfe18a6cb9a2ac0c`

Pinned Mininet R5 evidence:

collector verdict = PARTIAL_MISSING_REQUIRED_EVENT_CLASS
raw audit records = 108
normalized events = 28
missing class = FILE_READ_OR_WRITE

PROCESS_START_OR_EXEC = 10
PROCESS_EXIT = 4
FILE_CREATE_OR_OPEN = 6
FILE_DELETE = 2
SOCKET_BIND = 4
SOCKET_CONNECT = 1
SOCKET_ACCEPT = 1

logical-host joins = 4/4
namespace assertions = PASS
audit lost events = 0
TCP handshake = PASS

Pinned Track-L:
encoder = provx-adapted-live-v1
dimension = 32
detector trained = NO
formal experiment = NO

## Goal

Use the R5 benign, non-scored runtime evidence as a DEVELOPMENT FIXTURE to
implement and validate deterministic normalized-provenance -> causal graph
-> 32D tensor adaptation for event classes that are actually present.

Result remains PARTIAL because FILE_READ_OR_WRITE is absent.

Do NOT train.

## Requirements

1. Authenticate R5 runtime review, raw audit JSONL, normalized JSONL, PID/netns
   joins, child evidence, coverage/loss and pcap hash.
2. Independently recompute normalized serial -> raw serial and
   normalized raw_event_sha256 -> raw raw_sha256.
   Consume only records passing the recomputation.
3. Record the historical R5 normalized_raw_links_valid boolean discrepancy.
4. Freeze exact graphable normalized-event input schema.
   Missing mandatory identities => quarantine, never guess.
5. Deterministic node types:
   PROCESS, FILE, SOCKET, and OTHER only if existing Track-L schema permits.
6. Deterministic node IDs from source identities, not graph order.
7. Persist reversible graph_node_id -> normalized/raw evidence mapping.
8. Implement only evidence-backed causal edges allowed by R3/R4 Track-L design:
   parent/child process, process-file create/open/delete, process-socket
   bind/connect, accepted socket/process relationships, etc.
9. Do NOT synthesize FILE_READ_OR_WRITE edges.
10. Do NOT use pcap as provenance edge evidence.
11. Freeze run boundary, host boundary, timestamp order, tie breaks, duplicate
    policy, orphan policy, node ordering and edge ordering.
12. Regenerate twice independently and require identical graph hashes.
13. Feed partial graph into existing provx-adapted-live-v1 encoder.
    Verify x float32 [N,32], edge_index int64 [2,E], finite values,
    encoder identity and full hash chain.
14. Do not modify encoder schema or load original packaged 21D checkpoint.
15. Prepare a deterministic revalidation entry point for future E1C-R6 PASS evidence.
16. Full Stage-A collector-adapter PASS MUST remain NO while FILE_READ_OR_WRITE is absent.

## Outputs

- PROVX_R7_R5_EVIDENCE_AUTHENTICATION.json
- PROVX_R7_NORMALIZED_GRAPH_INPUT_SCHEMA.json
- PROVX_R7_NORMALIZED_TO_GRAPH_ADAPTER.py
- PROVX_R7_GRAPH_ADAPTER_TESTS.py
- PROVX_R7_R5_PARTIAL_GRAPH_MANIFEST.json
- PROVX_R7_R5_GRAPH_RAW_REVERSIBILITY.json
- PROVX_R7_R5_32D_TENSOR_MANIFEST.json
- PROVX_R7_DETERMINISTIC_REGENERATION_VERIFICATION.json
- PROVX_R7_E1C_R6_REVALIDATION_CONTRACT.json
- PROVX_R7_STAGE_A_PARTIAL_ADAPTER_REPORT.md

## Hard boundaries

NO detector training.
NO corpus acquisition.
NO FA1B2de actions.
NO formal evaluation.
NO synthetic FILE_READ_OR_WRITE edges.
NO 21D checkpoint load.
NO 32D schema mutation.

## Terminal

PROVX_R7_STAGE_A_PARTIAL_ADAPTER =
PASS_PARTIAL_WAITING_FOR_E1C_R6_FILE_RW | BLOCKED

R5_CONSUMED_NORMALIZED_RECORDS = <n>
R5_RAW_LINK_RECOMPUTATION = PASS | BLOCKED
GRAPH_DETERMINISM = PASS | BLOCKED
GRAPH_TO_32D_TENSOR = PASS | BLOCKED

FILE_READ_OR_WRITE_PRESENT = NO
STAGE_A_FULL_COLLECTOR_ADAPTER_PASS = NO

CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
FORMAL_EXPERIMENT_EXECUTED = NO

NEXT_ACTION =
FRESH_REVIEW_OF_PROVX_R7_STAGE_A_PARTIAL_ADAPTER

STOP = true
