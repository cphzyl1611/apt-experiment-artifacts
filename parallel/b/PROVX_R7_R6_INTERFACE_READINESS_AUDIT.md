# PROVX-R7 / Mininet E1C-R6 Interface Readiness Quick Audit

PROVX_R7_E1C_R6_INTERFACE_READINESS = BLOCKED
CURRENT_HEAD = 6842f28151dce9f57e451ab5ba3b6b86f1a906d1
AB0D016_IS_ANCESTOR = YES

R6_REQUIRED_OUTPUT_PATHS = PASS
R6_NORMALIZED_SCHEMA_COMPATIBILITY = PASS
RAW_LINK_COMPATIBILITY = PASS
PID_NETNS_JOIN_COMPATIBILITY = PASS
FILE_READ_OR_WRITE_ADAPTER_COMPATIBILITY = BLOCKED
FROZEN_32D_ENCODER_CHANGE_REQUIRED = NO

RUNTIME_EVIDENCE_PRESENT = NO
STAGE_A_FULL_COLLECTOR_ADAPTER_PASS = NO

CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
PROVX_INFERENCE_EXECUTED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
PUSH_EXECUTED = NO

NEXT_ACTION = REMEDIATE_R6_PROVX_INTERFACE
STOP = true

## Scope and authentication

This was a read-only QUICK_REVIEW. HEAD was authenticated as `6842f28151dce9f57e451ab5ba3b6b86f1a906d1`; `ab0d0161189ee7c98cd4eb2810cd2341de37f341` is its merge-base and is therefore an ancestor. The R6 producer, pre-run contract, file-access semantics contract, and existing R7 revalidation contract were read from committed `parallel/a`/`parallel/b` blobs. Concurrent Binding changes were preserved; nothing was staged, pushed, or modified in that checkout.

The R6 run directory currently contains only the producer/test sources. No privileged result, raw JSONL, normalized JSONL, PID/netns join JSONL, coverage/loss output, pcap, or runtime report exists. No runtime evidence has been invented.

## Required output-path crosswalk

The committed R6 producer declares paths for:

- `MININET_E1C_R6_PRIVILEGED_RUN_RESULT.json` and `MININET_E1C_R6_AUDITD_SMOKE_REPORT.md` (fresh runtime result/review);
- `MININET_E1C_R6_RAW_AUDIT_EVIDENCE.jsonl`;
- `MININET_E1C_R6_NORMALIZED_EVENTS.jsonl`;
- `MININET_E1C_R6_PID_NETNS_JOIN.jsonl`;
- `MININET_E1C_R6_COVERAGE_AND_LOSS_AUDIT.json`;
- `MININET_E1C_R6_SMOKE.pcap`, with `pcap_sha256` written into coverage and post-cleanup evidence.

These paths mechanically cover every input required by `PROVX_R7_E1C_R6_REVALIDATION_CONTRACT_V1`. The full crosswalk and committed-source hashes are in [PROVX_R7_R6_INTERFACE_FIELD_CROSSWALK.json](/home/cph/experiment-parallel/e0-b/PROVX_R7_R6_INTERFACE_FIELD_CROSSWALK.json) and [PROVX_R7_R6_INTERFACE_INPUT_AUTHENTICATION.json](/home/cph/experiment-parallel/e0-b/PROVX_R7_R6_INTERFACE_INPUT_AUTHENTICATION.json).

## Normalized schema compatibility

The R6 normalizer retains all R7 common identity/evidence fields: `run_id`, stable `event_id`, `event_type`, `raw_serial`, `raw_event_sha256`, `timestamp_source`, `pid`, `pid_start_time_ticks`, `ppid`, `logical_host_id`, `netns_inode`, and `join_status`. It also retains process executable data, file paths/`file_identity.paths`, socket family/endpoints, and exact raw bytes/hash material for later authentication.

`FILE_READ_OR_WRITE` rows additionally carry `evidence_basis=AUDIT_FILESYSTEM_PERMISSION_FILTER`, `watched_path`, `requested_access`, and `underlying_syscall`. The permission filter is bounded to one exact pre-created file and one live child PID; the syscall is retained as evidence and is not inferred from the permission filter. This is sufficient input material, so `R6_NORMALIZED_SCHEMA_COMPATIBILITY = PASS` and `RAW_LINK_COMPATIBILITY = PASS`/`PID_NETNS_JOIN_COMPATIBILITY = PASS`.

## Deterministic adapter incompatibility

The current R7 adapter has a concrete gap:

1. `_event_class()` maps the existing R5 classes but has no `FILE_READ_OR_WRITE` case, so its fallback is `other`.
2. The graph file-entity branch handles only `FILE_CREATE_OR_OPEN` and `FILE_DELETE`.
3. A future R6 `FILE_READ_OR_WRITE` row therefore falls through to the process-event path and is emitted as a process self-loop with class `other`, rather than a host-scoped file edge with class `write`.

There is a second deterministic wiring gap: the current R7 ingestion function is `authenticate_r5_evidence`, with hardcoded R5 run ID and R5 filenames. R6’s output names and run ID are distinct, and the existing adapter has no R6 input-path route. Together these make `FILE_READ_OR_WRITE_ADAPTER_COMPATIBILITY = BLOCKED`. This is a deterministic source/interface mismatch, not a claim about an absent runtime. The frozen R4 encoder already has the `write` event rank and `event_write_norm` feature (index 21), so `FROZEN_32D_ENCODER_CHANGE_REQUIRED = NO`. The required remediation is an explicit R7 adapter input/path and event-to-edge mapping contract; this quick audit does not implement it because adapter semantics are binding and the user instructed local artifacts only.

## Promotion and stopping rule

The existing promotion rule remains intact: Stage-A full collector-adapter PASS stays NO until actual R6 runtime evidence contains `FILE_READ_OR_WRITE > 0` and every revalidation gate passes. Because the static interface gap is present, the quick-audit terminal is `BLOCKED` and the next action is `REMEDIATE_R6_PROVX_INTERFACE`. No graph or tensor was regenerated, and no training, inference, formal experiment, or push was performed.
