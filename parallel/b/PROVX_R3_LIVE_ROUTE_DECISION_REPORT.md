# PROVX-R3 Live Route Decision Report

## Outcome

```text
PROVX_R3_FEATURE_VOCABULARY = OFFICIAL_21_FEATURE_VOCABULARY_NOT_AVAILABLE
PACKAGED_CHECKPOINT_DIRECT_LIVE_MININET_USE = NOT_VALIDATED
LIVE_PROVX_ROUTE = PROVX_ADAPTED_LIVE_DEPLOYMENT
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_PROVX_R3_LIVE_ROUTE_DECISION
STOP = true
```

The search was completed across the authenticated Zenodo artifact, all shipped source/data/checkpoint metadata, the local cited paper, R0-R2 evidence, and the official repositories cited by the paper. The complete source-by-source record is in [PROVX_R3_FEATURE_SEMANTICS_SEARCH_INVENTORY.json](PROVX_R3_FEATURE_SEMANTICS_SEARCH_INVENTORY.json).

## Why the official vocabulary is unavailable

The archive authenticates a concrete tensor interface: `x` is `torch.float32` with shape `[N,21]`, and the first checkpoint layer has shape `[64,21]`. It does not authenticate what any column means or how a raw event becomes a row. The archive README calls `x` a node feature matrix but publishes no names or sidecar. `data.py` only deserializes PyG objects; `detector.py` consumes the matrix; training, explanation, and evaluation code contain no feature construction. Checkpoint metadata records architecture and training settings, not feature order or normalization.

The paper (local PDF SHA-256 `74f2f0dca2f3deeb76f414358adecbf4268f4d8c2fe1ef5b1cfcd27ab159409d`) gives broad provenance context: process/file/socket examples, causal dependencies, a node feature matrix, and Louvain-based evaluation subgraphs. It does not publish an ordered 21-column vocabulary, one-hot enum, raw-to-graph implementation, normalization constants, or DARPA-to-column map. Its statement that deployment can use PIDS/EDR/SIEM/network/analyst alert sources also confirms that live acquisition is a replaceable upstream boundary rather than an artifact-provided pipeline.

The cited official repositories add source-data semantics but no ProvX mapping. `FiveDirections/OpTC-data` (HEAD `5b108604f11f767aa11ea79ff827595f3fad15fd`) documents endpoint JSON/eCAR fields such as timestamp, IDs, process, object, action, PID/TID, principal, and properties. `darpa-i2o/Transparent-Computing` (HEAD `244ae2401032ce92ac3b72f49b8039cae67d60d6`) documents TC E3 CDM/provenance releases. Neither repository contains ProvX source or a 21-feature encoder. These repositories were inspected read-only; no DARPA data was downloaded.

Therefore, assigning eCAR fields or paper entity examples to the 21 positions would be an invented mapping. The decision is recorded machine-readably in [PROVX_R3_OFFICIAL_21_FEATURE_VOCABULARY_DECISION.json](PROVX_R3_OFFICIAL_21_FEATURE_VOCABULARY_DECISION.json).

## Route comparison

| Route | Input/encoder | Checkpoint | Allowed use | R3 status |
|---|---|---|---|---|
| Track O exact artifact baseline | Shipped `Sample` `[N,21]` tensors; opaque feature meanings | Authenticated packaged GCN checkpoint | Reproduce artifact Sample path and non-formal Phase-II controls | Reproduced in R1/R2; not a live Mininet claim |
| Exact packaged checkpoint on new Mininet | Newly encoded live records forced into 21 columns | Same packaged checkpoint | Would require authenticated column compatibility | Rejected: `NOT_VALIDATED` |
| Track L adapted live deployment | Explicit `provx-adapted-live-v1` encoder, `[N,32]` | New checkpoint trained under a separate frozen protocol | Controlled-host/Mininet live route after adapter and checkpoint gates | Selected route; design only |

The exact/adapted boundaries, non-equivalence rules, and release gates are in [PROVX_R3_EXACT_VS_ADAPTED_DEPLOYMENT_CONTRACT.md](PROVX_R3_EXACT_VS_ADAPTED_DEPLOYMENT_CONTRACT.md).

## Track L design

The adapted route uses a new, explicit 32-dimensional encoder in [PROVX_R3_ADAPTED_LIVE_FEATURE_SCHEMA.json](PROVX_R3_ADAPTED_LIVE_FEATURE_SCHEMA.json). It is deterministic and versioned:

- Encoder ID: `provx-adapted-live-v1`
- Output: `torch.float32 [N,32]`
- Encoder SHA-256: `f27984513a39a004534f7bb409e3ff6410c48b442645656435c0534e64a15188`
- Entity categories: process, file, socket, other, with an explicit unknown flag
- Collector-visible fields: process PID/PPID/executable/command/user; file path/hash; socket protocol/endpoints/port; event classes and timestamps
- Event classes: create, read/open, write, execute, connect/send, close/delete, other
- Fixed transforms: `clip(log1p(value)/log1p(1024),0,1)` for counts/degrees, `clip(delta_seconds/3600,0,1)` for time, and clipped unknown-field fractions
- Unknown/missing policy: no synthesized values; unknown types/events are represented explicitly; non-finite records are rejected and logged
- Stable ordering: node key `(host_id, entity_type_rank, canonical_entity_id)` and edge key `(timestamp_ms, src, dst, event_class_rank, canonical_event_id)`
- Reversible evidence: `run_id`, source-record hashes, `node_map`, `edge_map`, and `normalization_map`; top-K edges remain analyst evidence, not enforcement commands

The adapted dimension is intentionally not 21. A new detector input layer and separately authenticated checkpoint are required; padding, truncating, projecting, or reordering to fit `model.bin` is invalid.

## Governance and evaluation separation

The 53-playbook/1796-action FA1B2de set is reserved as final held-out test material. It is excluded from encoder design, detector training, tuning, calibration, seed selection, and preprocessing decisions. Track L may conceptually train on separately authorized historical provenance partitions, non-formal corpora, or synthetic/reserved Mininet traces declared before freeze. Group splits occur at host/run/playbook boundaries, and any training-only negative sampling is predeclared and manifested. Full rules are in [PROVX_R3_TRAIN_EVAL_SEPARATION_CONTRACT.json](PROVX_R3_TRAIN_EVAL_SEPARATION_CONTRACT.json).

No Track L model has been trained. Adapter smoke tests, if later performed, must use non-scored reserved traces and cannot be relabeled as formal results.

## Phase-II randomness

The primary externally controlled Phase-II seed is pre-registered as `314159` before formal evaluation. Optional sensitivity seeds `[271828, 161803, 42]` are declared but disabled unless enabled before evaluation. Python, `PYTHONHASHSEED`, NumPy, Torch CPU/CUDA, backend flags, graph ordering, and canonical explanation hashes are recorded by [PROVX_R3_PHASE2_SEED_POLICY.json](PROVX_R3_PHASE2_SEED_POLICY.json). A seed may not be selected or changed based on favorable formal outcomes.

## R3 boundary

R3 resolves the vocabulary question and chooses the adapted route; it does not implement an adapter, train a detector, acquire raw DARPA data, execute a Mininet/APT action, run a formal benchmark, or authorize host enforcement. The next step is a fresh review of this route decision before any R4 implementation or R5 formal-evaluation work.
