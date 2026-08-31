# PROVX-R3 Exact versus Adapted Deployment Contract

## Decision

The authenticated artifact does not publish the ordered semantics of its 21 `x` columns. A tensor with shape `[N,21]` and `float32` values is therefore an interface constraint, not an authenticated live encoder. The packaged checkpoint may be used for the artifact-as-shipped `Sample` reproduction baseline, but it is not validated for arbitrary newly encoded Mininet provenance.

```text
PROVX_R3_FEATURE_VOCABULARY = OFFICIAL_21_FEATURE_VOCABULARY_NOT_AVAILABLE
PACKAGED_CHECKPOINT_DIRECT_LIVE_MININET_USE = NOT_VALIDATED
LIVE_PROVX_ROUTE = PROVX_ADAPTED_LIVE_DEPLOYMENT
```

## Track O: exact artifact reproduction baseline

Track O is a reproducibility control, not a live deployment claim.

Inputs and authority:

- Authenticated Zenodo record `20310415`, DOI `10.5281/zenodo.20310415`, archive SHA-256 `a46fe7dec840ea28d9f8acf8771879af7204e0d622e24d12a99ad95f4187e3ff`.
- Artifact-as-shipped `Sample` PyG partitions and the packaged `GCNConv` checkpoint (`model.bin` SHA-256 `d1307de5ad2b8410eca6b964f48e0afc9e9fdb0655e1702f9c85d6dfd07399f0`).
- Runtime model input is exactly `x + edge_index` with optional `batch`; `_VULN`, `_LINE`, `_SAMPLE`, and `sample_labels_all.pkl` remain evaluation metadata.
- Artifact source and defaults are unchanged. Phase-II defaults are 200 epochs, Adam `lr=0.05`, `alpha=0.9`, solidification factor `0.6`, stage ratio `0.6`, confidence bounds `0.05/0.95`, and BCE distance loss.
- Phase-II randomness is controlled externally by the R3 seed policy and the unchanged wrapper pattern in `provx-r2/control_seed_wrapper.py` (reference SHA-256 `da4d6a19455352bb152751bea71ca2f6d1c37cd057d4b93fa7225a585a110caf`); semantic outputs are compared by canonical content rather than Torch archive member names.

Permitted purpose:

- Reproduce the shipped Sample path and verify checkpoint/model/explainer interfaces.
- Exercise Phase-II on packaged Sample graphs as a non-formal control.

Prohibited interpretation:

- A successful Sample run does not authenticate the meaning of any of the 21 columns.
- A model-level MER/intervention flip is not host-level prevention or enforcement.
- Track O outputs cannot be used to select the Track L encoder, model, threshold, or formal evaluation seed.

## Track L: `PROVX_ADAPTED_LIVE_DEPLOYMENT`

Track L is the only permitted route for newly collected Mininet or controlled-host provenance after its gates are satisfied. It preserves the provenance-subgraph detector architecture, differentiable GNN requirement, Phase-II mask/explanation, staged solidification, MER semantics, and fixed-seed control, but it does not reuse the packaged 21-input checkpoint.

### Track L input and encoder

- Use `PROVX_R3_ADAPTED_LIVE_FEATURE_SCHEMA.json`, encoder ID `provx-adapted-live-v1`, output dimension 32, encoder SHA-256 `f27984513a39a004534f7bb409e3ff6410c48b442645656435c0534e64a15188`.
- Construct nodes only from collector-visible process, file, socket, or explicitly unknown entities; construct directed edges only from collector-visible causal event records.
- Persist deterministic node/edge ordering, source-record hashes, `node_map`, `edge_map`, and `normalization_map` so top-K model edges can be audited back to raw evidence.
- Do not pass `_VULN`, `_LINE`, `_SAMPLE`, `sample_labels_all.pkl`, playbook identity, or any analyst ground truth into the live tensor.
- Reject non-finite values and preserve unknown/missing fields through the declared policy; do not silently synthesize values.

### Track L checkpoint and training gate

1. Declare immutable training, calibration, and final evaluation manifests before fitting.
2. Train a new detector with input dimension 32 using only the approved training partition. The packaged 21-input checkpoint is not a warm start or compatibility reference for scored live use.
3. Freeze the encoder hash, detector architecture/configuration, training seed/RNG sources, checkpoint hash, calibration inputs, and Phase-II configuration.
4. Validate the adapter on non-scored synthetic/reserved Mininet traces and run a semantic round-trip test from raw record to graph to output envelope.
5. Only after gates 1-4 may a live alert-associated subgraph enter Phase I and Phase II. A live alert source may be PIDS/EDR/SIEM/network/analyst expansion; Louvain is optional and must be separately implemented and versioned.

### Track L intervention and action boundary

Phase II may remove selected graph edges and suppress incident node features for MER, using the same fixed detector and externally registered seed. The output is a ranked evidence list containing model edge indices, normalized endpoints, raw-key references, weights, and intervention result. It is analyst-prioritized guidance only. Any process termination, file quarantine, syscall block, or network restriction requires a separate deployment-specific safety authority and is outside this contract.

## Non-equivalence rules

The following substitutions are invalid:

- Renaming or guessing the 21 packaged columns from tensor statistics, learned weights, paper figures, or eCAR field names.
- Padding, truncating, reordering, or projecting the 32 adapted features into 21 dimensions to satisfy the packaged checkpoint.
- Treating broad paper examples (`Process`, `File`, `Socket`) as proof of an official one-hot layout.
- Using formal FA1B2de evaluation raws (53 playbooks, 1796 actions) to design, tune, calibrate, or select the adapted encoder or detector.
- Calling a model-level intervention flip a real-world block.

## Release gate

R3 is a design and decision stage. No Track L model has been trained, no Mininet action has been executed, and no formal benchmark has been run. The next action is a fresh review of this route decision before any R4 adapter implementation or R5 formal evaluation planning.
