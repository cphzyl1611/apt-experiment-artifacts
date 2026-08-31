# PROVX-R2 Exact Schema Pinning and Phase-II Determinism

## Terminal

```text
PROVX_R2_SCHEMA_PINNING = PASS
EXTERNAL_SEED_CONTROL = DETERMINISTIC_FOR_FIXED_SEED
LIVE_ADAPTER_TARGET_SCHEMA = READY_FOR_ADAPTER_DESIGN
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_PROVX_R2_SCHEMA_AND_DETERMINISM
STOP = true
```

R2 used the authenticated artifact copy under `provx-r1/artifact` and a separate working area under `provx-r2`. R0 and R1 hashes were verified before inspection. The official artifact source was not modified. No retraining, tuning, DARPA raw-data acquisition, APT action, formal benchmark, or authority mutation occurred.

## 1. Packaged PyG schema

All three packaged partitions are Python lists of PyTorch Geometric `Data` objects loaded with `weights_only=False` in read-only inspection. Every object has exactly these five fields, with no additional actual fields:

| Field | Type | Shape | Dtype | Role |
|---|---|---|---|---|
| `x` | Tensor | `[N, 21]` | `torch.float32` | model node features |
| `edge_index` | Tensor | `[2, E]` | `torch.int64` | PyG COO endpoint indices; row 0 source, row 1 destination |
| `_VULN` | Tensor | `[N]` | `torch.int64` | benchmark node-level ground truth; graph label is any positive node |
| `_LINE` | Tensor | `[N]` | `torch.int64` | original node identifiers for line localization |
| `_SAMPLE` | Tensor | `[N]` | `torch.int64` | sample/subgraph identifier, constant within each graph |

All fields are CPU tensors in the packaged files. `x`, `_VULN`, `_LINE`, and `_SAMPLE` lengths align with `N`; all edge endpoints are valid; no duplicate edge columns were found. Self-loops are present in a minority of graphs and are handled by the artifact's normalization path.

### Partition distributions

| Partition | Graphs | N min/median/mean/max | E min/median/mean/max | Graph labels 0/1 | x global rows |
|---|---:|---:|---:|---:|---:|
| `train_100nodes` | 8,625 | 1 / 101 / 100.0115 / 312 | 1 / 100 / 87.1217 / 4,212 | 8,144 / 481 | 862,599 |
| `val_100nodes` | 1,231 | 1 / 101 / 99.9180 / 164 | 1 / 100 / 87.2551 / 306 | 1,163 / 68 | 122,999 |
| `test_100nodes` | 2,463 | 1 / 101 / 100.1994 / 250 | 1 / 100 / 86.4454 / 2,094 | 2,326 / 137 | 246,791 |

The most common node counts are 101 and 100. The most common edge counts are 100, then very small graphs with 1-5 edges, and 200-edge graphs. The complete quantiles, top-count distributions, self-loop distributions, feature statistics, label/value counts, and field shape distributions are in [PROVX_R2_SAMPLE_GRAPH_SCHEMA.json](PROVX_R2_SAMPLE_GRAPH_SCHEMA.json).

`x` values are finite and range from 0 to 1. The artifact does not define the meaning or vocabulary of the 21 columns; no feature-column semantics are inferred here. There is no edge-feature tensor.

## 2. Runtime input versus evaluation metadata

The binding semantic boundary is:

```text
MODEL_RUNTIME_INPUT = x + edge_index (+ optional batch)
EVALUATION_GROUND_TRUTH_OR_METADATA = _VULN + _LINE + _SAMPLE + sample_labels_all.pkl
```

`Detector.forward(self, x, edge_index, batch=None, **kwargs)` is verified from `provx_usenix/detector.py:102-107`. It creates an all-zero `torch.long` batch when omitted, transforms `x`, performs message passing over `edge_index`, pools by `batch`, and returns `[B,2]` float logits. It does not read `_VULN`, `_LINE`, `_SAMPLE`, or any other Data field. Training uses `_VULN` only to derive graph labels; localization evaluation uses `_VULN`, `_LINE`, `_SAMPLE`, and the auxiliary pickle.

A future live adapter therefore must not require `_VULN` as a sensor input. The full evidence is in [PROVX_R2_MODEL_INPUT_VS_EVALUATION_METADATA.json](PROVX_R2_MODEL_INPUT_VS_EVALUATION_METADATA.json).

## 3. Checkpoint input contract

The packaged checkpoint is `GCNConv/checkpoint-best-acc/model.bin`, SHA-256 `d1307de5ad2b8410eca6b964f48e0afc9e9fdb0655e1702f9c85d6dfd07399f0`, 193,297 bytes. It is an `OrderedDict` with 14 float32 CPU tensors. The first feature-transform weight has shape `[64,21]`, pinning input feature dimension 21. The checkpoint metadata and state shapes pin:

- GCNConv backbone;
- input transform to 256 features;
- hidden size 64;
- two message-passing layers;
- mean pooling;
- two output classes;
- dropout 0.1;
- CPU loading works through `map_location`; model tensors are float32.

Only a GCNConv checkpoint is packaged. No GAT or GraphSAGE checkpoint is included. Exact state-key shapes and metadata are in [PROVX_R2_CHECKPOINT_INPUT_CONTRACT.json](PROVX_R2_CHECKPOINT_INPUT_CONTRACT.json).

## 4. ARTIFACT_AS_SHIPPED_BASELINE versus PAPER_STATED_PARAMETER_BASELINE

R2 did not change or substitute parameters. The Phase-II repetitions used only the artifact defaults:

```text
epochs = 200
lr = 0.05
alpha = 0.9
solidification_factor = 0.6
solidification_stage_start_ratio = 0.6
confident_threshold_low = 0.05
confident_threshold_high = 0.95
use_l1_distance = false
```

The paper-stated baseline remains separate: detector training 50 epochs with Adam at `0.001`; Phase-II 200 epochs at `0.01`; `R_S=0.6`, `gamma_S=0.5`, `tau_low=0.05`, `tau_high=0.95`. No paper-baseline run was performed.

## 5. Ten unseeded Phase-II repetitions

The unchanged artifact API/configuration was run in 10 separate CPU processes on the same bounded sample (`test_100nodes`, detector-positive `graph_index=19`, `sample_id=497`, top-K 30). Each run saved its explanation artifact and a row containing all top-K edges and weights, runtime, output hash, prediction, and model-level flip result.

- Runs: 10; unique raw output hashes: 10/10.
- Original prediction: `1` in every run.
- MER/intervention flip: `1` in every run, strictly `MODEL_LEVEL_INTERVENTION_FLIP_ONLY`.
- Runtime: min `0.3691 s`, median `0.4916 s`, mean `0.5178 s`, max `1.0053 s`.
- Pairwise comparisons: 45.
- Top-30 overlap: min 16, median 20, mean 19.8, max 24.
- Top-30 Jaccard: min `0.3636`, median `0.5000`, mean `0.4954`, max `0.6667`.
- Common-edge mean absolute rank delta: mean `9.3084` ranks (median `9.8182`).
- Common-edge rank correlation: mean Spearman `0.1461`, range `-0.3611` to `0.5926`.

Result: `VARIABLE_RECORDED`. The artifact initializes the mask with `torch.randn`; `run_provx.py` exposes no Phase-II seed. Full repetition rows and top-K edge/weight records are in [PROVX_R2_UNSEEDED_VARIABILITY.json](PROVX_R2_UNSEEDED_VARIABILITY.json).

## 6. External fixed-seed control

`provx-r2/control_seed_wrapper.py` is outside the official artifact and invokes the exact unchanged package API `ProvXExplainer(model, ProvXConfig()).explain(graph)`. Its `set_external_seed()` sets Python `random`, `PYTHONHASHSEED`, NumPy, Torch, and CUDA Torch seeds when available. A test-first seed-stream test passed.

Two seed groups were run in three separate processes each:

- Seed 123: all three semantic explanation contents, top-K edges, and weights are identical.
- Seed 456: all three semantic explanation contents, top-K edges, and weights are identical.
- Cross-seed comparison: top-30 overlap `20/30`, Jaccard `0.5`; semantic canonical hashes differ.

Raw `.pt` file hashes differ even within a fixed-seed group because Torch serialization embeds the output filename in ZIP member names (`rep_1/...`, `rep_2/...`). After loading, canonical hashes over metadata, edge-index tensor, and edge-weight tensor are identical within each seed. Therefore the decision is:

`DETERMINISTIC_FOR_FIXED_SEED` — deterministic semantic explanation content for a fixed external seed, with raw archive hash comparison requiring canonicalization or a fixed archive member name.

The complete seeded rows, raw hashes, canonical hashes, top-K records, runtime, and cross-seed comparison are in [PROVX_R2_EXTERNAL_SEED_CONTROL.json](PROVX_R2_EXTERNAL_SEED_CONTROL.json). The official source hash remains unchanged.

## 7. LIVE_ADAPTER_TARGET_SCHEMA

The adapter target is ready for R3 design, with no invented feature semantics:

- `x`: `torch.float32`, `[N,21]`, stable node-row order, finite values; 21 columns remain opaque until an artifact-defined vocabulary is available.
- `edge_index`: `torch.int64`, `[2,E]`, valid endpoint indices, row 0 source/row 1 destination, deterministic column order with an accompanying reversible edge map; no edge-feature tensor.
- `batch`: optional `torch.int64`, `[N]`, all zero for one graph; omitted means Detector creates it.
- `_VULN`, `_LINE`, `_SAMPLE`, `sample_labels_all.pkl`: optional evaluation/ground-truth metadata, never live sensor prerequisites.
- `run_id`: required stable controlled-execution identifier, not passed to the model.
- `raw_key`: required stable identifier for each raw audit record/normalized causal edge, not passed to the model.
- `node_map` and `edge_map`: required mappings from model indices/columns to raw entities/events and `raw_key` references.
- `normalization_map`: required record of self-loop removal, duplicate coalescing, post-coalesce edge order, and coalesced raw-key sets because the artifact removes self-loops and coalesces edges before Phase-II masking.
- Output envelope must retain `run_id`, raw-key references, checkpoint/config hashes, top-K model edge indices, top-K raw keys, weights, and model-level flip result. It is analyst evidence, not enforcement.

The machine-readable target is [PROVX_R2_LIVE_ADAPTER_TARGET_SCHEMA.json](PROVX_R2_LIVE_ADAPTER_TARGET_SCHEMA.json). Event enums, causal construction, feature meanings, alert seeding/expansion, clock policy, and host enforcement mapping remain explicitly unpinned for R3.

