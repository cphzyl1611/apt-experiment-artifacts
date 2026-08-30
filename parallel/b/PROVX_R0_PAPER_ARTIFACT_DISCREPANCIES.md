# PROVX-R0 Paper / Artifact Discrepancies

## Comparison basis

- Paper: `sec26cycle2-final500(2).pdf`, SHA-256 `74f2f0dca2f3deeb76f414358adecbf4268f4d8c2fe1ef5b1cfcd27ab159409d`.
- Artifact: Zenodo record `20310415`, `ProvX-USENIX-artifact.zip`, archive SHA-256 `a46fe7dec840ea28d9f8acf8771879af7204e0d622e24d12a99ad95f4187e3ff`.
- Source facts below were read from the extracted archive; no import, model load, training, inference, or evaluation command was run.

## Identity

**Match.** The record title and description identify “Artifact for Paper ‘Cutting the Fuse: Actionable APT Attack Blocking in Provenance-based IDS’” and describe the GNN detector, interventional mask learning, staged solidification, and evaluation utilities. The DOI, record ID, creator (Wu, Weiheng), publication date (`2026-05-20`), latest-record relation, and MIT license are captured in `PROVX_R0_ZENODO_RECORD_METADATA.json` and the acquisition manifest.

## Detector architecture

**Broad match with artifact-specific detail.** The paper specifies a 2-layer GNN with ReLU/Dropout, average pooling, and a 2-layer MLP classifier (Sec. 6.1.2, p. 8). `provx_usenix/detector.py:32-106` implements an input feature transform (`Linear -> ReLU -> Linear`), a pre-GNN `Linear -> ReLU -> Dropout`, two configurable message-passing layers, ReLU/Dropout after each layer, configurable global add/mean/max pooling, and a 2-layer linear classifier. The artifact therefore implements the paper's high-level shape but adds unreported feature-transform and pre-GNN dimensions.

The artifact supports `GCNConv`, `GAT`, and `GraphSAGE`, matching the paper's detector families. Only one `GCNConv` checkpoint is packaged; there are no GAT or GraphSAGE checkpoints.

## Detector training

| Contract | Paper | Artifact | Status |
|---|---|---|---|
| Epochs | 50 | `TrainConfig.epochs=50`; CLI default is 1 (`training.py:24-35`, `scripts/train_detector.py:24`) | **Matches library default; CLI default differs** |
| Optimizer | Adam | `torch.optim.AdamW` (`training.py:172-177`) | **Mismatch** |
| Learning rate | `0.001` | `0.005` in `TrainConfig`, CLI, and packaged checkpoint metadata | **Mismatch** |
| Batch size | Not pinned in paper | 32 | Artifact-only detail |
| Sampling | Paper reports random negative sampling for scarce OpTC malicious subgraphs | WeightedRandomSampler with inverse class counts, replacement, multiplier 3 (`training.py:62-82`); no negative-sample generation script | **Mismatch/implementation distinction** |
| Seed | Not pinned in paper | seed 1; Python, `PYTHONHASHSEED`, NumPy, torch, and CUDA seeds set (`training.py:53-59`) | Artifact-only detail; deterministic algorithms not enabled |

The packaged GCN checkpoint metadata independently records 50 epochs, seed 1, and learning rate `0.005`, reinforcing that the artifact's checkpoint was not trained with the paper-pinned `0.001` value unless the metadata is incomplete.

## Phase-II mask optimization

| Contract | Paper | Artifact | Status |
|---|---|---|---|
| Epochs | 200 | `ProvXConfig.epochs=200`; CLI default 200 | **Matches** |
| Optimizer | Learning rate `0.01` | Adam with `lr=0.05` (`provx.py:15-23`, `97`) | **Learning-rate mismatch** |
| Alpha | Trade-off parameter; sensitivity study, no single required value | Default `0.9`; CLI exposes `--alpha` | Artifact default must be frozen explicitly |
| Solidification start | `R_S=0.6` | `solidification_stage_start_ratio=0.6`; snapshot at `int(epochs*ratio)` | **Conceptually matches; naming differs** |
| Solidification factor | `gamma_S=0.5` | `solidification_factor=0.6` | **Mismatch** |
| Thresholds | `tau_low=0.05`, `tau_high=0.95` | `0.05`, `0.95` | **Matches** |
| Distance loss | `BCE(sigmoid(M_hat), A_k)` (Eq. 6) | BCE(mask, all-ones) by default, or optional L1 norm of `1-mask` (`provx.py:70-78`) | **Objective mismatch** |
| Prediction loss | Paper writes probability of original threat class, `P(Y_hat_k, A_tilde_k)` (Eq. 5) | `relu(logits[:, target_label]).sum()` on raw logits (`provx.py:70-78`) | **Objective/form mismatch** |

The artifact uses PyG `MessagePassing` explanation masks on sparse `edge_index`, removes existing self-loops, adds remaining self-loops during optimization, and removes self-loops from output (`provx.py:80-130`). This is not the paper's explicitly written dense adjacency-matrix presentation and must be treated as an implementation detail to reproduce, not silently translated.

## Graph, labels, and preprocessing

**Artifact schema is concrete but not paper-equivalent in provenance detail.** The README states that the three `.pt` files are Python lists of PyTorch Geometric `Data` objects with:

- `x`: node feature matrix;
- `edge_index`: PyG COO connectivity;
- `_VULN`: node-level labels;
- `_LINE`: original node identifiers;
- `_SAMPLE`: subgraph sample identifier.

The package derives a graph label by any positive `_VULN` node and uses `_LINE`/`sample_labels_all.pkl` for line-based localization (`data.py`, `evaluation.py`). No edge-feature field, provenance entity-type vocabulary, causal event normalization, raw audit-log parser, or Louvain implementation is included. The paper describes process/file/socket entities and causal edges and uses Louvain in its DARPA evaluation path, but the artifact distributes only preprocessed sample graphs. The README says raw audit logs are not included.

The artifact's sample partitions are named `Sample/{train_100nodes,val_100nodes,test_100nodes}.pt`; their provenance, exact split construction, and correspondence to the paper's DARPA TC E3/OpTC 7:1:2 split are not documented in the archive. No DARPA OpTC data or full Cadets/Theia/Trace raw data is present.

## Top-K and MER behavior

**High-level behavior matches; implementation details are concrete.** The artifact ranks `1 - sigmoid(mask)` and `topk()` selects the largest weights (`provx.py:27-36`, `127-135`). Evaluation removes selected edges, zeros features of incident nodes, adds self-loops, runs the same fixed detector, and compares argmax (`evaluation.py:107-122`), matching the paper's model-level structural-plus-attribute intervention and MER intent.

Differences/constraints:

- `run_provx.py` defaults to ground-truth malicious graphs and does not require predicted-alert filtering unless `--only-alerts` is passed; the pipeline wrapper passes `--only-alerts`.
- The explanation's default target is the original model prediction, while the caller can override it.
- The paper's top-K values (`K=10` OpTC, `K=30` TC E3) are not global artifact configuration; scripts expose `--top-k` only at evaluation and default to 30.
- The artifact's output is a PyTorch-saved list of tensors/IDs, not a standalone analyst-facing edge/action schema.

The boundary remains: `MODEL_LEVEL_INTERVENTION_FLIP != REAL_WORLD_PREVENTED/BLOCKED`. The artifact performs no host enforcement.

## Runtime and entry points

**Artifact facts:** `requirements.txt` pins `torch==2.8.0`, `torch-geometric==2.6.1`, `numpy==2.0.2`, and `scikit-learn==1.6.1`. No Python version, OS image, Conda/Docker file, lockfile, or networkx dependency is declared. Scripts default to CPU but accept `--device`.

**Entry points:**

- `scripts/check_package.py`: loads sample data/checkpoint and performs a detector forward pass; not executed in R0.
- `scripts/train_detector.py`: trains and writes checkpoints; not executed in R0.
- `scripts/run_provx.py`: loads a checkpoint, optimizes explanations, and writes a `.pt` explanation list; not executed in R0.
- `scripts/evaluate_explanations.py`: loads explanations/checkpoint and reports localization/MER; not executed in R0.
- `scripts/run_pipeline.py`: subprocesses training, explanation, and evaluation; not executed in R0.

The paper reports Ubuntu 22.04.5 CPU-only evaluation and approximately 1.4-1.6 GB peak memory for listed stages. The artifact does not provide the OS/environment or a complete preprocessing-resource bound.

## Checkpoint status

**Partial.** One `GCNConv` `checkpoint-best-acc/model.bin` and metadata are included. GAT and GraphSAGE checkpoints are absent. Checkpoint metadata records architecture dimensions, 50 epochs, seed 1, weighted sampler, and learning rate `0.005`; it contains no Phase-II configuration. Whether the supplied checkpoint is the exact checkpoint used for every paper table is not established by artifact metadata.

## R1 implications

R0 authentication passes for the cited artifact bytes and inspectable software/data interfaces. R1 must choose and freeze whether to reproduce the paper's values or the artifact's defaults, record the discrepancies above, and avoid claiming paper-table reproduction until the choice is experimentally verified.

