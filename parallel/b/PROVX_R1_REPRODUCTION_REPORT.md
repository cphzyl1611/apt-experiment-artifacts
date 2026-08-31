# PROVX-R1 Official Sample Reproduction Report

## Terminal decision

```text
PROVX_R1_ARTIFACT_SAMPLE_REPRODUCTION =
PASS

PACKAGE_CHECK = PASS
GCN_SAMPLE_INFERENCE = PASS
PHASE2_SAMPLE_RUN = PASS
REPEATABILITY = VARIABLE_RECORDED

FORMAL_EXPERIMENT_EXECUTED = NO

NEXT_ACTION =
FRESH_REVIEW_OF_PROVX_R1_SAMPLE_REPRODUCTION

STOP = true
```

The PASS covers the artifact-as-shipped Sample path only. It is not a formal FA1B2de result and does not reproduce the paper's full DARPA pipeline.

## R0 byte freeze

- R0 extracted SHA-256 verification: PASS for all 57 extracted regular files.
- Separate R1 copy: `provx-r1/artifact`.
- R1 copied project-file SHA-256 verification: PASS for all 23 project files.
- R0 extracted directory was not modified.

## Isolated runtime

Environment: `provx-r1/venv_r1_cpu` using Python `3.10.12` (`sys.prefix` is the R1 venv and `base_prefix` is `/usr`). The exact artifact requirements resolved as:

| Requirement | Resolved |
|---|---|
| `torch==2.8.0` | `2.8.0+cpu` |
| `torch-geometric==2.6.1` | `2.6.1` |
| `numpy==2.0.2` | `2.0.2` |
| `scikit-learn==1.6.1` | `1.6.1` |

Torch is the CPU build. The complete environment and transitive package lock is in `PROVX_R1_ENVIRONMENT_LOCK.json`. No system Python or conda base package was modified.

## Package check

Command: `../venv_r1_cpu/bin/python scripts/check_package.py --dataset Sample --partition test_100nodes --gnn-model GCNConv --device cpu --limit-graphs 1`, from `provx-r1/artifact`.

Exit code was `0`. The artifact loaded all `2,463` test graphs and the packaged GCN checkpoint. The first graph has `102` nodes, `100` stored edges, and `21` input features; the checkpoint-compatible forward pass returned logits shape `(1, 2)` and prediction `0`. Full captured stdout/stderr and command metadata are in `PROVX_R1_PACKAGE_CHECK.json` and `provx-r1/package_check.stdout_stderr.log`.

## Packaged GCN inference

Using only `Sample/test_100nodes.pt` and `GCNConv/checkpoint-best-acc/model.bin`, the detector was run twice on CPU with no training. Both independent processes produced the same 2,463 predictions and metrics:

- Accuracy: `0.996752`
- Precision: `0.984962`
- Recall: `0.956204`
- F1: `0.970370`
- AUC: `0.991533`
- Confusion counts: TN `2324`, FP `2`, FN `6`, TP `131`
- Prediction sequence SHA-256: `37df743ed89a058f82697bc81dea4fc4684eea62ffdc4f6d0b795edcdfc88585`

The complete prediction arrays are retained in `provx-r1/inference_run1.json` and `provx-r1/inference_run2.json`; the summarized required output is `PROVX_R1_GCN_SAMPLE_INFERENCE.json`.

## Phase-II sample run

The bounded run explained the first detector-positive graph encountered by the artifact path: `graph_index=19`, `sample_id=497`, original prediction/target `1`, with `100` non-self-loop edges. The shipped defaults were used first and are pinned in `PROVX_R1_PHASE2_SAMPLE_RUN.json`:

- epochs `200`
- optimizer Adam, learning rate `0.05`
- alpha `0.9`
- solidification factor `0.6`
- stage start ratio `0.6`
- confidence thresholds `0.05` and `0.95`
- evaluation top-K `30`
- Phase-II seed: none exposed

Both `run_provx.py` executions and both evaluation utility executions exited `0`. Each produced one explanation and the same bounded metrics:

- Accuracy `1.0000`
- Precision `1.0000`
- Recall `0.3069`
- F1 `0.4697`
- MER `1.0000`

MER is recorded strictly as `MODEL_LEVEL_INTERVENTION_FLIP_ONLY`; it is not real-world prevention or blocking.

## Repeatability

GCN inference was deterministic across the two runs: full output hashes and prediction sequence hashes matched.

Phase-II was variable under identical inputs/configuration because `ProvXExplainer._set_masks` uses `torch.randn` and `run_provx.py` exposes no Phase-II seed. The explanation graph identity and `edge_index` matched, but edge weights differed:

- Output SHA-256: `f683eecc...1fa5` vs `e26e74...2660`
- Edge-weight max absolute delta: `0.0447169542`
- Edge-weight mean absolute delta: `0.0111771403`
- Top-30 overlap: `22/30`; same set: false
- Evaluation metrics: identical

This is reported as `VARIABLE_RECORDED`, not hidden or normalized. Full comparison evidence is in `PROVX_R1_REPEATABILITY_AUDIT.json`.

## Paper/artifact boundary

R1 executes `ARTIFACT_AS_SHIPPED_BASELINE` only. It does not execute the paper-stated parameter baseline. The artifact's shipped values differ from the paper in detector optimizer/LR (`AdamW`, `0.005` vs `Adam`, `0.001`), Phase-II LR (`0.05` vs `0.01`), solidification factor (`0.6` vs `0.5`), and the written mask-loss forms. These discrepancies remain documented in `PROVX_R0_PAPER_ARTIFACT_DISCREPANCIES.md` and must be resolved/frozen before R2/R5.

## Hard-boundary record

No DARPA raw data was acquired, no Mininet or APT action was executed, no formal benchmark was run, no FA1B2de tuning occurred, and no binding or scoring authority was mutated.

