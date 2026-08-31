# PROVX R1 Official Sample Reproduction

Date: 2026-08-30  
Scope: artifact-as-shipped `Sample` path only; CPU-only; no formal experiment.

## R0 freeze

The R0 extracted manifest was verified from `provx-r0/extracted` with
`sha256sum -c PROVX_R0_EXTRACTED_SHA256SUMS.txt`: 57/57 files passed. The R0
archive SHA256 is `a46fe7dec840ea28d9f8acf8771879af7204e0d622e24d12a99ad95f4187e3ff`.
The extracted R0 directory was not modified. R1 uses the separate byte-identical
copy at `provx-r1/artifact`.

## Environment

Dedicated interpreter: `provx-r1/venv_r1_cpu/bin/python` (Python 3.10.12).
Installed versions are `torch 2.8.0+cpu`, `torch-geometric 2.6.1`,
`numpy 2.0.2`, and `scikit-learn 1.6.1`. Torch was installed from the official
CPU wheel index. See `PROVX_R1_ENVIRONMENT_LOCK.json`.

## Results

`scripts/check_package.py` passed. It loaded all 2,463 test graphs, loaded the
packaged GCNConv checkpoint, and completed the detector forward pass on the
first graph (102 nodes, 100 edges, 21 features, logits `(1, 2)`, prediction 0).

Packaged GCN inference over all 2,463 test graphs passed with accuracy
`0.9967519`, precision `0.9849624`, recall `0.9562044`, and F1 `0.9703704`.
Two identical inference repeats produced identical prediction and logit
digests. Details are in `PROVX_R1_GCN_SAMPLE_INFERENCE.json`.

Phase-II used the shipped defaults on one bounded alert graph (`graph_index=19`,
`sample_id=497`): epochs 200, effective internal lr 0.05, alpha 0.9,
solidification factor 0.6, stage start ratio 0.6, thresholds 0.05/0.95, CPU,
and evaluator top-K 30. Both runs and evaluation passed; evaluator metrics were
accuracy 1.0, precision 1.0, recall 0.3069, F1 0.4697, and
`MER=1.0`, where MER is `MODEL_LEVEL_INTERVENTION_FLIP_ONLY`.

The run script exposes no seed. Repeated runs had identical edge indices,
predictions, and metrics, but explanation weights differed (maximum absolute
difference `0.0673085451`) and output hashes differed. Therefore repeatability
is `VARIABLE_RECORDED`.

## Boundary and terminal state

No DARPA acquisition, Mininet APT action, formal 53-playbook benchmark, tuning,
or binding/scoring mutation was performed. Paper-stated parameters remain
distinct from the artifact-as-shipped baseline.

```text
PROVX_R1_ARTIFACT_SAMPLE_REPRODUCTION = PASS
PACKAGE_CHECK = PASS
GCN_SAMPLE_INFERENCE = PASS
PHASE2_SAMPLE_RUN = PASS
REPEATABILITY = VARIABLE_RECORDED
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_PROVX_R1_SAMPLE_REPRODUCTION
STOP = true
```

