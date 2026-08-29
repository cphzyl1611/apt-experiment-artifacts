# EXP-E0-B PROVX Training/Test Separation

## Binding rule

The formal FA1B2de evaluation set is 53 playbooks and 1796 raw actions. These runs are final test material and must not silently become detector-training, mask-tuning, calibration, threshold-selection, feature-selection, or preprocessing-design examples.

## What the paper says

The paper evaluates DARPA TC E3 (Cadets, Theia, Trace) and DARPA OpTC. It reports random negative sampling for scarce OpTC malicious behavior subgraphs and a training/validation/test split of `7:1:2` (Sec. 6.1.1, paper p. 8). The paper does not establish whether the ProvX artifact includes pretrained checkpoints, nor does this workspace contain the artifact to verify that fact.

## Required partitions

1. **Detector training partition:** benchmark data explicitly assigned before any formal FA1B2de run. Used only to train the 2-layer GNN detector (50 epochs, Adam, learning rate `0.001`, unless an authenticated artifact configuration is the authoritative discrepancy).
2. **Calibration/validation partition:** a separately identified partition for threshold, `alpha`, response budget `K`, solidification choices, and preprocessing decisions. If the artifact ships a pretrained model with a declared calibration protocol, preserve that protocol and hash its inputs. Do not use formal actions.
3. **Final FA1B2de test partition:** all 53 playbooks/1796 raw actions, held out until `PROVX-R5`. It is evaluated once under the frozen configuration; test outputs cannot feed retraining or parameter selection.
4. **Non-scored smoke partition:** synthetic or separately reserved Mininet traces for R3/R4. These traces may validate adapters and schemas but cannot be used to tune formal scores unless they were declared training/calibration data before freeze.

## Pretrained-model decision gate

At R0, record one of these mutually exclusive states:

- `PRETRAINED_CHECKPOINTS_PRESENT_AND_AUTHENTICATED`: use only if artifact files, hashes, and intended dataset/split are documented.
- `RETRAINING_REQUIRED`: no usable checkpoint, or checkpoint provenance does not match the declared benchmark contract.
- `CHECKPOINT_STATUS_UNRESOLVED`: artifact unavailable; do not train or score until resolved.

If retraining is required, create immutable train/validation/test manifests before training. If the paper's `7:1:2` split cannot be reproduced from artifact metadata, report the discrepancy and retain both the paper and artifact definitions.

## Freeze manifest required before formal evaluation

The R5 manifest must include: artifact archive/file hashes; source revision; dependency lock and OS/runtime identity; preprocessing code and version; raw-data and graph hashes; node/edge vocabulary and feature normalization; split membership; checkpoint hash; detector architecture and training hyperparameters; every random seed and RNG source; Phase-II optimizer/epochs/learning rate; `alpha`; `K`; `R_S`; `gamma_S`; `tau_low`; `tau_high`; alert/subgraph acquisition settings; intervention semantics; output schema; and failure/retry policy.

No formal output may be used to alter this manifest. A changed manifest receives a new configuration identity and produces a separately labeled run.

## Current evidence

No artifact, data, checkpoint, configuration, or prior log exists locally. Consequently the pretrained/retraining decision is `CHECKPOINT_STATUS_UNRESOLVED`, formal evaluation is not executed, and no training/test contamination can occur in this preflight.

