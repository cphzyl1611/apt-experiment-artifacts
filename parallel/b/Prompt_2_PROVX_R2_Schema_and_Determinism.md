# PROVX-R2 — Exact Schema Pinning and Phase-II Determinism

Continue from successful PROVX-R1 artifact-as-shipped sample reproduction.

Reported:
- PACKAGE_CHECK = PASS
- GCN_SAMPLE_INFERENCE = PASS
- PHASE2_SAMPLE_RUN = PASS
- REPEATABILITY = VARIABLE_RECORDED
- top-30 overlap = 22/30

## Goal

Pin the exact artifact graph/model input schema and determine whether Phase-II variability can be controlled with an external seed wrapper without modifying official PROVX source.

## Required work

1. Authenticate R0 artifact bytes and R1 output hashes. Create separate `provx-r2/`.

2. Inspect packaged train/val/test PyG objects and record:
   - graph count
   - x shape/dtype and feature dimension
   - edge_index shape/dtype
   - node/edge distributions
   - _VULN, _LINE, _SAMPLE shapes/types
   - all additional actual Data fields

3. Freeze the semantic boundary:
   MODEL_RUNTIME_INPUT = x + edge_index
   EVALUATION_GROUND_TRUTH_OR_METADATA = _VULN + _LINE + _SAMPLE + auxiliary label files

   Verify detector forward code. A future live adapter must not require `_VULN` as a sensor input.

4. Pin packaged checkpoint input compatibility:
   feature dimension, hidden sizes, layers, pooling, classes, dtype/device expectations.

5. Run at least 10 identical unseeded bounded Phase-II repetitions and record:
   - output hashes
   - top-K edges/weights
   - MER/prediction flip
   - runtime
   - pairwise top-K overlap/Jaccard/rank summary

6. Without editing official artifact source, create an experiment-control wrapper that sets Python, NumPy and Torch RNG seeds before invoking the exact same package API/config.
   Test:
   - same seed >=3 repetitions
   - at least two distinct seeds

   Decide:
   `DETERMINISTIC_FOR_FIXED_SEED | STILL_VARIABLE | BLOCKED`.

7. Keep ARTIFACT_AS_SHIPPED_BASELINE separate from PAPER_STATED_PARAMETER_BASELINE. Do not change optimizer/LR/epochs/solidification parameters.

8. Produce `LIVE_ADAPTER_TARGET_SCHEMA` containing exact tensor fields/dtypes/dimensions/order requirements plus reversible mapping metadata for `raw_key/run_id`.
   Do not invent feature-column semantics if the artifact does not define them.

## Outputs

- PROVX_R2_SAMPLE_GRAPH_SCHEMA.json
- PROVX_R2_CHECKPOINT_INPUT_CONTRACT.json
- PROVX_R2_MODEL_INPUT_VS_EVALUATION_METADATA.json
- PROVX_R2_UNSEEDED_VARIABILITY.json
- PROVX_R2_EXTERNAL_SEED_CONTROL.json
- PROVX_R2_LIVE_ADAPTER_TARGET_SCHEMA.json
- PROVX_R2_SCHEMA_AND_DETERMINISM_REPORT.md

## Boundaries

No model retraining/tuning, DARPA raw-data acquisition, APT actions, formal benchmark, official source modification, or authority mutation.

## Terminal

PROVX_R2_SCHEMA_PINNING = PASS | BLOCKED
EXTERNAL_SEED_CONTROL = DETERMINISTIC_FOR_FIXED_SEED | STILL_VARIABLE | BLOCKED
LIVE_ADAPTER_TARGET_SCHEMA = READY_FOR_ADAPTER_DESIGN | BLOCKED
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_PROVX_R2_SCHEMA_AND_DETERMINISM
STOP = true
