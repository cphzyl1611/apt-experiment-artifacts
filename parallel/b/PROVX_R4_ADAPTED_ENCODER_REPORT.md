# PROVX-R4 Adapted Encoder and Training Preflight Report

## Terminal

```text
PROVX_R4_ADAPTED_ENCODER = PASS_READY_FOR_TRAINING_REVIEW
ENCODER_SCHEMA_ID = provx-adapted-live-v1
ENCODER_DIMENSION = 32
GOLDEN_FIXTURE_DETERMINISM = PASS
MODEL_INTERFACE_32D = PASS
TRAINING_CORPUS_ROUTE = READY_FOR_SELECTION
DETECTOR_TRAINED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_PROVX_R4_ADAPTED_ENCODER_AND_TRAINING_PREFLIGHT
STOP = true
```

R4 implemented the frozen R3 Track-L encoder and validated it only against synthetic, benign, non-scored records. The R3 schema was not edited: schema SHA-256 is `53caab007f9cea84e83a5fb92ddea0cb9082cb816d19752db896cc58c675f68a`, encoder identity SHA-256 is `f27984513a39a004534f7bb409e3ff6410c48b442645656435c0534e64a15188`, and the implementation SHA-256 is `013d9b77297308843144ccfce4c3eec4b03dc3cc5172dabd6eb3320e7bc46547`.

## Encoder implementation

[PROVX_R4_ENCODER_IMPLEMENTATION.py](PROVX_R4_ENCODER_IMPLEMENTATION.py) is a dependency-light pure converter from normalized provenance records to:

- `x`: NumPy `float32`, shape `[N,32]`;
- `edge_index`: NumPy `int64`, shape `[2,E]`;
- deterministic `node_map` and `edge_map`;
- duplicate/self-loop `normalization_map`;
- a run manifest containing encoder/schema/implementation hashes and source-record hashes.

It enforces the R3 process/file/socket/other entity vocabulary, declared event classes, fixed count/time transforms, unknown and missing handling, non-finite rejection, canonical node/edge order, and reversible raw-key references. It never reads `_VULN`, `_LINE`, `_SAMPLE`, `sample_labels_all.pkl`, the packaged checkpoint, or formal evaluation data.

## Test and golden evidence

[PROVX_R4_ENCODER_TESTS.py](PROVX_R4_ENCODER_TESTS.py) contains seven tests covering all required paths. The isolated command:

```text
provx-r1/venv_r1_cpu/bin/python -m unittest -v PROVX_R4_ENCODER_TESTS.py
```

completed with `Ran 7 tests ... OK`. The first red phase was observed before implementation: importing the tests failed with `ModuleNotFoundError: No module named 'PROVX_R4_ENCODER_IMPLEMENTATION'`.

[PROVX_R4_GOLDEN_FIXTURES.jsonl](PROVX_R4_GOLDEN_FIXTURES.jsonl) contains ten synthetic records covering process/file/socket/other nodes, all seven event buckets, an unknown event, missing socket fields, a duplicate, and self-loops. Two independent Python processes regenerated identical canonical content:

- `x` shape `[5,32]`; bytes SHA-256 `b6a49e514e78ce2e883a49d7d6cd9f31a79030416de108efb623db11b7088ba6`;
- `edge_index` shape `[2,9]`; bytes SHA-256 `6fc7d733791b0b73669c0b685a7275e3a5e0db305f28b246fd394d3467c928eb`;
- duplicate coalescing: 10 input records to 9 edges;
- self-loop columns: `[3,6]`;
- canonical output SHA-256 `70b5830fdc0a50514e0d00e366d69d0a1350e2d95be8307c763e128425c17687`.

The complete expected values are in [PROVX_R4_GOLDEN_TENSOR_HASHES.json](PROVX_R4_GOLDEN_TENSOR_HASHES.json), and [PROVX_R4_ENCODER_VERIFICATION.json](PROVX_R4_ENCODER_VERIFICATION.json) records the verification gates.

## 32D model interface

An untrained, newly constructed `provx_usenix.detector.Detector` with `GCNConv` and `input_feature_dim=32` accepted fixture tensors on CPU and returned finite logits of shape `[1,2]` and dtype `torch.float32`. No packaged 21-input checkpoint was loaded. This check validates only tensor/device/dtype compatibility; it reports no accuracy, detection, or Phase-II result. Evidence is in [PROVX_R4_32D_MODEL_INTERFACE_CHECK.json](PROVX_R4_32D_MODEL_INTERFACE_CHECK.json).

## Training-corpus preflight

[PROVX_R4_TRAINING_CORPUS_PREFLIGHT.json](PROVX_R4_TRAINING_CORPUS_PREFLIGHT.json) inventories official OpTC, official DARPA TC E3, reserved non-scored Mininet traces, separately generated benign traces, and separately authorized non-formal adversary/emulation traces. It records compatibility, preprocessing burden, known/unknown storage size, labels, grouped split feasibility, leakage risks, and access constraints. No large corpus was downloaded. The FA1B2de set remains excluded: all 53 playbooks and 1796 raw actions are held out and were not acquired or used for fixtures, encoder design, training, tuning, calibration, or seed selection.

## Track-L training protocol

[PROVX_R4_TRAINING_PROTOCOL_DESIGN.json](PROVX_R4_TRAINING_PROTOCOL_DESIGN.json) freezes a design-only protocol separate from Track O: a new 32-input GCN detector, grouped host/run/scenario splits, training-only imbalance handling, predeclared optimizer/loss candidates, validation-only model selection and calibration, checkpoint identity requirements, training seeds distinct from the Phase-II seed, and the unchanged `314159` Phase-II registration. No detector was trained or retrained.

## Boundary

R4 is ready for fresh review before training selection. It does not authorize raw DARPA acquisition, APT execution, formal evaluation, packaged-checkpoint live use, or host enforcement.
