# PROVX-R5 Track-L Training Corpus Freeze

Status: design frozen and ready for a later human acquisition review. No corpus was acquired, no detector was trained, and no formal experiment was executed.

## Authenticated starting point

The R3/R4 inputs are authenticated by `PROVX_R5_INPUT_AUTHENTICATION.json`. The Track-L encoder remains `provx-adapted-live-v1` with 32 output columns. The local R4 implementation, tests, fixtures, golden tensor hashes, verification, 32D interface check, corpus preflight, protocol design, and report all byte-match the corresponding `parallel/b` files at pinned review commit `90513ab76a2d392398fefd0456ad53a4660a3e8a` (`round5`). The R3 contracts are authenticated from the local workspace; they are not claimed to be in that commit.

Key authenticated hashes:

- R3 adapted schema: `53caab007f9cea84e83a5fb92ddea0cb9082cb816d19752db896cc58c675f68a`
- R4 encoder implementation: `013d9b77297308843144ccfce4c3eec4b03dc3cc5172dabd6eb3320e7bc46547`
- R4 golden tensor hash manifest: `27b7aeb52f90ddb62240e72a558f2807eec2325813df3ec3fe581567caaa8c48`
- R4 interface check: `86c848a7047625be88aa8a4ec03cdc2e998db4bda992b0cbbb758e6dbdaca406`

## Frozen staged route

`PROVX_R5_STAGED_TRAINING_CORPUS_STRATEGY.json` freezes this sequence:

1. Stage A uses reserved non-scored Mininet and benign process/file/socket traces for collector-to-graph-to-32D round-trip validation only. It remains blocked until Mininet E1C passes and is never silently promoted into fitting or calibration.
2. Stage B is separately generated controlled benign background: at least 24 whole host/run/day/workload groups, with run manifests and process/file/socket coverage.
3. Stage C is authorized, isolated, non-FA1B2de emulation for positive groups (at least 12 scenario groups). Bounded OpTC and TC E3 subsets are frozen as optional fallbacks or diversity augmentation, not as an implicit full-dataset acquisition.

The packaged 21-input Sample tensors and `_VULN`/`_LINE`/`_SAMPLE` metadata remain Track O controls and are excluded from Track-L training.

## Official subset feasibility

`PROVX_R5_OFFICIAL_CORPUS_SUBSET_ACQUISITION_DESIGN.json` records official URLs, pinned documentation revisions/hashes, release terms, labels, normalization, checksum method, and stop conditions without downloading data.

- OpTC: the official README documents approximately one terabyte compressed data and about 500 hosts over a two-week evaluation, hosted on Google Drive. The frozen fallback selects the first eight eligible hosts (UTF-8 order), two earliest complete benign days and one earliest ground-truth-overlap day per host, and the earliest passing 3600-second window in each. Target: 24 groups; transfer ceiling: 20 GiB compressed/50 GiB expanded.
- DARPA TC E3: the official README-E3 lists good topics for five performers. The frozen fallback selects the first good topic per performer, then one earliest complete benign and one earliest ground-truth-overlap 3600-second window. Target: 10 groups; transfer ceiling: 10 GiB compressed/30 GiB expanded.

The subset is blocked if eligibility, labels, provider object identity, checksums, or caps cannot be satisfied; criteria may not be relaxed post hoc. Public-domain/public-release, as-is/no-warranty language is preserved as documentation evidence, but provider terms and authorization must be rechecked at acquisition.

## Split, leakage, and contamination freeze

`PROVX_R5_TRAIN_VALIDATION_SPLIT_CONTRACT.json` defines source-specific whole-group keys and a pre-acquisition assignment: SHA-256 of canonical `{source_id, canonical_group_key, source_revision}`, first eight hex digits modulo 20, buckets 0–13 train, 14–16 validation, and 17–19 calibration. There is no alternate seed or post-hoc reassignment. Stage A is smoke-only. A materialized manifest must persist group digests, partition, source/label provenance, raw/graph/feature hashes, and the contract hash.

`PROVX_R5_LABEL_LEAKAGE_AND_CONTAMINATION_CONTRACT.json` keeps labels, ground truth, playbook/action identity, outcomes, analyst annotations, and Track O metadata out of the encoder. Host/path/user identifiers are de-identified; literal command lines and tool/action tokens are scrubbed; IDs are metadata-only. Exact raw/canonical/graph duplicate hashes, overlapping windows, denylist hits, and feature-dependency violations quarantine the affected material and block release. FA1B2de’s 53 playbooks and 1796 raw actions are denied everywhere before final evaluation.

## Frozen training search

`PROVX_R5_TRAINING_SEARCH_POLICY.json` freezes one GCNConv architecture (`input_feature_dim=32`, hidden 64, feature 256, two layers, mean pool, dropout 0.1) and exactly two complete optimizer/loss tuples:

- `cfg-01-adamw-ce-sampler`: AdamW, cross-entropy, learning rate 0.005, inverse-frequency train sampler (multiplier 3).
- `cfg-02-adam-weighted-ce`: Adam, class-weighted cross-entropy, learning rate 0.001, no sampler.

Batch size is 32, epoch cap 50, gradient clip 1.0, and early stopping monitors validation balanced accuracy with patience 10 and best-epoch restoration. Selection uses validation balanced accuracy, then binary F1, then loss, then fixed lexical/epoch tie-breaks. The default output is argmax; any threshold grid (0.00–1.00 by 0.01) is calibration-only and must be frozen before formal evaluation. Training seeds are 1 (primary) and optional predeclared 7/17 sensitivity; Phase-II seed 314159 remains separate.

## Human gates and current state

`PROVX_R5_CORPUS_ACQUISITION_DECISION_PACKET.json` is `PENDING_HUMAN_APPROVAL` and offers only `APPROVE_BOUNDED_TRAINING_CORPUS_ACQUISITION`, `REJECT_CORPUS_ROUTE`, or `REQUEST_SMALLER_OR_DIFFERENT_SUBSET`. No choice is recorded. `PROVX_R5_TRAINING_RELEASE_GATES.json` marks design gates pass and all acquisition/training/formal gates closed. Training cannot begin until corpus hashes, split manifest, encoder compatibility, contamination audit, class-count audit, train/eval exclusion check, search registration, and a separate human training authorization all pass.

## Terminal

```text
PROVX_R5_TRAINING_CORPUS_FREEZE = READY_FOR_CORPUS_ACQUISITION_REVIEW
TRACK_L_ENCODER = provx-adapted-live-v1
TRACK_L_DIMENSION = 32
STAGED_CORPUS_STRATEGY = FROZEN
SPLIT_PROTOCOL = FROZEN
TRAINING_SEARCH_POLICY = FROZEN
CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_PROVX_R5_TRAINING_CORPUS_FREEZE
STOP = true
```
