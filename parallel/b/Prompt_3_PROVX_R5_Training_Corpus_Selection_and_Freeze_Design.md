# PROVX-R5 — Track-L Training Corpus Selection and Freeze Design

Continue from fresh-reviewed PROVX-R4.

Pinned state:

```text
TRACK_O = EXACT_OFFICIAL_ARTIFACT_REPRODUCTION_BASELINE
TRACK_L = PROVX_ADAPTED_LIVE_DEPLOYMENT

ENCODER_ID = provx-adapted-live-v1
ENCODER_DIMENSION = 32
ENCODER_R4 = PASS
GOLDEN_FIXTURE_DETERMINISM = PASS
MODEL_INTERFACE_32D = PASS

DETECTOR_TRAINED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
```

Pinned GitHub review commit:
`90513ab76a2d392398fefd0456ad53a4660a3e8a`

## Goal

Select and freeze a defensible Track-L training-corpus strategy and acquisition/split protocol.

Do NOT train a detector.
Do NOT download terabyte-scale datasets.
Do NOT execute FA1B2de actions.
Do NOT use the 1796 benchmark for training/tuning/calibration.

## 1. Authenticate R3/R4

Pin:
- R3 adapted schema;
- R3 train/eval separation contract;
- R3 Phase-II seed policy;
- R4 encoder implementation/hash;
- R4 golden hashes;
- R4 32D model-interface check;
- R4 training-corpus preflight.

## 2. Select a staged training strategy

Evaluate the R4 candidate sources and choose an explicit staged route.

Required route design should separate:

### Stage A — adapter/collector validation corpus
Preferred:
- reserved non-scored Mininet traces;
- benign process/file/socket traces.

Purpose:
- verify auditd/collector -> normalized provenance -> 32D encoder -> graph round-trip;
- not detector performance.

This stage may remain blocked until Mininet E1C passes.

### Stage B — benign training/background corpus
Use separately generated controlled benign traces with:
- run-level manifests;
- diverse process/file/socket behaviors;
- disjoint train/validation run groups.

### Stage C — positive/adversary training corpus
Choose one or more:
- separately authorized non-FA1B2de emulation traces;
- selected official OpTC subset;
- selected DARPA TC E3 subset.

Do not require full-dataset acquisition if a smaller scientifically defensible subset can be frozen.

## 3. Official corpus subset feasibility

For OpTC and TC E3, investigate official metadata/documentation only as needed.

Design a bounded subset acquisition strategy:
- exact host/day/run/engagement selection criteria;
- expected download size if discoverable;
- official source URL;
- checksum acquisition method;
- licensing/release terms;
- red-team/label availability;
- schema normalization requirements.

Do not download the corpus in R5.

## 4. Positive/negative balance

Design exact roles:
- benign/background;
- positive/adversary;
- calibration;
- validation.

Prevent label leakage:
- labels never become encoder inputs;
- path/host/run identifiers must not trivially encode class;
- split at run/host/scenario boundary, never random event split.

## 5. Frozen split protocol

Design deterministic split identities before data acquisition.

For each source define:
- grouping key;
- train groups;
- validation groups;
- optional calibration groups;
- exclusion rules;
- duplicate/cross-group detection;
- contamination checks.

No formal FA1B2de group is allowed.

## 6. Training hyperparameter authority

R4 defined design candidates.

R5 must freeze a bounded training search policy, not choose based on test outcomes.

Define:
- architecture candidates;
- optimizer/loss candidate set;
- learning-rate candidate set;
- epoch cap;
- early stopping;
- class-balance policy;
- fixed training seeds;
- validation metric;
- model-selection rule;
- calibration rule;
- checkpoint naming/hash contract.

Keep the primary Phase-II seed `314159` separate from training seeds.

## 7. Acquisition gate

Define a later human approval gate for external data acquisition if required.

Allowed later actions:

```text
APPROVE_BOUNDED_TRAINING_CORPUS_ACQUISITION
REJECT_CORPUS_ROUTE
REQUEST_SMALLER_OR_DIFFERENT_SUBSET
```

No approval performed now.

## 8. Training gate

Even after corpus acquisition, training requires a separate later gate after:
- corpus hashes;
- split manifest;
- encoder compatibility;
- contamination audit;
- class-count audit;
- train/eval exclusion check.

Do not train in R5.

## Outputs

- `PROVX_R5_INPUT_AUTHENTICATION.json`
- `PROVX_R5_STAGED_TRAINING_CORPUS_STRATEGY.json`
- `PROVX_R5_OFFICIAL_CORPUS_SUBSET_ACQUISITION_DESIGN.json`
- `PROVX_R5_TRAIN_VALIDATION_SPLIT_CONTRACT.json`
- `PROVX_R5_LABEL_LEAKAGE_AND_CONTAMINATION_CONTRACT.json`
- `PROVX_R5_TRAINING_SEARCH_POLICY.json`
- `PROVX_R5_CORPUS_ACQUISITION_DECISION_PACKET.json`
- `PROVX_R5_TRAINING_RELEASE_GATES.json`
- `PROVX_R5_TRAINING_CORPUS_FREEZE_REPORT.md`

## Hard boundaries

NO:
- external large-data download;
- detector training;
- benchmark leakage;
- FA1B2de action execution;
- packaged 21D checkpoint misuse;
- authority mutation.

## Terminal

```text
PROVX_R5_TRAINING_CORPUS_FREEZE =
READY_FOR_CORPUS_ACQUISITION_REVIEW | BLOCKED

TRACK_L_ENCODER = provx-adapted-live-v1
TRACK_L_DIMENSION = 32

STAGED_CORPUS_STRATEGY = FROZEN | BLOCKED
SPLIT_PROTOCOL = FROZEN | BLOCKED
TRAINING_SEARCH_POLICY = FROZEN | BLOCKED

CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
FORMAL_EXPERIMENT_EXECUTED = NO

NEXT_ACTION =
FRESH_REVIEW_OF_PROVX_R5_TRAINING_CORPUS_FREEZE

STOP = true
```
