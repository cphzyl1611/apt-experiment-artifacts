# Prompt 2 — EXP-E0-B PROVX Reproduction Preflight

You are preparing the FA1B2de experiment.

The supervisor-selected defense system is fixed:

**PROVX — "Cutting the Fuse: Actionable APT Attack Blocking in Provenance-based IDS"**

Do NOT evaluate alternative defense systems.

This task is **paper/artifact reproduction preparation only**.

## Goal

Build an exact paper-to-artifact-to-runtime reproduction contract for PROVX before any installation, model training, or attack replay.

Use the local paper:

`sec26cycle2-final500(2).pdf`

if it is available in this workspace.

If the paper is not locally available, report that fact and do not invent paper-specific details.

The paper references an Open Science artifact:

- ProvX Artifact
- Zenodo record: `20310415`
- DOI: `10.5281/zenodo.20310415`

Do not download it in this E0 task unless it is already present locally.

## A. Paper-derived architecture

Extract and pin the exact paper claims for:

### Phase I — Threat Detection

- provenance graph construction
- process/file/socket causal entities and edges
- alert-associated provenance subgraphs
- Louvain-based subgraph acquisition in the paper's evaluation path
- GCN / GAT / GraphSAGE detector role
- detector input/output format
- malicious/benign prediction semantics

### Phase II — Attack Mitigation

- continuous edge mask
- counterfactual prediction-flip objective
- mask-distance objective
- staged solidification
- top-K core edge output
- choke-point localization
- model-level intervention semantics
- MER definition.

Keep an explicit boundary:

`MODEL_LEVEL_INTERVENTION_FLIP != REAL_WORLD_PREVENTED/BLOCKED`

The paper treats the core-edge list as analyst-prioritized blocking guidance; do not reinterpret it as autonomous enforcement.

## B. Paper parameter pinning

Verify and record from the paper:

- detector architecture:
  2-layer GNN + ReLU/Dropout + average pooling + 2-layer MLP
- detector training:
  50 epochs
  Adam
  learning rate = 0.001
- Phase-II edge-mask optimization:
  200 epochs
  learning rate = 0.01
- staged-solidification baseline parameters:
  `R_S = 0.6`
  `gamma_S = 0.5`
  `tau_low = 0.05`
  `tau_high = 0.95`
- datasets:
  DARPA TC E3
  DARPA OpTC

If the artifact later disagrees with the paper, that discrepancy must be reported rather than silently normalized.

## C. Local artifact inventory

Search read-only for existing local copies of:

- PROVX/ProvX source code
- Zenodo artifact
- preprocessing scripts
- trained GCN/GAT/GraphSAGE models
- DARPA TC/OpTC data
- processed provenance graphs
- experiment configurations
- old reproduction logs/results.

Record exact paths and Git/hash identities where available.

Do not clone or download anything.

## D. Runtime/dependency contract

From local source/metadata if available, derive:

- Python version
- PyTorch version
- graph-learning framework
- networkx or related graph dependencies
- CPU/GPU requirement
- model/data entry points
- training entry point
- inference entry point
- Phase-II entry point
- config files
- random seed handling
- output artifact formats.

The paper reports CPU-only evaluation on Ubuntu 22.04.5 and measured PROVX memory around the 1.4–1.6 GB range for the reported stages, but do not treat this as a complete preprocessing-resource bound.

## E. Exact Mininet integration gap

Analyze the required live pipeline:

`APT raw action`
→ `Mininet / controlled host execution`
→ `host audit/provenance collection`
→ `process/file/socket causal events`
→ `provenance graph`
→ `alert-associated subgraph`
→ `Phase-I differentiable GNN`
→ `PROVX Phase II`
→ `core edge list`

Identify every adapter not provided by the original paper artifact.

In particular determine:

- original PROVX operates on live audit streams or offline/preprocessed provenance graphs;
- graph schema expected by the model;
- node features;
- edge features;
- entity/event typing;
- subgraph construction requirements;
- how a live run can be transformed into the exact expected input.

Do NOT implement adapters in this task.

## F. Training/evaluation leakage

Formal FA1B2de evaluation will eventually cover:

- 53 playbooks
- 1796 raw actions.

These formal runs must not silently become detector training/tuning examples before evaluation.

Determine:

- whether the official artifact includes pretrained models;
- whether reproduction requires retraining;
- what training/calibration datasets are needed;
- how to separate training, calibration, validation, and final FA1B2de test runs;
- what configuration must be frozen before final evaluation.

## G. Reproduction stages

Produce the recommended sequence:

```text
PROVX-R0 artifact authentication
PROVX-R1 original paper-path reproduction
PROVX-R2 preprocessing/model/output schema pinning
PROVX-R3 live provenance adapter
PROVX-R4 Mininet non-scored integration smoke test
PROVX-R5 frozen formal-evaluation configuration
```

Do not skip R1 and directly claim Mininet reproduction.

## Required outputs

- `EXP_E0_B_PROVX_PAPER_ARTIFACT_CONTRACT.md`
- `EXP_E0_B_PROVX_REPRODUCTION_PREFLIGHT.json`
- `EXP_E0_B_PROVX_MININET_INTEGRATION_GAP.md`
- `EXP_E0_B_PROVX_REPRODUCTION_SEQUENCE.md`
- `EXP_E0_B_PROVX_TRAIN_TEST_SEPARATION.md`

## Hard boundaries

DO NOT:

- download the artifact;
- install dependencies;
- train models;
- run inference;
- replay attacks;
- create formal scores;
- mutate binding/scoring authority;
- mutate Git refs.

## Required terminal

```text
EXP_E0_B_DEFENSE_SYSTEM =
PROVX_FIXED_BY_SUPERVISOR

EXP_E0_B_REPRODUCTION_READINESS =
READY_FOR_PROVX_R0 | BLOCKED_MISSING_PAPER_OR_ARTIFACT_INPUT

FORMAL_EXPERIMENT_EXECUTED = NO
BINDING_AUTHORITY_MUTATION = NO
SCORING_AUTHORITY_MUTATION = NO

STOP = true
```
