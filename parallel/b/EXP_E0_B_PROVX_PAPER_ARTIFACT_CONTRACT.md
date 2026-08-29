# EXP-E0-B PROVX Paper-to-Artifact-to-Runtime Contract

## Scope and binding decisions

- Defense system: **PROVX — "Cutting the Fuse: Actionable APT Attack Blocking in Provenance-based IDS"**.
- This is reproduction preparation only. No artifact was downloaded, no dependency was installed, no model was trained, no inference or attack replay was run, and no formal score was created.
- Paper source: `sec26cycle2-final500(2).pdf`, local SHA-256 `74f2f0dca2f3deeb76f414358adecbf4268f4d8c2fe1ef5b1cfcd27ab159409d` (18 pages; PDF page references below are the printed-paper pages as extracted from the local file).
- Artifact source named by the paper: **ProvX Artifact**, Zenodo record `20310415`, DOI `10.5281/zenodo.20310415`. No local copy is present.
- The workspace is not a Git checkout; no Git commit, tag, or repository identity is available.

## Paper-derived architecture

### Phase I — Threat Detection

1. Host audit records are converted into a provenance graph `G_host = (V, E)`. Nodes represent system entities or events, including process/file/socket entities shown or discussed by the paper; edges represent causal dependencies, with examples including a process creating a file and a process sending data over the network (Sec. 4.1 and Fig. 3, paper pp. 5 and 4).
2. The paper's evaluation path uses Louvain community partitioning to obtain manageable provenance subgraphs. Benign subgraphs contain only benign system entities; malicious subgraphs contain at least one attack-related entity/stage. Hub nodes may occur in multiple subgraphs for contextual completeness (Sec. 4.1, p. 5).
3. This Louvain step is an evaluation instantiation, not a deployment requirement. In deployment, an alert-associated subgraph may instead come from an existing PIDS, EDR/SIEM alarm expanded with provenance queries, network indicators mapped to host events, or analyst-guided expansion (Secs. 3.1, 4.1, and 7, pp. 4-5 and 13).
4. The detector is a differentiable graph-level GNN classifier. The paper evaluates GCN, GAT, and GraphSAGE; Phase II requires a differentiable detector so gradients can optimize the edge mask (Sec. 4.1, p. 5).
5. Detector input is an extracted provenance subgraph `G_k`; the formal Phase-II representation is `G_k = (A_k, X_k)`, where `A_k` is the binary adjacency matrix and `X_k` is the node-feature matrix (Secs. 4.2.1 and 4.3, pp. 5 and 7). The paper does not publish an exact feature dimension or serialized file schema.
6. The detector outputs class probabilities `P(c | G_k)` for `c in {0,1}` and predicts `Y_hat_k = arg max_c P(c | G_k)` (Eq. 2, p. 5). `0` means all entities in the subgraph are benign; `1` means at least one malicious system entity/attack stage is present. A malicious prediction triggers an alert and is eligible for Phase II.

### Phase II — Attack Mitigation

1. **Continuous edge mask.** For alerted `G_k`, learn `M_hat_k` with the same dimensions as `A_k`; `sigmoid(M_hat_k)` is a soft retain mask and `A_tilde_k = A_k o sigmoid(M_hat_k)` (Eq. 3, p. 5). Values near 0 simulate blocking/removal and values near 1 simulate retaining an edge.
2. **Counterfactual prediction-flip objective.** The detector parameters remain fixed. The paper seeks the smallest structural change `d(G_tilde_k, G_k)` subject to `Y_hat_tilde_k != Y_hat_k` (Eq. 1, p. 4). In the implementation description, `L_pred = P(Y_hat_k, A_tilde_k)` minimizes the probability of the original threat prediction (Eq. 5, p. 6).
3. **Mask-distance objective.** `L_dist = BinaryCrossEntropy(sigmoid(M_hat_k), A_k)` penalizes broad graph modification (Eq. 6, p. 6). The primary loss is `L_CFX = alpha L_pred + (1-alpha) L_dist` (Eq. 7, p. 6).
4. **Staged solidification.** After the exploratory phase beginning at `T_start`, record the mask snapshot. Edges below `tau_low` and above `tau_high` are held toward their snapshot values by a squared-distance penalty `L_S`; total loss is `L_PROVX = L_CFX + gamma_S L_S` (Eqs. 8-9, p. 6). The paper names `R_S`, `gamma_S`, `tau_low`, and `tau_high` as controls; the required baseline values are pinned below.
5. **Top-K core edge output.** Convert the final mask to blocking priority `1 - sigmoid(M_hat_k*)`, select the `K` highest-scoring edges, and form the top-K core edge subgraph/list (Sec. 4.3, p. 7). `K` is a user-defined response budget; paper evaluations use `K=10` for OpTC and `K=30` for TC E3 (Secs. 4.3 and 6.2-6.3, pp. 7-9).
6. **Choke-point localization.** The top-K list is the concise analyst-facing output. It ranks edges by necessity to the current detector's malicious decision, not by operational safety or ease of enforcement (Sec. 4.3, p. 7).
7. **Model-level intervention semantics.** For MER evaluation, remove selected edges from `A_k` and suppress features of their incident endpoint nodes, then feed the intervened graph to the same fixed detector without retraining (Sec. 6.3, p. 9; Eq. 10).
8. **Mitigation Efficacy Rate (MER).** `MER = (1/N) sum_k p_k`, where `p_k=1` when the intervention changes `f(G_k)` and `f(I_K(G_k))`, otherwise `0` (Eq. 10, p. 9). It measures detector-prediction flips under a controlled structural-plus-attribute intervention.

**Boundary:** `MODEL_LEVEL_INTERVENTION_FLIP != REAL_WORLD_PREVENTED/BLOCKED`. The paper explicitly says a feasible counterfactual does not prove a host action is safe, feasible, or sufficient. The core-edge list is analyst-prioritized blocking guidance, not autonomous enforcement (Secs. 3.1 and 4.2, p. 4).

## Paper parameter pinning

| Item | Pinned paper claim | Evidence |
|---|---|---|
| Detector architecture | 2-layer GNN + ReLU/Dropout + average pooling + 2-layer MLP classifier | Sec. 6.1.2, p. 8 |
| Detector training | 50 epochs; Adam; learning rate `0.001` | Sec. 6.1.2, p. 8 |
| Phase-II edge-mask optimization | 200 epochs; learning rate `0.01` | Sec. 6.1.2, p. 8 |
| Staged solidification baseline | `R_S=0.6`; `gamma_S=0.5`; `tau_low=0.05`; `tau_high=0.95` | Sec. 6.1.2, p. 8 |
| Datasets | DARPA TC E3 (Cadets, Theia, Trace scenarios selected) and DARPA OpTC | Sec. 6.1.1, p. 8 |
| Dataset split | Training/validation/test ratio `7:1:2`; random negative sampling for scarce OpTC malicious subgraphs | Sec. 6.1.1, p. 8 |
| Reported host | Ubuntu 22.04.5 LTS; Intel Xeon Silver 4208, 14 cores/14 threads, 2.10 GHz; 256 GB RAM | Sec. 6.1.2, p. 8 |
| CPU-only evaluation | Evaluation across all three GNN backbones in a CPU-only environment | Sec. 6.6, p. 12 |
| Reported overhead | Generation: 113/174/140 s and 1377/1405/1379 MB; training: 733/1196/994 s and 1491/1519/1391 MB; mitigation evaluation: 3/4/4 s and 1541/1561/1461 MB for GCN/GAT/GraphSAGE respectively | Table 8, p. 12 |

If the artifact later disagrees with any paper value, preserve both values and report the discrepancy; do not silently normalize.

## Local artifact inventory (read-only preflight)

| Asset | Local finding | Identity |
|---|---|---|
| Local paper | `./sec26cycle2-final500(2).pdf` | SHA-256 above; 18 pages |
| Prompt | `./Prompt_2_EXP_E0_B_PROVX_Reproduction_Preflight.md` | No Git identity available |
| PROVX/ProvX source | Not found | `UNAVAILABLE_LOCALLY` |
| Zenodo artifact / record payload | Not found | `UNAVAILABLE_LOCALLY`; do not download in E0 |
| Preprocessing scripts | Not found | `UNAVAILABLE_LOCALLY` |
| Trained GCN/GAT/GraphSAGE models | Not found | `UNAVAILABLE_LOCALLY` |
| DARPA TC/OpTC data | Not found | `UNAVAILABLE_LOCALLY` |
| Processed provenance graphs | Not found | `UNAVAILABLE_LOCALLY` |
| Experiment configs | Not found | `UNAVAILABLE_LOCALLY` |
| Prior reproduction logs/results | Not found | `UNAVAILABLE_LOCALLY` |

The inventory was performed with read-only filesystem searches. No clone or download was attempted.

## Runtime and dependency contract

| Contract item | Current evidence | Required R0 action |
|---|---|---|
| Python version | `UNAVAILABLE_LOCALLY` | Read artifact metadata/environment files |
| PyTorch version | `UNAVAILABLE_LOCALLY` | Read artifact metadata/lock files |
| Graph-learning framework | `UNAVAILABLE_LOCALLY`; paper only names GCN/GAT/GraphSAGE | Identify PyTorch Geometric, DGL, or local implementation from artifact |
| networkx/graph dependencies | `UNAVAILABLE_LOCALLY` | Read artifact dependency manifests |
| CPU/GPU | Paper reports CPU-only evaluation; no complete preprocessing bound | Confirm artifact prerequisites and reproduce CPU path first |
| Model/data entry points | `UNAVAILABLE_LOCALLY` | Identify scripts/modules and invocation contracts |
| Training entry point | `UNAVAILABLE_LOCALLY` | Identify after artifact authentication |
| Inference entry point | `UNAVAILABLE_LOCALLY` | Identify after artifact authentication |
| Phase-II entry point | `UNAVAILABLE_LOCALLY` | Identify after artifact authentication |
| Config files | `UNAVAILABLE_LOCALLY` | Inventory and freeze before formal evaluation |
| Random seed handling | `UNAVAILABLE_LOCALLY`; paper states random negative sampling but no seed | Locate seed controls; record all seeds and generators |
| Output formats | `UNAVAILABLE_LOCALLY`; paper describes adjacency/features and a top-K edge list conceptually | Inspect serializers and write a schema manifest |
| Memory | Paper reports roughly 1.4-1.6 GB peak for listed stages; not a full preprocessing bound | Measure only after R1/R2 and retain stage-specific measurements |

## Reproduction gate

The paper is present and sufficient to define the paper contract. The artifact is absent, so artifact authentication, dependency verification, pretrained-model verification, and runtime entry-point verification cannot be completed in E0. Readiness is therefore `BLOCKED_MISSING_PAPER_OR_ARTIFACT_INPUT` for the next artifact-authentication action, with the exact paper contract ready for `PROVX-R0` once the artifact is supplied through an authorized channel.

## Required terminal

```text
EXP_E0_B_DEFENSE_SYSTEM =
PROVX_FIXED_BY_SUPERVISOR

EXP_E0_B_REPRODUCTION_READINESS =
BLOCKED_MISSING_PAPER_OR_ARTIFACT_INPUT

FORMAL_EXPERIMENT_EXECUTED = NO
BINDING_AUTHORITY_MUTATION = NO
SCORING_AUTHORITY_MUTATION = NO

STOP = true
```
