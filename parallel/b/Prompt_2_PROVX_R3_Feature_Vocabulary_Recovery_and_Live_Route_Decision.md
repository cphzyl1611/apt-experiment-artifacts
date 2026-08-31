# PROVX-R3 — 21-Feature Vocabulary Recovery and Live Deployment Route Decision

Continue from fresh-reviewed PROVX-R2.

Accepted:
- PROVX_R2_SCHEMA_PINNING=PASS
- EXTERNAL_SEED_CONTROL=DETERMINISTIC_FOR_FIXED_SEED
- x=float32 [N,21]
- edge_index=int64 [2,E]
- detector runtime input is x + edge_index

Critical unresolved fact: the official artifact does not define the semantics/vocabulary of the 21 x columns. The packaged checkpoint is therefore not yet validated for arbitrary newly encoded Mininet provenance.

Goal: exhaustively resolve whether the official 21-feature vocabulary can be authenticated. If not, design an adapted-PROVX live route while keeping exact artifact reproduction separate.

1. Search read-only across official artifact source, README/docs/scripts, checkpoint metadata, Sample metadata, auxiliary labels, comments/docstrings, R0/R1/R2 artifacts, local paper/supplementary material for feature encoding, node/entity types, one-hot vocabulary, preprocessing, Louvain, DARPA/TC mapping, etc. Do not infer semantics from statistics alone.

2. If local evidence is insufficient and network access is available, query only official/cited sources (Zenodo, official paper supplementary/artifact links, official author repository explicitly linked by the artifact). Pin URLs/hashes. Do not use third-party implementations as authority.

3. Decide only:
OFFICIAL_21_FEATURE_VOCABULARY_RECOVERED
OFFICIAL_21_FEATURE_VOCABULARY_NOT_AVAILABLE
BLOCKED_INCOMPLETE_SEARCH

If recovered: freeze ordered 21-column vocabulary and deterministic live encoder, and prove compatibility with packaged sample/checkpoint.

If not available: set PACKAGED_CHECKPOINT_DIRECT_LIVE_MININET_USE=NOT_VALIDATED. Do not invent a mapping.

4. If semantics are unavailable, define two methodology tracks:

Track O — exact artifact reproduction baseline:
official Sample + packaged checkpoint + artifact-as-shipped params + fixed external Phase-II seed wrapper.

Track L — PROVX_ADAPTED_LIVE_DEPLOYMENT:
preserve provenance-subgraph detector architecture, GCN/GNN structure, Phase-II mask/explanation, staged solidification, MER semantics, and fixed-seed control; define a new explicit live feature encoder and retrain under a separately frozen protocol.

5. Design (do not train) an adapted live feature schema:
- deterministic
- collector-visible provenance only
- process/file/socket distinctions
- no evaluation labels as runtime inputs
- ordered features
- normalization/unknown handling
- versioned encoder ID/hash
Do not force 21 dimensions unless justified.

6. Design train/eval separation. The 1796 FA1B2de evaluation raws must not be used as detector training examples/labels. Define acceptable separate training sources conceptually.

7. Freeze a pre-registration policy for Phase-II randomness: one primary externally fixed seed chosen before formal evaluation, plus optional predeclared multi-seed sensitivity analysis. Do not choose a seed based on favorable formal results.

Outputs:
- PROVX_R3_FEATURE_SEMANTICS_SEARCH_INVENTORY.json
- PROVX_R3_OFFICIAL_21_FEATURE_VOCABULARY_DECISION.json
- PROVX_R3_EXACT_VS_ADAPTED_DEPLOYMENT_CONTRACT.md
- PROVX_R3_ADAPTED_LIVE_FEATURE_SCHEMA.json
- PROVX_R3_TRAIN_EVAL_SEPARATION_CONTRACT.json
- PROVX_R3_PHASE2_SEED_POLICY.json
- PROVX_R3_LIVE_ROUTE_DECISION_REPORT.md

No training/retraining, formal benchmark, APT action execution, official source modification, or authority mutation.

Terminal:
PROVX_R3_FEATURE_VOCABULARY = OFFICIAL_21_FEATURE_VOCABULARY_RECOVERED | OFFICIAL_21_FEATURE_VOCABULARY_NOT_AVAILABLE | BLOCKED_INCOMPLETE_SEARCH
PACKAGED_CHECKPOINT_DIRECT_LIVE_MININET_USE = VALIDATED | NOT_VALIDATED
LIVE_PROVX_ROUTE = EXACT_CHECKPOINT_LIVE_ROUTE | PROVX_ADAPTED_LIVE_DEPLOYMENT | BLOCKED
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_PROVX_R3_LIVE_ROUTE_DECISION
STOP = true
