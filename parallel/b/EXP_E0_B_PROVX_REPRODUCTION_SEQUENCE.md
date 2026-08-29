# EXP-E0-B PROVX Reproduction Sequence

The sequence below is mandatory. R1 is required; a Mininet result cannot be called a PROVX reproduction if the original paper path has not first been reproduced.

## PROVX-R0 artifact authentication

**Input:** authorized local copy of Zenodo record `20310415` / DOI `10.5281/zenodo.20310415`.

**Actions:** inventory files; record archive and file hashes; identify license and version; compare README/config claims with the paper; locate pretrained checkpoints, data references, scripts, and environment manifests; record any paper/artifact discrepancies.

**Gate:** artifact is locally authenticated, or the discrepancy/blocker is recorded. No download occurs in this E0 preflight.

## PROVX-R1 original paper-path reproduction

**Input:** authenticated artifact, its intended benchmark inputs, and paper-pinned configuration.

**Actions:** run the artifact's own offline preprocessing and detector path on DARPA TC E3 (Cadets, Theia, Trace) and DARPA OpTC; reproduce the paper's 2-layer GCN/GAT/GraphSAGE detector setup, 50-epoch Adam training at `0.001`, and `7:1:2` split where applicable; retain logs and hashes.

**Gate:** detector outputs and data shapes are understood, and any mismatch with paper tables is reported. Do not proceed by silently changing parameters.

## PROVX-R2 preprocessing/model/output schema pinning

**Input:** R1 code and outputs.

**Actions:** document raw-to-graph transformations; exact node/edge types and features; tensor dimensions and serialization; checkpoint format; seed handling; train/validation/test manifests; Phase-II invocation; top-K edge output and MER intervention format; exact dependency versions and entry points.

**Gate:** a versioned schema/config manifest can transform one known benchmark sample into the exact model input and output without ambiguity.

## PROVX-R3 live provenance adapter

**Input:** pinned R2 schema and an independently designed Mininet/audit collection layer.

**Actions:** define action identity propagation; collect controlled host audit records; normalize process/file/socket events; construct causal graph and node features; associate/expand alert subgraphs; serialize to the R2 contract; preserve reversible evidence mappings.

**Gate:** adapter conformance tests pass on synthetic/non-formal traces. No formal scores yet.

## PROVX-R4 Mininet non-scored integration smoke test

**Input:** R3 adapter and isolated controlled-host scenarios.

**Actions:** execute a small non-scored set; verify action-to-event coverage, graph construction, detector invocation, fixed-detector Phase-II mask optimization (200 epochs at `0.01` when using the paper baseline), top-K edge serialization, and analyst-readable evidence mapping.

**Gate:** end-to-end path completes with provenance and schema checks; no results enter training, calibration, or formal evaluation.

## PROVX-R5 frozen formal-evaluation configuration

**Input:** R0-R4 evidence and approved FA1B2de governance.

**Actions:** freeze artifact/code/dependency hashes; preprocessing and split manifests; checkpoints; all random seeds; detector and Phase-II parameters; `alpha`, `K`, solidification controls; output schema; logging and failure policy. Reserve the 53 playbooks and 1796 raw actions as final test material.

**Gate:** configuration is immutable for final runs. Any post-freeze change creates a new configuration identity and cannot overwrite scores.

## Current status

`PROVX-R0` is the next stage, but this workspace lacks the artifact payload. The paper contract is complete; no later stage is claimed complete.

