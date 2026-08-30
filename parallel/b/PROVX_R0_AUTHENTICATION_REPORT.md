# PROVX-R0 Authentication Report

## Decision

`PROVX_R0_ARTIFACT_AUTHENTICATION = PASS_READY_FOR_R1_REPRODUCTION`

This PASS authenticates the cited Zenodo record, the downloaded bytes, the safe extraction, and the inspectable artifact interfaces. It does **not** claim that PROVX reproduction, model inference, training, or formal evaluation succeeded.

## Official record

- Cited DOI: `10.5281/zenodo.20310415`
- Canonical record URL after DOI resolution: `https://zenodo.org/records/20310415`
- Metadata endpoint: `https://zenodo.org/api/records/20310415`
- Record ID: `20310415`; concept record: `20310414`; published/latest state: true/done
- Title: `Artifact for Paper "Cutting the Fuse: Actionable APT Attack Blocking in Provenance-based IDS"`
- Publication date: `2026-05-20`; record modified: `2026-05-31T08:28:58.404925+00:00`
- Creator: Wu, Weiheng (ORCID `0009-0001-3114-7422`)
- License: MIT (`mit-license`); access: open; resource type: Software
- Identity check: PASS. Title and description explicitly identify the ProvX artifact accompanying the paper. No similarly named artifact was substituted.

The complete server response is preserved at [PROVX_R0_ZENODO_RECORD_METADATA.json](provx-r0/PROVX_R0_ZENODO_RECORD_METADATA.json).

## Acquisition authentication

- Isolated directory: `provx-r0/`
- Published file count: 1
- Published file: `ProvX-USENIX-artifact.zip`
- Published/downloaded bytes: `11,549,911 / 11,549,911`
- Published MD5: `72467df3c22ba706cb33adfbd87a0681`
- Downloaded MD5: `72467df3c22ba706cb33adfbd87a0681` (MATCH)
- Downloaded SHA-256: `a46fe7dec840ea28d9f8acf8771879af7204e0d622e24d12a99ad95f4187e3ff`
- Existing files overwritten: no
- DARPA datasets downloaded separately: no

The acquisition manifest was created before extraction and records the URL, hashes, byte comparison, and extraction state.

## Safety authentication

- ZIP members: 68
- ZIP integrity check: pass
- Absolute paths: 0
- Path traversal members: 0
- Symlinks: 0
- Hardlinks: no hardlink metadata/type present
- Device/FIFO/socket members: 0
- Compressed bytes: 11,532,847
- Uncompressed bytes: 167,058,031
- Extraction target: fresh `provx-r0/extracted/`
- Extracted regular files: 57 (23 project files plus 34 macOS metadata files)

The complete safety evidence is in [PROVX_R0_ARCHIVE_SAFETY_AUDIT.json](provx-r0/PROVX_R0_ARCHIVE_SAFETY_AUDIT.json), with the extracted file list and SHA-256 list in the corresponding required outputs.

## Interface authentication

The archive contains:

- README and MIT license;
- exact dependency list (`torch==2.8.0`, `torch-geometric==2.6.1`, `numpy==2.0.2`, `scikit-learn==1.6.1`);
- PyG sample train/validation/test partitions and auxiliary labels;
- source for the detector, training, Phase-II explainer, evaluation, checkpoint loading, and five CLI entry points;
- one packaged GCNConv reference checkpoint and metadata.

No raw DARPA audit logs, raw-to-graph/Louvain preprocessing implementation, Docker/Conda environment, Python version declaration, GAT checkpoint, or GraphSAGE checkpoint is included.

## Required discrepancy disposition

Paper/artifact discrepancies are preserved in [PROVX_R0_PAPER_ARTIFACT_DISCREPANCIES.md](PROVX_R0_PAPER_ARTIFACT_DISCREPANCIES.md). The principal frozen issues for R1 are:

- artifact detector training uses AdamW at `0.005`, while the paper specifies Adam at `0.001`;
- artifact Phase-II default uses Adam `0.05` and solidification factor `0.6`, while the paper baseline specifies `0.01` and `0.5`;
- artifact mask losses operate on PyG message masks with raw-logit prediction loss and BCE-to-ones distance, not exactly the paper's written probability/BCE-to-adjacency equations;
- only a GCNConv checkpoint is packaged;
- packaged sample graphs are not the full DARPA TC E3/OpTC raw/provenance pipeline.

## Boundary and execution record

`MODEL_LEVEL_INTERVENTION_FLIP != REAL_WORLD_PREVENTED/BLOCKED` remains binding. No host action was executed or authorized.

```text
PROVX_R0_ARTIFACT_AUTHENTICATION =
PASS_READY_FOR_R1_REPRODUCTION

PROVX_MODEL_EXECUTED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
BINDING_AUTHORITY_MUTATION = NO
SCORING_AUTHORITY_MUTATION = NO

NEXT_ACTION =
FRESH_REVIEW_OF_PROVX_R0_ARTIFACT_AUTHENTICATION

STOP = true
```
