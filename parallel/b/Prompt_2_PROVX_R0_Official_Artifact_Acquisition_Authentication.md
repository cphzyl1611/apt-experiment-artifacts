# Prompt 2 — PROVX-R0 Official Artifact Acquisition and Authentication

Continue from EXP-E0-B.

The fixed defense system is:

**PROVX — "Cutting the Fuse: Actionable APT Attack Blocking in Provenance-based IDS"**

The local paper is already authenticated in the previous preflight.

The paper cites:

- Zenodo record: `20310415`
- DOI: `10.5281/zenodo.20310415`

## Goal

Perform only:

`PROVX_R0_OFFICIAL_ARTIFACT_ACQUISITION_AND_AUTHENTICATION`

This task may access the network only to obtain the official Zenodo record metadata and artifact files.

Do not install dependencies.
Do not train or execute PROVX.

## 1. Resolve official record

Resolve only through the cited DOI/Zenodo record.

Capture:
- final canonical record URL;
- record metadata JSON if available;
- title;
- version;
- publication/update date;
- creators;
- file list;
- file sizes;
- server-provided checksums;
- license;
- DOI.

If the DOI/record does not resolve to the PROVX artifact described by the paper, fail closed.

Do not substitute a similarly named provenance artifact.

## 2. Download artifact into isolated R0 directory

Create:

`~/experiment-parallel/e0-b/provx-r0/`

Download only the exact files published by the authenticated record.

Do not overwrite existing files.

For each downloaded file compute:
- SHA256;
- byte length;
- published MD5/checksum comparison where Zenodo supplies one.

Create an acquisition manifest before extraction.

## 3. Safe archive inspection

Before extraction:
- list archive members;
- reject absolute paths;
- reject `..` path traversal;
- record symlinks/hardlinks;
- reject unsafe device/FIFO members;
- record compressed/uncompressed size where available.

Extract only into a fresh directory under `provx-r0/extracted/`.

## 4. Internal artifact inventory

Generate:
- exact FILE_LIST;
- SHA256SUMS for extracted regular files;
- directory tree;
- README/license locations.

Inspect read-only:
- README;
- requirements/environment files;
- Python package metadata;
- Docker/Conda files;
- dataset download scripts;
- preprocessing;
- GCN/GAT/GraphSAGE code;
- Phase-II mask optimizer;
- staged solidification;
- evaluation/MER code;
- checkpoints/pretrained models;
- config files;
- random seeds;
- expected graph/node/edge formats;
- entry points.

Do not execute imports that trigger downloads/training.

## 5. Paper ↔ artifact discrepancy report

Compare exact artifact facts to the paper contract from E0-B:

- detector architecture;
- epochs/LR;
- Phase-II parameters;
- data split;
- graph features/schema;
- top-K/MER behavior;
- runtime dependencies;
- model checkpoints.

Do not silently reconcile mismatches.

## 6. Readiness decision

Allowed:

```text
PROVX_R0_ARTIFACT_AUTHENTICATION =
PASS_READY_FOR_R1_REPRODUCTION
|
BLOCKED
```

PASS means artifact bytes and interfaces are authenticated, not that reproduction succeeded.

## Required outputs

- `PROVX_R0_ZENODO_RECORD_METADATA.json`
- `PROVX_R0_ACQUISITION_MANIFEST.json`
- `PROVX_R0_ARCHIVE_SAFETY_AUDIT.json`
- `PROVX_R0_EXTRACTED_FILE_LIST.txt`
- `PROVX_R0_EXTRACTED_SHA256SUMS.txt`
- `PROVX_R0_RUNTIME_AND_ENTRYPOINT_INVENTORY.json`
- `PROVX_R0_PAPER_ARTIFACT_DISCREPANCIES.md`
- `PROVX_R0_AUTHENTICATION_REPORT.md`

## Hard boundaries

DO NOT:
- install packages;
- create/modify system environments;
- train models;
- run inference;
- download DARPA datasets unless they are themselves included as exact artifact files;
- execute APT actions;
- mutate binding/scoring authority;
- mutate Git refs.

## Terminal

```text
PROVX_R0_ARTIFACT_AUTHENTICATION =
PASS_READY_FOR_R1_REPRODUCTION | BLOCKED

PROVX_MODEL_EXECUTED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
BINDING_AUTHORITY_MUTATION = NO
SCORING_AUTHORITY_MUTATION = NO

NEXT_ACTION =
FRESH_REVIEW_OF_PROVX_R0_ARTIFACT_AUTHENTICATION

STOP = true
```
