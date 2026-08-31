# PROVX-R6 Corpus Acquisition Governance and Readiness

Status: ready for explicit human acquisition review. R6 is a design and governance step only: no external corpus was downloaded, no detector was trained, and no FA1B2de action was executed.

## Authenticated inputs

`PROVX_R6_INPUT_AUTHENTICATION.json` authenticates all R5 corpus, split, leakage, search, acquisition-decision, release-gate, and report artifacts, together with the R4 encoder implementation, fixtures, golden hashes, verification, interface check, preflight, protocol, and report. The Track-L identity remains `provx-adapted-live-v1`, dimension 32. The pinned review commit is `ef9cc3cf7566cbe2280c29fcc1dde958cebf12d9` (`R6`), parent `90513ab76a2d392398fefd0456ad53a4660a3e8a`; all nine R5 files byte-match the remote `parallel/b` files at that commit. The workspace has no local Git repository, and no authority was mutated.

## Local-first dependency and benign corpus

`PROVX_R6_STAGE_A_LOCAL_VALIDATION_DEPENDENCY.json` keeps Stage A at `WAIT_MININET_E1C`. Reserved non-scored Mininet and benign process/file/socket traces are limited to raw-collector → normalized-record → graph → 32D tensor round-trip and safety checks. They cannot train, tune, calibrate, or be promoted after observing results. The dependency has no authenticated E1C PASS evidence in this workspace.

`PROVX_R6_STAGE_B_BENIGN_GENERATION_CONTRACT.json` freezes 24 whole host/run/day/workload groups: four isolated hosts crossed with six workload families. Each run has a fixed seed from 6101–6124, 60-second warmup, 900-second analysis interval, and 60-second cooldown. Families cover process lifecycle, package/service, file read/write, archive/search, socket client/server, and scheduled/batch behavior. Every run must account for process, file, and socket records, causal edges, event classes, and explicit zero/unknown cases. Collector loss must be ≤1%, invalid records ≤2%, timestamp-order errors 0, and non-finite rows 0.

The required immutable hash chain is:

```text
raw_sha256
  -> normalized_sha256 (includes raw_sha256)
  -> graph_sha256 (includes normalized_sha256, node/edge/normalization maps)
  -> feature_sha256 (includes graph_sha256, encoder/schema identity, x/edge_index hashes)
```

Any mismatch, missing coverage, loss-threshold failure, or missing authorization quarantines the complete run group and blocks release.

## Stage-C positive options

`PROVX_R6_STAGE_C_POSITIVE_CORPUS_OPTIONS.json` freezes exactly four alternatives. Option A is the default review preference because it uses the same collector and gives controlled causal labels; official sources remain bounded fallbacks and are not implicitly downloaded.

| Option | Scientific value | Main burden/risk | Mininet dependency |
|---|---|---|---|
| `OPTION_A_AUTHORIZED_NON_FA1B2DE_EMULATION` | Direct local causal compatibility and controlled positive labels | Isolation/safety, scenario signatures, action-to-record alignment | E1C required for live readiness; separate emulation authorization required |
| `OPTION_B_BOUNDED_OPTC_SUBSET` | Broad endpoint/ecological validity and official red-team ground truth | eCAR/errata normalization; 20 GiB compressed/50 GiB expanded cap; shared background leakage | No acquisition dependency; common 32D compatibility and E1C readiness gates remain |
| `OPTION_C_BOUNDED_TC_E3_SUBSET` | Five-performer provenance diversity and engagement ground truth | Avro/CDM/parser burden; 10 GiB compressed/30 GiB expanded cap; performer artifacts | No acquisition dependency; common 32D compatibility and E1C readiness gates remain |
| `OPTION_D_COMBINATION_WITH_FIXED_CAPS` | Local causal data plus one official diversity source | Highest combined normalization and cross-source leakage burden; fixed source-specific caps | E1C and Option-A safety gates remain; official fallback does not remove them |

No option has been selected or acquired.

## Official pre-acquisition manifests

`PROVX_R6_OPTC_PRE_ACQUISITION_MANIFEST_SCHEMA.json` and `PROVX_R6_TC_E3_PRE_ACQUISITION_MANIFEST_SCHEMA.json` define exact, bounded manifests without transferring data.

- OpTC is pinned to FiveDirections commit `5b108604f11f767aa11ea79ff827595f3fad15fd` and its official Google Drive folder. The deterministic fallback selects eight eligible hosts in provider-hostname UTF-8 order, two earliest complete benign-only days and one earliest ground-truth-overlap day per host, and the earliest passing 3600-second window in each: 24 target groups.
- TC E3 is pinned to Transparent Computing commit `244ae2401032ce92ac3b72f49b8039cae67d60d6` and its official Google Drive release. The fallback selects the first README-listed good topic for each of cadets, clearscope, fivedirections, theia, and trace, then one earliest complete benign and one earliest ground-truth-overlap 3600-second window per topic: 10 target groups.

Both schemas require source revision, exact provider object IDs/paths, byte lengths, provider and local SHA-256 values, manifest hash, labels/ground-truth identity, terms evidence, and normalization identities before transfer. Provider object IDs and checksums are currently `null` by design; any null at transfer time is a hard stop. Size estimates remain null until an approved provider manifest exists. No full OpTC (~terabyte-scale) or unbounded TC E3 download is authorized.

Labels remain manifest/target metadata only. Ground-truth-overlap windows contribute positive labels only where an independent documented alignment supports them; unaligned background is not relabeled by proximity. Host/path/user identifiers, topic/action IDs, schedules, outcomes, and annotations never enter the 32D encoder.

## Human decision and separate gates

`PROVX_R6_ACQUISITION_DECISION_PACKET.json` offers only:

```text
APPROVE_BOUNDED_TRAINING_CORPUS_ACQUISITION
REJECT_CORPUS_ROUTE
REQUEST_SMALLER_OR_DIFFERENT_SUBSET
```

The decision and scope remain null. The packet states explicitly that acquisition approval does not authorize detector training or formal evaluation.

`PROVX_R6_ACQUISITION_AND_TRAINING_RELEASE_GATES.json` keeps design gates, acquisition gates, training gates, and the final formal-evaluation gate separate. Acquisition requires a human decision, authorization/terms, provider identity and checksum manifests, accepted caps, and the E1C dependency disposition. Training additionally requires raw/normalized/graph/feature hashes, a materialized R5 grouped split, coverage/loss/class audits, contamination/leakage clearance, 32D compatibility, registered search policy, and a separate human training authorization. Formal evaluation requires a new authenticated 32D checkpoint and frozen calibration; FA1B2de remains excluded from all earlier stages.

## Terminal

```text
PROVX_R6_CORPUS_ACQUISITION_GOVERNANCE = READY_FOR_EXPLICIT_HUMAN_ACQUISITION_REVIEW
R5_INPUT_AUTHENTICATION = PASS
STAGE_A_DEPENDENCY = WAIT_MININET_E1C
STAGE_B_GENERATION_CONTRACT = FROZEN
STAGE_C_OPTIONS = FROZEN
CORPUS_ACQUIRED = NO
DETECTOR_TRAINED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
NEXT_ACTION = FRESH_REVIEW_OF_PROVX_R6_CORPUS_ACQUISITION_GOVERNANCE
STOP = true
```
