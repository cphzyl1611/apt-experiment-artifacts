# R2R1 Hard-Boundary Semantic Consistency Remediation

## Terminal Verdict

```text
PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2R1_HARD_BOUNDARY_SEMANTIC_CONSISTENCY_REMEDIATION = PASS_READY_FOR_MATERIALIZATION
```

This is a design-only, safe non-privileged remediation. It does not create or authenticate an R6 runtime handoff and does not authorize runtime execution.

## Single Hypothesis

```text
AUTHORITATIVE_CANONICAL_VALUE = true
CONTRADICTING_COMPONENT = validator
ROOT_CAUSE = The R2R1 validator applied a universal false check to all hard-boundary values, but pcap_is_not_graph_edge_source is an inverse guard whose authoritative value is true. The schema and authenticated design prose already encode that meaning.
```

The semantic authority is unique. The R2 and R2R1 prose define PCAP as provenance/authentication only and prohibit graph-edge use. The R2 and R2R1 schemas require `pcap_is_not_graph_edge_source: true`. The paired `pcap_authentication.used_as_graph_edge_source` field remains `false`. The seven positive operation/mutation fields remain `false`.

Evidence is in `AUTHORITATIVE_SEMANTIC_EVIDENCE.md` and `AUTHORITATIVE_SEMANTIC_EVIDENCE.json`.

## Reproduction and TDD

Before the patch, the authenticated R2R1 baseline produced this truth table:

| Value | Schema | Validator | Satisfies both |
|---:|---|---|---|
| `true` | accept | reject: `HANDOFF_SCOPE_BOUNDARY_VIOLATED` | no |
| `false` | reject: `True was expected` | accept | no |

```text
PRE_FIX_SATISFYING_VALUE_COUNT = 0
RED_TEST_OBSERVED = YES
```

The two focused tests were run against a temporary copy of baseline commit `31bc08d3ddd0c836a4b610b53714cadea084172f` with the focused test file applied. They failed with one error and one failure. The exact result is recorded in `RED_TEST_EVIDENCE.json`.

## Minimal Fix

Only the validator was corrected. `_check_hard_boundaries` now explicitly enumerates the seven positive operation/mutation fields and requires each to be `false`; it separately requires the inverse PCAP guard to be `true`; it retains the existing `used_as_graph_edge_source == false` check.

The schema was not changed. Fixtures were not changed. The self-contained package includes the unchanged R2R1 schema and fixture corpus so the safe suite can be replayed.

## Post-Fix Verification

```text
POST_FIX_SATISFYING_VALUE_COUNT = 1
HARD_BOUNDARY_SEMANTIC_CONSISTENCY = PASS
```

- Targeted semantic tests: `2/2 PASS`.
- Full safe suite: `49/49 PASS` (`47` historical tests plus `2` targeted tests).
- Static validation: `PASS` (`22` operators; `H001-H017` complete).
- Draft 2020-12 meta-validation: `9/9 PASS`.
- Pinned R2 payload match: `31/31`.
- R7R1 adapter hash drift: `0`.
- Frozen encoder hash drift: `0`.

Detailed results are in `VERIFICATION_EVIDENCE.json`, `POST_FIX_SAFE_SUITE.txt`, and `NON_REGRESSION_HASHES.json`.

## Required Record

```text
AUTHORITATIVE_CANONICAL_VALUE = true
CONTRADICTING_COMPONENT = validator
ROOT_CAUSE_AUTHENTICATION = PASS
PRE_FIX_SATISFYING_VALUE_COUNT = 0
POST_FIX_SATISFYING_VALUE_COUNT = 1
SCHEMA_VALIDATOR_SATISFYING_VALUE_COUNT = 1
RED_TEST_OBSERVED = YES
HARD_BOUNDARY_SEMANTIC_CONSISTENCY = PASS
PINNED_R2_PAYLOAD_MATCH = 31/31
R7R1_ADAPTER_HASH_DRIFT = 0
ENCODER_HASH_DRIFT = 0
SAFE_SUITE = 49/49 PASS
STATIC_VALIDATION = PASS
DRAFT_2020_12_META_VALIDATION = 9/9 PASS
PRODUCER_RECEIPT_EMISSION_NOT_IMPLEMENTED = OPEN
SOURCE_LINEAGE_NOT_AUTHENTICATED = OPEN
MATERIALIZATION_MANIFEST_PATH = /home/cph/experiment-parallel/e0-b/PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2R1_HARD_BOUNDARY_SEMANTIC_CONSISTENCY_REMEDIATION/MATERIALIZATION_MANIFEST.json
MANIFEST_FORMAT = canonical-v1
MANIFEST_TRACK = e0-b
MANIFEST_TASK_ID = PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2R1_HARD_BOUNDARY_SEMANTIC_CONSISTENCY_REMEDIATION
MANIFEST_FILE_COUNT = 41
MANIFEST_VALIDATION = PASS
NEXT_PHASE = PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2R1_INDEPENDENT_REVIEW
```

## Runtime Boundary

```text
AUTHENTICATED_R6_RUNTIME_INPUT = ABSENT
R2_PRIVILEGED_EXECUTION_RECEIPT = ABSENT
SOURCE_LINEAGE_AUTHENTICATED = NO
PROVX_TRAINING = NO
PROVX_INFERENCE = NO
FORMAL_1796_EXPERIMENT_EXECUTED = NO
PRODUCER_RECEIPT_EMISSION_NOT_IMPLEMENTED = OPEN
SOURCE_LINEAGE_NOT_AUTHENTICATED = OPEN
```

No privileged runtime, Mininet, training, inference, formal experiment, producer receipt emission, or source-lineage authentication was performed.

## Materialization

The canonical-v1 manifest is generated only after the package files are finalized and all checks pass. It is validate/inspect-only; no apply, commit, or push is performed.

```text
MANIFEST_FORMAT = canonical-v1
MANIFEST_TRACK = e0-b
MANIFEST_TASK_ID = PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2R1_HARD_BOUNDARY_SEMANTIC_CONSISTENCY_REMEDIATION
```

`MATERIALIZATION_MANIFEST.json` is the package manifest. The next phase is:

```text
PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2R1_INDEPENDENT_REVIEW
```
