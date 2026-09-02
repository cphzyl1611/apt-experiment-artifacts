# E0C R2R1 Remediation Report

## Input Blockers

The R1 independent review identified that the prior schema accepted malformed
child counts, hashes, parent identity, duplicate child IDs, and false
conservation claims. It also identified that the acquisition contract did not
expose `PARTITION` or `GOVERNANCE` evidence classes.

## Remediations

### Schema and semantic validation

The R2 schema adds strict structural constraints and an explicit ordered,
unique child-ID index. The accompanying `validate_e0c_r2.py` validator performs
the normative cross-field checks:

| Requirement | R2 enforcement |
| --- | --- |
| Parent template identity | Exact comparison to the frozen crosswalk row |
| Frozen member-set hash | SHA-256 recomputation over canonical sorted keys |
| Child completeness | Every child is non-empty and every parent member is assigned |
| Child disjointness | Pairwise intersections and duplicate occurrence counts |
| Child count constraints | Each child count and total count are recomputed |
| Duplicate child IDs | Exact child-ID list comparison plus uniqueness check |
| Conservation recomputation | Union, overlap, unassigned, duplicate, hashes, cross-template, and Blocked31 checks |

The schema is intentionally paired with the validator: JSON Schema cannot
calculate SHA-256 or compare arbitrary arrays across object fields. A proposal
is accepted only when both validation layers pass.

Operative split records now also require non-null, non-empty, structurally valid
`future_resolution.evidence_manifest_reference` and
`future_resolution.independent_review_reference` values. The schema and
semantic validator enforce the same reference naming and fail-closed behavior.

### Evidence acquisition

The R2 acquisition contract now includes explicit `PARTITION` and `GOVERNANCE`
request classes with questions and acceptance criteria. It also requires
partition and governance request sections while retaining the existing
non-authoritative and zero-mutation boundaries.

## Evidence Generated

- `fixtures/VALID_SPLIT_PROPOSAL_FIXTURE.json` is accepted.
- Thirteen `fixtures/NEGATIVE_*.json` records are rejected with declared
  expected failure codes, covering malformed
  counts and hashes, invalid parent identity and hash, duplicate child IDs,
  incomplete or overlapping partitions, an isolated false conservation claim,
  four governance-reference defects, and an out-of-parent member.
- `E0C_EXACT12_SPLIT_OR_MORE_EVIDENCE_RESOLUTION_DESIGN_R2_VALIDATION_EVIDENCE.json`
  records the baseline reconciliation and fixture outcomes.
- `test_e0c_r2_validation.py` provides the repeatable local test harness.

The fixtures use the first frozen template only as a synthetic validator input.
They are not source evidence, human decisions, applied splits, or execution
plans.

## Boundary Confirmation

No Exact12 member identity or current state was changed. The copied crosswalk
still has 12 templates and 203 raw members, with zero overlap and zero drift.
The R2 boundary records:

```text
APPLIED_SPLITS = 0
STATUS_MUTATIONS = 0
EXECUTION_AUTHORIZATIONS = 0
DENOMINATOR_CHANGE = NO
FORMAL_EXPERIMENT_EXECUTED = NO
HUMAN_DECISIONS_CREATED = 0
PUSH_EXECUTED = NO
```

## Terminal

```text
E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R1 = PASS_READY_FOR_INDEPENDENT_REVIEW
SCHEMA_VALIDATION = PASS
SEMANTIC_VALIDATION = PASS
PARTITION_EVIDENCE_CLASS = PASS
GOVERNANCE_EVIDENCE_CLASS = PASS
NEGATIVE_FIXTURES_REJECTED = PASS
NEGATIVE_FIXTURE_REASONS = PASS
NEXT_ACTION = INDEPENDENT_REVIEW_OF_RESOLUTION_DESIGN_R2
STOP = true
```
