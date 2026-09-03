# E0C R2R2 Remediation Report

## Input Blockers

The R2R1 independent review identified one remaining blocker: the schema
accepted `foo/bar:baz` while the semantic governance-reference validator
rejected it.

## Remediations

### Governance-reference syntax alignment

R2R2 preserves the R2 schema grammar and replaces the semantic pattern with
the exact same grammar. `GOVERNANCE_REFERENCE_PATTERN` is the semantic source
used by `_governance_reference_errors`; the syntax-domain test asserts it is
identical to the schema `$defs.reference.pattern` and evaluates accepted and
rejected witnesses through both layers.

| Requirement | R2 enforcement |
| --- | --- |
| Parent template identity | Exact comparison to the frozen crosswalk row |
| Frozen member-set hash | SHA-256 recomputation over canonical sorted keys |
| Child completeness | Every child is non-empty and every parent member is assigned |
| Child disjointness | Pairwise intersections and duplicate occurrence counts |
| Child count constraints | Each child count and total count are recomputed |
| Duplicate child IDs | Exact child-ID list comparison plus uniqueness check |
| Conservation recomputation | Union, overlap, unassigned, duplicate, hashes, cross-template, and Blocked31 checks |

The existing strict cross-field and evidence-acquisition controls are unchanged.
Operative split records continue to require non-null, non-empty, structurally
valid `future_resolution.evidence_manifest_reference` and
`future_resolution.independent_review_reference` values.

## Evidence Generated

- `fixtures/VALID_SPLIT_PROPOSAL_FIXTURE.json` is accepted.
- Thirteen `fixtures/NEGATIVE_*.json` records are rejected with declared
  expected failure codes, covering malformed
  counts and hashes, invalid parent identity and hash, duplicate child IDs,
  incomplete or overlapping partitions, an isolated false conservation claim,
  four governance-reference defects, and an out-of-parent member.
- `GOVERNANCE_REFERENCE_SYNTAX_WITNESSES.json` isolates accepted and rejected
  governance-reference syntax, including `foo/bar:baz`.
- `E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2_VALIDATION_EVIDENCE.json`
  records the baseline reconciliation, syntax alignment, and fixture outcomes.
- `test_e0c_r2r2_validation.py` provides the repeatable local test harness.

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
E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2 = PASS_READY_FOR_INDEPENDENT_REVIEW
SCHEMA_VALIDATION = PASS
SEMANTIC_VALIDATION = PASS
GOVERNANCE_REFERENCE_SYNTAX_ALIGNMENT = PASS
PARTITION_EVIDENCE_CLASS = PASS
GOVERNANCE_EVIDENCE_CLASS = PASS
NEGATIVE_FIXTURES_REJECTED = PASS
NEGATIVE_FIXTURE_REASONS = PASS
NEXT_ACTION = INDEPENDENT_REVIEW_OF_RESOLUTION_DESIGN_R2R2
STOP = true
```
