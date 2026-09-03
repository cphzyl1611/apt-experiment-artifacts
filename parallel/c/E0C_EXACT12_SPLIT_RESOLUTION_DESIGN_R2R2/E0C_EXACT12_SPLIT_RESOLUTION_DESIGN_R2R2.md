# E0C Exact12 Split Resolution Design R2R2

E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2 = PASS_READY_FOR_INDEPENDENT_REVIEW
DESIGN_DATE = 2026-09-03

## Remediation Scope

R2R2 remediates only the governance-reference syntax disagreement found by the
R2R1 independent review:

1. schema and semantic governance-reference syntax alignment;
2. isolated witness coverage for that alignment.

The R2R1 package remains an immutable prior-review input. The R2R2 package does
not apply a split, make a human decision, mutate a status, change the
denominator, authorize execution, run an experiment, or push to a remote
repository.

## Strict Validation Boundary

`TEMPLATE_LEVEL_RESOLUTION_SCHEMA.json` is the structural gate. It requires:

- exact record type and R2 schema version;
- frozen template identity fields;
- current hold-state constants;
- non-empty child partitions;
- unique member keys within each child;
- child counts and SHA-256 fields;
- explicit ordered `child_partition_ids` with unique items;
- conservation fields and zero-mutation constants.

`validate_e0c_r2.py` is the semantic gate for relationships that cannot be
calculated by JSON Schema alone. It validates the record against the exact
crosswalk row and recomputes:

- parent template ID, frozen order, count, member-set hash, and reference;
- every child count and canonical member-set hash;
- child ID uniqueness and consecutive order;
- child membership subset, exact union, pairwise disjointness, unassigned
  members, and duplicate members;
- sum of child counts;
- cross-template overlap and Blocked31 overlap;
- submitted conservation claims against recomputed values;
- non-null, non-empty, structurally valid governance references for operative
  split records;
- unapplied split, zero status mutation, zero execution authority, and `NO`
  denominator change.

A proposal passes only when both gates return zero errors. The governance
reference grammar is declared once by the schema and is copied exactly into the
semantic validator; `foo/bar:baz` is an isolated accepted witness. Submitted
booleans, counts, and hashes cannot override recomputation.

## Evidence Acquisition Remediation

`MORE_EVIDENCE_ACQUISITION_CONTRACT.json` is R2 and now exposes:

- `PARTITION`: source-grounded predicate, raw-member assignment, UNKNOWN
  treatment, completeness, disjointness, count, and hash evidence;
- `GOVERNANCE`: independent reviewer, evidence manifest, separate approval
  boundary, and non-authoritative acquisition controls.

The contract remains design-only. Acquisition does not select an outcome, apply
a split, mutate a status, change the denominator, or authorize execution.

## Negative Fixtures

The `fixtures/` directory contains one valid synthetic proposal fixture and
thirteen
negative synthetic fixtures. They are validation inputs only and are not future
decisions or source evidence.

The negative fixtures cover:

- malformed child count;
- malformed child hash;
- invalid parent identity;
- invalid parent frozen-member hash;
- duplicate child ID;
- incomplete child partition;
- overlapping child partition;
- isolated false conservation claim;
- member outside the frozen parent.

Four additional fixtures cover null, missing, and malformed operative governance
references. Every negative fixture declares expected failure code(s), and the
harness requires those codes rather than accepting an unspecified rejection.

The executable test harness proves that the valid fixture is accepted and all
negative fixtures are rejected. `GOVERNANCE_REFERENCE_SYNTAX_WITNESSES.json`
proves the schema and semantic validator accept and reject the same declared
reference syntax domain.

## Frozen Baseline

The carried-forward Exact12 crosswalk remains unchanged in identity and current
state:

- templates: `12`, frozen order `1..12`;
- raw coverage: `203` unique members;
- cross-template overlap: `0`;
- member-set drift: `0`;
- Blocked31 overlap: `0`;
- union member-key SHA-256:
  `ffeb2704a1c971b89129e1959ae721bbc9ef159153a5f0a20f8abda13edb441a`;
- all source decisions: `REQUEST_SPLIT_OR_MORE_EVIDENCE`;
- all resolution states: `REQUEST_MORE_EVIDENCE`;
- all current split states: `NO_CURRENT_SPLIT`.

## Required Terminal

```text
E0C_EXACT12_SPLIT_RESOLUTION_DESIGN_R2R2 = PASS_READY_FOR_INDEPENDENT_REVIEW
FROZEN_TEMPLATE_COUNT = 12
FROZEN_RAW_COVERAGE = 203
CURRENT_REQUEST_MORE_EVIDENCE_COUNT = 12
SCHEMA_VALIDATION = PASS
SEMANTIC_VALIDATION = PASS
GOVERNANCE_REFERENCE_SYNTAX_ALIGNMENT = PASS
PARTITION_EVIDENCE_CLASS = PASS
GOVERNANCE_EVIDENCE_CLASS = PASS
NEGATIVE_FIXTURES_REJECTED = PASS
MEMBER_CONSERVATION = PASS
APPLIED_SPLITS = 0
STATUS_MUTATIONS = 0
EXECUTION_AUTHORIZATIONS = 0
DENOMINATOR_CHANGE = NO
FORMAL_EXPERIMENT_EXECUTED = NO
HUMAN_DECISIONS_CREATED = 0
PUSH_EXECUTED = NO
NEXT_ACTION = INDEPENDENT_REVIEW_OF_RESOLUTION_DESIGN_R2R2
STOP = true
```
