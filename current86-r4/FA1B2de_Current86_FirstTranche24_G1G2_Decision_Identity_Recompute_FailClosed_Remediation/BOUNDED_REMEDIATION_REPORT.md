# First-Tranche24 G1/G2 Decision Identity Recompute Fail-Closed Remediation

Date: 2026-09-03

## Terminal result

`FIRST_TRANCHE24_G1G2_DECISION_IDENTITY_RECOMPUTE_FAIL_CLOSED_REMEDIATION = PASS_READY_FOR_INDEPENDENT_REVIEW`

This package closes only the independent verifier acceptance defects identified
by the read-only review of authenticated commit
`7059e15ee3f6f7629dac573ff157968ef59dde75`.

## Defect closure

### Blocker A: unauthorized fields

Before the fix, `tools/independent_recompute.py` projected only selected basis
fields and never validated the top-level or nested object shape. A valid record
with `unauthorized_top_level_field` at the top level was accepted and returned
the unchanged valid identity values. The fix validates the exact authorized
top-level set and exact closed nested object sets before projection.

The targeted top-level and nested identity-field fixtures now reject with
`unauthorized top-level field` and `unauthorized or missing identity field`.

### Blocker B: identity-procedure mismatch

Before the fix, `decision_identity.identity_procedure_id` was never read by the
independent verifier. Both a missing value and `OTHER_PROCEDURE` were accepted.
The fix requires the existing contract value
`FIRST_TRANCHE24_GOVERNANCE_DECISION_IDENTITY_V2` before recomputation.

The missing fixture rejects with `missing required identity procedure`; the
mismatch fixture rejects with `identity procedure mismatch`.

No canonicalization profile, namespace, scope, governance identity, decision
content, or identity semantics were changed. No new contract field was added.

## Verification

- Defect reproduction: PASS; both pre-fix witnesses are recorded in
  `evidence/DEFECT_REPRODUCTION_EVIDENCE.json`.
- Red tests observed before fix: YES; see
  `evidence/RED_TEST_RESULT_BEFORE_FIX.txt`.
- Targeted green tests: 6/6 PASS.
- Preserved previous independent recomputation/contract tests: 10/10 PASS.
- Preserved primary negative fixtures: 6/6 rejected.
- Valid decision-record ID drift: 0.
- Valid transaction-hash drift: 0.
- Zero operational effect: PASS; see
  `evidence/ZERO_OPERATIONAL_EFFECT_VERIFICATION.json`.

## Modified files

Production source target:

- `tools/independent_recompute.py`

Test files:

- `tests/test_fail_closed_recompute.py`
- `tests/test_decision_identity.py` (local fixture path only)
- `tests/test_independent_recompute.py` (local fixture path only)

The copied `tools/decision_identity.py` is unchanged from the authenticated
package and is included only to keep the preserved contract tests self-contained.

## Boundary

This is a new bounded remediation package. The authenticated commit and
historical package were not modified. G1/G2 decision materialization, source
authority activation, source acquisition/authentication, Stage A/B, field pins,
operative records, P0/P1, and the formal 1796 experiment were not executed.
