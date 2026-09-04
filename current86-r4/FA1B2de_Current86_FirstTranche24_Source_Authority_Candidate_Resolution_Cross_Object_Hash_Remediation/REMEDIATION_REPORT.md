# FIRST_TRANCHE24 candidate-resolution cross-object hash remediation

## Verdict

`FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_RESOLUTION_CROSS_OBJECT_HASH_REMEDIATION = PASS_READY_FOR_MATERIALIZATION`

This bounded superseding package closes the sole residual blocker from the
independent candidate-resolution review. Historical materialized packages and
the authenticated Binding baseline were not modified. The only operative data
change is the deterministic candidate-set SHA-256 in
`RESOLVED_CANDIDATE_RECORD.json`, rebinding it to the already authenticated
corrected candidate-set bytes from the evidence-reference remediation.

## Exact reproduction

The historical resolved record embedded:

`75ef2657c0145990bf194651fb67c88e3b8c130c4332288fe8b2b28626c31082`

The exact historical candidate-set bytes have the same SHA-256. The effective
corrected candidate-set bytes have SHA-256:

`8a4581fbc1fa908430eb82661fbd61bba713f08511629058f02a0dc9c396aa11`

An isolated copy of the historical package, with only the corrected candidate
set substituted, was run through the unmodified historical validator. It
failed with `CANDIDATE_SET_INCONSISTENCY: candidate-set hash mismatch` (exit
code 1). This reproduces the review finding exactly.

## Bounded correction and dependency scope

The effective corrected candidate set is copied byte-for-byte from the
authenticated evidence-reference remediation and independently passes schema,
structure, candidate uniqueness, governance binding, exact scope, provenance,
and zero-effect checks. Its stale bad governance-binding reference count is
zero and candidate semantic drift is zero.

The dependency inventory found three cross-object fields: the resolved record's
`candidate_set_reference`, its `candidate_set_sha256`, and the decision record's
`candidate_set_reference`. Only the resolved record's SHA-256 is mechanically
dependent on candidate-set bytes and it alone changed. No derived IDs,
governance transaction hashes, or other deterministic identities depend on the
candidate-set content under the existing contract.

After correction, the resolved record embeds exactly
`8a4581fbc1fa908430eb82661fbd61bba713f08511629058f02a0dc9c396aa11`, yielding
`CROSS_OBJECT_CANDIDATE_SET_HASH_MATCH = PASS` and
`CANDIDATE_SET_INCONSISTENCY = CLOSED`.

## Verification

The existing static validator passes without modification. All ten historical
negative fixtures remain rejected (`10/10 REJECTED`), and the corrected
effective package is the positive resolution fixture (`PASS`). The packaged
tests pass (`3/3`). Provenance evidence mapping, governance binding, exact
FIRST_TRANCHE24 scope, and candidate-set consistency all pass.

The pending version state is unchanged:
`VERSION_POLICY_RESOLUTION = BLOCKED_PENDING_SOURCE_EVIDENCE`, with
`VERSION_EVIDENCE_PENDING_STATE_DRIFT = 0`. No source or version evidence was
acquired, no source-authority ID was derived, and no authority or downstream
operation was activated. Stage A/B admissions, field pins, operative records,
P0/P1, and the formal 1796 experiment remain zero/not executed.

See `DEPENDENCY_INVENTORY.json`, `evidence/CROSS_OBJECT_HASH_EVIDENCE.json`,
`evidence/AFTER_CROSS_OBJECT_HASH_EVIDENCE.json`,
`evidence/STATIC_VALIDATOR_AND_TEST_EVIDENCE.json`, and
`evidence/VERSION_AND_ZERO_EFFECT.json` for machine-readable evidence.

Next phase: `FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_RESOLUTION_INDEPENDENT_REVIEW`.
