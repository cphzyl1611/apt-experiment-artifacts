# FIRST_TRANCHE24 source-authority activation contract

## Transaction purpose

`FIRST_TRANCHE24_SOURCE_AUTHORITY_ACTIVATION` is a future, single-record
transaction that makes one precisely identified source authority eligible for
the already approved FIRST_TRANCHE24 governance scope. It is deliberately
later than, and independent from, the materialized G1/G2 decision. The
transaction may change only the source-authority activation pointer. It does
not fetch source bytes, run source authentication, admit Stage A, create field
pins, expose Stage B, create operative records, or run P0/P1/the formal 1796
benchmark.

The package contains no live authority candidate and therefore does not create
an authority ID. The record schema and synthetic fixture use a separately
marked `SYNTHETIC_TEST_ONLY` mode; that mode is structurally unable to express
`ACTIVATED`.

## Preconditions

The future executor must fail closed unless all of these are true:

1. The Binding branch and its remote-tracking reference are the same head and
   the head contains the materialized decision and its independent review.
2. The decision record ID, governance transaction hash, decision, principal
   reference, and `FIRST_TRANCHE24_ONLY` scope match the constants in
   `GOVERNANCE_TO_AUTHORITY_BINDING.json`.
3. The decision materialization commit is exactly
   `3c5c014238b569377963c1cb20f3d7df2600f135`, with parent
   `c3e911e865f5287d46703e5d0d7398ee653151f7`; the independently reviewed
   follow-on commit is exactly
   `10478b0961a601d0f684740b9564633a9930ebc9`.
4. The candidate has one unambiguous authority identity, one supported source
   class, and one immutable version policy. Candidate, provenance, and policy
   evidence all identify that same candidate.
5. No candidate is stale, revoked, superseded, or in conflict with a newer
   candidate for the same authority namespace, scope, or version.
6. The replay key is either new, or is an exact byte-for-byte replay of the
   same committed transaction. A reused key with any changed payload is a
   rejection.
7. The pre-state counters are still zero for every downstream operation listed
   in the zero-effect assertions.

The future executor also requires an explicit activation commit operation. A
governance approval is not that operation, and this design package does not
perform it.

## Exact scope

The only admissible scope is `FIRST_TRANCHE24_ONLY` with exactly these 24 raw
IDs, in this order:

```text
110,273,210,98,147,277,188,301,143,250,233,287,146,293,114,284,291,215,88,182,300,218,115,148
```

The scope array is a canonical identity input, not display metadata. The
schema uses a literal array constraint; the validator additionally checks
cardinality and uniqueness. A different order, a duplicate, a missing ID, an
additional ID, `Current86`, or a project-wide scope is rejected.

## Input object model

The closed activation record has these top-level objects:

- `activation_transaction`: transaction/record IDs, deterministic hash fields,
  atomicity declaration, and replay/reuse state.
- `governance_authorization_reference`: exact references to the materialized
  G1/G2 decision and its reviewed Binding lineage.
- `scope_reference`: the frozen scope ID and literal raw-ID array.
- `source_authority_identity`: the candidate's content/policy/scope composite
  identity and provenance binding.
- `source_authority_type_class`: the supported authority class and the future
  single-candidate adjudication procedure.
- `source_version_policy`: immutable source version form and digest.
- `source_provenance_evidence`: typed evidence references and same-candidate
  assertion. Evidence references are descriptors; this design phase does not
  acquire their external objects.
- `activation_status`: `READY_FOR_ACTIVATION` before the atomic commit or
  `ACTIVATED` after it. The fixture uses the separate
  `DESIGN_ONLY_NOT_EXECUTED` status.
- `canonicalization_profile`: the profile used for identity and transaction
  hashes.
- `zero_downstream_effect_assertions`: the explicit post-activation boundary.
- `outputs`: receipt and source-acquisition handoff status.

Unknown keys are forbidden at every level. Null is used only for an absent
receipt/reference in a non-operative state; it is never used for an authority
identity or version-policy field.

## Source-authority identity semantics

Identity is a composite of the supported authority type/class, canonical
authority namespace and version, normalized source locator, source-version
policy ID, immutable content digest, and the exact FIRST_TRANCHE24 scope. The
identity preimage is canonical JSON (UTF-8, sorted object keys, no insignificant
whitespace, integers represented as JSON integers) under
`FIRST_TRANCHE24_SOURCE_AUTHORITY_IDENTITY_V1`. The authority ID is
`sha256:<hex digest>` of that preimage. Transaction IDs and governance record
IDs are not identity inputs; they bind the decision but cannot change the
authority's identity.

The identity is therefore content-addressed and policy-addressed, with a scope
component. Including scope prevents a FIRST_TRANCHE24 authority object from
being silently reused as a Current86-wide authority. Excluded metadata
includes retrieval time, local file paths, evidence ordering, reviewer names,
transaction nonce, and descriptive labels. Those values belong in provenance
or audit evidence and cannot create a new authority.

The future adjudication procedure selects exactly one candidate after checking
all admissible evidence. A collision, an already-used ID with a different
preimage, a stale/superseded candidate, or mixed evidence from different
candidates fails closed. No concrete authority ID is selected by this design.

## Canonicalization and deterministic transaction identity

The activation transaction preimage is the complete closed activation record
with exactly these four derived fields omitted from `activation_transaction`:
`transaction_id`, `record_id`, `transaction_hash`, and
`canonical_preimage_sha256`. The remaining object is serialized under
`RFC8785_LIKE_UTF8_SORTED_JSON_V1`. `transaction_hash` and
`canonical_preimage_sha256` are the lower-case SHA-256 of those bytes;
`transaction_id` and `record_id` are the fixed schema prefixes followed by the
same digest.

The replay-key preimage contains exactly transaction type, decision record ID,
governance transaction hash, scope ID, literal raw-ID array, authority ID,
source-version-policy ID, and content SHA-256. It uses the same canonical
profile. This binds replay detection to the authorized source/version/scope
tuple without making audit timestamps or receipts identity-bearing.

## Source-version policy semantics

The version policy is a required closed object. Supported forms are:

- `CONTENT_DIGEST`: a content-addressed artifact with a SHA-256 digest;
- `GIT_COMMIT`: repository, full commit, tree, and content SHA-256;
- `RELEASE_TAG_WITH_DIGEST`: immutable release/tag plus content SHA-256.

Every form has `floating_reference_allowed: false`, a non-empty immutable
identifier, a SHA-256 content digest, lineage evidence, and
`update_policy: NEW_ACTIVATION_REQUIRED`. Branch names, mutable tags without a
digest, `latest`, date-only labels, ranges, and other floating references are
prohibited. An update or correction creates a new policy and a new activation
transaction; it never mutates an activated policy in place. Any digest,
commit/tree, release/tag, or lineage mismatch rejects the transaction.

## Governance-decision binding

`GOVERNANCE_TO_AUTHORITY_BINDING.json` is an exact constant binding to:

```text
DECISION_RECORD_ID = GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f
GOVERNANCE_TRANSACTION_HASH = b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38
GOVERNANCE_SCOPE = FIRST_TRANCHE24_ONLY
```

The binding also records the decision-materialization commit, its exact
parent, and the independent-review commit. An activation record must reproduce
all constants and the literal raw-ID array. The binding has
`scope_extension_permitted: false`; the executor compares the complete array,
not just a cardinality. A scope mismatch cannot be repaired by a second
reference in the same transaction.

This is not V1 circularity: the G1/G2 record predates and does not contain a
source authority ID or version policy. The future activation transaction reads
that immutable decision and binds a later, independently selected authority to
it.

## Required authentication evidence

Before a future `ACTIVATED` state, the executor must have typed, hash-bearing
evidence for:

1. the authority descriptor or registry entry, including its canonical
   locator, class, namespace, and immutable version policy;
2. the immutable content digest (and Git commit/tree or release metadata when
   applicable);
3. the lineage from the authority descriptor to the selected candidate;
4. the candidate adjudication showing exactly one candidate and no
   stale/superseded/conflicting candidate; and
5. the independent recomputation of authority identity, transaction hash, and
   the exact scope binding.

Evidence references must carry an artifact SHA-256, candidate authority ID,
and `PASS` attestation. A signed manifest, a Git object/commit/tree proof, or a
release artifact plus digest is admissible according to the policy form. A
synthetic deterministic evidence reference is admissible only in the static
fixture and can never satisfy a future `ACTIVATED` record.

## Fail-closed conditions

The machine-readable rule list in `FAIL_CLOSED_RULES.json` is normative. It
rejects missing or wrong governance references, any scope widening, missing or
ambiguous identity, missing or floating version policy, provenance mismatch,
unsupported identity procedure, unknown fields, duplicate/reuse mismatch,
stale/superseded candidates, and mixed-candidate evidence. Schema validation is
performed before semantic checks. There is no permissive fallback path.

## Duplicate/replay/reuse semantics

`replay_key` is the transaction identity key. A new key with a new transaction
hash may be proposed once. An exact replay of a committed key and identical
hash is idempotent and returns the existing receipt without changing state. A
same-key/different-hash replay, a same authority ID with a different identity
preimage, or a same policy ID with a changed digest is rejected. A supersession
must name a separate, reviewed transaction and may not be smuggled into a
replay.

## Zero-downstream-effect boundary

On a successful future activation, the only allowed state transition is the
source-authority activation pointer (`NO` to `YES`). Source acquisition remains
`NO`; source authentication execution remains `NO`; Stage A admissions, Stage B
exposures, field pins, operative records, P0, P1, and the formal 1796 benchmark
remain zero/`NO`. The activation record must assert this complete vector. The
static design phase asserts the stronger pre-state vector in
`evidence/ZERO_OPERATIONAL_EFFECT.json` and performs no state transition.

## Outputs

The future atomic commit emits:

- an immutable activation receipt containing transaction/record IDs, authority
  ID, policy ID, scope ID, and all evidence digests;
- a `READY_FOR_SOURCE_ACQUISITION` handoff that names the activated authority
  and immutable policy; and
- a post-state assertion with authority activation `YES` and every downstream
  effect still zero.

For `READY_FOR_ACTIVATION` or design-only records, receipt and handoff statuses
are `NOT_EMITTED`. The package's synthetic fixture is in that non-operative
state.

## Downstream handoff to source acquisition

Source acquisition may begin only after an independent consumer verifies the
committed activation receipt, rechecks the authority ID/policy digest/scope,
and observes the exact `READY_FOR_SOURCE_ACQUISITION` handoff. Acquisition then
reads the immutable locator and verifies the acquired bytes against the
activated digest. Failure leaves authority activation intact but blocks
acquisition and all later stages; it never silently changes the policy or
widens scope.
