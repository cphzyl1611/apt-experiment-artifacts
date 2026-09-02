# Authoritative Source-Class Policy

## Status and scope

This is a design contract, not a source-authority artifact, mapping registry, source-auth execution, admission decision, or field-pin decision. It is constrained to the frozen Current86 Binding target universe and the governance handoff SHA-256 `1dab277952aa74ddb716cb8c2fb236e6443e625de83d07ed0fd3bbf712731c6f`.

The existing normative source-class registry recognizes the class/fact-type pair below. This design does not activate it, add a manifest entry, or make any current source object a member of it.

```text
source_artifact_class = AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE
source_fact_type     = PINNED_CANONICAL_INTRINSIC_FIELD
```

## Qualifying class rule

Only an immutable source object that is explicitly included by a separately governed, authenticated source-admission authority MAY be treated as `AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE`. The admission authority must bind the exact target, source object, field semantics, and RFC6901 pointer. A source does not qualify merely because it is available locally, cryptographically hashed, structurally extractable, semantically plausible, or preferred by a reviewer.

The following source forms may qualify only after that separate authority action has occurred:

1. A direct upstream canonical-intrinsic object whose immutable bytes, issuer/owner authorization, version, schema, and field semantics are all pinned.
2. A deterministic canonical wrapper over an already authorized upstream canonical object, where the wrapper specification, extractor identity, input manifest, output object, and one-to-one locator contract are pinned and the governing authority explicitly designates the wrapper output as canonical.
3. A governed project canonical-intrinsic registry object whose source-of-truth ownership, immutable release bytes, schema, and exact field semantics are explicitly pinned.

These are eligible forms, not newly created source classes or current approvals. At the reviewed state, no source-admission registry root authorizes any production tuple for the first tranche. A source owner or governance authority must make that future authorization in a distinct governed transaction.

## Explicitly insufficient material

The following are insufficient for canonical intrinsic authority unless a future, separate governance act creates a new immutable canonical source object and admits it under the qualifying class rule:

- `AUTHENTICATED_SCORING_ROW_SOURCE` and its `PINNED_SCORING_ROW_FIELD` leaves. The 24 frozen targets currently link to this noncanonical candidate source class.
- `AUTHENTICATED_RAW_SOURCE_RECORD` and `PINNED_RAW_SOURCE_FIELD` material when it has not been separately admitted as a canonical-intrinsic object.
- Recovered C0 evidence, prospective wrappers, candidate wrapper objects, R5 dry-run objects, and source locators without a governed canonical source admission.
- `DERIVED_C2R1_COMPARATIVE_INTRINSIC_REFERENCE`, C2R1 comparative profiles, rankings, similarity results, model output, candidate inventories, and comparative pointers.
- Human prose, review sheets, recommendations, timestamps, labels, or a human assertion that a field is "best" or "canonical" without the authenticated source-object chain below.
- A source hash, a source row, a pointer list, or a unique candidate count by itself.

## Admission prerequisites

A future source object may support Stage A only when all of the following are present and recomputable:

1. An active governed source-authority record that authorizes the exact source class, fact type, scope, source owner, source version policy, and canonical field semantics.
2. A pinned immutable source artifact identity and SHA-256, plus a cryptographically verifiable acquisition record. Acceptable acquisition proof is an authorized signed release, a pinned signed Git commit/tree, or an equivalent governance-approved immutable content-addressed release. The proof type and verifier identity must be recorded.
3. A source-object locator with exact-one resolution under a pinned deterministic extraction rule. The source object bytes and object SHA-256 must recompute from the source artifact.
4. A canonical schema namespace, schema identity/version/hash, exact RFC6901 field pointer, field type, and canonicalization semantics that resolve directly against the authenticated source object.
5. A mapping evidence record conforming to the schema in this package, with a complete provenance chain, clean conflict recomputation, and no revocation or supersession that invalidates the record.

## Source identity and version pinning

Every authoritative mapping must name both the source artifact and the source object within it. The artifact identity includes its source-authority identifier, source owner/issuer identity, immutable version or commit/tree/release identity, and SHA-256. The object identity includes the extractor identity, exact locator, locator canonical hash, and object SHA-256. A mutable URL, a branch name without a pinned commit, a file path without content identity, or a timestamp is not sufficient identity.

## Cryptographic authentication

The source authority must be authenticated independently of the candidate evidence. The future verifier must be able to recompute:

- the source-authority artifact hash and authorization reference;
- the source artifact SHA-256 and signed-release or pinned-commit proof;
- the exact source object bytes from the pinned artifact and deterministic locator;
- the canonical field pointer resolution, type, and canonical value hash; and
- the canonical field identity and mapping-record identity from canonical JSON.

A cryptographic hash confirms byte identity, not canonical authority. Canonical authority comes only from the separately governed source-authority record that names the eligible source object and class.

## C2R1 boundary

Current C2R1 material is derived comparative evidence. It can preserve context, candidate linkage, and a reason for requesting more evidence, but it cannot prove that a candidate field is the canonical intrinsic field. Promoting it would make derived comparative output its own source of authority and would defeat the independent-source requirement. Therefore `ONLY_C2R1_DERIVED_COMPARATIVE_INTRINSIC_PRESENT` remains fail-closed until an independently authenticated canonical source object is admitted.

## Human governance and prose

Human governance has two bounded roles:

1. It may authorize or reject a future source-authority class, source acquisition, activation, or revocation through a separately authenticated governance artifact.
2. After Stage A, it may make the separately governed Stage B field-pin decision.

Human prose, a review recommendation, or a directly selected current candidate pointer is not source-object evidence and cannot substitute for an exact authenticated source object, schema, field identity, or pointer. Human references in a mapping record are auditable authorization references, not evidence bytes.

## Fail-closed rule

If any authority, artifact, object, locator, field identity, pointer, value hash, conflict state, activation state, or lineage condition is absent, invalid, ambiguous, stale, superseded, or unrecomputable, the outcome is `ADMISSION_NOT_READY_MISSING_PROVENANCE` or another non-clean disposition. Stage B remains unavailable and no field pin is created.
