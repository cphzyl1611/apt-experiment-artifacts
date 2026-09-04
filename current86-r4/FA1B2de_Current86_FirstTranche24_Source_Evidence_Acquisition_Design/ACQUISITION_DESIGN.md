# FIRST_TRANCHE24 Source Evidence Acquisition Design

## Purpose and boundary

This package defines the future, bounded transaction that can obtain the five
missing source-version evidence classes for the already resolved
`SOURCE_AUTHORITY_CANDIDATE_CLASS`. It does not acquire an object, authenticate
source evidence, derive a source-authority ID, activate authority, admit Stage
A, create field pins, expose Stage B, create operative records, or execute
P0/P1 or the formal 1796 benchmark.

The design preserves three independent gates:

```text
ACQUISITION != AUTHENTICATION
AUTHENTICATION != AUTHORITY ACTIVATION
AUTHORITY ACTIVATION != STAGE_A_ADMISSION
```

The package's complete fixture data is synthetic structural test data. It is
not an acquired source object and is not evidence for any source authority.

## Entry preconditions

The design may be used only after the following exact Binding state has been
authenticated:

```text
ENTRY_BINDING_HEAD = a67377396ae6d20e87c1870bddeed8700a6c871b
REVIEW_MATERIALIZATION_PARENT = 81c843c48619fd8e25983f68a7248d0273dc2192
REVIEW_MATERIALIZATION_MESSAGE = materialize binding: FIRST_TRANCHE24_SOURCE_VERSION_EVIDENCE_RESOLUTION_INDEPENDENT_REVIEW
SOURCE_VERSION_EVIDENCE_REVIEW = PASS_READY_FOR_SOURCE_EVIDENCE_ACQUISITION_DESIGN
```

The review commit must descend directly from the reviewed resolution commit
`81c843c48619fd8e25983f68a7248d0273dc2192`, whose parent is
`6171a460ef527b99f2176eb047d51ca7082d067a`. Local `HEAD`, the
`origin/artifact/binding` tracking ref, and the live Binding ref must be equal
to the review materialization commit before a future request is prepared.

The request must reproduce the exact governance tuple:

```text
HUMAN_GOVERNANCE_DECISION = APPROVE_BOTH_G1_AND_G2
GOVERNANCE_SCOPE = FIRST_TRANCHE24_ONLY
GOVERNANCE_DECISION_ID = GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f
GOVERNANCE_TRANSACTION_HASH = b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38
```

The exact ordered scope is the 24-ID array in every schema. No target may be
added, removed, substituted, or reordered. The candidate reference and its
class/fact type are also fixed exactly as specified in the schemas.

## Exact acquisition object set

One future transaction may request exactly these five classes, with one
consistent evidence set:

1. `CANONICAL_SOURCE_ARTIFACT`: exactly one eligible canonical source object.
2. `IMMUTABLE_VERSION_EVIDENCE`: one artifact-bound form using exactly one of
   `CONTENT_DIGEST`, `GIT_COMMIT`, or `RELEASE_TAG_WITH_DIGEST`.
3. `ARTIFACT_CONTENT_DIGEST_EVIDENCE`: bytes or a retained immutable bytes
   reference sufficient to recompute the SHA-256.
4. `DESCRIPTOR_ARTIFACT_LINEAGE_PROOF`: the three independently checkable
   edges from descriptor to artifact, artifact to version, and version to
   digest.
5. `OWNER_ISSUER_AUTHORIZATION_PROOF`: active authorization for the exact
   artifact, exact immutable version, and `FIRST_TRANCHE24_ONLY`.

The request is not a generic corpus request. It must declare the expected
class, fact type, exact candidate reference, one-artifact selection rule, and
the five object classes before any future acquisition attempt.

## Allowed object and channel classes

The channel policy permits only these channel classes:

- `CONTENT_ADDRESSED_OBJECT_HANDOFF` for a content-addressed object and its
  associated digest evidence.
- `GIT_COMMIT_TREE_SNAPSHOT_HANDOFF` for a full immutable commit/tree snapshot
  and its content digest.
- `RELEASE_ARTIFACT_WITH_DIGEST_HANDOFF` for an immutable release artifact,
  release/tag metadata, and its content digest.
- `SIGNED_DESCRIPTOR_AUTHORIZATION_BUNDLE_HANDOFF` for independently
  verifiable descriptor, lineage, or owner/issuer authorization records.

Every permitted channel must capture deterministic request, selection,
response, and retrieval-event hashes. A channel instance is represented by an
opaque evidence reference, not by a credential, secret, or unreviewed live
endpoint embedded in the design.

The following are prohibited: floating branches or heads, mutable tags without
a digest, `latest` or date-only references, public accessibility as the sole
authority signal, unauthenticated pages or listings, generic mirrors or bulk
exports, unscoped multi-artifact retrieval, user-supplied unverified objects,
and credential or secret payloads.

## Identifiers known before acquisition

The future request must know and bind before attempting retrieval:

- transaction type, request ID, transaction ID, replay key, and canonical
  transaction-preimage profile;
- the governance decision ID, governance transaction hash, reviewed Binding
  commit, and exact ordered scope;
- the resolved candidate reference, authority type, and source fact type;
- the requested artifact class and the rule that exactly one eligible object
  must resolve;
- the channel policy version and selected channel class;
- the permitted immutable version forms; no concrete artifact identity or
  source-authority ID may be invented before acquisition.

The unresolved artifact identity is represented as
`PENDING_EXACT_RESOLUTION` in a design-only request. A future request changes
to `UNIQUE_EXACT_RESOLUTION` only after exactly one eligible object is selected
and its identity is recorded.

## Provenance recording

The acquisition provenance record is deterministic and append-only. It must
contain the acquisition-attempt ID, channel class and policy version, request
descriptor hash, candidate and scope bindings, start/completion timestamps,
returned and selected object counts, the exact selection rule, selected object
reference, response-metadata hash, retrieval-event hash, and an explicit
assertion that credential material was not recorded.

The selection count must be exactly one. A zero result, multiple eligible
results, an ambiguous selector, an unbound response, or a provenance record
that cannot be recomputed is a hard rejection. Retrieval timestamps are audit
metadata only; they do not replace an immutable version or digest.

## Immutable version and digest binding

Exactly one supported form is selected for the artifact:

- `CONTENT_DIGEST`: the immutable identifier is the content digest itself.
- `GIT_COMMIT`: the full commit and tree identify the snapshot, and the bytes
  digest identifies the acquired content.
- `RELEASE_TAG_WITH_DIGEST`: the immutable release/tag metadata is paired with
  the acquired content digest.

The version object carries the artifact ID, policy ID, form, immutable
identifier, reference-kind data, and content SHA-256. Floating references are
always false. The digest evidence carries the exact artifact ID and policy ID,
the bytes evidence reference, bytes-evidence hash, independently recomputed
content digest, algorithm, byte length, and recomputation method
`SHA256_OVER_EXACT_RETRIEVED_BYTES`.

The future executor recomputes the digest from the exact retained bytes or
immutable bytes evidence. It must compare the recomputed digest to both the
version record and the digest evidence. A digest from another object, another
version, or another retrieval attempt is rejected.

## Descriptor-to-artifact lineage

The lineage proof is a three-edge chain:

```text
authority descriptor
    -> exact canonical artifact
    -> immutable version
    -> content digest
```

Each edge has its own evidence reference, edge hash, and authentication
status. The descriptor node must retain the exact frozen candidate reference,
authority type, and source fact type. The artifact node, version node, and
digest node are repeated in the proof so an independent consumer can compare
all edge endpoints without relying on names or ordering.

All edges must name the same artifact ID, version policy ID, and content
SHA-256. Mixed lineage is not repaired by taking the strongest edge from each
object. Any missing, broken, conflicting, or independently unauthenticatable
edge rejects the envelope.

## Owner/issuer authorization

Authorization is a separate evidence object. It must identify the owner,
issuer, or explicitly delegated authority; state the relationship to the exact
artifact; bind the exact immutable version and content digest; and carry an
active, non-expired, non-revoked, non-superseded status.

The authorization scope must be the literal ordered `FIRST_TRANCHE24_ONLY`
array, with permitted use `SOURCE_AUTHENTICATION_INPUT_ONLY` and scope
extension prohibited. The authorization record must carry issuance/effective
metadata, authorization ID, status-as-of time, proof/evidence reference, and
the fixed authentication procedure. Public or published accessibility is not
authorization and cannot substitute for the owner/issuer proof.

## Failure semantics

Acquisition succeeds only when exactly one eligible artifact has been acquired
into read-only quarantine, all five evidence classes are present, artifact,
version, digest, lineage, authorization, governance, scope, and provenance are
internally consistent, and the closed envelope is assembled. The terminal
acquisition-success state is `PENDING_AUTHENTICATION` with
`downstream_eligibility = NOT_ELIGIBLE`. It means only that the evidence
envelope is ready to be evaluated by the separate source-authentication gate;
it does not mean that any evidence claim has passed source authentication.

The transaction is fail-closed. Any one of the following rejects the complete
attempt and produces no downstream-eligible envelope:

- artifact identity mismatch, zero resolution, or multiple eligible artifacts;
- floating or unsupported version form;
- missing, mismatched, or cross-object digest;
- missing, broken, mixed, or unauthenticated lineage edge;
- owner/issuer mismatch, missing authorization, stale/revoked/superseded
  status, or scope widening;
- governance mismatch, candidate mismatch, or `FIRST_TRANCHE24` widening;
- unknown fields, ambiguous provenance, embedded credential material, or
  premature authenticated/activated status.

The failure reason records a stable failure code, failed state, concise
message, and optional evidence reference. A rejected attempt remains an audit
record and cannot be promoted by editing it in place.

## Duplicate and replay behavior

The replay key is derived from the transaction type, exact governance tuple,
ordered scope, candidate reference, requested artifact identity, channel policy,
and request descriptor hash. An exact byte-identical replay of a committed
request is idempotent and returns the existing acquisition receipt. Reuse of a
key with a changed request hash, changed channel, changed scope, changed
artifact, or changed evidence is a hard rejection. A new artifact version is a
new transaction; it is not a replay or an in-place mutation.

## Retention policy

Retention is minimal and quarantine-first. The future runner may retain the
closed transaction, deterministic provenance record, exact retrieved artifact
reference, immutable version proof, digest recomputation evidence, all three
lineage-edge proofs, and owner/issuer authorization evidence. If raw bytes are
needed for recomputation, they remain read-only in a quarantined,
content-addressed evidence store until the configured evidence-retention
period ends or an independent authentication decision records a longer need.

No credential material, unrelated corpus, broad search result set, mutable
working checkout, or non-evidence payload may be retained in this envelope.
Retention references are evidence references only; they do not grant
downstream execution rights.

## Downstream handoff boundary

The exact handoff is `ACQUIRED_EVIDENCE_ENVELOPE_SCHEMA.json`. It contains the
artifact identity, immutable version representation, digest recomputation
evidence, three-edge lineage proof, owner/issuer authorization, deterministic
acquisition provenance, governance binding, exact scope, and candidate
reference.

The envelope is marked `NOT_ELIGIBLE` while source authentication is
`NOT_EXECUTED` or `FAIL`. The source-authentication consumer must independently
validate the envelope, authenticate every evidence class, and issue its own
pass before any downstream consumer may use the artifact. Acquisition success
alone is never a source-authentication pass.

## Zero-operational-effect boundary

This design package itself records:

```text
SOURCE_AUTHORITY_ID_DERIVED = NO
SOURCE_AUTHORITY_ID = NONE
SOURCE_AUTHORITY_ACTIVATED = NO
SOURCE_ACQUISITION = NO
SOURCE_AUTH_EXECUTED = NO
STAGE_A_ADMISSIONS = 0
STAGE_B_EXPOSURES = 0
FIELD_PINS = 0
OPERATIVE_RECORDS = 0
P0_EXECUTED = NO
P1_EXECUTED = NO
FORMAL_1796_EXPERIMENT_EXECUTED = NO
```

No state in the acquisition state machine can activate source authority. No
design artifact derives a final source-authority ID. No source evidence is
consumed downstream until the later source-authentication gate passes.
