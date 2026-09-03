# FIRST_TRANCHE24 source-authority identity procedure

## Procedure identity

`FIRST_TRANCHE24_SOURCE_AUTHORITY_IDENTITY_V1` in namespace
`fa1b2de.source-authority/current86/first-tranche24` is the only identity
procedure accepted by the future activation transaction.

## Identity basis fields

The canonical identity preimage contains exactly these fields:

```json
{
  "identity_procedure_id": "FIRST_TRANCHE24_SOURCE_AUTHORITY_IDENTITY_V1",
  "identity_namespace": "fa1b2de.source-authority/current86/first-tranche24",
  "identity_version": "V1",
  "authority_type": "AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE",
  "source_class": "AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE",
  "source_locator": "<normalized locator>",
  "source_locator_type": "<URI/GIT/RELEASE form>",
  "source_version_policy_id": "<policy id>",
  "content_digest": "<lower-case SHA-256 hex>",
  "scope_id": "FIRST_TRANCHE24_ONLY",
  "raw_ids": [110,273,210,98,147,277,188,301,143,250,233,287,146,293,114,284,291,215,88,182,300,218,115,148]
}
```

The angle-bracket values above describe required fields; they are not values
in an activation record. A future candidate must supply concrete authenticated
values before `ACTIVATED` is possible.

## Canonicalization profile

The profile is `RFC8785_LIKE_UTF8_SORTED_JSON_V1`: UTF-8 encoding, recursively
sorted object keys, no insignificant whitespace, JSON integer values (not
decimal strings), and the literal array order above. Unicode strings are NFC
normalized and surrounding ASCII whitespace is removed only from locator
components where the source locator grammar explicitly permits it. Array order
is significant. The SHA-256 digest is rendered in lower-case hexadecimal.

## Excluded metadata

The following do not affect identity: transaction ID/hash/nonce, governance
decision ID/hash, retrieval timestamps, local paths, evidence order,
attestation text, reviewer metadata, file names, and activation receipt IDs.
Changing excluded metadata must not create a second authority ID.

## Identity form and rationale

The authority ID is a composite digest: it is content-addressed by the
immutable source digest, policy-addressed by the policy ID and immutable
version form, and scope-bound by the exact raw-ID array. This combination gives
stable identity for the same source/version while preventing accidental reuse
under a different policy or scope. The source locator is included to prevent
two independently hosted objects with coincidentally copied bytes from being
silently conflated.

## Collision, reuse, and scope handling

An existing ID is reusable only when the recomputed preimage is byte-identical,
the policy digest is identical, the candidate is not superseded/revoked, and
the scope is exactly FIRST_TRANCHE24. A digest collision or an ID already
associated with a different preimage is a hard rejection. A Current86-wide or
other tranche request must use a separately authorized namespace and
transaction; this task cannot authorize it.

## Provenance binding

Every provenance evidence item repeats the computed authority ID, policy ID,
and content digest. The evidence set must assert `all_same_candidate: true` and
must contain no item whose candidate ID or digest differs. A candidate's
identity is not considered authenticated merely because one evidence item
matches; lineage and the complete evidence set must agree.

