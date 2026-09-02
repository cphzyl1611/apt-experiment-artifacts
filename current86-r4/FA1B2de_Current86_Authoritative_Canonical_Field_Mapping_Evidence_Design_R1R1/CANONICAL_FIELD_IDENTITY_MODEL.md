# Canonical Field and Mapping Identity Model

## Status and authority boundary

This is a design-only identity contract. It defines how a future immutable canonical field and target-to-field evidence record are identified. It creates no mapping, field pin, source-auth execution, Stage A decision, or authority. A hash proves byte identity; canonical authority still requires a separately governed source-authority record.

## Canonical field identity

`canonical_field_identity` is the lowercase hexadecimal SHA-256 digest of the UTF-8 bytes produced by `PROJECT_CANONICAL_JSON_V1` over exactly the canonical field identity object. The object contains the source authority, immutable source artifact and version, exact source object locator and hash, extractor identity, schema and semantics identity, exact RFC6901 pointer, representation, value type, and canonicalization profile. It contains no review result, candidate ranking, field-pin decision, timestamp, or lineage state.

The exact field identity members are:

```text
source_authority_id
source_authority_artifact_sha256
source_authority_scope_id
source_artifact_identity
source_artifact_sha256
source_version_identity
source_object_locator
source_object_locator_sha256
source_object_sha256
object_extraction_rule_id
object_extraction_rule_sha256
field_namespace
field_schema_id
field_schema_version
field_schema_sha256
canonical_intrinsic_field_semantics_id
canonical_intrinsic_field_semantics_sha256
exact_rfc6901_pointer
field_representation
field_value_type
canonicalization_profile_id
canonicalization_profile_sha256
```

The pointer resolves exactly once in the authenticated source object. The resolved value is committed as:

```text
authenticated_value_sha256 =
  SHA256(UTF8(PROJECT_CANONICAL_JSON_V1(exact_resolved_field_value)))
```

Strings are not trimmed, translated, case-folded, or silently normalized. Structured values are hashed as their exact JSON subtree and are not silently decomposed into scalar fields.

## Deterministic `mapping_record_id`

`mapping_record_id` is computed before Stage A and is never issued or changed by Stage A:

```text
mapping_record_id =
  "mapev1_sha256_" +
  SHA256(UTF8(PROJECT_CANONICAL_JSON_V1(record_identity.identity_basis)))
```

`record_identity.identity_basis` contains exactly these members, in this contract order:

```text
1. target
2. source_authority
3. source_artifact
4. source_object
5. canonical_field
6. authenticated_value_sha256
7. evidence_acquisition
8. provenance_links
```

The basis includes the target index, `source_binding_target_id`, target-manifest hash, authority identity/scope/activation hash, immutable artifact and version identity, owner/issuer identity, exact object locator/extractor/object hash, field schema/semantics/pointer/type/representation/profile, authenticated value hash, acquisition record hash, and the four provenance-link hashes. The supplied ID must equal the independent recomputation exactly. The `MAPR1R1_RECORD_ID_V1` procedure profile and the field's `PROJECT_CANONICAL_JSON_V1` profile/version are fixed inputs to the procedure and are carried in the record for independent verification; no host serializer is permitted to substitute another profile.

## Canonical byte serialization

The serialization profile is `PROJECT_CANONICAL_JSON_V1`, whose authenticated profile SHA-256 is:

```text
8b7f3e0c11bcef7368e002038b9c7f7cbcf2580aee37506c78d319e18c607c24
```

For identity bytes, the verifier MUST apply all of these rules:

- RFC 8785 semantics with object-member ordering by UTF-16 code units.
- Strict UTF-8 without BOM, with no trailing newline and no insignificant whitespace outside JSON tokens.
- Normative strings must already be NFC and are validated; non-NFC input fails closed rather than being silently rewritten.
- Numbers are integer-only under the declared schema range; floating-point and non-JSON numeric tokens are prohibited.
- Arrays preserve order unless an explicitly declared set profile defines a separate ordering. The mapping identity basis itself has no unordered array.
- Duplicate object member names, invalid UTF-8, unpaired surrogates, or invalid JSON fail closed.

The canonicalizer is independently implemented or independently re-run from the declared profile; locale, filesystem order, process state, and serializer defaults cannot affect the result.

## Excluded metadata

The following are excluded from the `mapping_record_id` basis: creation time, creator, display labels, URLs, human comments, review identity/time, admission status, conflict recomputation, Stage A and Stage B record hashes, field-pin decisions, lineage references, rollback state, candidate ranking, candidate selection, reviewer preference, sequence/process identifiers, and random values.

Exclusion from identity does not make metadata mutable in place. The full evidence record is immutable canonical JSON bytes. Changing excluded metadata creates a different full record byte hash; it never updates the original record or changes its `mapping_record_id`.

## Creation, duplicate, and collision procedure

1. Verify that the separately governed activation and acquisition predecessor records already exist and that their referenced bytes are immutable.
2. Construct the complete mapping evidence record without any Stage A, Stage B, field-pin, admission, conflict, or lineage back-reference.
3. Canonicalize only `record_identity.identity_basis` under `MAPR1R1_RECORD_ID_V1` and compute the expected namespaced ID.
4. Reject the record if its supplied ID differs from the recomputed ID.
5. Canonicalize the complete evidence record and compute its full evidence-record SHA-256. This is the hash that a later Stage A admission record may reference.
6. If an existing record has the same mapping ID and byte-for-byte identical full record bytes, treat the submission as an idempotent duplicate and retain one logical record.
7. If the mapping ID matches but any identity-basis or full-record bytes differ, fail closed as `MAPPING_RECORD_ID_REUSE_OR_IDENTITY_MISMATCH`; do not choose a winner or mutate either record.
8. If two distinct identity bases produce the same SHA-256 digest, fail closed as `MAPPING_RECORD_HASH_COLLISION`; do not truncate, salt, timestamp, randomize, or silently substitute an alternate ID.
9. An independent verifier recomputes both the mapping ID and the full evidence-record hash from immutable bytes and compares those values with every later reference.

No timestamp, sequence number, random UUID, process ID, insertion order, reviewer preference, or candidate ranking contributes to `mapping_record_id`.

## Lifecycle and historical immutability

The acyclic record-reference order is:

```text
SOURCE_AUTHORITY_ACTIVATION
  -> CANONICAL_SOURCE_OBJECT_ACQUISITION
  -> CANONICAL_FIELD_MAPPING_EVIDENCE
  -> STAGE_A_ADMISSION_RECORD
  -> STAGE_B_EXPOSURE_RECORD
```

The evidence record is created and content-addressed before its separate Stage A admission record. Stage A references the evidence `mapping_record_id` and full evidence-record SHA-256; the evidence record never references Stage A. Supersession, revocation, and rollback are new append-only lineage records that point to existing immutable hashes. No record is edited, deleted, or rewritten to add a later decision.

Two source fields remain distinct whenever any identity-basis member differs, including equal values at different pointers, equal pointers in different artifacts or authority roots, candidate versus authoritative sources, and scalar versus structured representations. Neither a field identity nor a mapping identity is a field pin, and neither is created for the current first tranche.
