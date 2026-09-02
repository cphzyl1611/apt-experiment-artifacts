# Canonical Field Identity Model

## Purpose

This model identifies one canonical intrinsic field without collapsing it into an equal-looking field from another source object, source version, namespace, pointer, or canonicalization rule. It is a future evidence identity model only; it does not assign an identity to any current first-tranche field.

## Identity tuple

The canonical field identity basis is canonical JSON with exactly these members:

```text
{
  "source_authority_id": "...",
  "source_authority_artifact_sha256": "...",
  "source_authority_scope_id": "...",
  "source_artifact_identity": "...",
  "source_artifact_sha256": "...",
  "source_version_identity": "...",
  "source_object_locator": "...",
  "source_object_locator_sha256": "...",
  "source_object_sha256": "...",
  "object_extraction_rule_id": "...",
  "object_extraction_rule_sha256": "...",
  "field_namespace": "...",
  "field_schema_id": "...",
  "field_schema_version": "...",
  "field_schema_sha256": "...",
  "canonical_intrinsic_field_semantics_id": "...",
  "canonical_intrinsic_field_semantics_sha256": "...",
  "exact_rfc6901_pointer": "...",
  "field_representation": "SCALAR | STRUCTURED",
  "field_value_type": "string | integer | boolean | null | object | array",
  "canonicalization_profile_id": "...",
  "canonicalization_profile_sha256": "..."
}
```

`canonical_field_identity` is `SHA256(PROJECT_CANONICAL_JSON_V1(identity_basis))`. Record creation timestamps, review timestamps, display labels, URLs, and human comments are excluded from the identity basis.

## Required interpretation

- `source_authority_*` identifies the governance root that grants canonical status. It prevents a hash-matched noncanonical copy from inheriting authority.
- `source_artifact_*` and `source_version_identity` bind the exact release, commit/tree, or content-addressed artifact. A mutable branch or URL is not a version identity.
- `source_object_*` and the extraction rule distinguish an object at a particular canonical location from a byte-equal object elsewhere.
- `field_namespace`, schema identity/version/hash, and semantics identity distinguish fields whose pointer spelling or values happen to match but whose schema meanings differ.
- `exact_rfc6901_pointer` is an exact RFC6901 token sequence. No Unicode normalization, case folding, alias substitution, path rewriting, sentence segmentation, or semantic inference is permitted.
- `field_representation`, `field_value_type`, and canonicalization profile prevent a scalar, array, object, or differently canonicalized value from sharing an identity merely because its rendered text matches.

## Value commitments

The field identity names the field, not a time-varying display value. A mapping evidence record also carries a value commitment:

```text
authenticated_value_sha256 = SHA256(canonical_json(exact resolved field value))
```

For a scalar field, the resolved JSON scalar is hashed with the pinned canonicalization profile. Strings preserve exact Unicode code points and are not trimmed, translated, tokenized, summarized, or normalized. For a structured field, the exact JSON subtree is hashed with the same profile and its schema identity must define the permitted object/array shape. Structured values are never silently decomposed into scalar fields.

## Collision prevention

Two source fields must have different identities when any identity-basis member differs. In particular:

- identical values at different pointers are distinct;
- identical pointers in different source objects, artifacts, versions, schemas, namespaces, or authority roots are distinct;
- a field before and after an upstream source version change is distinct unless the version identity and artifact hash are intentionally identical;
- a candidate-source field and an authoritative-source field are distinct even if their pointer, object value, and value hash match;
- a structured field and a scalar derived from it are distinct.

A future Stage A verifier must reject a record where the tuple-derived identity does not equal the supplied `canonical_field_identity`, where the pointer does not resolve exactly once, or where the value/type commitment differs from the authenticated source object.

## Mapping identity is separate

The canonical field identity is not a field pin and not a target mapping. A mapping evidence record adds `source_binding_target_id` and the frozen target-manifest identity to bind one target to one independently identified canonical field. The mapping record identity is separately computed from the evidence record's identity basis. This prevents either two targets sharing a source field or one target having conflicting source fields from being hidden by field-level deduplication.
