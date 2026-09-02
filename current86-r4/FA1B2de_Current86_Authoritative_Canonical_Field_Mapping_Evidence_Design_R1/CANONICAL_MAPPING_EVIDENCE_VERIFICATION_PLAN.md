# Canonical Mapping Evidence Verification Plan

## Scope

This plan defines future independent recomputation gates. It does not authorize the acquisition, activation, admission, or execution it describes. It must operate over immutable committed bytes and authenticated remote state, not generated prose or mutable worktree files.

## Preconditions

1. Authenticate the remote repository, requested ref, and exact governing source-authority snapshot.
2. Recompute the frozen target manifest hash and preserve the target order before reading mapping evidence.
3. Authenticate the active R7 state and confirm that the proposed process has not changed R7/R8/R8R1 historical artifacts.
4. Build the evaluation snapshot from append-only record hashes only. Reject missing, malformed, duplicate, or cyclic references.

## Required gates

### 1. Exact source authentication

For every purported canonical mapping record:

- Recompute the source-authority artifact SHA-256 and verify that its active authorization permits `AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE` and `PINNED_CANONICAL_INTRINSIC_FIELD` for the target scope.
- Verify the source owner's signed release, pinned signed commit/tree, or governance-approved content-addressed release using the declared verifier.
- Recompute the source artifact SHA-256, immutable version identity, source-object locator canonical hash, deterministic extractor hash, exactly-one object match, and source-object SHA-256.
- Reject current C2R1 comparative evidence, R8 candidate packets, scoring rows, raw rows, dry-run wrappers, and human prose as a source-authority substitute.

### 2. Exact mapping-record hash

- Parse the future record as canonical JSON.
- Recompute `mapping_record_id` from its defined identity basis and require exact equality.
- Recompute `canonical_field_identity` using the model in `CANONICAL_FIELD_IDENTITY_MODEL.md`.
- Verify every referenced SHA-256 and that timestamps and display text are not included in identity bases.

### 3. Exact target conservation

- Parse `FIRST_TRANCHE_24_MAPPING_EVIDENCE_REQUIREMENTS.jsonl` and the frozen first-tranche source.
- Require exactly 24 records, unique target identities, and the exact ordered indices:

```text
110, 273, 210, 98, 147, 277, 188, 301, 143, 250, 233, 287,
146, 293, 114, 284, 291, 215, 88, 182, 300, 218, 115, 148
```

- Recompute every target ID, source key, source locator, source-row SHA-256, R5 wrapper object ID, and R8 candidate-packet linkage against committed bytes.
- Reject addition, deletion, duplication, reordering, target substitution, or an attempt to replace a frozen candidate link with an inferred canonical pointer.

### 4. Exact pointer and field recomputation

- Interpret the candidate exact pointer only as RFC6901, with no alias map, Unicode normalization, semantic matching, array reorder, text segmentation, or alternate-pointer search.
- Resolve it against the authenticated canonical source object exactly once.
- Recompute the actual JSON field type, representation, canonical value, `authenticated_value_sha256`, field schema hash, semantics hash, canonicalization profile hash, and canonical field identity.
- Reject a mapping if any record value differs from recomputation.

### 5. Source-object-to-field recomputation

- Verify the source artifact to source object link through the pinned acquisition proof, source version, extractor, locator, and object hash.
- Verify the source object to canonical field link through the pinned schema/semantics and exact pointer.
- Verify the canonical field to target link through the mapping record's target identity and manifest SHA-256.
- Reject an evidence record whose authority is supplied by the same C2R1 derived evidence it is attempting to replace.

### 6. Conflict recomputation

- Enumerate all active mapping evidence records for each target in the same authority scope.
- Apply valid append-only revocation and supersession records without deleting historical records.
- Recompute the canonical field identity for every active record.
- Return `AUTHORITATIVE_MAPPING_PRESENT` only if exactly one active complete identity remains. Return `MULTIPLE_AUTHORITATIVE_MAPPINGS_CONFLICT` for two or more distinct identities, even if a reviewer prefers one.

### 7. Stage A admission recomputation

- Require all preceding gates to pass for the exact record and target.
- Require clean conflict state and active non-superseded lineage.
- Require a separate Stage A decision record that identifies the exact mapping record hash and reports `ADMISSION_READY` only after its own recomputation.
- A failed or missing gate must produce a non-ready disposition and leave Stage B disabled.

### 8. Zero unauthorized pin creation

- Inspect all changed paths and transaction record kinds. Confirm no field-pin registry entry, `FIELD_PIN_DECISION`, selected pointer, source-auth execution record, P0/P1 result, publication artifact, or R7/R8/R8R1 mutation was created as part of the evidence-design or Stage A process.
- Recompute field-pin count from the authoritative field-pin registry only if such a registry is separately created in a later governed task. Until then, require `FIELD_PINS_CREATED = 0`.

## Expected independent-review outputs

The reviewer should emit only recomputed facts, the exact failed gate(s), an evidence snapshot hash, and one of:

```text
AUTHORITATIVE_MAPPING_PRESENT
AUTHORITATIVE_MAPPING_ABSENT
MULTIPLE_AUTHORITATIVE_MAPPINGS_CONFLICT
SOURCE_AUTHORITY_UNRESOLVED
SOURCE_OBJECT_UNAUTHENTICATED
FIELD_IDENTITY_AMBIGUOUS
CANONICAL_POINTER_MISSING
EVIDENCE_STALE_OR_SUPERSEDED
```

No output should rank candidate pointers, recommend one, create a field pin, or execute source-auth.
