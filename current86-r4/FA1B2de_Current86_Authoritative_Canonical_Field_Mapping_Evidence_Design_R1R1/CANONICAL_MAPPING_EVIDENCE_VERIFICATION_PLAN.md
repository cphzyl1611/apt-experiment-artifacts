# Canonical Mapping Evidence Verification Plan

## Scope and non-effects

This plan defines future independent recomputation gates only. It does not authorize source acquisition, source-authority activation, Stage A admission, Stage B exposure, field-pin creation, source-auth, P0/P1, publication, or any mutation of R7, R8, or R8R1. It operates over immutable committed bytes and authenticated remote state, never generated prose or mutable worktree state.

## Preconditions

1. Authenticate the exact governing source-authority snapshot, source-owner authorization, acquisition proof, requested artifact version, and extraction rule.
2. Recompute the frozen target manifest and preserve the exact first-tranche order before evaluating any mapping record.
3. Authenticate the active R7 state and confirm that R7/R8/R8R1 historical artifacts and decisions are unchanged.
4. Build an evaluation snapshot from append-only record hashes. Require the topological order `SOURCE_AUTHORITY_ACTIVATION -> CANONICAL_SOURCE_OBJECT_ACQUISITION -> CANONICAL_FIELD_MAPPING_EVIDENCE -> STAGE_A_ADMISSION_RECORD -> STAGE_B_EXPOSURE_RECORD`.
5. Reject missing, malformed, duplicate-inconsistent, dangling, backward, self-referential, or cyclic records.

## Gate 1: exact source authority and acquisition

For every purported canonical mapping record:

- Recompute the source-authority artifact SHA-256 and verify its active scope, source class, fact type, owner/issuer, and version policy.
- Verify the source-owner authorization and the signed release, pinned signed Git commit/tree, or governance-approved content-addressed release.
- Recompute the immutable source artifact SHA-256, source version, source-object locator canonical hash, deterministic extractor hash, exact-one match, source-object bytes, and source-object SHA-256.
- Reject C2R1 comparative evidence, R8 candidate packets, scoring rows, raw rows, dry-run wrappers, and human prose as authority substitutes.

## Gate 2: exact mapping identity

- Parse the evidence record with duplicate-key rejection and strict UTF-8 validation.
- Verify `record_identity.profile_id = MAPR1R1_RECORD_ID_V1` and the authenticated `PROJECT_CANONICAL_JSON_V1` profile hash `8b7f3e0c11bcef7368e002038b9c7f7cbcf2580aee37506c78d319e18c607c24`.
- Recompute `mapping_record_id` from exactly, and only, the ordered identity members `target`, `source_authority`, `source_artifact`, `source_object`, `canonical_field`, `authenticated_value_sha256`, `evidence_acquisition`, and `provenance_links`.
- Independently project those eight identity members from the operative evidence fields and require byte-for-byte equality with `record_identity.identity_basis`; require `identity_projection_matches_record = true` only after that recomputation. A claimed marker is not accepted without the projection check.
- Require RFC 8785 UTF-16 key ordering, UTF-8 without BOM, no trailing newline, NFC validation without silent rewrite, integer-only numbers, and declared array ordering.
- Recompute the full evidence-record SHA-256. Stage A must reference this exact hash; it must not be copied into the evidence record.
- Reject timestamp/random/sequence/process/reviewer metadata as identity inputs, mapping ID reuse with changed bytes, or a distinct-basis SHA-256 collision.

## Gate 3: exact target conservation

Parse `FIRST_TRANCHE_24_MAPPING_EVIDENCE_REQUIREMENTS.jsonl` and require:

```text
count = 24
sha256 = 2c88f67ff154c5d6bfa2deb13dc51588b854e1c35ea74dc44749af8b537cb316
order = 110, 273, 210, 98, 147, 277, 188, 301, 143, 250, 233, 287,
        146, 293, 114, 284, 291, 215, 88, 182, 300, 218, 115, 148
```

Require unique target identities and exact conservation of each target index, `source_binding_target_id`, frozen R5 wrapper reference, R8 packet reference, source key, source locator, source-row SHA-256, and candidate object ID. Reject addition, deletion, duplication, reordering, substitution, or inferred canonical pointers. The R1R1 crosswalk bytes must equal the R1 crosswalk bytes exactly.

## Gate 4: exact canonical field recomputation

- Interpret the canonical pointer only as RFC6901 and resolve it exactly once against the authenticated canonical source object.
- Recompute field type, representation, canonical value, `authenticated_value_sha256`, schema hash, semantics hash, canonicalization profile hash, and `canonical_field_identity`.
- Reject pointer aliases, Unicode or semantic normalization, array reordering, text segmentation, alternate-pointer search, and any mismatch between bytes and declared fields.

## Gate 5: conflict and Stage A recomputation

- Enumerate all active mapping evidence records for the target in the authority scope.
- Apply only valid append-only lineage records; never delete or edit history.
- Return `AUTHORITATIVE_MAPPING_PRESENT` only when exactly one active complete non-equivalent mapping identity remains.
- Append Stage A only after the evidence record exists and all prior gates pass. Stage A references the exact mapping ID and full evidence hash, records independent recomputation, and reports `ADMISSION_READY` only for the clean state.
- Any missing or failed gate yields a separately append-only `STAGE_A_ADMISSION_RECORD` with `decision.status = ADMISSION_NOT_READY`, the exact fail-closed disposition, `stage_b_enabled = false`, and `FIELD_PIN_NOT_EXPOSED_GATED_ON_ADMISSION`; it leaves Stage B disabled.

## Gate 6: exact Stage B candidate linkage

Stage B is permitted only after Stage A is independently verified `ADMISSION_READY` for the exact target. Verify all of the following:

1. The packet locator is the exact R8 JSONL source path plus line selector and target selector. Do not invent an embedded packet ID.
2. `packet_sha256` is SHA-256 of the exact R8 record bytes in UTF-8 without BOM and excluding only its LF line terminator, under `R8_PACKET_RAW_JSONL_LINE_SHA256_V1`.
3. The Stage B target equals the evidence target and packet target byte-for-byte.
4. Recompute the exact R5 candidate identity basis (`schema`, `authority_status`, `route_rule_id`, `source_binding_target_id`, `source_side`, `source_key`, `source_locator`, `source_file_sha256`, and `row_bytes_sha256`). Require its SHA-256 to equal `candidate_object_id` and `candidate_object_sha256`, R5 `candidate_object_id`, R8 `candidate_wrapper_object_id`, and R8 `wrapper_object_hash` under `R5_CANDIDATE_WRAPPER_OBJECT_ID_V1`.
5. Independently recompute the R8 `active_source_object_sha256` and R8 `wrapper_object.wrapper_record_sha256`; the candidate object locator identifies the exact R5 wrapper record and R8 wrapper-object fields.
6. Copy the complete R8 `candidate_scalar_pointers` list into `R8_POINTER_SET_V1`, preserving each exact pointer/value-hash/type tuple and recomputing sorted-unique set bytes and digest using UTF-16 code-unit pointer ordering.
7. Require the admitted exact RFC6901 pointer to be a member of that set. This is a linkage check, not automatic selection.
8. Require every tuple linkage boolean to be true. Any mismatch returns `STAGE_B_NOT_EXPOSED_CANDIDATE_LINK_MISMATCH` and creates no exposure record.

Stage B must set `selected_canonical_pointer = null`, `selected_candidate_object_id = null`, `auto_selection = false`, and `field_pin_created = false`. Human approval, rejection, or request for more evidence remains a separate governed decision record.

## Gate 7: zero unauthorized effects

Inspect changed paths, record kinds, and downstream state. Require:

```text
CURRENT_AUTHORITATIVE_FIELD_MAPPINGS_CREATED = 0
FIELD_PINS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO
R7_R8_R8R1_AUTHORITY_MUTATED = NO
```

No design review or R1R1 package build may create a mapping record, Stage A admission, Stage B exposure, candidate selection, field pin, source-auth result, P0/P1 result, publication artifact, or change to the R7/R8/R8R1 packages.

## Expected independent-review output

The reviewer should emit only recomputed facts, the exact failed gate(s), an evidence snapshot hash, the acyclicity result, the 24-record conservation result, and one of:

```text
AUTHORITATIVE_MAPPING_PRESENT
AUTHORITATIVE_MAPPING_ABSENT
MULTIPLE_AUTHORITATIVE_MAPPINGS_CONFLICT
SOURCE_AUTHORITY_UNRESOLVED
SOURCE_OBJECT_UNAUTHENTICATED
FIELD_IDENTITY_AMBIGUOUS
CANONICAL_POINTER_MISSING
EVIDENCE_STALE_OR_SUPERSEDED
STAGE_B_NOT_EXPOSED_CANDIDATE_LINK_MISMATCH
```

No output may rank candidate pointers, recommend one, create a field pin, execute source-auth, or authorize P0/P1/publication.
