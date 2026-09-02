# Binding Authoritative Canonical Field-Mapping Evidence Design R1R1

## Purpose and status

This package is the local R1 design remediation for the three blockers identified by the pinned independent review `ca5dc55741c0d78b08b2772a6c7f2c81a712d715` on `artifact/binding`. It is design-only and non-authoritative. It creates no mapping, pin, source-auth result, P0/P1 result, publication, or repository mutation.

The frozen first tranche remains 24 exact targets, all currently `REQUEST_MORE_EVIDENCE`. The current evidence is candidate-side comparative material only. C2R1 is not authority; human prose is not source authority; a hash alone is not authority.

## Preserved boundaries

- `AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE` and `PINNED_CANONICAL_INTRINSIC_FIELD` remain future governed class/fact-type requirements, not current approvals.
- Governance authorization, source-owner authorization, and source acquisition authentication remain separate required acts.
- The current R5 and R8 artifacts remain unchanged candidate evidence. R8 candidate packets remain unselected and evidence-only.
- The first-tranche 24 records remain exactly ordered and conserved. Current authoritative mappings and field pins remain zero.
- No source-auth, P0, P1, binding publication, formal experiment, or R7/R8/R8R1 mutation is performed by this design remediation.

## B1: acyclic Stage A transaction model

The former forward-reference risk is closed by separating immutable evidence from its later admission decision. Activation and acquisition are mandatory predecessors to evidence; evidence is mandatory predecessor to Stage A; Stage A is mandatory predecessor to Stage B:

```text
SOURCE_AUTHORITY_ACTIVATION
  -> CANONICAL_SOURCE_OBJECT_ACQUISITION
  -> CANONICAL_FIELD_MAPPING_EVIDENCE
  -> STAGE_A_ADMISSION_RECORD
  -> STAGE_B_EXPOSURE_RECORD
```

The transaction rules are:

1. Append the separately governed source-authority activation record and verify its scope, owner/issuer, class, fact type, version policy, and governance proof.
2. Append the source-object acquisition record referencing the activation hash. It pins the immutable artifact, acquisition proof, version, deterministic extractor, exact locator, exact-one match, and object hash.
3. Create and content-address the complete immutable mapping evidence record. It references only already-existing activation and acquisition hashes. It contains no Stage A, Stage B, admission, conflict, field-pin, or lineage back-reference.
4. Compute the evidence record's full canonical-byte SHA-256 and deterministic `mapping_record_id` before review.
5. Append a separate Stage A admission record referencing the evidence `mapping_record_id` and full evidence-record SHA-256. Stage A records independent recomputation and `ADMISSION_READY` or a fail-closed non-ready result. It never edits evidence.
6. Append Stage B exposure only after Stage A is independently verified `ADMISSION_READY` and all candidate linkage checks pass.

Record hashes are external content addresses; a record does not embed its own hash. A verifier topologically sorts all references and fails closed on a missing, dangling, backward, self-referential, or cyclic edge. Supersession, revocation, and rollback are new immutable lineage records. `SUPERSEDE` requires an existing successor record; `REVOKE` and `ROLLBACK_REACTIVATE` have no successor. None mutates or deletes historical bytes.

## B2: deterministic `mapping_record_id`

The exact ID procedure is:

```text
mapping_record_id =
  "mapev1_sha256_" +
  SHA256(UTF8(PROJECT_CANONICAL_JSON_V1(record_identity.identity_basis)))
```

The identity basis contains exactly these members in contract order:

```text
target
source_authority
source_artifact
source_object
canonical_field
authenticated_value_sha256
evidence_acquisition
provenance_links
```

The procedure profile is `MAPR1R1_RECORD_ID_V1`; the canonicalization profile is `PROJECT_CANONICAL_JSON_V1` with authenticated profile SHA-256 `8b7f3e0c11bcef7368e002038b9c7f7cbcf2580aee37506c78d319e18c607c24`. Canonical bytes use RFC 8785 semantics, UTF-16 code-unit key ordering, strict UTF-8 without BOM, no trailing newline, NFC validation without silent rewrite, integer-only numbers, and order-sensitive arrays unless a declared set profile applies. The digest is SHA-256 rendered as 64 lowercase hexadecimal characters with prefix `mapev1_sha256_`.

Creation time, creator, review metadata, admission status, conflict result, Stage A and Stage B hashes, field-pin decision, lineage, candidate ranking or selection, reviewer preference, timestamps, sequence/process IDs, and random values are excluded from the ID basis. They remain immutable full-record metadata when present; changing them creates a different full record hash and never updates an existing record.

An independent verifier recomputes the ID and full evidence-record hash. Byte-identical submissions with the same mapping ID are idempotent duplicates. Same ID with changed identity or full bytes fails closed as `MAPPING_RECORD_ID_REUSE_OR_IDENTITY_MISMATCH`. Distinct identity bases with the same SHA-256 fail closed as `MAPPING_RECORD_HASH_COLLISION`. No timestamp or random value is used to disambiguate.

## B3: explicit Stage B candidate-object linkage

The existing R8 packet has no embedded packet ID. R1R1 therefore does not invent one. A Stage B exposure record identifies the packet by:

- exact R8 source path and JSONL line selector plus target selector;
- `packet_schema = FA1B2DE_CURRENT86_EXACT317_FIELD_PIN_CANDIDATE_PACKET_R8_V1`;
- `packet_sha256 = SHA256` of the exact single R8 JSONL record bytes in UTF-8, without BOM and excluding only its LF line terminator; and
- packet identity profile `R8_PACKET_RAW_JSONL_LINE_SHA256_V1` with locator profile `R8_JSONL_SOURCE_LOCATOR_V1`.

The candidate object linkage is exact and independently recomputed:

```text
candidate_object_id = R5.candidate_object_id
                     = R8.candidate_wrapper_object_id
                     = R8.wrapper_object_hash
```

`candidate_object_id` is recomputed as SHA-256 of the exact R5 identity basis (`schema`, `authority_status`, `route_rule_id`, `source_binding_target_id`, `source_side`, `source_key`, `source_locator`, `source_file_sha256`, and `row_bytes_sha256`) under `R5_CANDIDATE_WRAPPER_OBJECT_ID_V1`. `candidate_object_sha256` is this same identity digest; the separate R8 `active_source_object_sha256` and `wrapper_record_sha256` are byte hashes of the exact source object and wrapper record. The Stage B record carries exact R5 and R8 object locators. The target tuple must match byte-for-byte across evidence, Stage A, packet, and candidate object references.

The complete R8 `candidate_scalar_pointers` list is preserved as `R8_POINTER_SET_V1`, with each exact `pointer`, `value_sha256`, and `value_type` tuple. The verifier recomputes the sorted-unique pointer-set digest using UTF-16 code-unit pointer ordering and rejects hidden pruning, top-k truncation, pointer addition, pointer deletion, pointer substitution, or pointer normalization. The admitted exact pointer must be present in the complete set; membership is linkage, not selection.

Any target, packet, candidate-object, pointer-set, or Stage A mismatch fails closed as `STAGE_B_NOT_EXPOSED_CANDIDATE_LINK_MISMATCH` and produces no exposure. Stage B requires `ADMISSION_READY`, sets `auto_selection = false`, `selected_canonical_pointer = null`, `selected_candidate_object_id = null`, and `field_pin_created = false`. Human approve, reject, or request-more-evidence action remains a separate governed decision record.

## First-tranche state and exact conservation

`FIRST_TRANCHE_24_MAPPING_EVIDENCE_REQUIREMENTS.jsonl` remains unchanged from R1:

```text
count = 24
sha256 = 2c88f67ff154c5d6bfa2deb13dc51588b854e1c35ea74dc44749af8b537cb316
order = 110, 273, 210, 98, 147, 277, 188, 301, 143, 250, 233, 287,
        146, 293, 114, 284, 291, 215, 88, 182, 300, 218, 115, 148
```

Every line remains `BLOCKED`, `ADMISSION_NOT_READY_MISSING_PROVENANCE`, and `FIELD_PIN_NOT_EXPOSED_GATED_ON_ADMISSION`, with `REQUEST_MORE_EVIDENCE`, null canonical source/pointer/value/pin, separate governance and owner/acquisition requirements, and unchanged R5/R8 candidate linkage. This package adds no evidence record or decision record for those targets.

## Exact next gate

The next action is exact materialization of this self-consistent R1R1 design package into the governed artifact repository. Exact materialization is a separate step and must revalidate the schemas, 24-line crosswalk, zero state, and acyclic record-reference graph before any downstream operation. No downstream operation is authorized by this package.

## Terminal

```text
BINDING_CANONICAL_FIELD_MAPPING_EVIDENCE_DESIGN_R1_THREE_BLOCKER_REMEDIATION = PASS_READY_FOR_EXACT_ARTIFACT_MATERIALIZATION
B1_STAGE_A_FORWARD_REFERENCE_CYCLE = CLOSED
B2_MAPPING_RECORD_IDENTITY_PROCEDURE = CLOSED
B3_CANDIDATE_OBJECT_ID_STAGE_B_LINKAGE = CLOSED
R1_PREVIOUS_PASSING_BOUNDARIES_PRESERVED = PASS
FIRST_TRANCHE_COUNT = 24
CURRENT_MORE_EVIDENCE_COUNT = 24
CURRENT_AUTHORITATIVE_FIELD_MAPPINGS_CREATED = 0
FIELD_PINS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO
R7_R8_R8R1_AUTHORITY_MUTATED = NO
PUSH_EXECUTED = NO
ARTIFACT_REPOSITORY_MUTATED = NO
NEXT_ACTION = EXACT_MATERIALIZATION_OF_R1R1
STOP = true
```
