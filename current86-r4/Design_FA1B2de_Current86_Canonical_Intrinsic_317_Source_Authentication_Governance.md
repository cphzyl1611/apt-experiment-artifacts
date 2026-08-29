# Design: FA1B2de Current86 Canonical Intrinsic 317 Source Authentication Governance

## Design-only boundary

This document defines the minimum source-authentication governance for the exact Current86 317-target set. It is a proposal, not an execution record. It does not materialize authenticated source facts, run P0 or P1, select an owner, publish a binding, or modify scoring or binding authority.

The governance is intentionally exact-317-only. It cannot enlarge, shrink, reorder, or reinterpret the target set. Any source package that is not proven to be the exact package described below is outside this design's authority and is rejected for this scope.

## Authenticated current state

| Item | Authenticated value |
|---|---|
| Target scope | `EXACT_317` |
| Target count | `317` |
| Raw-side source bindings | `86` |
| Candidate-side source bindings | `231` |
| Authentication closed | `0` |
| Requires new source governance | `317` |
| Existing canonical manifest entries | `0` |
| C0 recovered corpus | `YES`, exact 60-row subset |
| P0 executed | `NO` |
| P1 executed | `NO` |
| Owner decided | `NO` |
| Binding published | `NO` |

The current state remains blocked at the canonical-source layer. Existing raw and scoring objects are authenticated only for their declared noncanonical classes. The C0 recovery is a byte-preserving recovery of source bytes and provenance, not a source-fact publication.

## 1. Exact 317 target-set identity

The target set is the immutable set in `CURRENT86_Canonical_Intrinsic_317_Exact_Targets.json`, identified by all of the following values together:

- `audit_scope_id = 34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306`;
- exact-target manifest SHA256 = `d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac`;
- required class/fact pair = `AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE` / `PINNED_CANONICAL_INTRINSIC_FIELD`;
- exact counts = 317 total, 86 `RAW`, and 231 `CANDIDATE`;
- raw binding identity-set SHA256 = `dc97465eba0d2fb1235cb93e47d8be57221b85c4a75c24b5f34c087ed379a4ed`;
- candidate binding identity-set SHA256 = `3f70daaecfae52ea24bcef669d00e0ec788f88000da31e07c28db866826780c1`.

Each target is identified by the existing `source_binding_target_id`, computed with SHA256 over `PROJECT_CANONICAL_JSON_V1` (recursively bytewise-sort object keys, preserve array order, compact UTF-8 JSON) using these fields:

```text
audit_scope_id
bound_candidate_scoring_id
bound_raw_key
source_artifact_class
source_fact_type
source_side
```

The target ordering is `RAW` before `CANDIDATE`; within each side it is the bytewise ascending UTF-8 order of the bound identity. A target is not a relation outcome, a score, an occupancy result, or a human decision. `affected_relation_count` is descriptive input metadata only and is not an authentication key.

The exact target-set gate is:

```text
recomputed_target_ids == manifest_target_ids
and count == 317
and raw_count == 86
and candidate_count == 231
and audit_scope_id == pinned_audit_scope_id
```

Any failure is `TARGET_SET_IDENTITY_FAIL` and stops the governance run before a source object can be promoted.

## 2. Source-candidate object identity

A source candidate is an immutable byte-addressed object that may be evaluated by this governance. It is not a canonical source merely because its row can be found or because its current class is authenticated.

The candidate has two identities:

1. `candidate_corpus_id`: artifact-level identity for the source corpus.
2. `candidate_object_id`: row/object-level identity within that corpus.

`candidate_corpus_id` is the SHA256 of the canonical record below. Paths are locators and never an authority by themselves:

```json
{
  "declared_source_artifact_class": "...",
  "declared_source_fact_type": "... or null",
  "logical_artifact_identity": "...",
  "source_artifact_sha256": "...",
  "source_manifest_sha256": "...",
  "source_archive_sha256": "... or null",
  "producer_script_sha256": "...",
  "input_manifest_checkpoint": "..."
}
```

`candidate_object_id` is the SHA256 of the same canonical JSON form over:

```json
{
  "candidate_corpus_id": "...",
  "source_side": "RAW or CANDIDATE",
  "source_row_identity": "raw_key or scoring_id",
  "source_row_bytes_sha256": "...",
  "source_locator": "byte range or immutable line locator",
  "source_provenance_identity": "..."
}
```

The source row identity is exact and side-specific:

- `RAW` requires `bound_raw_key` and a null `bound_candidate_scoring_id`.
- `CANDIDATE` requires `bound_candidate_scoring_id` and a null `bound_raw_key`.

An object ID is not derived from similarity, parsed field values, relation membership, occupancy, or historical outcomes. Re-encoding a row changes its byte hash and therefore does not silently preserve object identity.

## 3. Source corpus provenance requirements

Every proposed canonical source corpus must ship with an immutable manifest and a machine-verifiable provenance chain. The minimum record for each corpus and row is:

- exact logical artifact identity and declared source class/fact type;
- full source-artifact SHA256;
- archive SHA256 when an archive is the transport boundary;
- source manifest SHA256 and checksum-inventory SHA256;
- producer script or producer binary SHA256;
- immutable input-manifest/checkpoint identity;
- schema/version identity;
- exact row locator, row identity, and raw row-byte SHA256;
- provenance identity computed from those fields;
- explicit `supersedes` and `superseded_by` links, or explicit nulls;
- membership proof that the row belongs to this exact Current86 target set.

The verifier must resolve bytes from the pinned artifact or immutable archive, not from a mutable path or a current working copy. File timestamps, filenames, directory placement, model output, and human prose are not provenance proofs.

For the currently known C0 lineage, the available anchors are retained exactly as evidence: full source SHA256 `0036c42fb02026182274a7ac2a33b103b03b1e527856eb33b5ad650ceddd5c32`, exact 60-row byte-subset SHA256 `8273c9b241cab806adbc9452a4ce572c11277657760f2e6e7b6210357829f54a`, source archive SHA256 `339a8d04a767bb69ea24c2b772c2519420a778555aaede34c799bc0242112f27`, producer script SHA256 `c988283ad4b9288555c01870ae9b12029a74a2e8c60a05cfc2eb5fa31160c6af`, source manifest SHA256 `d18053e55fb1ee7bb538476c6e4ebaa863181fbbc5a6990c09beb4b450ea672f`, and checksum inventory SHA256 `56b5769572440f6e8531f9cfce218dffea4baed19248ca5ade53a95e727075c3`.

Those anchors prove lineage and byte recovery. They do not, by themselves, prove canonical class, field pin, source fact, scoring correction, owner, or binding.

## 4. Exact-byte/source-object authentication rule

An object may receive `SOURCE_OBJECT_AUTHENTICATED` only when all checks below pass for the same immutable bytes:

1. The corpus manifest has the required exact-317 scope ID and class/fact registry identity.
2. The full artifact bytes match the pinned SHA256; if archived, the archive and its member bytes both match.
3. The selected row/object is found exactly once at its pinned locator.
4. The raw row bytes match `source_row_bytes_sha256`, including UTF-8 bytes and line-ending bytes. No parse-and-reserialize operation is used for this comparison.
5. Parsing the verified bytes yields exactly one object whose side-specific identity equals the target's bound key.
6. The object has no conflicting duplicate under the same logical identity. Byte-identical copies may be recorded as aliases only when their complete provenance chain is identical; different bytes are a hard conflict.
7. The provenance chain and producer/input lineage checks in this document pass.
8. The proposed class is explicitly admitted as `AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE`; a class label is not changed by string relabeling.

The result authenticates the source object only. It does not authenticate any scalar field and does not create a source fact.

### Candidate-to-canonical promotion predicate

Promotion is a new authenticated classification backed by the same bytes, not a relabeling of an existing candidate record. A candidate object can enter `SOURCE_OBJECT_AUTHENTICATED` only if the future governance record proves all of these predicates for one exact target:

```text
candidate_object_id maps to exactly one target in EXACT_317
and candidate side/key equals the target side/key
and canonical source class/fact registry identity is pinned
and full-artifact, row-byte, locator, and provenance hashes pass
and immutable producer/input lineage passes
and no superseded, rejected, or conflicting object is selected
```

The promotion record preserves the candidate corpus identity and all byte/provenance links, adds the canonical class admission, and receives a new authentication-record identity. It cannot change the target ID, bound key, scoring ID, relation result, owner, or any binding authority. A promotion record alone is not a field pin and is not a materialized source fact.

## 5. Immutable producer/input lineage

The producer and every input that can affect the selected bytes must be immutable and independently addressable by hash. The lineage verifier recomputes, at minimum:

```text
source archive bytes
  -> member source-artifact bytes
  -> exact row bytes
  -> parsed object
  -> RFC6901 field evaluation (later stage)
```

The producer implementation, producer version/schema, input checkpoint, source manifest, and all dependency artifacts are pinned. A producer may not read an unpinned filesystem path, network response, model response, or mutable registry during verification. Reproduction must be possible from the pinned bytes and declared deterministic procedure.

The current source-class/fact registry remains the frozen registry identified by registry ID `8cef6206dfc3581c3e7b6358bde7a36e90f4ba99078176cc0e5aff4b238298a7` and file SHA256 `3df4262faa4137996d2ff8d163bcc665d5bed76b3d719e6ff66cf4154252d72f`. Governance may read this registry, but it may not modify it in this design.

## 6. Supersession rule

Supersession is explicit, monotonic, and source-local:

- A new corpus or object gets a new immutable identity; it never overwrites an old identity.
- A replacement must name `supersedes_source_object_id` or `supersedes_candidate_corpus_id` and include the old identity in the new manifest.
- The independent verifier must prove the replacement before the old object is marked `SUPERSEDED`.
- A superseded, rejected, or stale object cannot satisfy canonical authentication and cannot be used as a fallback.
- Dependent field pins and provisional facts of a superseded object become non-current and require re-verification against the replacement.
- There is no implicit "latest wins" rule. If two non-superseded objects with the same target identity disagree in bytes, provenance, or scalar result, the target fails closed.

Historical C1B imported bindings are permanently `REJECTED_SUPERSEDED` for this scope. They are retained only as denylisted history and cannot be an alternate authority, a tie breaker, or a source of replacement values.

## 7. Allowed source classes

The allowlist is deliberately narrow.

| Role | Class | Use in this governance |
|---|---|---|
| Canonical output | `AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE` | The only class eligible for `SOURCE_OBJECT_AUTHENTICATED` |
| Raw candidate input | `AUTHENTICATED_RAW_SOURCE_RECORD` | Candidate evidence for 86 RAW objects; never sufficient alone for canonical promotion |
| Candidate input | `AUTHENTICATED_SCORING_ROW_SOURCE` | Candidate evidence for 231 CANDIDATE objects; never sufficient alone for canonical promotion |
| Restricted recovered corpus | `C0_TYPED_OPERATION_SEMANTICS` | Byte/provenance evidence for the affected 60 RAW objects only; requires the same canonical wrapper and checks |
| Out of scope | `AUTHENTICATED_PINNED_PROJECT_TAXONOMY_SOURCE` | Not an intrinsic source for this exact target set |
| Forbidden | `DERIVED_C2R1_COMPARATIVE_INTRINSIC_REFERENCE` | Derived comparative profile, never normative source |
| Forbidden | `HISTORICAL_C1B_BINDING` | Superseded historical import, never substitute authority |

Execution-contract artifacts, P0/P1 runtime outputs, relation outcomes, occupancy/similarity artifacts, free-form semantic paraphrases, and LLM assertions are not allowed source classes. Candidate classes may be promoted only through evidence-backed authentication; they are never promoted by renaming their class field.

## 8. Exact scalar field/pointer rule

`FIELD_PIN_AUTHENTICATED` requires an exact RFC 6901 JSON Pointer evaluated against the already authenticated source object. The pointer must:

- be present in the target's source package and be byte-for-byte identical in both producer and verifier records;
- resolve to exactly one existing leaf;
- use only valid RFC 6901 escaping (`~0` and `~1`);
- identify a parsed scalar of exactly one of these types: boolean, integer, null, or string;
- preserve the source parser's value without trimming, case folding, coercion, guessed defaults, or semantic normalization;
- have a deterministic scalar encoding whose SHA256 is recorded as `authenticated_value_sha256`.

Objects, arrays, floating-point numbers, missing paths, duplicate matches, wildcard paths, and inferred alternate paths fail closed. An empty/root pointer is invalid unless the root itself is an allowed scalar, which the canonical source object schema must explicitly permit. A pointer into an array is valid only when it names one exact numeric index and resolves to one allowed scalar.

The field-pin record stores the exact pointer, parsed scalar type, scalar hash, source object ID, and provenance ID. This design intentionally does not populate a scalar value.

## 9. Source-object to fact binding rule

For each exact target tuple, the future binding record must prove this one-to-one chain:

```text
source_binding_target_id
  -> one authenticated_source_object_id
  -> one authenticated field_pin_id
  -> one provisional source_fact_candidate_id
```

The binding record must repeat the exact scope ID, source side, bound raw key or bound candidate scoring ID, canonical source class, required fact type, source object ID, field-pin ID, source provenance identity, and verification status. It must not introduce a new scoring ID, relation outcome, owner, or binding disposition.

No target may bind across sides. A RAW target cannot be satisfied by a scoring row, and a CANDIDATE target cannot be satisfied by a raw registry row. An object may be reused only where the exact target identity and side-specific bound identity are identical; this exact-317 manifest contains unique required bindings, so a claimed reuse must still pass exact set recomputation.

`source_fact_candidate` is provisional evidence. Its deterministic ID may use the existing source-fact ID contract, but it is explicitly excluded from evidence fact sets, P0 input, scoring, and binding publication until independent verification passes.

## 10. Fail-closed ambiguity rule

The following conditions produce a hard failure for the affected target and prevent package admission:

- target-set hash, scope ID, side count, or target ID mismatch;
- zero or multiple corpus/object matches for a target;
- duplicate rows with conflicting bytes or conflicting provenance;
- full artifact, archive, member, row, manifest, producer, or input-checkpoint hash mismatch;
- broken, unpinned, mutable, or non-reproducible producer lineage;
- wrong source class/fact type, including a derived profile presented as canonical;
- missing, malformed, non-scalar, multiply resolving, or type-invalid RFC6901 pointer;
- scalar value disagreement between producer and independent verifier;
- stale, rejected, or superseded object presented as current;
- any LLM assertion, similarity, occupancy, or historical relation outcome used as proof;
- missing independent verification signature/record.

No heuristic chooses among ambiguous candidates. No nearest object, highest occupancy, or most similar profile is a tie breaker. If one of 317 targets fails, the exact-317 P0 source-substrate gate remains closed; there is no partial P0 source substrate for this design.

## 11. RAW versus CANDIDATE source-side distinction

The sides are separate namespaces and separate authentication obligations:

| Side | Count | Required key | Current candidate corpus |
|---|---:|---|---|
| `RAW` | 86 | `bound_raw_key` | `raw_action_registry.jsonl`, authenticated for raw-record class only |
| `CANDIDATE` | 231 | `bound_candidate_scoring_id` | `c2_scoring_snapshot_post_c1.jsonl`, authenticated for scoring-row class only |

RAW source evidence describes the raw action object. CANDIDATE source evidence describes the scoring-row object. Neither side may borrow a field from the other side, and neither side may use C2R1's derived comparative profile as a normative substitute. Candidate-side authentication does not authenticate any relation-level result.

The 86/231 split is a source-side conservation partition, not a scoring or owner decision. The exact 317 target set remains 86 + 231 = 317 throughout the lifecycle.

## 12. Legal role of the recovered C0 corpus

The recovered C0 corpus is a legal provenance and exact-byte source candidate for the 60 affected RAW targets. Its full-file and exact-subset hashes, immutable archive, producer hash, manifest hash, checksum inventory, row locators, and membership proof may be supplied to the canonical governance package.

Its legal role is limited:

- it can satisfy the corpus/row-byte and immutable-lineage prerequisites for those 60 RAW candidates;
- it cannot by itself set the canonical source class;
- it cannot by itself pin a field or materialize a source fact;
- it cannot fill the other 257 targets;
- it cannot be replaced by the C2R1 derived profile or historical C1B import;
- it cannot alter scoring, owner, or binding authority.

The recovered C0 file is therefore an admissible input to the lifecycle, not an already authenticated canonical source object.

## 13. Source authentication is not scoring correction

Authentication answers only: "Which immutable source bytes and exact scalar field are proven for this target?" It does not answer whether a score, taxonomy, relation label, hard-negative disposition, or candidate ID is correct.

If an authenticated scalar conflicts with a frozen scoring row, the governance records a source/scoring discrepancy and keeps both authorities unchanged. Resolving that discrepancy would require a separately authorized scoring-correction design. This document does not authorize such a correction and does not use source authentication to rewrite any score or relation result.

## 14. Source authentication is not an owner/binding decision

Authentication does not choose a human or system owner, establish an A2 owner, decide human-EQ, or publish a raw-level binding. A source object and field pin may be mechanically valid while the associated owner/binding decision remains absent. The source governance record must not contain a new owner, decision, adjudication, or published disposition.

## Minimal lifecycle (design only; not executed here)

The permitted lifecycle is:

```text
candidate source
  -> provenance verification
  -> authenticated source object
  -> exact field pin
  -> source fact candidate
  -> independent verification
```

### State definitions

| State | Meaning | What it does not mean |
|---|---|---|
| `CANDIDATE_SOURCE` | Existing exact raw/scoring/C0 object is queued with declared class and bytes | Not canonical; no field or fact is trusted |
| `PROVENANCE_VERIFIED` | Corpus, object identity, exact bytes, and immutable lineage pass | No scalar field is authenticated |
| `SOURCE_OBJECT_AUTHENTICATED` | The object is admitted under the exact canonical source class | No field pin or source fact exists |
| `FIELD_PIN_AUTHENTICATED` | One exact RFC6901 scalar pointer/type/hash is verified | Not yet a materialized source fact |
| `SOURCE_FACT_CANDIDATE` | Provisional target/object/field chain is recorded | Not in evidence sets or P0 substrate |
| `INDEPENDENT_VERIFICATION_PASS` | Fresh independent verifier recomputes all package and field checks | Does not decide owner or scoring |
| `SOURCE_FACT_MATERIALIZED` | Only now may the independently verified fact be admitted to a future source substrate | Still not a scoring correction or owner/binding decision |

Transitions are monotonic within one source identity. Any failed check creates a terminal reject/pending record for that target; it does not trigger heuristic substitution. A superseded source identity cannot transition forward again.

### Final P0 admission gate

P0 may consume a canonical source substrate only after a fresh independent verification record proves, for the exact package:

```text
target_set_identity_pass
and canonical_source_object_coverage == 317/317
and field_pin_coverage == 317/317
and source_fact_candidate_coverage == 317/317
and independent_verification_status == PASS
and ambiguous_count == 0
and conflicting_count == 0
and superseded_current_count == 0
and owner_decision == NO
and scoring_authority_mutation == NO
```

Until this predicate is true, `SOURCE_FACT_MATERIALIZED` is unavailable to P0 and the source substrate is `BLOCKED`. This document does not execute any transition or produce any fact.

## Mechanical package contract for a future execution

A future package may contain manifests and verification records, but it must not be accepted unless it includes:

1. the exact target-set identity and both side identity-set hashes;
2. one immutable source corpus manifest per admitted corpus;
3. one candidate/source-object record per exact target;
4. exact artifact, row, provenance, producer, and input hashes;
5. one exact RFC6901 field-pin record per target;
6. one provisional source-fact-candidate record per target;
7. a fresh independent verification record covering every target and every check;
8. an explicit denylist check proving no historical C1B, C2R1-derived profile, LLM assertion, similarity, occupancy, or historical outcome was used as authority;
9. an unchanged scoring/binding authority and no owner decision.

The package must fail closed on omission. A count claim without the exact identity set is insufficient, as is a field value without exact bytes and provenance.

## Design status

```text
AUTHENTICATION_CLOSED = 0
AUTHENTICATION_REQUIRES_NEW_SOURCE_GOVERNANCE = 317
C0_60_RECOVERED = YES

DESIGN_STATUS = PROPOSED_NOT_EXECUTED
TARGET_SCOPE = EXACT_317

NEW_OWNER_AUTHORITY = NO
NEW_BINDING_AUTHORITY = NO
SCORING_AUTHORITY_MUTATION = NO

NEXT_ACTION =
FRESH_INDEPENDENT_REVIEW_OF_EXACT317_SOURCE_AUTHENTICATION_GOVERNANCE_DESIGN

STOP
```
