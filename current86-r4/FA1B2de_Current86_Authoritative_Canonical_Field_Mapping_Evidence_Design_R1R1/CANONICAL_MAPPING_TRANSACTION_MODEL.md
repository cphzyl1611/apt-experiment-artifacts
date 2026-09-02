# Canonical Mapping Transaction Model

## Status and boundary

This is a design-only lifecycle contract for future canonical mapping evidence. It is not an authority store, source-auth transaction, field-pin transaction, activation of R7/R8/R8R1, or mutation of any historical artifact. All records are append-only immutable canonical-JSON bytes.

## Record hashes and reference direction

Every materialized record is stored as canonical JSON bytes and addressed externally by:

```text
record_sha256 = SHA256(UTF8(PROJECT_CANONICAL_JSON_V1(record_without_transport_envelope)))
```

The record does not embed its own content hash. A later record may contain the SHA-256 of an earlier record, but an earlier record must never contain a hash of a later record. `mapping_record_id` is a separate deterministic identity for the evidence claim; it is not a Stage A decision ID and is not a substitute for the full evidence-record SHA-256.

The only forward lifecycle graph permitted by this design is:

```text
SOURCE_AUTHORITY_ACTIVATION
  -> CANONICAL_SOURCE_OBJECT_ACQUISITION
  -> CANONICAL_FIELD_MAPPING_EVIDENCE
  -> STAGE_A_ADMISSION_RECORD
  -> STAGE_B_EXPOSURE_RECORD
```

The graph is acyclic by construction. A verifier must topologically sort the referenced records and fail closed on a missing node, a dangling hash, a self-reference, a backward reference, or a cycle.

## Record families

| Record family | Required effect | May create a field pin? |
| --- | --- | --- |
| `SOURCE_AUTHORITY_ACTIVATION` | Activates an exact governed source authority, scope, class, fact type, owner/issuer, and version policy. | No |
| `CANONICAL_SOURCE_OBJECT_ACQUISITION` | Pins immutable artifact bytes, acquisition proof, extractor, locator, exact-one match, and source-object hash. | No |
| `CANONICAL_FIELD_MAPPING_EVIDENCE` | Binds one frozen target to one recomputed canonical field identity. | No |
| `STAGE_A_ADMISSION_RECORD` | Records an independent review of the already-created evidence and either admits it or leaves it non-ready. | No |
| `STAGE_B_EXPOSURE_RECORD` | Exposes unchanged R8 candidate material only after Stage A admission and exact linkage checks. | No |
| `SUPERSESSION_OR_REVOCATION` | Adds governed lineage state without changing historical bytes. | No |
| `FIELD_PIN_DECISION` | A future separate governed human action outside this design package. | Only if separately authorized |

A source-authority proposal or source-owner authorization may be required outside this record family before activation. It cannot be used as a substitute for the activated record, acquisition proof, or evidence bytes.

## Acyclic transaction sequence

1. Verify a separately governed source-owner and governance authorization for the proposed source class, scope, source owner/issuer, version policy, and field semantics.
2. Append a `SOURCE_AUTHORITY_ACTIVATION` record after that governance proof is independently authenticated. It is inactive for evidence purposes unless its status is `ACTIVE` and its exact scope/class/fact-type tuple validates.
3. Append a `CANONICAL_SOURCE_OBJECT_ACQUISITION` record that references the activation record hash. It pins the immutable source artifact, acquisition proof, version, deterministic extractor, exact locator, exact-one match, source-object bytes, and source-object SHA-256.
4. Construct and persist the immutable `CANONICAL_FIELD_MAPPING_EVIDENCE` record. It references only the already-existing activation and acquisition hashes and contains no Stage A, Stage B, admission, conflict, field-pin, or lineage back-reference. Compute its deterministic `mapping_record_id` and its full evidence-record SHA-256 before any review.
5. A separate independent reviewer reads the evidence bytes by the full evidence-record SHA-256, recomputes the mapping ID, field identity, provenance chain, active lineage, and conflict state, then appends a `STAGE_A_ADMISSION_RECORD`. The Stage A record references the evidence ID and full evidence hash; the evidence record remains unchanged.
6. Only an `ADMISSION_READY` Stage A record permits a separate `STAGE_B_EXPOSURE_RECORD`. Stage B references the Stage A hash, evidence hash, exact target, raw R8 packet locator/hash, exact R5/R8 candidate object identity, and complete pointer set. Stage B never chooses a pointer and is not a pin decision.

The evidence-first rule is specifically relative to Stage A: immutable evidence bytes are committed first, and a separate append-only admission record references them. Activation and acquisition are mandatory predecessors to evidence, not fields that evidence creates or updates.

## Stage A review and admission

Stage A is a review/admission record, not a field on the evidence record. The reviewer first projects the eight identity-basis members from the operative evidence fields and requires byte-for-byte equality before accepting the mapping ID. A successful record can report `ADMISSION_READY` only when all of these independently recompute:

- the exact evidence bytes and full evidence-record hash;
- the deterministic `mapping_record_id` and `canonical_field_identity`;
- the active source authority, source artifact, acquisition proof, source object, extractor, locator, pointer, and value hash;
- the target and target-manifest identity;
- the active lineage snapshot with no revocation or supersession invalidating the evidence; and
- a conflict snapshot with exactly one active non-equivalent mapping identity for the target.

Any missing or failed prerequisite yields a fail-closed non-ready disposition. Stage A passage does not create a field pin and does not alter R7, R8, R8R1, source-auth, P0, P1, or publication state.

The non-ready result is itself an append-only `STAGE_A_ADMISSION_RECORD` with the exact disposition, `decision.status = ADMISSION_NOT_READY`, `decision.stage_b_enabled = false`, and `decision.stage_b_blocker = FIELD_PIN_NOT_EXPOSED_GATED_ON_ADMISSION`. It never uses a successful-record placeholder or silently omits the failed gate.

## Atomicity and duplicate handling

Each record is atomic: its canonical bytes and all required predecessor hashes either validate together or the record is not admitted. A multi-target batch is only a transport grouping; each of the 24 targets retains an independent evidence identity, full record hash, Stage A result, and failure state. Batch completeness and exact target order must be verified separately.

Byte-for-byte duplicate evidence submissions with the same mapping ID are idempotent and retain one logical record. A reused mapping ID with changed identity or full bytes fails closed. A SHA-256 collision between distinct identity bases fails closed; no timestamp, random salt, sequence, or alternate digest is introduced.

## Supersession, revocation, and rollback lineage

Lineage actions are new immutable `SUPERSESSION_OR_REVOCATION` records:

- `SUPERSEDE` must name an existing successor record hash. If the affected record is a mapping record, the successor mapping ID is included when applicable. The verifier rejects a dangling successor or a successor that does not cover the declared scope.
- `REVOKE` names the affected record hash and governance proof, with no successor. The affected record remains readable but cannot support Stage A.
- `ROLLBACK_REACTIVATE` names an existing prior valid record to reactivate and has no successor. It is a governed active-state computation, not deletion or rewriting of later records.

Lineage records never update an affected record in place. The active state is recomputed from the append-only graph, and a conflict is not resolved by timestamp, insertion order, reviewer preference, or candidate score. Two live non-equivalent mappings remain `MULTIPLE_AUTHORITATIVE_MAPPINGS_CONFLICT` until a valid governed lineage action changes the state.

## Historical and authority boundaries

R7 remains the source-authority baseline; R8 remains candidate evidence only; R8R1 remains 24 human `REQUEST_MORE_EVIDENCE` decisions. This design can cite their immutable hashes for historical or candidate linkage but cannot mutate, reinterpret, or promote them. C2R1 comparative evidence, human prose, a hash alone, a wrapper, or candidate cardinality cannot supply canonical authority. Governance, source owner, and acquisition remain separate required concerns.

The non-effects remain invariant:

```text
CURRENT_AUTHORITATIVE_FIELD_MAPPINGS_CREATED = 0
FIELD_PINS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO
R7_R8_R8R1_AUTHORITY_MUTATED = NO
```
