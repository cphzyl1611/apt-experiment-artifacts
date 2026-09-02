# Canonical Mapping Transaction Model

## Status and boundary

This is a lifecycle design for future canonical mapping evidence records. It is not an authority store, registry, activation, source-auth transaction, field-pin transaction, or amendment of R7, R8, or R8R1. Historical artifacts remain immutable input evidence.

## Records and identity

All future records are immutable canonical-JSON bytes addressed by SHA-256. A record references prior records by hash. Human authorization is represented only by the hash of a separately authenticated governance artifact, never by free-form prose embedded as authority.

The minimum record families are:

| Record family | Effect | May create a field pin? |
| --- | --- | --- |
| `SOURCE_AUTHORITY_PROPOSAL` | States a proposed source class, source owner, source scope, and acquisition policy. | No |
| `SOURCE_AUTHORITY_ACTIVATION` | Separately governed activation of an eligible canonical source authority. | No |
| `CANONICAL_SOURCE_OBJECT_ACQUISITION` | Pins authenticated artifact and exact source object extraction evidence. | No |
| `CANONICAL_FIELD_MAPPING_EVIDENCE` | Binds one target to a proposed canonical field identity with complete source evidence. | No |
| `STAGE_A_ADMISSION_DECISION` | Independently admits or blocks the evidence record. | No |
| `STAGE_B_EXPOSURE_RECORD` | Exposes the already admitted tuple for a separate human field-pin review. | No |
| `FIELD_PIN_DECISION` | A future separately governed action outside this design package. | Only if separately authorized |
| `SUPERSESSION_OR_REVOCATION` | Marks a prior record non-active while preserving its history. | No |

## Append-only creation

1. Create a source-authority proposal. It identifies a contemplated class or source but is inactive and cannot be used for admission.
2. Obtain a separately governed source-owner/acquisition authorization if the candidate source is not already covered by active authority.
3. Append a source-authority activation record only after its governance proof is verified. It must state scope, permitted class/fact type, version policy, and revocation authority.
4. Append a canonical-source-object acquisition record. It pins artifact bytes, source version, acquisition proof, deterministic extractor, exact locator, exact-one match, and source-object hash.
5. Append one canonical mapping evidence record per target. The record must satisfy the schema in this package and refer only to already immutable predecessor hashes.
6. An independent reviewer recomputes the full evidence chain and appends a Stage A decision record. The decision is `ADMISSION_READY` only for the clean disposition.
7. Only then may a Stage B exposure record reference the exact admitted tuple and unchanged R8 candidate packet. The Stage B record is not a pin decision.

No transaction may overwrite a predecessor, update an existing record in place, silently replace source bytes, or use a mutable branch/URL as a substitute for a pinned source version.

## Atomicity

Each record is individually atomic: either its canonical bytes, required references, and content hash are committed together, or it does not exist. A Stage A decision must not be active unless all referenced source-authority, acquisition, mapping-evidence, conflict, and lineage records exist and validate.

For a multi-target batch, each target retains an individual mapping-record identity and independent Stage A result. The batch commit must provide a complete target list and target-conservation hash; batch success cannot hide a failed target. An incomplete batch leaves affected targets blocked.

The activation set is computed from a single immutable snapshot of all record hashes in scope. An evaluator must reject a snapshot with missing referenced objects, dangling supersession references, cycles, duplicate active identities, or inconsistent target-manifest hashes.

## Review and activation separation

Creation, review, activation, and Stage B are separate events:

- An evidence record says what bytes are claimed; it has no admission effect by itself.
- A Stage A decision says whether the claim satisfies the independent recomputation gate; it has no field-pin effect.
- A Stage B exposure record says that candidate material may be presented to the separate governed human field-pin process; it has no selection effect.
- A future field-pin decision must be separate and byte-for-byte equal to the admitted tuple. It must never update the evidence record to make the equality true.

## Supersession, revocation, and rollback

A source authority, source artifact, source object, field semantics definition, mapping evidence record, or Stage A decision may be superseded or revoked only by a new immutable governed record that names the affected record hash, reason code, effective scope, and successor hash when one exists.

The evaluator calculates active state from the append-only lineage graph:

- A superseded record remains inspectable but is not active when a valid successor governs its same scope.
- A revoked record remains inspectable but cannot support Stage A.
- A rollback is a new activation record that reactivates a named prior valid record after explicit governance; it does not delete later records or rewrite history.
- A conflict with two live non-equivalent records is not resolved by temporal ordering. It remains `MULTIPLE_AUTHORITATIVE_MAPPINGS_CONFLICT` until governance explicitly supersedes or revokes the conflicting state.

## Relationship to R7, R8, and R8R1

R7 remains the active source-authority baseline and currently has source-auth execution count zero with no field-pin registry. R8 remains evidence-only candidate-packet material with no selected pointers. R8R1 preserves the first-tranche decision state: 24 `REQUEST_MORE_EVIDENCE` decisions, zero approvals, zero pins.

Future records may cite immutable hashes from those artifacts as historical input or candidate linkage. They must not modify their bytes, reinterpret a candidate packet as source authority, overwrite its decisions, or change the R7 consumer pointer. The canonical mapping evidence layer is additive and separate; its eventual activation requires a distinct governed transaction outside this design task.

## Non-effects

This model must preserve the following through design, record creation, review, and Stage A:

```text
FIELD_PINS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO
R7_R8_R8R1_AUTHORITY_MUTATED = NO
FORMAL_EXPERIMENT_EXECUTED = NO
```
