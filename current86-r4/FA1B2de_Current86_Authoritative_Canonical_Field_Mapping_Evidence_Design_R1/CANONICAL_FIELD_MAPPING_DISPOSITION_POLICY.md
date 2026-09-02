# Canonical Field Mapping Disposition Policy

## Rule

The disposition engine is deterministic, evidence-bound, and fail-closed. It evaluates authenticated bytes and governed state; it does not rank candidates, infer semantics, normalize pointer aliases, or accept a reviewer preference as authority. Every state other than the single clean state below blocks Stage A and prohibits Stage B exposure.

## Dispositions

| Disposition | Exact condition | Stage A | Stage B |
| --- | --- | --- | --- |
| `AUTHORITATIVE_MAPPING_PRESENT` | Exactly one active mapping record for the exact target has a complete validated chain, a valid authorized canonical source object, a resolvable canonical field identity, and no conflict, revocation, or supersession. | Eligible for `ADMISSION_READY`; Stage A must still write an independent decision. | Not yet exposed until the Stage A decision passes. |
| `AUTHORITATIVE_MAPPING_ABSENT` | No active, complete, valid mapping record exists for the target. | Blocked. | Prohibited. |
| `MULTIPLE_AUTHORITATIVE_MAPPINGS_CONFLICT` | Two or more active valid mapping records for one target have distinct canonical field identities, source-object identities, semantics IDs, or exact pointers. | Blocked. | Prohibited. |
| `SOURCE_AUTHORITY_UNRESOLVED` | The source-authority record is missing, inactive, outside scope, unauthenticated, or fails to authorize the class/fact-type pair. | Blocked. | Prohibited. |
| `SOURCE_OBJECT_UNAUTHENTICATED` | Source artifact, acquisition proof, source object, locator, extractor, version, or object cardinality cannot be cryptographically recomputed exactly. | Blocked. | Prohibited. |
| `FIELD_IDENTITY_AMBIGUOUS` | Namespace, schema, semantics, pointer tokenization, field type, representation, or canonicalization profile is missing or non-unique. | Blocked. | Prohibited. |
| `CANONICAL_POINTER_MISSING` | No exact RFC6901 pointer is supplied, the pointer resolves zero or multiple times, or the resolved value cannot be bound to the record. | Blocked. | Prohibited. |
| `EVIDENCE_STALE_OR_SUPERSEDED` | The authority, artifact, source version, mapping record, or field identity is revoked, superseded, expired under its explicit version policy, or is not the active lineage result. | Blocked. | Prohibited. |

## Conflict recomputation

For each target, collect every active mapping evidence record in the evaluated scope after applying append-only activation, revocation, and supersession records. Recompute the canonical field identity from source bytes and record fields. The result is clean only when exactly one identity remains.

Byte-for-byte duplicate copies of the same mapping record are not a second mapping, but independently created records with the same claimed identity must be treated as an integrity failure unless their record identities, provenance links, and activation references are exactly identical. An evaluator must not choose the newest, first, highest-ranked, or otherwise preferred record to break a conflict.

## Absence and ambiguity

Absence is evidence of no authority, not an invitation to infer a mapping. The following do not reduce ambiguity: a smaller candidate set, a unique source row, equal field values, matching text, a source wrapper object, a C2R1 relation, or a human statement. A current `REQUEST_MORE_EVIDENCE` decision remains a request for the missing authoritative chain; it is neither approval nor rejection of a pointer.

## Revocation and rollback

Revocation or supersession never erases historical bytes. It changes only the recomputed active disposition. A revoked mapping, source artifact, source authority, or extraction rule yields `EVIDENCE_STALE_OR_SUPERSEDED` until a distinct successor record establishes a complete, non-conflicting chain. A rollback is a governed activation of a prior valid record, not deletion or mutation of later records.

## Fail-closed result

All non-clean dispositions produce an admission result other than `ADMISSION_READY`, retain `FIELD_PIN_NOT_EXPOSED_GATED_ON_ADMISSION`, and create zero field pins. No fallback to C2R1, scoring, raw, C0, candidate-packet, or reviewer evidence is permitted.
