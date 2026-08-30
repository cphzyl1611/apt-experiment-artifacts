# Production Source-Auth Normative Authority Design R1

Design-only governance artifact for the authenticated Current86 exact317 population. No authority root is frozen and no execution result is produced.

## Inputs and authentication

Target manifest SHA256: `d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac` (317 targets: 86 RAW, 231 CANDIDATE).

All input identities used by this design are recorded in `EXACT317_AUTHORITY_DESIGN_GROUPS.json` with direct SHA256 and byte length. GOV-R4, EXEC-R4, the source class/fact-type registry, V4 extraction schema lineage, Prompt 4 closure package, source-recovery lineage, C0 recovery bytes, raw registry, and scoring snapshot were inspected in read-only mode. Candidate corpora remain authenticated only for their declared noncanonical classes; C0 remains evidence-only.

## Exact structural groups

| Group | Side | Count | Structural candidate | Rule result |
|---|---:|---:|---|---|
| `RAW_REGISTRY_ONLY` | RAW | 26 | CAND-RAW-REGISTRY; cardinality 1 | NO deterministic production rule |
| `RAW_C0_EVIDENCE` | RAW | 60 | CAND-C0-TYPED-OPERATION-SEMANTICS; cardinality 1 | NO deterministic production rule |
| `CANDIDATE_SCORING` | CANDIDATE | 231 | CAND-CANDIDATE-SNAPSHOT; cardinality 1 | NO deterministic production rule |

The groups conserve exactly to the frozen manifest in manifest order: `26 + 60 + 231 = 317`. Grouping uses side, declared corpus/schema, exact locator, gap reason, and observed cardinality only. No semantic similarity, owner history, ranking, or model recommendation is used.

## Deterministic admission assessment

No proposed source-admission rule is emitted. Every observed candidate row lacks at least one authority-critical component: an authenticated canonical-intrinsic source manifest entry, a provenance-backed `candidate_object_id`, a canonical intrinsic semantics ID, or an exact RFC6901 pointer. The authenticated V4 extraction schema is a lineage rule for atomic fact shape, not a production admission rule. Promoting RAW, scoring, or C0 classes would violate the source class/fact-type registry.

Zero or multiple rows, conflicting identities, missing provenance, missing canonical objects, missing semantics, and missing pointers all fail closed. Alternate-pointer trial, ranking, nearest-neighbor matching, model judgment, historical owner substitution, and reviewer choice are prohibited.

## Field-pin design

No deterministic field-pin rule is emitted. GOV-R4 SA-B2 requires exactly one authenticated SA-B1 admission tuple first, and every field-pin tuple must equal that admission tuple byte-for-byte. Since no admission tuple or exact pointer exists, all 317 targets require later target-level field-pin governance after admission. No alternate pointer may be tried.

## Human governance packets

Three compact group packets are materialized in `HUMAN_GOVERNANCE_DECISION_PACKETS.jsonl`. Each packet names its exact target IDs, expansion-set commitment, input hashes, first/last examples, negative cases, and the only permitted actions:

- `APPROVE_EXACT_RULE_AS_PRODUCTION_AUTHORITY`
- `REJECT_RULE_KEEP_TARGETS_BLOCKED`
- `REQUEST_NARROWER_RULE_OR_MORE_EVIDENCE`

No default action is selected and no human action record is created.

## Workload and downstream dependencies

Schema-rule approval units = 0; exact-registry approval units = 0; target-level human admission units = 317; target-level human field-pin units = 317; unresolved source/provenance units = 317. The common-input freeze and runtime whitelist remain downstream mechanical dependencies. The future EXEC-R4 mapping contains no rule entries because no exact production IDs exist; it is explicitly non-executable and leaves EXEC-R4 untouched.

## Terminal

```text
PRODUCTION_NORMATIVE_AUTHORITY_DESIGN_R1 = READY_FOR_HUMAN_GOVERNANCE_REVIEW
EXACT317_TARGET_COUNT = 317
TARGET_CONSERVATION = PASS
SCHEMA_RULE_APPROVAL_UNITS = 0
EXACT_REGISTRY_APPROVAL_UNITS = 0
TARGET_LEVEL_HUMAN_ADMISSION_UNITS = 317
TARGET_LEVEL_HUMAN_FIELD_PIN_UNITS = 317
UNRESOLVED_SOURCE_OR_PROVENANCE_UNITS = 317
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
RAW_LEVEL_HUMAN_DECISIONS = 0
BINDING_PUBLICATION = NO
NEXT_ACTION =
FRESH_INDEPENDENT_REVIEW_OF_PRODUCTION_NORMATIVE_AUTHORITY_DESIGN_R1
STOP = true
```
