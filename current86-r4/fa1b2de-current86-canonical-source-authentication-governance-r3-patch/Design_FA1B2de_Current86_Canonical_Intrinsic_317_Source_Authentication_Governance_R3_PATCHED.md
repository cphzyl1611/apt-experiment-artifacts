# Design FA1B2de Current86 Canonical Intrinsic 317 Source Authentication Governance R3 — PATCHED

Date: 2026-08-29  
Status: `DESIGN_ONLY_COMPLETE`  
Scope: `CURRENT86_CANONICAL_INTRINSIC_317_SOURCE_BINDING_RECONSTRUCTION_ONLY`  
Patch purpose: `MINIMAL_R2_TO_R3_DESIGN_ONLY_PATCH_OF_SA_B2_HUMAN_FIELD_PIN_AUTHORITY_GAP`

## 0. Hard boundary

This document closes one design-level authority-path gap in R2 §5.1. It does not execute source authentication, create a source fact, create a human governance decision, run Current86 P0/P1, publish a binding, change accepted bindings, mutate scoring or binding authority, change a denominator, or mutate a Git ref.

It does not redesign SA-B1 or SA-B3. It does not change any R2 scalar canonicalization rule.

## 1. Exact incorporated lineage and precedence

The reviewed repository state is frozen as:

```text
REPOSITORY = cphzyl1611/apt-experiment-artifacts
REVIEWED_COMMIT = 38f913b52bcdcc289aa5507be0c6a67516d802f2
REVIEWED_TREE = 2540105e5adf477f7bfb168e5d7d21d4b4296071
```

The incorporated R2 design is the exact blob at:

```text
current86-r4/fa1b2de-current86-canonical-source-authentication-governance-r2-patch/
Design_FA1B2de_Current86_Canonical_Intrinsic_317_Source_Authentication_Governance_R2_PATCHED.md

Git blob object = d48f940ee68185e0219434e7f35b2d52ebf6749d
content SHA256 = e71bd2272438bff2feed4eef889f9a3fc9a231621826b7dae6ba3a2d25833c4b
```

R2 itself incorporates the exact R1 design by SHA256 `185c1df2c1fa0e3e90060311c96e1aaf2ee606e2c04797b778be0d8f2d3e47c6`.

This R3 design incorporates R1+R2 by those exact identities. R3 replaces only R2 §5.1, `Field-pin authority`, with §3 through §7 below and narrows the corresponding human-field-mapping sentence in R2 §8 to the same rules. Every other R1/R2 clause remains normative and unchanged.

Specifically preserved without modification:

- SA-B1 normative source-object admission;
- R2 §5.2 RFC 6901 pointer bytes and traversal, including Unicode normalization `NONE`;
- R2 §5.3 scalar types and lexical policy;
- R2 §5.4 canonical scalar byte encoding `FA1B2DE_CANONICAL_INTRINSIC_SCALAR_V1`, `authenticated_value_sha256`, and `field_pin_id`;
- SA-B3 independent-verifier isolation;
- exact-317 population, side partition, ordering, identities, authorities, and all fail-closed boundaries.

## 2. Review defect accepted for this patch

The reviewed R2 §5.1 contains three machine field-pin authority paths, while R2 §8 permits last-resort human field mapping. R2 defines no normative record by which that human mapping can become authority-eligible. R3 adds exactly one fourth path:

```text
HUMAN_FIELD_PIN_GOVERNANCE_RECORD
```

It is unavailable unless an exact, frozen, machine-verifiable `NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF` passes. It is never a tie breaker or override.

## 3. Machine field-pin authority set

The machine MUST evaluate all three R2 machine paths before human governance is eligible:

1. exact pointer embedded in the exact target authority;
2. authenticated `FIELD_PIN_REGISTRY` exact tuple record;
3. authenticated deterministic corpus/schema rule expanding to an exact field-pin tuple.

The field-pin tuple is exactly:

```text
(
  source_binding_target_id,
  candidate_object_id,
  canonical_intrinsic_field_semantics_id,
  exact_RFC6901_pointer
)
```

For each path, the evaluator authenticates the complete frozen authority input set, expands or looks up all records, validates scope and tuple components, and sorts valid tuple IDs by `BYTEWISE_ASCENDING_UTF8`. Identical tuple values emitted by multiple authenticated machine sources collapse to one tuple ID; any nonidentical tuple component for the same target is a conflict. `machine_valid_field_pin_tuple_count` is the cardinality of this deduplicated exact tuple-ID set.

The machine authority input set is immutable and complete:

```text
MACHINE_FIELD_PIN_AUTHORITY_INPUT_SET =
  exact target authority inputs
  union FIELD_PIN_REGISTRY inputs
  union deterministic corpus/schema-rule inputs
```

`machine_field_pin_authority_input_set_id` is the self-excluding `PROJECT_CANONICAL_JSON_V1` identity of the ordered artifact records, each binding logical artifact ID, authority role, SHA256 or pinned identity, byte length, schema/rule ID, provenance ID, and common-input membership. Human records and no-machine proofs are excluded from this set, avoiding circular derivation.

## 4. `NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF`

### 4.1 Exact proof record

A proof is valid only when all three machine paths have zero valid tuples. Its exact schema contains only these members:

```text
schema = FA1B2DE_CURRENT86_NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF_V1
audit_scope_id
exact_target_manifest_sha256
source_binding_target_id
candidate_object_id
canonical_intrinsic_field_semantics_id
machine_field_pin_authority_input_set_id
exact_target_pointer_authority_set_id
field_pin_registry_authority_set_id
deterministic_corpus_schema_rule_authority_set_id
field_pin_authority_evaluation_contract_id
exact_target_valid_tuple_ids
field_pin_registry_valid_tuple_ids
deterministic_corpus_schema_rule_valid_tuple_ids
machine_valid_field_pin_tuple_ids
valid_exact_target_pointer_authority_count
valid_field_pin_registry_tuple_count
valid_deterministic_corpus_schema_rule_tuple_count
machine_valid_field_pin_tuple_count
machine_conflict_count
machine_authority_evaluation_evidence_id
no_machine_field_pin_authority_proof_id
```

All four tuple-ID arrays MUST be empty, all four valid counts MUST equal integer zero, and `machine_conflict_count` MUST equal integer zero. The evaluation evidence binds the complete input-open audit, authority authentication results, deterministic expansion outputs, rejected-record reason codes, and ordered set commitments. A missing, unread, unauthenticated, or unevaluated machine authority is not zero evidence and cannot produce this proof.

### 4.2 Deterministic identity

The proof ID is exactly:

```text
no_machine_field_pin_authority_proof_id =
lowercase_hex(
  SHA256(
    PROJECT_CANONICAL_JSON_V1(
      all exact proof members except no_machine_field_pin_authority_proof_id
    )
  )
)
```

Object keys use the inherited bytewise UTF-8 sorting rule; array order is preserved and already required to be bytewise tuple-ID order. Duplicate keys, unlisted keys, wrong JSON types, a noncanonical serialization, or an identity mismatch reject the proof.

### 4.3 Freshness and exact binding

The proof is current only when its scope, target manifest, target ID, candidate object ID, semantics ID, machine authority input-set ID, evaluation-contract ID, and evaluation-evidence ID exactly equal those consumed by the pending field-pin derivation. Any authority artifact addition, removal, replacement, hash change, registry change, deterministic-rule change, target/candidate/semantics change, or evaluation-contract change makes the proof stale.

A stale proof cannot be refreshed by a human record. The machine MUST reevaluate all three authority paths and derive a new proof. A proof with any valid tuple or conflict is invalid rather than a human-governance ticket.

## 5. `HUMAN_FIELD_PIN_GOVERNANCE_RECORD`

### 5.1 Eligibility

The fourth authority path is eligible only when the exact proof in §4 authenticates. The human field-pin record is then a last-resort normative field mapping for one exact target/candidate/semantics tuple. It does not authenticate the source object, scalar value, source fact, owner, relation, score, or binding.

The native human action supplies only the intended exact RFC 6901 pointer for the pre-bound target/candidate/semantics context. Machines precompute and display the immutable context, capture the native event, compute all hashes and IDs, validate provenance, and build the record. Humans do not transcribe target IDs, candidate IDs, semantics IDs, hashes, provenance IDs, or governance metadata.

### 5.2 Exact record schema

The exact record contains only these members:

```text
schema = FA1B2DE_CURRENT86_HUMAN_FIELD_PIN_GOVERNANCE_RECORD_V1
audit_scope_id
source_binding_target_id
candidate_object_id
canonical_intrinsic_field_semantics_id
exact_RFC6901_pointer
exact_RFC6901_pointer_utf8_sha256
no_machine_field_pin_authority_proof_id
human_native_decision_bytes_sha256
human_origin_provenance_mode
governance_event_id
independent_capture_verification_id
human_field_pin_governance_record_id
```

`exact_RFC6901_pointer_utf8_sha256` is the lowercase SHA256 of the exact strict UTF-8 pointer bytes defined by unchanged R2 §5.2. `human_native_decision_bytes_sha256` binds the exact native event bytes. `human_origin_provenance_mode` MUST equal one exact allowed mode in the frozen governance input. `governance_event_id` MUST bind the native event, event role, frozen target/candidate/semantics context, and event provenance. `independent_capture_verification_id` MUST bind an independently produced verification of exact event bytes, human origin, context equality, and capture integrity.

The native decision event schema permits only an exact pointer selection/confirmation for the pre-bound context. It cannot carry an owner, owner decision, relation outcome, binding disposition, scoring correction, authority mutation, publication instruction, or denominator instruction.

The record ID is exactly:

```text
human_field_pin_governance_record_id =
lowercase_hex(
  SHA256(
    PROJECT_CANONICAL_JSON_V1(
      all exact human record members except human_field_pin_governance_record_id
    )
  )
)
```

Duplicate or unlisted members, wrong types, noncanonical serialization, or an identity mismatch reject the record. The record schema and its native decision semantics MUST NOT contain or authorize:

```text
owner
owner decision
relation outcome
binding disposition
scoring correction
scoring authority mutation
binding authority mutation
publication
denominator change
```

### 5.3 Authentication predicate

A human record is authenticated only when all conditions hold:

```text
record schema and self-excluding identity recompute
AND audit_scope_id equals the exact Current86 audit scope
AND target/candidate/semantics equal the no-machine proof
AND pointer UTF-8 hash recomputes
AND no-machine proof authenticates and is current
AND native decision bytes hash recomputes
AND human-origin provenance mode is frozen and allowed
AND governance event ID recomputes
AND independent capture verification authenticates
AND no prohibited field or semantic authorization exists
AND the record is frozen in COMMON_INPUT_SET before primary/verifier derivation
```

This record makes its exact pointer authority-eligible only. The pointer and resolved scalar MUST still pass unchanged R2 §5.2 through §5.4 independently in primary and verifier before `FIELD_PIN_AUTHENTICATED` is possible.

## 6. Exact authority-selection state machine

The evaluator MUST execute this state machine without reviewer, producer, verifier, or model discretion:

```text
evaluate all three frozen machine authority paths
derive deduplicated machine_valid_field_pin_tuple_ids
derive machine conflicts

if machine_valid_field_pin_tuple_count == 1 and machine_conflict_count == 0:
    select the one machine-authorized exact tuple
    set human_field_pin_authority_eligible = false
    do not consume any human field-pin record
    continue to unchanged R2 §5.2-§5.4

else if machine_valid_field_pin_tuple_count > 1
     or machine_conflict_count > 0:
    set target readiness state = BLOCKED_FIELD_PIN
    set human_field_pin_authority_eligible = false
    human fallback is forbidden

else if machine_valid_field_pin_tuple_count == 0
     and machine_conflict_count == 0:
    require one current NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF
    set HUMAN_FIELD_PIN_GOVERNANCE_REQUIRED

    if exactly one authenticated, nonconflicting
       HUMAN_FIELD_PIN_GOVERNANCE_RECORD occurrence exists
       and it binds the exact proof and exact target/candidate/semantics tuple:
        make its pointer authority-eligible
        continue to unchanged R2 §5.2-§5.4
    else:
        set target readiness state = BLOCKED_FIELD_PIN
```

An unnecessary human record present when a machine tuple exists is non-authoritative and cannot be consumed. It cannot override, alter, or block the selected machine tuple. A human record is never used when machine authorities conflict.

In the zero-machine branch, each of these independently yields `BLOCKED_FIELD_PIN`:

- missing, invalid, or stale no-machine proof;
- zero human records;
- multiple human record occurrences or identities;
- conflicting human records;
- wrong scope, target, candidate, or semantics;
- pointer/hash mismatch;
- invalid human-origin provenance or governance event;
- missing or failed independent capture verification;
- a prohibited field or prohibited semantic authorization; or
- failure under unchanged R2 §5.2, §5.3, or §5.4.

No alternate pointer is tried after failure.

## 7. Human workload and machine responsibilities

Machine authority paths 1 through 3 are always evaluated first for every target. A human-governance task may be emitted only for a target carrying a valid, current zero-machine-authority proof. No bulk conversion of the exact-317 population to manual review is allowed.

One native human action produces at most one exact field-pin governance record for one target/candidate/semantics tuple. Machines perform artifact and hash authentication, tuple expansion, zero-authority proof construction, metadata binding, native-event capture, provenance construction, independent capture verification, canonical identities, pointer/value validation, conservation, and audit packaging.

This design produces zero human actions and zero human records.

## 8. Exact-317 conservation and unchanged authorities

The frozen population remains:

```text
AUDIT_SCOPE_ID = 34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306
SOURCE_AUTH_TARGET_COUNT = 317
RAW_SIDE_TARGET_COUNT = 86
CANDIDATE_SIDE_TARGET_COUNT = 231
317 = 86 + 231
```

Target IDs, target ordering, RAW/CANDIDATE side identities, source-class/fact-type authority, readiness-state vocabulary, accepted bindings, denominator, scoring authority, and binding authority are unchanged. Failure to obtain or validate a human field pin retains the target as `BLOCKED_FIELD_PIN`; it never removes a target or raw.

The current design-only partition remains `NOT_EXECUTED_PENDING_SOURCE_AUTH_GOVERNANCE = 317`. No source-auth terminal result is asserted.

## 9. Required terminal status

```text
SOURCE_AUTH_GOVERNANCE_R3_PATCH_STATUS = DESIGN_ONLY_COMPLETE
EXACT317_SCOPE = PASS
SA_B1_NORMATIVE_SOURCE_OBJECT_ADMISSION = PASS_PRESERVED
SA_B2_EXACT_FIELD_PIN_AND_CANONICALIZATION = CLOSED_CANDIDATE
SA_B3_INDEPENDENT_VERIFIER_ISOLATION = PASS_PRESERVED

SOURCE_AUTH_TARGET_COUNT = 317
RAW_SIDE_TARGET_COUNT = 86
CANDIDATE_SIDE_TARGET_COUNT = 231

SOURCE_AUTH_EXECUTED = NO
CURRENT86_P0_EXECUTED = NO
CURRENT86_P1_EXECUTED = NO
RAW_LEVEL_HUMAN_DECISIONS = 0
BINDING_PUBLICATION = NO
SCORING_AUTHORITY_MUTATION = NO
BINDING_AUTHORITY_MUTATION = NO
DENOMINATOR_CHANGE = NO
ACCEPTED_BINDING_COUNT_CHANGE = NO
GIT_REF_MUTATION = NO

NEXT_ACTION = FRESH_TARGETED_INDEPENDENT_REVIEW_OF_CURRENT86_EXACT317_SOURCE_AUTH_GOVERNANCE_R3
```

`CLOSED_CANDIDATE` is a design-review candidate only. It is not source-authentication, human adjudication, field-pin execution, source-fact materialization, or binding progress.
