# Design FA1B2de Current86 Canonical Intrinsic 317 Source Authentication Governance R4 — PATCHED

Date: 2026-08-29  
Status: `DESIGN_ONLY_COMPLETE`  
Scope: `CURRENT86_CANONICAL_INTRINSIC_317_SOURCE_BINDING_RECONSTRUCTION_ONLY`  
Patch purpose: `MINIMAL_R3_TO_R4_DESIGN_ONLY_PATCH_OF_SA_B2_ADMISSION_FIELD_PIN_CROSS_BINDING_GAP`

## 0. Hard boundary

This document adds one fail-closed cross-binding from the already-authenticated SA-B1 admission tuple into SA-B2 field-pin authority selection. It does not redesign SA-B1 or SA-B3, add an independent semantic authority, change R2 §5.2–§5.4, execute source authentication, create a human decision, run Current86 P0/P1, publish a binding, alter accepted bindings, mutate scoring or binding authority, change a denominator, or mutate a Git ref.

## 1. Exact incorporated lineage and precedence

The reviewed R3 repository state is:

```text
REPOSITORY = cphzyl1611/apt-experiment-artifacts
R3_COMMIT = bc54c0feea1a8af346e2c70b39679cd01f4f3577
R3_TREE = d4c22f1e4310dc791e75fc15db4ba69c32e0997f
R3_PARENT = 38f913b52bcdcc289aa5507be0c6a67516d802f2
```

The exact incorporated R3 design is:

```text
current86-r4/fa1b2de-current86-canonical-source-authentication-governance-r3-patch/
Design_FA1B2de_Current86_Canonical_Intrinsic_317_Source_Authentication_Governance_R3_PATCHED.md

Git blob object = 05b41f34bcbab9d89e60d8ce8dc40966282eb737
content SHA256 = ca8f84d7a9f86713913a6c24960593a0b5771b04a920d2351290ae8d86d62d0f
```

R3 incorporates R2, and R2 incorporates R1, by their exact recorded hashes. R4 incorporates that complete lineage and replaces only these R3 elements:

- the entry condition for R3 §3 machine field-pin authority processing;
- the exact R3 §4 `NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF` schema and freshness rule;
- the exact R3 §5 `HUMAN_FIELD_PIN_GOVERNANCE_RECORD` schema, eligibility, and native-action constraint; and
- the R3 §6 state machine only to enforce admission-tuple equality.

All other R1/R2/R3 clauses remain normative and unchanged. In particular, R4 does not alter SA-B1 admission semantics, SA-B3 verifier isolation, or the inherited R2 §5.2–§5.4 rules for RFC 6901 traversal, duplicate keys, missing/null, scalar types, Unicode normalization `NONE`, canonical scalar envelope `FA1B2DE_CANONICAL_INTRINSIC_SCALAR_V1`, `authenticated_value_sha256`, and `field_pin_id`.

## 2. Mandatory authenticated admission input

Before any target enters field-pin authority processing, the machine MUST resolve exactly one authenticated SA-B1 `admission_record_id`. The record MUST authenticate under the incorporated SA-B1 predicate and bind exactly:

```text
source_binding_target_id
candidate_object_id
canonical_intrinsic_field_semantics_id
exact_RFC6901_pointer
```

Zero authenticated admission records, more than one authenticated admission record, a conflicting record, a stale record, or any record/target mismatch blocks field-pin processing. SA-B2 cannot repair, replace, or choose an SA-B1 admission.

The exact admission tuple is:

```text
admission_tuple =
(
  source_binding_target_id,
  candidate_object_id,
  canonical_intrinsic_field_semantics_id,
  exact_RFC6901_pointer
)
```

Its exact identity basis is this JSON object with exactly these four members and JSON types inherited from the authenticated admission record:

```json
{
  "candidate_object_id": "<exact candidate object ID>",
  "canonical_intrinsic_field_semantics_id": "<exact semantics ID>",
  "exact_RFC6901_pointer": "<exact pointer string>",
  "source_binding_target_id": "<exact target ID>"
}
```

Then:

```text
admission_tuple_id =
lowercase_hex(
  SHA256(
    PROJECT_CANONICAL_JSON_V1(exact admission tuple identity basis)
  )
)

admitted_exact_RFC6901_pointer_utf8_sha256 =
lowercase_hex(
  SHA256(exact strict UTF-8 bytes of admission_record.exact_RFC6901_pointer)
)
```

Pointer bytes use the unchanged R2 §5.2 decoding and Unicode-normalization policy. The admission record ID, tuple ID, and admitted-pointer hash are frozen in the field-pin derivation context before any machine authority or human-governance evaluation.

## 3. One tuple identity across admission and field pin

Every machine or human field-pin authority record emits one field-pin tuple using the same exact four-member identity basis and derivation as §2. Its identity is `selected_field_pin_tuple_id` after selection.

For every authority path, all of these predicates are mandatory before the pointer is authority-eligible:

```text
field_pin_tuple.source_binding_target_id
  == admission_tuple.source_binding_target_id

field_pin_tuple.candidate_object_id
  == admission_tuple.candidate_object_id

field_pin_tuple.canonical_intrinsic_field_semantics_id
  == admission_tuple.canonical_intrinsic_field_semantics_id

exact_UTF8(field_pin_tuple.exact_RFC6901_pointer)
  == exact_UTF8(admission_tuple.exact_RFC6901_pointer)

selected_field_pin_tuple_id
  == admission_tuple_id
```

The first three comparisons are exact identifier-byte equality. The pointer comparison is exact strict UTF-8 byte equality after JSON string parsing and before RFC 6901 traversal, with Unicode normalization `NONE`. Hash equality alone cannot substitute for the byte comparison; both byte equality and recomputed identity equality are required.

Any mismatch fails closed:

```text
target readiness state = BLOCKED_FIELD_PIN
reason = ADMISSION_FIELD_PIN_TUPLE_MISMATCH
alternate pointer attempt = PROHIBITED
human fallback = PROHIBITED
```

The mismatching tuple is not a candidate alternative and cannot change the SA-B1 admission tuple.

## 4. Cross-bound machine authority paths

The existing three machine field-pin authority paths remain the only machine paths:

1. exact pointer embedded in the exact target authority;
2. authenticated `FIELD_PIN_REGISTRY` exact tuple record;
3. authenticated deterministic corpus/schema rule expanding to an exact field-pin tuple.

They now act only as independent field-pin authority/confirmation for the exact already-admitted tuple. Every valid output for the current target is cross-checked under §3 before deduplication or selection.

If one or more machine paths emit the identical admitted tuple and no path emits a nonidentical tuple, identical emissions collapse to `admission_tuple_id`; `machine_valid_field_pin_tuple_count == 1`, and the machine tuple is used. Human fallback is forbidden.

If any authenticated machine path emits a nonidentical tuple for the current target—even when another path emits the admitted tuple—the result is `BLOCKED_FIELD_PIN` with reason `ADMISSION_FIELD_PIN_TUPLE_MISMATCH`. Human fallback is forbidden. The nonidentical tuple cannot be ranked, retried, substituted, or routed to human choice.

If multiple nonidentical machine tuples or another machine conflict exists, the existing conflict rule also yields `BLOCKED_FIELD_PIN`; human fallback remains forbidden.

Only when all three complete machine authority paths emit zero valid tuples for the current target, emit no nonidentical tuple, and have no conflict may the no-machine proof branch begin.

## 5. Cross-bound `NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF`

### 5.1 Extended exact schema

The R4 exact proof schema is the R3 exact schema with these three mandatory members added:

```text
admission_record_id
admission_tuple_id
admitted_exact_RFC6901_pointer_utf8_sha256
```

The complete exact schema therefore contains only:

```text
schema = FA1B2DE_CURRENT86_NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF_V2
audit_scope_id
exact_target_manifest_sha256
source_binding_target_id
candidate_object_id
canonical_intrinsic_field_semantics_id
admission_record_id
admission_tuple_id
admitted_exact_RFC6901_pointer_utf8_sha256
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
machine_admission_tuple_mismatch_count
machine_authority_evaluation_evidence_id
no_machine_field_pin_authority_proof_id
```

All tuple-ID arrays MUST be empty. All four valid counts, `machine_conflict_count`, and `machine_admission_tuple_mismatch_count` MUST equal integer zero. A missing or unevaluated machine authority is not zero evidence.

The proof ID remains the deterministic self-excluding canonical identity:

```text
no_machine_field_pin_authority_proof_id =
lowercase_hex(
  SHA256(
    PROJECT_CANONICAL_JSON_V1(
      all exact R4 proof members except no_machine_field_pin_authority_proof_id
    )
  )
)
```

### 5.2 Admission binding and freshness

The proof authenticates only if its `admission_record_id`, `admission_tuple_id`, admitted-pointer hash, target ID, candidate ID, and semantics ID equal the frozen §2 derivation context, and if the proof's zero counts and complete-input evaluation independently recompute.

Any change to the admission record ID or any admission tuple component—including an exact pointer-byte change—makes the proof stale. Any change to the machine authority input set or existing R3 freshness inputs also makes it stale. A stale proof cannot authorize human fallback and cannot be repaired by a human record.

This proof states that no separate machine field-pin authority exists for the exact already-admitted tuple; it does not permit a different tuple.

## 6. Cross-bound `HUMAN_FIELD_PIN_GOVERNANCE_RECORD`

### 6.1 Extended exact schema

The R4 exact human record schema is the R3 exact schema with these three mandatory members added:

```text
admission_record_id
admission_tuple_id
admitted_exact_RFC6901_pointer_utf8_sha256
```

The complete exact schema therefore contains only:

```text
schema = FA1B2DE_CURRENT86_HUMAN_FIELD_PIN_GOVERNANCE_RECORD_V2
audit_scope_id
source_binding_target_id
candidate_object_id
canonical_intrinsic_field_semantics_id
admission_record_id
admission_tuple_id
admitted_exact_RFC6901_pointer_utf8_sha256
exact_RFC6901_pointer
exact_RFC6901_pointer_utf8_sha256
no_machine_field_pin_authority_proof_id
human_native_decision_bytes_sha256
human_origin_provenance_mode
governance_event_id
independent_capture_verification_id
human_field_pin_governance_record_id
```

Its record ID remains the deterministic self-excluding canonical identity:

```text
human_field_pin_governance_record_id =
lowercase_hex(
  SHA256(
    PROJECT_CANONICAL_JSON_V1(
      all exact R4 human record members except human_field_pin_governance_record_id
    )
  )
)
```

Duplicate or unlisted members, wrong types, noncanonical serialization, or identity mismatch reject the record.

### 6.2 Ratification-only native action

The native human action is limited to confirming or declining the exact pointer already pre-bound by the authenticated SA-B1 admission record under the separate field-pin-governance role. The action MUST NOT select, edit, substitute, normalize, or propose a pointer.

Before the record is authority-eligible, the machine MUST prove:

```text
human_record.admission_record_id == frozen admission_record_id
human_record.admission_tuple_id == frozen admission_tuple_id
human_record.admitted_exact_RFC6901_pointer_utf8_sha256
  == frozen admitted_exact_RFC6901_pointer_utf8_sha256
exact_UTF8(human_record.exact_RFC6901_pointer)
  == exact_UTF8(admission_record.exact_RFC6901_pointer)
human_record.exact_RFC6901_pointer_utf8_sha256
  == admitted_exact_RFC6901_pointer_utf8_sha256
selected_field_pin_tuple_id == admission_tuple_id
```

The no-machine proof ID in the human record MUST identify the current proof cross-bound to the same admission record and tuple. The native-event bytes, governance event ID, and independent capture verification MUST bind the same pre-bound context and ratification-only role.

Any mismatch is `BLOCKED_FIELD_PIN` with reason `ADMISSION_FIELD_PIN_TUPLE_MISMATCH`. No alternate pointer may be tried.

Human governance cannot override machine authority, break a machine conflict, change the SA-B1 admission tuple, choose another target or candidate, choose another semantics ID or pointer, or alter source, scoring, relation, owner, binding, publication, or denominator semantics.

### 6.3 Authority eligibility is not field-pin authentication

An exactly cross-bound human record makes only the already-admitted pointer authority-eligible. It MUST still pass unchanged R2 §5.2 through §5.4 independently in primary and verifier before `FIELD_PIN_AUTHENTICATED` is possible.

## 7. Exact cross-bound state machine

The R3 state machine is narrowed to this exact sequence:

```text
authenticate exactly one SA-B1 admission record
derive and freeze admission_record_id
derive and freeze admission_tuple and admission_tuple_id
derive and freeze admitted_exact_RFC6901_pointer_utf8_sha256

evaluate all three complete machine field-pin authority paths
cross-check every current-target machine tuple against admission_tuple

if any machine tuple is nonidentical to admission_tuple:
    BLOCKED_FIELD_PIN(ADMISSION_FIELD_PIN_TUPLE_MISMATCH)
    human fallback forbidden
    no alternate pointer

else if machine conflict exists:
    BLOCKED_FIELD_PIN
    human fallback forbidden

else if machine_valid_field_pin_tuple_count == 1
     and selected_field_pin_tuple_id == admission_tuple_id:
    use the exact machine confirmation
    human fallback forbidden
    continue to unchanged R2 §5.2-§5.4

else if machine_valid_field_pin_tuple_count == 0:
    authenticate current NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF
    require proof admission_record_id, admission_tuple_id,
            and admitted pointer hash to equal frozen admission context
    set HUMAN_FIELD_PIN_GOVERNANCE_REQUIRED

    if exactly one authenticated, nonconflicting human record exists
       and all admission cross-bindings and pointer-byte equality pass:
        set selected_field_pin_tuple_id = admission_tuple_id
        continue to unchanged R2 §5.2-§5.4
    else:
        BLOCKED_FIELD_PIN

else:
    BLOCKED_FIELD_PIN
```

No branch may modify the admission tuple or try another pointer. The existing `field_pin_id` already binds `admission_record_id`; R4 makes the complete cross-component equality predicate in §§2–7 a mandatory precondition before that `field_pin_id` can authenticate.

## 8. Exact-317 conservation and unchanged authority

The frozen population remains:

```text
AUDIT_SCOPE_ID = 34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306
SOURCE_AUTH_TARGET_COUNT = 317
RAW_SIDE_TARGET_COUNT = 86
CANDIDATE_SIDE_TARGET_COUNT = 231
317 = 86 + 231
```

No target ID, ordering, side identity, source-class/fact-type authority, scoring authority, binding authority, accepted-binding count, denominator, or readiness-state vocabulary changes. A cross-binding failure retains the target as `BLOCKED_FIELD_PIN`; it never removes a target or raw.

The current design-only partition remains `NOT_EXECUTED_PENDING_SOURCE_AUTH_GOVERNANCE = 317`. No source-auth result, no-machine proof, human record, field pin, or human decision is created by this patch.

## 9. Required terminal status

```text
SOURCE_AUTH_GOVERNANCE_R4_PATCH_STATUS = DESIGN_ONLY_COMPLETE
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

NEXT_ACTION = FRESH_TARGETED_INDEPENDENT_REVIEW_OF_CURRENT86_EXACT317_SOURCE_AUTH_GOVERNANCE_R4
```

`CLOSED_CANDIDATE` is a design-review candidate only. It is not source-authentication execution, human adjudication, field-pin execution, source-fact materialization, or binding progress.
