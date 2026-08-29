# Design FA1B2de Current86 Canonical Intrinsic 317 Source Authentication Governance R2 — PATCHED

Date: 2026-08-29  
Status: `DESIGN_ONLY_COMPLETE`  
Scope: `CURRENT86_CANONICAL_INTRINSIC_317_SOURCE_BINDING_RECONSTRUCTION_ONLY`

## 0. Design-only boundary

This document is a narrow normative patch to the authenticated R1 design. It closes candidate design defects SA-B1, SA-B2, and SA-B3 only. It does not authenticate a source object, select a source field, create a source fact, run Current86 P0/P1, make an owner or binding decision, publish a binding, mutate scoring or binding authority, change the denominator, or change the accepted binding count.

The counting unit is not a raw. It is:

```text
UNIQUE_REQUIRED_CANONICAL_INTRINSIC_SOURCE_CLASS_SIDE_BINDING_TUPLE
```

The immutable population is:

```text
317 targets = 86 RAW-side targets + 231 CANDIDATE-side targets
```

## 1. Authenticated R1 basis and patch precedence

The R1 basis is exactly:

```text
/home/cph/experiment-artifacts/fa1b2de-current86-canonical-source-authentication-r1/
Design_FA1B2de_Current86_Canonical_Intrinsic_317_Source_Authentication_Governance.md
SHA256 = 185c1df2c1fa0e3e90060311c96e1aaf2ee606e2c04797b778be0d8f2d3e47c6
```

The exact target authority is exactly:

```text
/home/cph/experiment-artifacts/fa1b2de-current86-canonical-intrinsic-317-r1/
CURRENT86_Canonical_Intrinsic_317_Exact_Targets.json
SHA256 = d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac
audit_scope_id = 34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306
```

Its 317 target IDs, target ordering, target-side identities, and target-ID derivation are unchanged. The companion input-authentication artifact records the corresponding independent review and the existing source-class/fact-type and scoring/binding authorities.

This R2 document and the exact R1 document together form the patched design. Where this document explicitly says `REPLACES_R1`, this document controls. All other R1 clauses remain byte-preserved and normative. In particular, R1's already-reviewed exact-317 scope, authority separation, legal C0 role, and fail-closed rules are not redesigned.

The three replacements are:

- `REPLACES_R1 §4 candidate-to-canonical promotion predicate` with §4 below;
- `REPLACES_R1 §8 exact scalar field/pointer rule` with §5 below;
- `REPLACES_R1 fresh-independent-verifier prose in §§10, 15, and 16` with §6 below.

## 2. Normative vocabulary and canonical hash primitive

`PROJECT_CANONICAL_JSON_V1` means strict UTF-8 JSON, recursively sorted object member names by bytewise ascending UTF-8, preserved array order, and compact serialization without insignificant whitespace. Any JSON input containing a BOM, invalid UTF-8, an unpaired surrogate, a duplicate object member name at any nesting depth, or a non-JSON numeric token is rejected before canonicalization.

Unless a rule below specifies a domain-separated byte envelope, an identity is:

```text
lowercase_hex(SHA256(PROJECT_CANONICAL_JSON_V1(identity_basis_object)))
```

The identity basis never contains the identity field being derived. Every manifest and authority record is immutable, content-addressed, and frozen before either derivation process starts. A mutable path, filename, timestamp, occupancy, earlier outcome, or model statement is never an authority identity.

The following states are distinct:

- `SOURCE_CANDIDATE_BYTES_AUTHENTICATED`: artifact, locator, extraction, bytes, object representation, and provenance are mechanically authenticated;
- `SOURCE_OBJECT_AUTHENTICATED`: the exact candidate/target/semantics/pointer tuple is also normatively admitted under the canonical intrinsic source class;
- `FIELD_PIN_AUTHENTICATED`: the authority-pinned pointer resolves under §5 and the scalar commitment is valid;
- `SOURCE_AUTHENTICATED`: the complete independent comparison passes. This is readiness only, not a published source fact or binding.

## 3. Frozen pre-execution authority package

Before any future source-authentication run, an input-freeze transaction outside the primary and verifier contexts MUST freeze one `COMMON_INPUT_MANIFEST`. Its ID is the hash of its canonical content. Every entry contains at least:

```text
logical_artifact_id
authority_role
absolute_origin_locator
mounted_logical_path
sha256_or_explicit_pinned_identity
byte_length
media_type
schema_or_contract_id
provenance_id
read_mode = READ_ONLY
```

The manifest MUST include the exact target manifest, the existing source-class/fact-type registry, all candidate corpus artifacts and extraction schemas, every source-admission authority, every field-pin authority, this R2 design plus its exact R1 basis, and the deterministic runtime/tool whitelist. `authority_role` is normative and may not be inferred from content or location.

An authority artifact is `AUTHENTICATED_FROZEN_AUTHORITY` only when all of these hold:

1. its bytes and length equal its common-input entry;
2. its schema and self-excluding identity recompute exactly;
3. its `authority_role` is exactly the role consumed by the rule;
4. its provenance chain terminates in an explicit pre-run governance freeze record whose identity is also in the common input manifest;
5. that freeze record expressly authorizes the artifact for this audit scope and exact-317 target population; and
6. it was not created by the primary, verifier, comparator, a model assertion, or an execution result from this run.

Zero matching governance roots, more than one nonidentical root, a hash mismatch, a role mismatch, missing provenance, or a scope mismatch is fail-closed. This design does not create or activate any such authority.

## 4. SA-B1 — normative canonical-source admission (`REPLACES_R1 §4`)

### 4.1 Candidate object authentication

A candidate corpus is usable only when its authoritative artifact identity, exact bytes or pinned identity, extraction schema, and provenance are frozen in the common input manifest. Object locating and extraction MUST be deterministic.

Each extraction rule has a frozen `object_extraction_rule_id` and MUST define:

- the permitted media type;
- strict parser identity and options;
- the exact object locator syntax;
- locator resolution from the artifact root;
- the expected side-specific bound identity;
- zero-match and multiple-match behavior; and
- the exact returned byte span or parsed JSON node.

For JSON/JSONL, parsing uses §2. A locator MUST resolve exactly once. JSONL is split only on LF (`0x0a`); a final absent LF does not create another record; CR immediately before LF is part of the record and therefore makes strict JSON parsing fail unless the frozen parser rule explicitly consumes it as line termination. The extracted source row is represented as `PROJECT_CANONICAL_JSON_V1(parsed_object)`. No semantic normalization, field inference, row merging, or repair is allowed.

The candidate object identity is mechanically derived from:

```json
{
  "audit_scope_id": "<exact scope id>",
  "candidate_corpus_id": "<content-derived corpus id>",
  "source_artifact_identity": "<frozen artifact identity>",
  "source_artifact_sha256_or_pinned_identity": "<frozen identity>",
  "source_side": "RAW|CANDIDATE",
  "bound_raw_key": "<exact key or null>",
  "bound_candidate_scoring_id": "<exact id or null>",
  "object_locator": "<exact structured locator>",
  "object_locator_canonical_sha256": "<hash of canonical locator object>",
  "object_extraction_rule_id": "<frozen rule id>",
  "extracted_byte_span_sha256": "<hash>",
  "canonical_object_representation_sha256": "<hash>",
  "source_provenance_id": "<recomputed id>"
}
```

`candidate_object_id` is the identity of this canonical basis. Authentication passes only if all fields independently recompute, side and bound identity equal the exact target, the artifact and extraction rule authenticate, the locator resolves exactly once, and provenance passes. Otherwise the target becomes `BLOCKED_SOURCE_OBJECT` or `BLOCKED_PROVENANCE`; no candidate is guessed.

### 4.2 Smallest normative admission unit

The only normative canonical-admission decision unit is the exact tuple:

```text
(
  source_binding_target_id,
  candidate_object_id,
  canonical_intrinsic_field_semantics_id,
  exact_RFC6901_pointer
)
```

Canonical admission exists if and only if exactly one authenticated authority path below emits that exact tuple and no authenticated authority path emits a conflicting tuple for the target:

1. `SOURCE_ADMISSION_REGISTRY`: an authenticated frozen registry containing exact tuple records; or
2. `SOURCE_ADMISSION_CORPUS_SCHEMA_RULE`: an authenticated frozen deterministic corpus/schema rule whose complete expansion emits exact tuple records; or
3. `HUMAN_NORMATIVE_ADMISSION_RECORD`: an explicit, separately authenticated human governance record, permitted only when the machine proves that paths 1 and 2 emit zero tuples for that target.

Registry lookup and rule expansion are exact byte comparisons. A deterministic rule MUST pin its complete input artifact set, implementation-independent rule text/schema, expansion algorithm, output sort order, and expected expansion-set hash. A rule that requires a reviewer, producer, verifier, or model to choose among outputs is not deterministic and is rejected.

Every admitted tuple record includes:

```text
audit_scope_id
source_binding_target_id
candidate_object_id
canonical_intrinsic_field_semantics_id
exact_RFC6901_pointer_utf8_sha256
exact_RFC6901_pointer
admission_authority_type
admission_authority_artifact_id
admission_authority_sha256_or_pinned_identity
admission_authority_provenance_id
admission_record_id
```

`admission_record_id` is the canonical identity of all preceding fields. A human record additionally binds the no-machine-rule proof ID, exact native decision bytes, human-origin provenance mode, governance event identity, and independent capture-verification identity. It is not an owner adjudication and cannot contain an owner or binding disposition.

The admission predicate is:

```text
candidate_bytes_authenticate
AND target_membership_is_exact
AND authority_artifact_authenticates
AND authority_expansion_or_lookup_recomputes
AND exact_admission_tuple_count_for_target == 1
AND no_conflicting_authenticated_tuple_exists
AND source_class == AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE
AND source_fact_type == PINNED_CANONICAL_INTRINSIC_FIELD
```

If the tuple count is zero, the result is `BLOCKED_NORMATIVE_ADMISSION`. If the count exceeds one or any tuple component conflicts, it is `BLOCKED_NORMATIVE_ADMISSION` with reason `AMBIGUOUS_OR_CONFLICTING_ADMISSION`. Candidate byte equality, hashes, provenance, corpus membership, occupancy, similarity, a prior owner, a prior disposition/relation outcome, and model assertions may locate or verify evidence but cannot satisfy this predicate.

### 4.3 Exact 60 C0-covered RAW targets

The R1 C0 identity anchors and exact 60-target membership remain evidence only. For each of those exact targets, the machine applies this frozen branch with no heuristic tie-break:

```text
expand authenticated SOURCE_ADMISSION_REGISTRY entries
union authenticated SOURCE_ADMISSION_CORPUS_SCHEMA_RULE entries
filter by exact target ID and exact four-component tuple
if exactly one nonconflicting tuple exists:
    use that exact candidate object and pointer
else if zero tuples exist:
    emit HUMAN_NORMATIVE_ADMISSION_REQUIRED
    accept only a later authenticated HUMAN_NORMATIVE_ADMISSION_RECORD
else:
    BLOCKED_NORMATIVE_ADMISSION(AMBIGUOUS_OR_CONFLICTING_ADMISSION)
```

The raw-candidate object and C0-candidate object have no default priority. Byte equality does not collapse their identities or choose one. Until an authenticated authority selects one exact tuple, the target remains unresolved. This R2 patch performs zero such human decisions.

## 5. SA-B2 — exact field pin and scalar canonicalization (`REPLACES_R1 §8`)

### 5.1 Field-pin authority

The exact pointer MUST be frozen by exactly one nonconflicting authenticated source:

1. an exact pointer embedded in the exact target authority;
2. an authenticated `FIELD_PIN_REGISTRY` exact tuple record; or
3. an authenticated deterministic corpus/schema rule that expands to an exact field-pin tuple.

If multiple sources exist, their decoded pointer bytes, semantics ID, candidate object ID, and target ID MUST be identical. Producer/verifier agreement is evidence of reproducibility, not authority. A pointer proposed in a run package, selected by a reviewer or model, inferred from a field name, or discovered by similarity is inadmissible.

If no unique authoritative pointer can be mechanically resolved:

```text
FIELD_PIN_AUTHENTICATION = BLOCKED
target readiness state = BLOCKED_FIELD_PIN
```

### 5.2 Exact RFC 6901 pointer bytes and traversal

The authority artifact contains the pointer as a JSON string. `exact_RFC6901_pointer_bytes` is the strict UTF-8 encoding of the parsed JSON string, with Unicode normalization set to `NONE`. The bytes are not case-folded, NFC/NFD-normalized, percent-decoded, or re-escaped.

Validation and evaluation are exact:

- the empty pointer is permitted only when the authenticated schema rule explicitly authorizes a scalar root;
- a nonempty pointer begins with the single byte `/`;
- each reference token is split on `/` before tilde unescaping;
- each `~` MUST be followed by `0` or `1`; decode `~1` to `/` and `~0` to `~` exactly once; every other tilde form is invalid;
- wildcards, URI-fragment form, relative pointers, negative indices, `-`, and implicit alternate paths are prohibited;
- at an object, a token matches one exact parsed member name by Unicode scalar sequence, with no normalization or case folding;
- at an array, a token MUST match `0|[1-9][0-9]*`, is interpreted as an arbitrary-precision nonnegative base-10 integer, and MUST be in bounds; leading zeros are invalid except for `0`;
- encountering a scalar before the final token, a missing member/index, or more than one result blocks the field pin.

Missing and null are different. Missing is `BLOCKED_FIELD_PIN`. JSON null is an allowed scalar with the `null` encoding below. Duplicate JSON keys at any nesting depth reject the complete candidate source object before pointer traversal.

Objects and arrays may be traversed but are not scalar fact values. A composite terminal value is allowed only if the authenticated field-pin authority also pins `value_kind=COMPOSITE` and a separately authenticated deterministic composite canonicalizer ID. This R2 contract whitelists no composite canonicalizer; therefore every object or array terminal value is `BLOCKED_FIELD_PIN`.

### 5.3 Scalar types and lexical policy

Allowed terminal values are JSON null, boolean, integer, and string.

- Null has type tag `null` and an empty payload.
- Boolean has type tag `boolean` and payload ASCII `true` or `false`.
- Integer source tokens MUST match `0|-?[1-9][0-9]*`. `-0`, fraction syntax, and exponent syntax are rejected. Integers are arbitrary precision; the canonical payload is the minimal base-10 ASCII token with no plus sign or leading zero.
- String decoding uses strict JSON escapes and strict UTF-8. BOM, invalid UTF-8, non-scalar Unicode, and unpaired surrogate escapes are rejected. Unicode normalization is `NONE`; the canonical payload is the exact UTF-8 encoding of the parsed Unicode scalar sequence.
- All floating-point tokens are rejected, including syntactically valid fractional/exponent JSON numbers. NaN, Infinity, `-Infinity`, and every other non-finite token are rejected by strict JSON parsing.

### 5.4 Canonical scalar byte encoding and value hash

Let `payload` be the bytes defined above and `payload_length` be its nonnegative byte count encoded as minimal ASCII base 10. The canonical scalar bytes are exactly:

```text
ASCII("FA1B2DE_CANONICAL_INTRINSIC_SCALAR_V1")
|| 0x00
|| ASCII(type_tag)
|| 0x00
|| ASCII(payload_length)
|| 0x00
|| payload
```

Then:

```text
authenticated_value_sha256 = lowercase_hex(SHA256(canonical_scalar_bytes))
```

This definition is independent of host integer width, locale, JSON serializer, and Unicode-normalization library.

The field-pin record binds the exact scope ID, target ID, candidate object ID, admission record ID, semantics ID, pointer bytes and their SHA256, parsed scalar type, canonical-scalar format ID, `authenticated_value_sha256`, and provenance ID. `field_pin_id` is the canonical identity of that complete self-excluding record. Any mismatch is `BLOCKED_FIELD_PIN`; no alternate pointer or value is tried.

## 6. SA-B3 — mechanically enforceable independent verifier isolation

### 6.1 Frozen filesystem and readable sets

Every future run contract MUST instantiate separate OS processes and mount namespaces with these exact logical roots:

| Logical root | Primary | Verifier | Comparator |
|---|---:|---:|---:|
| `/sa/common` | read-only | read-only | read-only |
| `/sa/runtime-primary` | read-only | absent | absent |
| `/sa/runtime-verifier` | absent | read-only | absent |
| `/sa/primary-private` | read-write | absent | absent |
| `/sa/verifier-private` | absent | read-write | absent |
| `/sa/commitments/primary` | write-only freeze handoff | absent | read-only after both runs |
| `/sa/commitments/verifier` | absent | write-only freeze handoff | read-only after both runs |
| `/sa/compare` | absent | absent | read-write |

The working directories are exactly `/work/primary`, `/work/verifier`, and `/work/compare`, each private to its process. No host workspace, parent directory, user home, shared temporary directory, prior run directory, `/proc` entry for another role, debug channel, clipboard, IPC endpoint, or inherited file descriptor is visible.

The frozen sets are content identities, not merely path strings:

```text
COMMON_INPUT_SET = entries mounted below /sa/common
PRIMARY_PRIVATE_OUTPUT_SET = every inode/content identity writable or emitted by primary,
                             including its commitment and logs
VERIFIER_READABLE_SET = COMMON_INPUT_SET union VERIFIER_RUNTIME_SET
```

The mandatory predicate is:

```text
VERIFIER_READABLE_SET ∩ PRIMARY_PRIVATE_OUTPUT_SET = ∅
```

It is checked after resolving symlinks, hard links, bind mounts, device nodes, open descriptors, IPC handles, and content-address aliases. Symlinks and hard links crossing set boundaries, device mounts, FUSE mounts, writable common inputs, and unlisted descriptors fail isolation.

The common input set contains no primary-selected source object, selected pointer, rationale, ranking, admission conclusion, intermediate output, result vector, audit log, or commitment. Source corpora and normative authority artifacts are common inputs; a selection made from them is not.

### 6.2 Runtime, implementation, context, and run identities

The common input manifest freezes the operating-system/container image digest, executable hashes, interpreter/compiler hashes, library/lockfile hashes, locale database hash, parser and hash-tool identities, and the shared deterministic tool whitelist. Role-specific implementations are frozen separately:

```text
PRIMARY_IMPLEMENTATION_ID  = hash(primary executable + source + dependencies + build recipe)
VERIFIER_IMPLEMENTATION_ID = hash(verifier executable + source + dependencies + build recipe)
PRIMARY_IMPLEMENTATION_ID != VERIFIER_IMPLEMENTATION_ID
```

A shared runtime/tool may appear in both contexts only when its exact content identity is in the deterministic shared-runtime whitelist and it does not encode role outputs. The source-authentication derivation implementation itself is never a shared-whitelist item. A single executable with a role flag does not satisfy the inequality.

Each context identity is the canonical hash of role, mount-namespace identity, readable content-identity set, writable roots, runtime/tool identities, exact environment, network policy, UID/GID, umask, current directory, argv, inherited-descriptor set, and process-launch contract:

```text
PRIMARY_CONTEXT_ID != VERIFIER_CONTEXT_ID
```

Each run ID binds role, context ID, implementation ID, common-input-set ID, fresh OS process identity, launch nonce from the frozen orchestrator record, and start-event identity. Primary and verifier run IDs MUST differ. The same process, implementation, context, writable root, or launch record cannot manufacture both roles; any equality fails `INDEPENDENT_VERIFICATION`.

### 6.3 Environment, network, and invocation contract

Both processes start from an empty environment and receive only an exact frozen allowlist such as `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, `TZ=UTC`, and a content-pinned `PATH`. No `HOME`, proxy, credential, API key, session, model, editor, or host-language startup variable is present. Temporary storage is private to the role.

Network access is disabled by a distinct network namespace with no external interface or route; loopback is down. Capabilities are dropped, `no_new_privs` is set, and the frozen syscall policy prohibits networking, mounting, ptrace, and cross-process inspection. Any network-capable exception requires a new reviewed contract and is not authorized here.

Process invocation uses an exact frozen argv array with no shell evaluation, exact working directory, exact UID/GID, `umask 077`, closed inherited descriptors except standard streams bound to role-private audit files, and a frozen resource-limit profile. Exit other than zero or any undeclared read/write is failure.

### 6.4 Required audit evidence

The isolation auditor, separate from both derivations, records and hashes:

- common, runtime, readable, and private-output manifests with path, inode/content identity, byte length, mode, and SHA256;
- executable, source, dependency, container/OS, parser, locale, and hash-tool identities;
- PID/process tree, user and mount/network namespace IDs, UID/GID, capabilities, syscall-policy ID, umask, cwd, argv, environment, resource limits, and inherited descriptors;
- resolved mount table and symlink/hard-link/device checks;
- file-open audit proving every read is a member of the role's readable set and every write is role-private or its one-way commitment handoff;
- network namespace/interface/route audit proving the frozen policy;
- launch, exit, freeze, and compare event order, exit status, and immutable output manifests.

`isolation_audit_id` is the canonical identity of this evidence. Missing or internally inconsistent evidence is `BLOCKED_INDEPENDENT_VERIFICATION`.

### 6.5 Freeze/derive/commit/compare sequence

The only valid sequence is:

```text
1. freeze COMMON_INPUT_SET and all contracts
2. isolated primary derives its complete 317-result vector
3. freeze primary private output manifest and PRIMARY_COMMITMENT
4. tear down primary; do not mount its outputs or commitment for verifier
5. isolated verifier independently derives its complete 317-result vector
6. freeze verifier private output manifest and VERIFIER_COMMITMENT
7. attest both commitments existed and were immutable before comparator launch
8. launch comparator, which may now read both commitments and common-input identity
9. freeze COMPARISON_COMMITMENT and conservation audit
```

Neither derivation sees the other's commitment. The verifier independently derives candidate/source/pointer/admission/value/status results from the same frozen common input; it does not validate a primary proposal.

Each role commitment contains exactly: schema ID, role, common-input-set ID, implementation ID, context ID, run ID, isolation-audit ID, ordered result-vector SHA256, exact terminal-state count map, exact target-ID-set SHA256, and private-output-manifest SHA256. Its commitment ID is the canonical identity of these self-excluding fields. A commitment contains no rationale or uncommitted mutable locator.

The comparator checks all frozen identities, isolation predicates, event order, 317 target IDs in manifest order, exact tuple/value/status equality, exact-one terminal state, and conservation. It cannot repair, select, rerun, or break a tie. Any mismatch yields `BLOCKED_INDEPENDENT_VERIFICATION` for every affected target and no authenticated result is admitted.

## 7. Exact-317 conservation

The exact manifest is immutable:

```text
SOURCE_AUTH_TARGET_COUNT = 317
RAW_SIDE_TARGET_COUNT = 86
CANDIDATE_SIDE_TARGET_COUNT = 231
raw binding identity-set SHA256 = dc97465eba0d2fb1235cb93e47d8be57221b85c4a75c24b5f34c087ed379a4ed
candidate binding identity-set SHA256 = 3f70daaecfae52ea24bcef669d00e0ec788f88000da31e07c28db866826780c1
```

For an execution snapshot, every target ID MUST occur exactly once in exactly one terminal readiness state:

```text
SOURCE_AUTHENTICATED
BLOCKED_NORMATIVE_ADMISSION
BLOCKED_SOURCE_OBJECT
BLOCKED_FIELD_PIN
BLOCKED_PROVENANCE
BLOCKED_INDEPENDENT_VERIFICATION
```

The required equation is:

```text
count(SOURCE_AUTHENTICATED)
+ count(BLOCKED_NORMATIVE_ADMISSION)
+ count(BLOCKED_SOURCE_OBJECT)
+ count(BLOCKED_FIELD_PIN)
+ count(BLOCKED_PROVENANCE)
+ count(BLOCKED_INDEPENDENT_VERIFICATION)
= 317
```

Before execution, the separate design-snapshot state is `NOT_EXECUTED_PENDING_SOURCE_AUTH_GOVERNANCE = 317`; it is not an execution result. An execution atomically replaces that design-snapshot state with one of the six terminal readiness states for every target. No partial publication is allowed.

Side counts, target IDs, target ordering, audit scope ID, and identity-set hashes MUST remain exact. A failure preserves its target as blocked; it never deletes a raw, target, relation, or binding-denominator member. Downstream-only unresolved raws are outside this source-auth target population and cannot be inserted.

## 8. Human/machine boundary

Machines locate artifacts, authenticate hashes, apply deterministic extraction, expand admission and field-pin authorities, canonicalize values, build provenance, independently derive results, compare commitments, prove conservation, and construct audit packages.

Human governance is permitted only for an exact target whose machine-verifiable proof shows no authenticated registry or deterministic authority rule can decide the normative admission or field mapping. The human record is one exact admission or field-pin governance record, not a review of all 317 targets and not an owner adjudication. No human decision is performed by this design patch.

## 9. Required terminal status

```text
SOURCE_AUTH_GOVERNANCE_R2_PATCH_STATUS = DESIGN_ONLY_COMPLETE
EXACT317_SCOPE = PASS
SA_B1_NORMATIVE_SOURCE_OBJECT_ADMISSION = CLOSED_CANDIDATE
SA_B2_EXACT_FIELD_PIN_AND_CANONICALIZATION = CLOSED_CANDIDATE
SA_B3_INDEPENDENT_VERIFIER_ISOLATION = CLOSED_CANDIDATE

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

NEXT_ACTION = FRESH_TARGETED_INDEPENDENT_REVIEW_OF_CURRENT86_EXACT317_SOURCE_AUTH_GOVERNANCE_R2
```

`CLOSED_CANDIDATE` is a design-review candidate only. It is not source-authentication progress, an execution result, or binding progress.
