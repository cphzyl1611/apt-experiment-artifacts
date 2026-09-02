# Binding Authoritative Canonical Field-Mapping Evidence Design

## Purpose

The frozen first tranche contains 24 exact targets, all currently decided as `REQUEST_MORE_EVIDENCE`. Their R8 packets expose only multiple candidate pointers from `CANDIDATE`-side scoring rows. The common blocker is:

```text
ONLY_C2R1_DERIVED_COMPARATIVE_INTRINSIC_PRESENT
NO_AUTHORITATIVE_FIELD_MAPPING
Stage A = ADMISSION_NOT_READY_MISSING_PROVENANCE
Stage B = FIELD_PIN_NOT_EXPOSED_GATED_ON_ADMISSION
```

The design answers what a future reviewer must verify before Stage A can determine that one source object independently establishes the canonical intrinsic field for one target. It deliberately does not make that determination now.

## Inspected authority state

The design is grounded in committed local artifacts and authenticated remote state. The authenticated artifact-repository `origin/main` was `99f9c0d7fe8b4ecec896837b3991e8d23ebbb608` at inspection. R7 reports committed source authority but zero source-auth executions and an absent field-pin registry. R8 contains 317 evidence-only candidate packets, all classified as `MULTIPLE_CANDIDATE_POINTERS`; its first tranche is the exact frozen ordered set of 24 targets. The provenance remediation review confirms 24 explicit human `REQUEST_MORE_EVIDENCE` decisions, no approvals, no pins, and preservation of R7/R8/R8R1.

The existing source-class registry already defines the required class/fact-type pair:

```text
AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE
PINNED_CANONICAL_INTRINSIC_FIELD
```

It also distinguishes the present `AUTHENTICATED_SCORING_ROW_SOURCE` / `PINNED_SCORING_ROW_FIELD` material from that class. The first-tranche provenance recovery results label every currently linked scoring row as noncanonical and report the missing canonical-intrinsic source manifest and extraction authority.

## Design

The proposed future evidence chain is:

```text
governed source authority
  -> authenticated immutable source artifact
  -> exactly one authenticated source object
  -> canonical field identity
  -> append-only mapping evidence record
  -> independent Stage A admission
  -> only later Stage B candidate exposure
  -> separate governed human field-pin decision, if any
```

The chain uses both authority identity and byte identity. A SHA-256 proves that bytes are stable; it does not by itself grant canonical status. The source authority must independently identify the permissible class, owner/issuer, scope, version policy, schema, and semantics. The object extractor and locator must recompute exactly one object. The pointer must be an exact RFC6901 pointer that resolves in that object under a pinned schema and canonicalization profile. The resulting field identity includes the authority, artifact, object, schema, semantics, pointer, type, representation, and canonicalization profile, which prevents accidental collapse of equal-looking fields.

The evidence schema intentionally includes no `field_pin_id`, no selected candidate pointer field, and no command that can run source-auth. It holds a future mapping claim and the data needed to independently reject it. The disposition policy treats absence, ambiguity, conflict, untrusted bytes, missing pointers, and stale lineage as fail-closed states.

## Alternatives considered

### 1. Promote current C2R1 comparative evidence to authority

This fails the independent-source requirement. C2R1 is already classified as derived comparative intrinsic evidence, and the current blocker specifically records that it is the only such material present. It may preserve context or explain why a reviewer requested more evidence, but promoting it would make comparative output the canonical provenance it is meant to evaluate. No source owner, immutable canonical source object, schema-level field semantics, or authorized pointer is thereby established.

### 2. Have a human reviewer directly choose a current candidate pointer

This would turn reviewer preference into source authority. Current R8 packets are intentionally evidence-only, expose multiple candidate pointers, and retain `selected_canonical_pointer = null`. A human can govern a future Stage B pin decision only after Stage A establishes an authenticated canonical source tuple. Direct candidate selection does not prove source ownership, source version, source-object identity, canonical schema semantics, or source-to-field provenance.

### 3. Add a separate canonical-field authority layer with authenticated source-object provenance

This is the design adopted here. It preserves the current authority boundaries by requiring a separate governance/source-acquisition act, exact source bytes, exact object extraction, exact field identity, conflict recomputation, append-only lineage, and independent Stage A review. It is minimally sufficient because each assertion needed to admit a mapping can be recomputed from governed state and immutable bytes rather than reviewer preference or candidate ranking.

### 4. Treat a prospective wrapper specification as canonical authority

Existing wrapper specifications can describe a deterministic future extraction route, but their own artifacts state that they are prospective, unactivated, or candidate-only. A deterministic wrapper can become part of the proof only after a separately governed authority admits its upstream source and explicitly designates the wrapper output canonical. Determinism without authority is insufficient.

## Why the design is minimally sufficient

The design requires no semantic ranking engine and no invented field mapping. It asks only for the smallest information set that lets an independent reviewer answer six questions from bytes and governance state alone:

1. Does an active authority permit this source class for this target scope?
2. Which immutable source artifact and exact source object are authoritative?
3. Which exact canonical field, pointer, type, and value are established by that object?
4. Is the full provenance chain complete and cryptographically reproducible?
5. Is there exactly one active non-conflicting mapping for the target?
6. Can Stage A admit the evidence while Stage B and field-pin creation remain separate?

The answer to any missing or ambiguous question is fail-closed. This avoids both circular promotion of C2R1 and speculative candidate selection.

## Current first-tranche state

`FIRST_TRANCHE_24_MAPPING_EVIDENCE_REQUIREMENTS.jsonl` preserves the frozen order and exact R5/R8 candidate linkage for every target. Each record states:

- `CURRENT_ADMISSION_STATUS = BLOCKED`
- required class `AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE`
- required fact type `PINNED_CANONICAL_INTRINSIC_FIELD`
- current canonical source object, pointer, value, and field pin as JSON `null`
- `authority_design_alone_sufficient = false`
- separate governance and owner/source-acquisition actions required

No line creates an authority record, canonical pointer, canonical value, mapping record, Stage A decision, Stage B exposure, or field pin.

## Unresolved governance and source-acquisition questions

1. Which source owner or governance authority can authorize a canonical-intrinsic source for the 231 candidate-scoring route?
2. Which immutable upstream artifact, signed release, or pinned commit/tree is the legitimate canonical source for each target, if any?
3. What exact source schema and `canonical_intrinsic_field_semantics_id` define the canonical intrinsic field without relying on C2R1 or candidate semantics?
4. Which governed record activates the source authority, defines its scope and revocation policy, and authorizes the deterministic extraction rule?
5. If two independently authenticated canonical sources disagree, which future governance process can supersede or revoke one without heuristic selection?

These questions require a separate source-owner/governance and acquisition process. This design does not answer them with inference.

## Exact next gate

The next action is independent review of this design package. That review should verify the contracts, crosswalk conservation, source-class boundary, and zero-state only. It must not acquire sources, execute source-auth, admit a target, expose Stage B, or create a field pin.

## Terminal

```text
BINDING_AUTHORITATIVE_CANONICAL_FIELD_MAPPING_EVIDENCE_DESIGN =
PASS_READY_FOR_INDEPENDENT_DESIGN_REVIEW

FIRST_TRANCHE_COUNT = 24
CURRENT_MORE_EVIDENCE_COUNT = 24

AUTHORITATIVE_SOURCE_CLASS_POLICY_DESIGNED = PASS
CANONICAL_FIELD_IDENTITY_MODEL_DESIGNED = PASS
MAPPING_EVIDENCE_SCHEMA_DESIGNED = PASS
PROVENANCE_CHAIN_CONTRACT_DESIGNED = PASS
CONFLICT_ABSENCE_POLICY_DESIGNED = PASS
STAGE_A_STAGE_B_GATE_CONTRACT_DESIGNED = PASS
FIRST_TRANCHE_24_REQUIREMENT_CROSSWALK = PASS
APPEND_ONLY_TRANSACTION_MODEL_DESIGNED = PASS
INDEPENDENT_VERIFICATION_PLAN_DESIGNED = PASS

CURRENT_AUTHORITATIVE_FIELD_MAPPINGS_CREATED = 0
FIELD_PINS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO
R7_R8_R8R1_AUTHORITY_MUTATED = NO

PUSH_EXECUTED = NO

NEXT_ACTION =
INDEPENDENT_REVIEW_OF_CANONICAL_FIELD_MAPPING_EVIDENCE_DESIGN

STOP = true
```
