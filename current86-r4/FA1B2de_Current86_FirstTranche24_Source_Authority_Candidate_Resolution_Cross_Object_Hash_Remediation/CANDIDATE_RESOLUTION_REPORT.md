# FIRST_TRANCHE24 Source-Authority Candidate Resolution

## Phase boundary

This package executes only `FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_RESOLUTION`.
It resolves an admissible source-authority candidate class from already
authenticated project evidence. It does not activate source authority, acquire
or authenticate a live source object, admit Stage A, create field pins, execute
P0/P1, or run the formal 1796 benchmark.

The frozen scope is exactly the ordered 24-ID set:

`[110, 273, 210, 98, 147, 277, 188, 301, 143, 250, 233, 287, 146, 293, 114, 284, 291, 215, 88, 182, 300, 218, 115, 148]`

It has cardinality 24, unique cardinality 24, and no scope extension.

## Entry Binding authentication

The authenticated Binding worktree is
`/home/cph/fa1b2de-artifact-worktrees/binding` in repository
`/home/cph/fa1b2de-review-artifacts`, branch `artifact/binding`.

The local branch ref, remote-tracking ref, and previously authenticated live
remote-head evidence all resolve to:

`e6e885e17e60f1b12af47a7ddb363b8d2934f8b7`

The commit has direct parent
`10478b0961a601d0f684740b9564633a9930ebc9`, with message
`materialize binding: FIRST_TRANCHE24_SOURCE_AUTHORITY_ACTIVATION_DESIGN`.
The entry evidence records head equality and no unexplained lineage drift.

Entry evidence reference:
`FA1B2de_Current86_FirstTranche24_Source_Authority_Activation_Design_Independent_Review/evidence/LINEAGE_AUTHENTICATION.json`

Entry evidence SHA-256:
`9a0c2254a0aea8d6fcf20aed0df3879db216831d613da5bcf15c16e0126d86a5`

## Candidate search space

The reviewed activation design permits an authority candidate to be considered
as one of these forms:

1. A direct upstream canonical intrinsic object.
2. A deterministic canonical wrapper over an authorized upstream object.
3. A governed project canonical intrinsic registry object.

The frozen class and fact-type target for this tranche is:

- Authority type: `AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE`
- Source class: `AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE`
- Fact type: `PINNED_CANONICAL_INTRINSIC_FIELD`

Search-space evidence includes the class/fact-type registry, the authoritative
source-class policy, and the source-authority activation contract. Their
references and hashes are recorded in `CANDIDATE_SET.json`.

## Evidence examined

The resolution uses only materialized project evidence already present in the
Binding workspace:

- Governance decision materialization binds `APPROVE_BOTH_G1_AND_G2` to
  decision ID `GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f`,
  transaction hash
  `b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38`, and
  scope `FIRST_TRANCHE24_ONLY`.
- `CANONICAL_SOURCE_COHORT_CLASSIFICATION.json` records that all 24 targets
  share the canonical source class/fact type and have no exception cohort.
- `SOURCE_AUTHORITY_AND_OWNER_GAP_REPORT.json` records that all 24 targets
  lack a canonical source-manifest entry, exact source object, and owner or
  issuer authorization.
- The authoritative source-class policy excludes scoring rows and noncanonical
  wrappers from the canonical intrinsic source class.
- The activation design and its independent review define the closed identity,
  version, provenance, and fail-closed requirements.
- The prospective wrapper independent verification and historical authority
  reference provide authenticated evidence for candidate elimination.

The complete claim-to-artifact mapping is in
`PROVENANCE_EVIDENCE_MAP.json`. Class-level claims are marked
`PASS_CLASS_ONLY`; concrete source-object provenance is not asserted.

## Candidate elimination

### Rejected prospective scoring-wrapper candidate

Reference:
`36831020b75a201420bd5cfce97a54ada12d44246f56a7812455bc21b99f9477`

This candidate is rejected because its source class is
`AUTHENTICATED_SCORING_ROW_SOURCE`, its fact type is
`PINNED_SCORING_ROW_FIELD`, its scope is `EXACT_CURRENT86_ONLY`, and its
independent verification marks it prospective and non-active. The evidence
does not identify an admitted canonical intrinsic source object.

### Rejected historical Current86 authority reference

Reference:
`FA1B2de_Current86_BSO_A2_Authority_Candidate_PROSPECTIVE_R2/02_old_authority_reference.json#workflow_architecture_authority_hash`

This candidate is rejected because it is a historical Current86-wide authority
reference, not a newly selected `FIRST_TRANCHE24_ONLY` canonical source object.
This task cannot narrow its scope or reuse it as the tranche authority.

## Resolution and uniqueness

Exactly one admissible class-level candidate remains:

`03_frozen_lineage/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json#class_to_type_mapping[0]`

Resolved candidate type:
`SOURCE_AUTHORITY_CANDIDATE_CLASS`

Resolved semantic label:
`AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE / PINNED_CANONICAL_INTRINSIC_FIELD`

The uniqueness result is class-only. No concrete source artifact, source
object, locator, extractor, or immutable source version is selected. The two
examined object-level alternatives are explicitly rejected with authenticated
evidence, and no plausible unrejected candidate remains.

Therefore:

`CANDIDATE_RESOLUTION_DECISION = CANDIDATE_RESOLVED_VERSION_EVIDENCE_PENDING`

This is a candidate-resolution result, not an authority activation result.

## Version-policy resolution

The activation design requires exactly one immutable V1 policy form, with
`floating_reference_allowed: false` and
`update_policy: NEW_ACTIVATION_REQUIRED`.

The supported forms are:

- `CONTENT_DIGEST`
- `GIT_COMMIT`
- `RELEASE_TAG_WITH_DIGEST`

Existing evidence does not identify which supported form applies to the
concrete source object, because the source-manifest entry and source artifact
are absent. No floating reference or invented digest is substituted.

`VERSION_POLICY_RESOLUTION = BLOCKED_PENDING_SOURCE_EVIDENCE`

## Provenance and authentication requirements

Class and scope claims are traceable to authenticated project artifacts. The
following concrete evidence remains required before activation:

- Exact canonical source-manifest entry.
- Exact canonical source artifact or object identity and locator.
- One supported immutable version form and identifier.
- Artifact content SHA-256, plus Git commit/tree or release proof when
  applicable.
- Deterministic extractor, canonical schema namespace, field semantics, exact
  RFC6901 pointer, and authenticated field-value hash.
- Source owner or issuer authorization.
- Complete same-candidate provenance chain and independent recomputation of the
  concrete authority identity.

These gaps are recorded in `VERSION_POLICY_RESOLUTION.json`,
`PROVENANCE_EVIDENCE_MAP.json`, and `CANDIDATE_RESOLUTION_DECISION.json`.

## Activation blockers

Activation remains blocked by missing concrete source evidence and immutable
version identity. In particular, this package does not derive a source
authority ID from the class-only result. `RESOLVED_CANDIDATE_RECORD.json`
therefore records `source_authority_id_derived: false` and
`source_authority_id: NONE`.

All operational state remains unchanged: source authority is not activated,
source acquisition and source authentication were not executed, Stage A/B
counts and field pins remain zero, and P0/P1/formal 1796 execution remains
`NO`.

## Decision

`CANDIDATE_RESOLUTION_DECISION.json` records
`CANDIDATE_RESOLVED_VERSION_EVIDENCE_PENDING` with exact governance binding,
exact tranche scope, and no activation effect.

Next phase:

`FIRST_TRANCHE24_SOURCE_AUTHORITY_CANDIDATE_RESOLUTION_INDEPENDENT_REVIEW`
