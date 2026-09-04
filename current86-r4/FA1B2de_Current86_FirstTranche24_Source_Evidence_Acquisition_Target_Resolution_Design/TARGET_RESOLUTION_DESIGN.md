# FIRST_TRANCHE24 Source Evidence Acquisition Target Resolution Design

## 1. Purpose and strict boundary

This package defines the governed layer between the already reviewed
source-authority class/fact-type pair and any later source-evidence acquisition
request. Its output is either a closed proof that exactly one candidate claim is
eligible under frozen rules, or a bounded ambiguity packet for governance. It
does not retrieve, inspect, authenticate, or activate the source object.

The exact reviewed target is:

```text
candidate reference = 03_frozen_lineage/FA1B2de_BSO_EQ_Current86_Source_Class_Fact_Type_Registry_R2.json#class_to_type_mapping[0]
candidate type      = SOURCE_AUTHORITY_CANDIDATE_CLASS
authority type      = AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE
source fact type    = PINNED_CANONICAL_INTRINSIC_FIELD
```

The exact governance tuple is `APPROVE_BOTH_G1_AND_G2`,
`FIRST_TRANCHE24_ONLY`, decision ID
`GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f`,
and transaction hash
`b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38`.

The boundary is:

```text
TARGET DISCOVERY / CANDIDATE ENUMERATION / TARGET RESOLUTION
    != SOURCE EVIDENCE ACQUISITION
    != SOURCE AUTHENTICATION
    != SOURCE AUTHORITY ACTIVATION
    != STAGE A ADMISSION
```

This design therefore does not derive a source-authority ID, create field pins,
admit Stage A, expose Stage B, create operative records, execute P0/P1, or run
the formal 1796 benchmark.

## 2. Discovery boundary

This package defines discovery inputs but performs no discovery. A future
discovery request may enumerate candidate claims from these admissible source
classes only:

1. `AUTHENTICATED_PROJECT_INDEX`: a project-controlled index whose own
   provenance and integrity are already authenticated by a separate gate.
2. `GOVERNED_MANIFEST_INDEX`: a governed manifest or registry that explicitly
   binds object identity and scope.
3. `SIGNED_DESCRIPTOR_INDEX`: a descriptor index with independently checkable
   descriptor references. A signature is evidence to evaluate, not an
   automatic authority result.
4. `VERSIONED_PROJECT_METADATA`: immutable project metadata that names a
   concrete artifact identity or version claim and has a later evidence path.

Generic search results, public listings, popularity, search rank, user-supplied
references, and official-looking domains are lead-only inputs. They may
generate a bounded discovery lead, but they cannot by themselves create an
eligible candidate or a selected target. A generic search result can never be
promoted directly to acquisition.

Discovery provenance records the channel class, evidence references, claim
status, and whether the source was used as the sole selection basis. The
candidate schema explicitly keeps these values as claims. No discovery source
class establishes canonical authority merely by being public, signed-looking,
official-looking, frequently cited, or highly ranked.

## 3. Candidate enumeration

Enumeration creates a closed candidate set. Every candidate receives a stable
`candidate_id` and a claim-only record containing:

- the frozen candidate class and fact type;
- a concrete artifact identity claim and non-floating locator claim;
- discovery channel and provenance;
- owner or issuer claim, without authentication status;
- version-form claim, without authenticated digest or version evidence;
- descriptor-to-artifact, artifact-to-version, and version-to-digest lineage
  claims, without authenticated lineage status;
- authorization claims bound to the literal `FIRST_TRANCHE24_ONLY` scope;
- references to evidence that a later gate must authenticate; and
- an explicit candidate disposition.

The candidate set preserves the full enumerated population. The set carries
parallel `enumerated_candidate_ids` and `dispositioned_candidate_ids` lists;
the validator requires exact equality. A candidate may be rejected, collapsed
as an evidenced duplicate or alias, retained as a noncanonical mirror, or
remain eligible, but it may not disappear silently.

The package's static fixtures contain synthetic candidate records only. They do
not represent a discovery execution: `TARGET_DISCOVERY_EXECUTED = NO` and
`TARGET_CANDIDATES_DISCOVERED = 0` remain fixed even when a fixture contains
claim records for validator coverage.

## 4. Normalization and canonical artifact identity

Normalization is deterministic and deliberately narrow:

- Artifact identity comparison uses exact parsed token and byte equality under
  the candidate schema. Fuzzy, semantic, or similarity matching is prohibited.
- Locator normalization lowercases the URI scheme and host, removes a default
  port, resolves dot segments, and normalizes unreserved percent encoding.
  Path case, fragments, and other identity-bearing distinctions are preserved.
- Unicode normalization is not applied to artifact identities or paths.
- Query-parameter reordering is prohibited unless a later channel policy
  explicitly defines it.
- A locator is never an artifact identity by itself. Identity requires a
  concrete claim, an identity namespace, and an identity basis.
- Floating tokens such as `latest`, `head`, branch names, ranges, or date-only
  labels cannot satisfy identity or version uniqueness.

The canonical-artifact identity model is the tuple:

```text
(authority type, source fact type, candidate class,
 artifact identity namespace, concrete artifact identity claim,
 non-floating locator claim, immutable-version claim when present)
```

This is a pre-authentication identity claim, not an authenticated source
identity. Content digests, commit/tree identities, release proofs, owner
authorization, and final authority identity remain later evidence.

## 5. Deduplication, aliases, mirrors, and variants

Deduplication is a disposition operation, not a preference ranking.

- `EXACT_DUPLICATE`: same artifact identity and same version claim. One
  representative may remain, while every duplicate ID and disposition is
  retained.
- `ALIAS`: a different name or locator explicitly proven to identify the same
  artifact. The evidence must identify the canonical representative; naming
  similarity is insufficient.
- `MIRROR`: a copy at a different locator. A mirror remains noncanonical unless
  explicit origin, mirror, and same-version evidence identifies its canonical
  origin. The mirror itself is not promoted by availability.
- `FORK_OR_COPY`: a related project or copied object with distinct identity,
  ownership, or history. It remains distinct and is not canonical by default.
- `DERIVATIVE`: transformed, filtered, repackaged, or generated output. It
  remains a distinct artifact and cannot be collapsed into its source.
- `VERSION_VARIANT`: the same artifact identity with a different immutable
  version claim. Each version remains distinct; target resolution does not
  choose the newest or most convenient one.
- `UNRELATED_LOOKALIKE`: similar naming, content, or presentation without an
  explicit relationship. It remains separate.

If a claimed relationship cannot be established, the relationship is
`UNPROVEN`, the candidates remain separate, and automatic uniqueness fails
closed. A mirror is never canonical solely because it is easier to access or
appears more official.

## 6. Eligibility

Eligibility is a minimum gate for a candidate claim. It requires exact class
and fact-type match, admissible discovery provenance, concrete non-floating
artifact identity and locator, and a viable later path to immutable-version,
content-digest, descriptor-lineage, and owner/issuer authorization evidence.
It also requires that no unresolved relationship prevents canonical identity.

Eligibility does not require final authentication in this layer. Candidate
records must explicitly carry `authentication_status = NOT_EXECUTED` for owner,
lineage, and authorization claims. Eligibility is not authority, source
authentication, activation, or Stage A admission.

## 7. Uniqueness and precedence

Uniqueness is established only after the candidate set is complete,
deduplication dispositions are explicit, and every candidate has an eligibility
outcome. The uniqueness proof records both eligible-candidate count and
distinct canonical-representative count.

The precedence policy is exactly:

```text
PRECEDENCE_POLICY = NO_AUTOMATIC_PRECEDENCE
```

No frozen project authority currently supports a deterministic authoritative
ordering among otherwise eligible artifact candidates. Therefore the resolver
never chooses first, newest, most popular, most convenient, highest-ranked,
most cited, or most official-looking. A tie-breaker is not recorded as a
precedence rule after the fact.

When exactly one eligible canonical representative remains, the resolver may
emit `UNIQUE_TARGET_RESOLVED`. The selected acquisition channel is then bound
by the frozen version-form map:

```text
CONTENT_DIGEST          -> CONTENT_ADDRESSED_OBJECT_HANDOFF
GIT_COMMIT              -> GIT_COMMIT_TREE_SNAPSHOT_HANDOFF
RELEASE_TAG_WITH_DIGEST -> RELEASE_ARTIFACT_WITH_DIGEST_HANDOFF
```

`SIGNED_DESCRIPTOR_AUTHORIZATION_BUNDLE_HANDOFF` is an allowed supporting
channel for later lineage or authorization evidence; it does not, by itself,
select an artifact.

## 8. Ambiguity and governance handoff

If two or more candidates remain equally eligible, or if an alias/mirror
relationship cannot establish one canonical representative, resolution fails
closed. The transaction must use:

```text
resolution_state = REQUIRES_GOVERNANCE_ADJUDICATION
selected_candidate_id = null
selected_acquisition_channel_class = null
downstream_acquisition_eligibility = false
```

The governance handoff contains the complete candidate-set reference, all
ambiguous candidate IDs, distinguishing evidence references, the stable
uniqueness-failure reason, and one exact question:

> Which, if any, of the equally eligible candidate claims is the canonical
> FIRST_TRANCHE24 acquisition target, and which policy-authorized acquisition
> channel class should be bound?

The permitted decision vocabulary is limited to selecting one candidate and
binding a channel, rejecting all and requesting new discovery, returning for
more provenance, or deferring with no selection. This package does not create
the human decision and does not reinterpret the existing G1/G2 decision as an
artifact-selection decision.

## 9. Handoff to later acquisition

Only `UNIQUE_TARGET_RESOLVED` may produce an acquisition-target handoff. The
handoff repeats the candidate-set and transaction references, the exact
governance and scope bindings, the resolved identity and locator claims, the
selected channel class, and deterministic provenance.

The handoff is a permission to prepare a later acquisition request, not a
retrieved object. It must state:

```text
SOURCE_ACQUISITION = NO
ARTIFACT_ACQUISITION_ATTEMPTED = NO
SOURCE_AUTHENTICATION_STATUS = NOT_EXECUTED
SOURCE_AUTHORITY_ID = NONE
SOURCE_AUTHORITY_ACTIVATED = NO
```

The later acquisition phase must revalidate the handoff, acquire into its own
quarantine boundary, and produce its separate evidence envelope. Target
resolution cannot fill in a digest, authenticated version, lineage proof,
authorization proof, or source-authority ID by inference.

## 10. State machine

The state machine starts at `DESIGN_ONLY`. A future implementation may prepare
a discovery request, assemble a candidate set, evaluate eligibility, and
evaluate uniqueness. Its terminal outcomes are:

- `UNIQUE_TARGET_RESOLVED`: exactly one eligible canonical representative and
  one policy-consistent future acquisition channel;
- `REQUIRES_GOVERNANCE_ADJUDICATION`: ambiguity remains and selection is null;
  or
- `REJECTED`: no eligible candidate or a hard policy failure.

The machine contains no acquired, authenticated, activated, Stage A, Stage B,
field-pin, operative-record, P0/P1, or benchmark state. The state machine is a
resolution protocol, not an execution protocol.

## 11. Automation conclusion

```text
TARGET_RESOLUTION_AUTOMATION_MODEL = AUTOMATIC_WHEN_UNIQUE_BY_FROZEN_RULES
```

This model is conservative because automation is limited to checking frozen
identity, eligibility, deduplication, cardinality, and channel mapping. Any
case requiring a substantive authority judgment remains a governance
adjudication. The absence of automatic precedence is itself frozen and cannot
be bypassed by an implementation convenience.

## 12. Zero operational effect

This design task records no operational execution:

```text
TARGET_DISCOVERY_EXECUTED = NO
TARGET_CANDIDATES_DISCOVERED = 0
TARGET_SELECTED = NO
SOURCE_ACQUISITION = NO
ARTIFACT_ACQUISITION_ATTEMPTED = NO
SOURCE_AUTH_EXECUTED = NO
SOURCE_AUTHORITY_ID_DERIVED = NO
SOURCE_AUTHORITY_ID = NONE
SOURCE_AUTHORITY_ACTIVATED = NO
STAGE_A_ADMISSIONS = 0
STAGE_B_EXPOSURES = 0
FIELD_PINS = 0
OPERATIVE_RECORDS = 0
P0_EXECUTED = NO
P1_EXECUTED = NO
FORMAL_1796_EXPERIMENT_EXECUTED = NO
ZERO_OPERATIONAL_EFFECT = PASS
```

No external discovery, live endpoint, repository, source credential, source
object, authentication execution, authority activation, or Stage A admission
is used by the local validator or by the package fixtures.
