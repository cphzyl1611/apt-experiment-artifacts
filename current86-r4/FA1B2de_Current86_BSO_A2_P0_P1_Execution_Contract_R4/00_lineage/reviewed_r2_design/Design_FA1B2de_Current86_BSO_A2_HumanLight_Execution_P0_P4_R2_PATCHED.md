# Design_FA1B2de_Current86_BSO_A2_HumanLight_Execution_P0_P4

**Revision:** `R2_PATCHED`
**R2 patch scope:** close only `P3_CURRENT_STATE_DISPOSITION_AND_PENDING_INVALIDATION_UNDERSPECIFIED` and `P4_NONAUTHORITATIVE_WORKLOAD_MAY_CONTAMINATE_NORMATIVE_FINAL_FREEZE_ID`; retain M1/M2 as mandatory P0 materialization requirements.

**Document role:** subordinate execution design / execution contract  
**Scope:** exact frozen Current86 only  
**Architecture:** P0 → P1 → P2 → P3 → P4  
**Design status:** `PROPOSED_NOT_EXECUTED`  
**Authority transition status:** no new authority layer is introduced by this document  
**Execution status at publication of this design:** no P0/P1/P2/P3/P4 execution has been performed under this design

---

## 0. Purpose and hard boundary

This document consolidates the already accepted five-layer Human-Light execution architecture for
Current86 B-SO-A2 into one formal execution design. It does **not** create another authority layer,
does **not** perform adjudication, and does **not** publish any binding.

The five layers are fixed as:

```text
P0  FULL CURRENT86 EXECUTION PREPARATION
P1  DETERMINISTIC SINGLE-RAW REAL PILOT
P2  FRESH READ-ONLY INDEPENDENT PILOT REVIEW
P3  SCALE-OUT EXECUTION FOR REMAINING NON-TERMINAL RAWS
P4  CURRENT86 A2 FINAL FREEZE / CONSERVATION / INDEPENDENT VERIFICATION
```

The following direction is accepted for consolidation:

```text
FIVE_LAYER_ARCHITECTURE_DIRECTION = ACCEPTED_FOR_CONSOLIDATION

RETURN_TO_4161_RELATION_EQ = NO
CONTINUE_OLD_44_RELATION_EQ_PILOT = NO
```

The currently active governance state for the exact Current86 critical path is:

```text
NEW_BSO_A2_AUTHORITY_STATUS = ACTIVE_FOR_EXACT_CURRENT86

ACTIVE_BSO_A2_AUTHORITY_CANDIDATE_ID =
36831020b75a201420bd5cfce97a54ada12d44246f56a7812455bc21b99f9477

H2_PROVENANCE_EVIDENCE_ID =
939cc0c72e77bc437f0ab436cdf61c276d0ba1959273bbe0f46344e77ddff99e

ACTIVATION_TRANSACTION_ID =
bf4569d2116ac16a994feda733468faf2eeac92cc1f6eda46a77eac7312b718f

ACTIVATION_SCOPE = EXACT_CURRENT86_ONLY
```

The frozen Current86 population remains:

```text
RAW_COUNT = 86
STRUCTURALLY_ELIGIBLE_RELATION_COUNT = 4219
AUTHENTICATED_HARD_NEGATIVE_COUNT = 58
FORMER_HUMAN_EQ_RELATION_COUNT = 4161
```

Count equality is diagnostic only. Exact object/set equality remains normative.

This design preserves:

```text
PROJECT_SCORING_AUTHORITY =
18fd70d4a57f07a3e06242d9f0e077a4e6838120

PROJECT_BINDING_AUTHORITY_BASELINE =
d309c01d6178a75cac88b6236d36179563a88239

PROJECT_ACCEPTED_BINDINGS = 1045/1796
```

Nothing in P0–P4 changes those project-level scoring or binding authorities.

---

# 1. Normative classification

Every important statement in this design belongs to one of three classes.

## 1.1 FACT

`FACT` is an authenticated project state or already observed/frozen identity. This design may cite it
but does not create it.

Examples:

- exact Current86 contains 86 raws and 4,219 structurally eligible relations;
- the 4,219 relations are partitioned into 58 authenticated hard negatives and 4,161 former
  human-EQ relations;
- H2 activation transaction
  `bf4569d2116ac16a994feda733468faf2eeac92cc1f6eda46a77eac7312b718f`
  has been fresh-independently verified;
- B-SO-A2 authority candidate
  `36831020b75a201420bd5cfce97a54ada12d44246f56a7812455bc21b99f9477`
  is active for exact Current86;
- the old B-SO-EQ authority remains byte-preserved and is superseded only for the Current86 critical
  path.

## 1.2 EXISTING AUTHORITY

`EXISTING AUTHORITY` is a normative rule already inherited from the activated B-SO-A2 authority or
its reviewed lineage.

This design SHALL NOT weaken or silently reinterpret it.

Core inherited authority includes:

```text
COMPLETE_CANDIDATE_UNIVERSE_PRESERVED = YES

MACHINE_PROPOSAL = NON_AUTHORITATIVE_MACHINE_PROPOSAL

HIDDEN_PRUNING = PROHIBITED
TOP_K_CANDIDATE_TRUNCATION = PROHIBITED

PROPOSAL_SCORE_AS_NORMATIVE_SIGNAL = PROHIBITED
PROPOSAL_RANK_AS_BINDING_SIGNAL = PROHIBITED

NEW_SCORING_SEMANTICS = PROHIBITED
NEW_BINDING_SEMANTICS = PROHIBITED
NEW_RANKING_SEMANTICS = PROHIBITED

PROPOSAL_EVIDENCE_SET
⊆
ADMISSIBLE_NORMATIVE_SOURCE_FACT_SET

HUMAN_NORMATIVE_UNIT = ONE_RAW

HUMAN_ACTIONS = {
  CONFIRM_PROPOSED_OWNER,
  REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE,
  NOT_SURE_ESCALATE
}

A2_OWNER_ADJUDICATION_FROZEN
and
A2_ESCALATION_FROZEN
are mutually exclusive terminal classes.

A2_ESCALATION_FROZEN_COUNTS_AS_OWNER_CLOSURE = NO
```

## 1.3 PROPOSED EXECUTION RULE

`PROPOSED EXECUTION RULE` is a subordinate execution rule introduced by this document to make the
active authority executable and auditable.

These rules become usable for runtime materialization only after the consolidated design receives
independent design review and, if the review determines a normative human acceptance is required,
one explicit human acceptance.

Examples:

- deterministic pilot ordering;
- computational-contract identity schema;
- canonical object hashing contract;
- P3 execution-state partition;
- attempt/pending/accepted ledger separation;
- fresh checkpoint review scheduling;
- P4 final-freeze packaging and handoff rules.

No `PROPOSED EXECUTION RULE` in this document creates a new scoring, binding, ranking, or owner
authority.

---

# 2. Global canonicalization and hashing contract

## 2.1 Two distinct hash classes

This design distinguishes exact-file hashes from semantic object identities.

### RAW_FILE_SHA256

For an immutable file artifact:

```text
RAW_FILE_SHA256(file) = SHA256(exact file bytes)
```

No newline normalization, Unicode normalization, whitespace rewriting, archive reordering, or
pretty-print rewrite is permitted before this hash is calculated.

### CANONICAL_OBJECT_ID

For a structured normative object:

```text
CANONICAL_OBJECT_ID(object, self_id_field) =
SHA256(
  UTF8(
    PROJECT_CANONICAL_JSON_V1(
      object with exactly self_id_field omitted
    )
  )
)
```

If the object has no derived self-ID field, no field is omitted.

## 2.2 PROJECT_CANONICAL_JSON_V1

`PROJECT_CANONICAL_JSON_V1` is the single canonical serialization contract for all P0–P4 structured
IDs/hashes.

It SHALL use RFC 8785 JSON Canonicalization Scheme semantics, with these additional project
constraints:

1. Input MUST be valid JSON with no duplicate object keys.
2. Text encoding MUST be UTF-8 without BOM.
3. Strings MUST already be valid Unicode and NFC-normalized. The canonicalizer MUST validate NFC and
   fail closed if a normative string is not NFC; it MUST NOT silently rewrite the normative value.
4. Normative numeric values MUST be integers within the explicitly declared schema range.
5. Floating-point values are PROHIBITED in normative identity-bearing objects. Measurements that
   require fractions SHALL use integer base units, e.g. milliseconds.
6. Object-key order in source files is non-normative; canonical ordering is defined only by the
   canonicalization algorithm.
7. Arrays are order-sensitive unless the schema explicitly declares the field to be a mathematical
   set.
8. A schema-declared set MUST first be transformed to a canonical array by the field-specific
   ordering rule defined in that schema, then canonicalized.
9. Pretty printing, filesystem enumeration order, locale, process locale, insertion order, platform
   newline convention, and host operating system SHALL NOT affect the canonical result.
10. All self-derived identity fields SHALL be omitted only when the exact schema says so. No other
    field may be dropped.

The canonicalization contract itself SHALL be versioned and hash-bound by all execution manifests:

```text
canonicalization_contract = PROJECT_CANONICAL_JSON_V1
```

Any change to the canonicalization semantics creates a different execution contract and cannot be
silently applied to already-produced records.

## 2.3 Identity-bearing objects covered

The same canonicalization contract SHALL govern at least:

```text
*_id
*_hash where the hash denotes a structured object
execution_manifest_id
proposal_input_bundle_id
primary_commitment_id
verifier_commitment_id
comparison_id
human_packet_id / human_packet_hash
human_decision_record_id
terminal_record_id
ledger_append_id
ledger_snapshot_id
checkpoint_review_id
resume_token_id
promotion_record_id
current_disposition_id
set_ordering_registry_id
final_freeze_normative_manifest_id
final_freeze_package_manifest_id
CURRENT86_A2_FINAL_FREEZE_ID
```

Raw file checksums continue to use exact-byte `RAW_FILE_SHA256`.

## 2.4 MANDATORY_P0_MATERIALIZATION_REQUIREMENT M1 — frozen SET_ORDERING_REGISTRY

The design-level canonicalization rule is complete only when every identity-bearing mathematical set
has one exact deterministic ordering rule. This subordinate detail MAY be materialized in P0, but it
MUST be frozen before **any** P0/P1 runtime identity using such a set is computed.

P0 SHALL materialize:

```text
SET_ORDERING_REGISTRY
```

with at least:

```text
schema
canonicalization_contract
entries = [
  {
    schema_field_path,
    mathematical_set_type,
    element_identity_field_or_tuple,
    comparison_encoding,
    comparison_rule
  },
  ...
]
set_ordering_registry_id
```

and:

```text
set_ordering_registry_id =
CANONICAL_OBJECT_ID(
  SET_ORDERING_REGISTRY,
  "set_ordering_registry_id"
)
```

At minimum the registry SHALL freeze these orderings:

```text
Current86 raw set:
  canonical_raw_key
  ordered by BYTEWISE_ASCENDING_UTF8

relation set:
  relation_identity
  ordered by BYTEWISE_ASCENDING_UTF8

per-raw complete candidate-universe entries:
  tuple(
    candidate_scoring_id,
    relation_identity
  )
  compared lexicographically by UTF-8 bytes of the first element,
  then UTF-8 bytes of the second element

evidence fact set:
  source_fact_id / canonical_fact_id
  ordered by BYTEWISE_ASCENDING_UTF8

owner terminal raw set:
  canonical_raw_key
  ordered by BYTEWISE_ASCENDING_UTF8

escalation terminal raw set:
  canonical_raw_key
  ordered by BYTEWISE_ASCENDING_UTF8

each P3 current-state partition raw set:
  canonical_raw_key
  ordered by BYTEWISE_ASCENDING_UTF8
```

If any additional identity-bearing mathematical set is introduced by a subordinate P0/P1 schema, the
registry SHALL define its exact ordering before that schema may compute an ID.

The registry SHALL NOT derive ordering from filesystem enumeration, locale, model output order,
dictionary insertion order, candidate score, confidence, evidence richness, or historical
disposition.

The P0 execution manifest SHALL pin the exact `set_ordering_registry_id`.

This is:

```text
MANDATORY_P0_MATERIALIZATION_REQUIREMENT = M1
```

and does not create a new authority layer.

---

# 3. Canonical raw identity and deterministic pilot ordering

## 3.1 Canonical raw key

The canonical positional raw identity SHALL be:

```text
{playbook_id}::S{stage:02d}::A{action:03d}
```

where:

- `playbook_id` is the exact canonical decimal playbook identifier from the frozen raw identity;
- `stage` is rendered as exactly two ASCII decimal digits;
- `action` is rendered as exactly three ASCII decimal digits;
- separators are literal ASCII `::`, `S`, and `A`;
- no leading/trailing whitespace is permitted.

Example shape:

```text
6000002::S03::A007
```

The canonical raw key remains positional identity. VID/UUID or candidate identities SHALL NOT replace
it.

## 3.2 Ordering

Pilot and P3 raw ordering SHALL use:

```text
BYTEWISE_ASCENDING_UTF8(canonical_raw_key)
```

Because the canonical representation is ASCII-only, this is also ordinary ascending ASCII byte
ordering. Locale-sensitive collation is prohibited.

## 3.3 Initial pilot

The first P1 pilot raw SHALL be:

```text
PILOT_RAW_KEY =
MIN_BY_BYTEWISE_ASCENDING_UTF8(EXACT_CURRENT86_RAW_SET)
```

Pilot selection SHALL NOT use:

```text
candidate count
model confidence
evidence richness
historical disposition
historical owner
historical EQ result
proposal agreement
candidate popularity
embedding similarity
semantic difficulty
```

## 3.4 Pilot continuation

If a valid first pilot reaches a legitimate pre-human terminal escalation and therefore does not
exercise the Human-Light human path, P2 may declare pilot continuation required.

The next pilot SHALL be:

```text
MIN_BY_BYTEWISE_ASCENDING_UTF8(
  EXACT_CURRENT86_RAW_SET
  minus
  ACCEPTED_TERMINAL_RAW_SET
)
```

A previously accepted pilot raw SHALL NOT be re-adjudicated merely to obtain a human-path example.

---

# 4. Proposer / verifier computational contract identity

This section closes the computational-identity gap. A proposer/verifier contract hash SHALL bind an
actual, mechanically reconstructable contract object rather than an abstract label.

## 4.1 Contract object

Each computational role SHALL have one object:

```text
A2_COMPUTATIONAL_CONTRACT
```

with at least:

```text
schema
role

implementation_identity
prompt_template_identity
model_runtime_identity
tool_permission_boundary

input_schema_identity
output_schema_identity

normative_source_profile_identity
source_class_fact_type_registry_identity
historical_output_denylist_identity

isolation_contract_identity
isolation_enforcement_identity
canonicalization_contract
set_ordering_registry_identity

computational_contract_id
```

## 4.2 Implementation identity

`implementation_identity` SHALL bind the exact executable implementation used by that role.

It SHALL contain, as applicable:

```text
repository_commit
entrypoint
implementation_files = [
  {path, RAW_FILE_SHA256},
  ...
]
dependency_lockfile_hashes
interpreter_or_runtime_version
agent_or_cli_version
configuration_file_hashes
```

If no repository commit exists for a generated standalone implementation, the complete exact
implementation file inventory and byte hashes SHALL be sufficient to reconstruct the identity.

Unpinned implementation files that can affect normative outputs are prohibited.

## 4.3 Prompt/template identity

`prompt_template_identity` SHALL bind:

```text
exact system/task template bytes or canonical template object
template RAW_FILE_SHA256 or canonical template ID
template version
all injected normative instructions that can affect proposal semantics
```

Dynamic runtime data such as the raw action and source facts SHALL not be merged into the template
identity; they belong to the proposal input bundle.

A prompt/template change changes the computational contract identity.

Private chain-of-thought is explicitly excluded:

```text
PRIVATE_CHAIN_OF_THOUGHT_IS_NORMATIVE_ARTIFACT = NO
PRIVATE_CHAIN_OF_THOUGHT_CAPTURE_REQUIRED = NO
```

The persisted normative output is the structured commitment and its source-grounded evidence
references, not hidden reasoning.

## 4.4 Model/runtime identity

Where an LLM or agent runtime is used, the contract SHALL bind all stable identity fields exposed by
the runtime, for example:

```text
provider
model_id
model_variant_or_snapshot_if_exposed
runtime_or_agent_version
decoding_parameters
seed_if_supported
context_policy_version_if_exposed
tool_mode
```

If a runtime does not expose a stable model build/snapshot identifier, the object SHALL record:

```text
field_status = UNAVAILABLE_BY_RUNTIME
```

together with the observable runtime identity actually available. The implementation MUST NOT invent
a build ID.

The absence of an unexposed field does not permit omission of exposed fields.

## 4.5 Tool-permission boundary

The contract SHALL declare the exact allowed capability boundary, for example:

```text
filesystem_read_scope
filesystem_write_scope
network_access
shell_execution
external_connector_access
mutable_workspace_access
allowed_tools
denied_tools
```

For normative proposer/verifier derivation, the preferred boundary is read-only access to the
authenticated input bundle plus only the tools explicitly needed to parse/hash those inputs.

Unpinned external retrieval SHALL NOT become normative proposal evidence.

## 4.6 Input/output schemas

Both roles SHALL bind exact schema identities.

Primary/verifier input SHALL include:

```text
raw_key
active_authority_id
execution_manifest_id

raw_identity_hash

complete_candidate_universe_hash
complete_relation_set_hash

raw_source_bundle_hash
candidate_source_bundle_set_hash
admissible_source_fact_set_hash

normative_source_profile_hash
historical_output_denylist_hash
source_registry_id

proposal_input_bundle_id
```

Output SHALL be a structured commitment with at least:

```text
role
raw_key
proposal_input_bundle_id
complete_candidate_universe_hash
complete_relation_set_hash

result_status

selected_candidate_scoring_id | null
selected_relation_identity | null

evidence_fact_ids
evidence_set_hash

hard_gate_results

context_identity
run_identity

commitment_id
```

Allowed result statuses SHALL be frozen by schema. At minimum:

```text
UNIQUE_EXISTING_OWNER_PROPOSAL

ESCALATE_AMBIGUOUS
ESCALATE_STRUCTURE
ESCALATE_SCORING_AUTHORITY
ESCALATE_PROVENANCE
ESCALATE_IDENTITY
```

When `UNIQUE_EXISTING_OWNER_PROPOSAL` is emitted, selected candidate and relation MUST be non-null.
For escalation statuses, both MUST be null.

## 4.7 Isolation contract

Primary and verifier SHALL satisfy:

```text
PRIMARY.input_bundle_id == VERIFIER.input_bundle_id

PRIMARY.complete_candidate_universe_hash
==
VERIFIER.complete_candidate_universe_hash
```

and:

```text
PRIMARY.context_identity != VERIFIER.context_identity
PRIMARY.run_identity != VERIFIER.run_identity
```

These unequal identities are necessary but are **not sufficient** isolation proof.

Before the verifier commitment is frozen, the verifier SHALL NOT receive:

```text
primary selected owner
primary selected relation
primary rationale
primary evidence selection
primary hidden score
primary rank
primary shortlist
primary pruning state
mutable primary derivation artifacts
```

Execution order SHALL be:

```text
freeze common input
→ primary derivation
→ freeze primary commitment
→ isolated verifier derivation
→ freeze verifier commitment
→ comparison
```

Both commitments SHALL exist and be immutable before comparison.

### 4.7.1 MANDATORY_P0_MATERIALIZATION_REQUIREMENT M2 — mechanical verifier isolation

P0 SHALL materialize and hash-bind an auditable isolation-enforcement object:

```text
A2_VERIFIER_ISOLATION_ENFORCEMENT_CONTRACT
```

containing the exact enforcement mechanism actually used, with at least:

```text
schema
common_frozen_input_root_identity

verifier_workspace_identity
verifier_precommit_read_roots
verifier_precommit_readable_input_set_hash

primary_private_output_roots
primary_commitment_output_roots
primary_private_or_commitment_output_set_hash

filesystem_acl_or_permission_snapshot_hash | null
container_or_sandbox_identity | null
tool_permission_boundary_identity

enforcement_mechanism
audit_method

isolation_enforcement_id
```

The implementation MAY use exact read roots, isolated immutable workspaces, filesystem/container
ACLs, process sandboxing, equivalent capability isolation, or a combination. Whatever mechanism is
used MUST be represented by the exact materialized enforcement object and independently auditable.

Before verifier commitment freeze, the implementation SHALL mechanically establish:

```text
VERIFIER_PRECOMMIT_READABLE_INPUT_SET
∩
PRIMARY_PRIVATE_OR_COMMITMENT_OUTPUT_SET
=
∅
```

and also:

```text
VERIFIER_PRECOMMIT_READABLE_INPUT_SET
==
FROZEN_COMMON_VERIFIER_INPUT_SET
```

except for explicitly whitelisted deterministic runtime libraries/tools that cannot carry primary
derivation outputs. Such whitelist entries MUST be frozen in the enforcement contract.

A mere assertion that:

```text
PRIMARY.context_identity != VERIFIER.context_identity
```

or:

```text
PRIMARY.run_identity != VERIFIER.run_identity
```

does NOT satisfy M2 by itself.

The exact `isolation_enforcement_id` SHALL be pinned by both proposer/verifier computational
contracts and by the P0 execution manifest.

This is:

```text
MANDATORY_P0_MATERIALIZATION_REQUIREMENT = M2
```

and does not create a new architecture or authority layer.

## 4.8 Computational contract ID

For each role:

```text
computational_contract_id =
CANONICAL_OBJECT_ID(
  A2_COMPUTATIONAL_CONTRACT,
  "computational_contract_id"
)
```

The P0 execution manifest SHALL pin exact primary and verifier computational contract IDs.

A change to implementation, prompt/template, model/runtime identity, permission boundary, schema,
normative evidence profile, or isolation semantics changes the contract ID.

---

# 5. Five-layer architecture

# 5.1 P0 — Full Current86 execution preparation

## Purpose

P0 prepares the complete execution substrate for all exact Current86 raws without performing
normative adjudication.

Hard invariant:

```text
PREPARE_86 = YES
ADJUDICATE_86 = NO
```

P0 SHALL authenticate and prepare:

- exact Current86 raw membership;
- exact 4,219 relation membership;
- per-raw complete candidate universes;
- authenticated normative source facts;
- proposal input bundles;
- primary/verifier computational contracts;
- human packet schema;
- decision/terminal schemas;
- attempt/pending/accepted ledger schemas;
- P3 state-partition schema;
- conservation logic.

P0 SHALL NOT request human decisions, freeze owners/escalations, publish bindings, or execute
B-SO-V/P.

## P0 execution manifest

The proposed artifact is:

```text
current86_a2_execution_manifest.json
```

It SHALL pin at least:

```text
active_bso_a2_authority_id
activation_transaction_id
h2_provenance_evidence_id

exact_current86_scope_id
exact_current86_raw_set_hash
exact_current86_relation_set_hash
exact_current86_candidate_registry_hash

raw_count
relation_count
hard_negative_count
former_human_eq_relation_count

canonicalization_contract
set_ordering_registry_id
pilot_selection_rule

primary_computational_contract_id
verifier_computational_contract_id
verifier_isolation_enforcement_contract_id

proposal_evidence_profile_hash
historical_output_denylist_hash
source_registry_id

human_packet_schema_id
human_decision_schema_id
terminal_record_schema_id
ledger_schema_id
state_partition_schema_id

execution_manifest_id
```

Initial P0 terminal:

```text
A2_P0_STATUS = PREPARED_NOT_ADJUDICATED
RAW_LEVEL_HUMAN_DECISIONS = 0
```

---

# 5.2 P1 — Deterministic single-raw real pilot

Hard invariants:

```text
PILOT_IS_REAL_A2_ADJUDICATION = YES
DETERMINISTIC_NON_SEMANTIC_SELECTION = YES
```

P1 executes one real Current86 raw through the exact frozen execution contract.

Normal flow:

```text
deterministic pilot selection
→ preflight gates
→ freeze proposal input bundle
→ primary commitment
→ verifier commitment
→ comparison
→ immutable human packet
→ native human decision
→ provenance validation
→ terminal candidate
→ pending review
→ STOP
```

P1 SHALL NOT auto-start P2 or P3.

## Normal confirmation eligibility

Human confirmation eligibility requires:

```text
PRIMARY.result_status = UNIQUE_EXISTING_OWNER_PROPOSAL
VERIFIER.result_status = UNIQUE_EXISTING_OWNER_PROPOSAL

PRIMARY.selected_candidate_scoring_id
==
VERIFIER.selected_candidate_scoring_id

PRIMARY.selected_relation_identity
==
VERIFIER.selected_relation_identity

all primary gates PASS
all verifier gates PASS
isolation gate PASS
```

Otherwise normal confirmation is not eligible.

## Human packet

The human packet SHALL:

- show exact raw key and authenticated raw action;
- label machine proposal as `NON_AUTHORITATIVE_MACHINE_PROPOSAL`;
- show concise source-grounded raw-side and candidate-side support;
- show independent verifier agreement/isolation/admissibility status;
- disclose `N/N` complete candidate consideration;
- state `Hidden pruning: NO` and `Top-k truncation: NO`;
- provide an auditable full-candidate-universe expansion;
- expose exactly three normative actions.

Human actions:

```text
CONFIRM_PROPOSED_OWNER

REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE

NOT_SURE_ESCALATE
```

No blank/default/timeout action becomes approval.

The human SHALL NOT be required to manually copy:

```text
candidate IDs
relation IDs
evidence IDs
hashes
```

## Reject/select path

A human-selected alternative candidate does not become owner merely because the human selected it.

It SHALL undergo exact-candidate evidence binding and fresh independent validation. If the selected
alternative passes, it may produce `A2_OWNER_ADJUDICATION_FROZEN`; if it fails, the raw SHALL
fail closed to a legal escalation terminal.

## Legitimate pre-human escalation

A valid proposer/verifier disagreement or another authority-defined semantic escalation may produce
a legitimate pre-human escalation terminal.

Such a terminal can count toward final Current86 process coverage after P2 validation, but:

```text
PILOT_HUMAN_PATH_EXERCISED = NO
PILOT_SCALE_OUT_ELIGIBILITY = NO
```

until a deterministic pilot continuation successfully exercises the human path.

## Technical defect distinction

A technical or contract-integrity defect is not a semantic escalation.

Examples:

```text
checksum mismatch
identity mismatch
missing authenticated source
candidate-universe mismatch
schema violation
software exception
ledger corruption
```

These SHALL produce:

```text
PILOT_RECORD_VALIDITY = BLOCKED
```

and SHALL NOT count as a valid Current86 terminal.

---

# 5.3 P2 — Fresh independent pilot review

Hard invariant:

```text
FRESH_READ_ONLY_INDEPENDENT_REVIEW = YES
```

P2 SHALL be executed in a fresh context that did not create the P1 proposer/verifier/materialization
artifacts.

P2 MAY recompute but SHALL NOT repair or re-adjudicate.

P2 SHALL independently verify:

```text
active authority
pilot selection
raw identity
complete candidate-universe equality
source admissibility
primary commitment
verifier isolation
comparison
human packet fidelity
human provenance
terminal shape
conservation
no downstream side effects
```

P2 SHALL output two distinct decisions:

```text
PILOT_RECORD_VALIDITY
PILOT_SCALE_OUT_ELIGIBILITY
```

They SHALL NOT be conflated.

### Normal human-path PASS

```text
PILOT_RECORD_VALIDITY = PASS
PILOT_HUMAN_PATH_EXERCISED = YES
PILOT_SCALE_OUT_ELIGIBILITY = YES
```

### Valid pre-human escalation

```text
PILOT_RECORD_VALIDITY = PASS
PILOT_HUMAN_PATH_EXERCISED = NO
PILOT_SCALE_OUT_ELIGIBILITY = NO
```

### Invalid execution attempt

```text
PILOT_RECORD_VALIDITY = BLOCKED
PILOT_SCALE_OUT_ELIGIBILITY = NO
```

A P1 terminal becomes an accepted A2 terminal only after the required P2 review passes.

---

# 5.4 P3 — Scale-out execution

P3 requires:

1. a valid pilot;
2. pilot Human-Light path exercised;
3. fresh P2 scale-out eligibility;
4. one explicit human scale-out release binding the unchanged execution contract and exact remaining
   raw set.

The scale-out release is not a new authority layer. It is a one-time execution-release event for the
already reviewed subordinate execution contract.

## Human normative unit

Hard invariants:

```text
HUMAN_NORMATIVE_UNIT = ONE_RAW
HUMAN_PACKET_ACTIVE_COUNT = 1

NO_RELATION_LEVEL_MANUAL_OUTCOMES = YES
NO_MANUAL_EVIDENCE_ID_OR_HASH_COPYING = YES
```

P3 may prepare a bounded machine window, but only one normative human packet may be active at once.

## Raw scheduling

P3 SHALL select the next raw by:

```text
MIN_BY_BYTEWISE_ASCENDING_UTF8(
  REMAINING_NON_TERMINAL_RAW_SET
)
```

Semantic or confidence-based queue ordering is prohibited.

## Operational scheduling parameters

The recommended defaults are:

```text
MACHINE_PREPARATION_WINDOW = 5
P3_CHECKPOINT_BATCH_SIZE = 5
```

Both are:

```text
NON_NORMATIVE_OPERATIONAL_SCHEDULING_PARAMETER
```

Changing either value alone SHALL NOT change:

```text
owner semantics
complete candidate universe
source admissibility
human normative authority
human action vocabulary
terminal semantics
scoring semantics
binding semantics
ranking semantics
```

A change to these scheduling values does not require a new authority transition. It requires only
that the implementation continue to satisfy the same normative execution contract.

## Per-raw verification and checkpointing

Each raw SHALL first receive deterministic per-raw structural verification.

Pending terminal candidates may then be grouped for fresh read-only checkpoint review. The default
checkpoint size is 5; the final checkpoint may contain fewer than 5 if no remaining raws exist.

A checkpoint PASS promotes the reviewed terminal candidates to the accepted terminal ledger.
Checkpoint BLOCK quarantines the unaccepted batch and causes an execution pause. Previously accepted
records are not rolled back.

---

# 6. P3 exact execution-state partition

At every P3/P4-relevant instant, every exact Current86 raw SHALL belong to exactly one top-level
execution-state set:

```text
S_ACCEPTED_TERMINAL
S_PENDING_REVIEW
S_IN_PROGRESS_OR_INCOMPLETE
S_BLOCKED_ATTEMPT
S_NOT_STARTED_FOR_ADJUDICATION
```

Historical ledger entries are audit history. They do **not** by themselves determine current-state
membership.

Current-state membership SHALL be derived only from each raw's unique current authoritative
disposition head under the append-only disposition contract below.

## 6.1 State definitions

### ACCEPTED_TERMINAL

The raw's current authoritative disposition is `ACCEPTED_TERMINAL`, and it has exactly one
independently accepted A2 terminal record.

It SHALL NOT be automatically re-adjudicated.

Historical blocked, pending, incomplete, or failed attempts remain byte-preserved audit history and
do not make the raw a member of any other current-state set.

### PENDING_REVIEW

The raw's current authoritative disposition is `PENDING_REVIEW`.

It has exactly one **current reviewable pending terminal candidate** awaiting the required P2/P3
independent review and has not yet been promoted or substantively invalidated.

Historical stale/invalidated pending-ledger rows do not make the raw a member of
`S_PENDING_REVIEW`.

### IN_PROGRESS_OR_INCOMPLETE

The raw's current authoritative disposition is `IN_PROGRESS_OR_INCOMPLETE`.

Normative execution has started, but no current reviewable terminal candidate exists. This includes
machine-preparation/proposal/verifier/human-capture stages and controlled remediation that has
re-entered execution.

### BLOCKED_ATTEMPT

The raw is in `S_BLOCKED_ATTEMPT` iff:

```text
current authoritative disposition = BLOCKED_ATTEMPT
AND
no current reviewable pending terminal exists
AND
no accepted terminal exists
```

The fact that a historical attempt failed is insufficient.

A raw with an old failed attempt but a later current state of `PENDING_REVIEW`,
`IN_PROGRESS_OR_INCOMPLETE`, or `ACCEPTED_TERMINAL` is **not** currently blocked.

### NOT_STARTED_FOR_ADJUDICATION

The raw's current authoritative disposition is `NOT_STARTED_FOR_ADJUDICATION`.

P0 substrate may already exist, but P1/P3 normative adjudication for this raw has not started.

## 6.2 Append-only current-disposition contract

P0 SHALL materialize an exact disposition schema before runtime adjudication.

Every raw SHALL have an append-only disposition chain. Each disposition record SHALL contain at
least:

```text
schema
raw_key
disposition_type

prior_state
next_state

disposition_sequence
prior_disposition_id | null

referenced_attempt_id | null
referenced_pending_terminal_id | null
referenced_review_id | null
referenced_accepted_terminal_id | null

reason_class | null

disposition_id
```

with:

```text
disposition_id =
CANONICAL_OBJECT_ID(
  disposition_record,
  "disposition_id"
)
```

For a raw, `disposition_sequence` SHALL start from the schema-defined initial value and increase by
exactly one for each legal state transition. Each non-initial record SHALL bind the immediately prior
`disposition_id`.

The **current authoritative disposition head** for a raw is the unique valid chain head after full
chain validation. A fork, duplicate sequence, missing parent, invalid transition, or two candidate
heads is a fail-closed state-integrity error and causes `GLOBAL_PAUSE`.

The exact 86 current disposition heads form:

```text
CURRENT86_CURRENT_DISPOSITION_HEAD_SET
```

canonically ordered by `canonical_raw_key` under M1.

Its identity SHALL be frozen as:

```text
current_disposition_head_set_hash
```

and is the normative source from which all five current-state sets are reconstructed.

### 6.2.1 Required `PENDING_TERMINAL_INVALIDATED` object

When an independent checkpoint/review substantively rejects the terminal candidate itself, the
system SHALL append:

```text
PENDING_TERMINAL_INVALIDATED
```

with at least:

```text
raw_key
pending_terminal_id
blocking_review_id
invalidation_reason_class

prior_state = PENDING_REVIEW
next_state = BLOCKED_ATTEMPT

disposition_sequence
prior_disposition_id
disposition_id
```

Semantics:

```text
PENDING_REVIEW
→ append PENDING_TERMINAL_INVALIDATED
→ BLOCKED_ATTEMPT
```

The old pending terminal and its pending-ledger row remain byte-preserved audit history, but become
**stale for current-state derivation** and SHALL NOT remain in the reconstructed current
`S_PENDING_REVIEW`.

A pending row is current only when:

```text
current disposition head.next_state = PENDING_REVIEW
AND
current disposition head references that exact pending_terminal_id
```

Any older pending row for the same raw is historical and excluded from current pending membership.

### 6.2.2 Reviewer/infrastructure failure without substantive terminal invalidation

If an independent reviewer, review runtime, transport, or review infrastructure fails **without**
making a substantive determination that the terminal candidate is invalid:

```text
current state remains PENDING_REVIEW
```

and:

```text
GLOBAL_PAUSE = YES
```

No `PENDING_TERMINAL_INVALIDATED` record is appended.

The candidate remains the current reviewable pending terminal until review can be safely resumed or a
later valid review substantively disposes of it.

This rule prevents reviewer/infrastructure failure from being misclassified as a blocked raw
adjudication attempt.

### 6.2.3 Controlled remediation

Controlled remediation of a currently blocked raw SHALL append a new disposition/transition record:

```text
REMEDIATION_RESTARTED
  raw_key
  prior_state = BLOCKED_ATTEMPT
  next_state = IN_PROGRESS_OR_INCOMPLETE
  prior_disposition_id
  remediation_reference
  disposition_sequence
  disposition_id
```

Historical blocked attempts and invalidated pending terminals remain audit history only.

### 6.2.4 Acceptance disposition

When the required independent review passes and a terminal is promoted, the system SHALL append:

```text
TERMINAL_ACCEPTED
  raw_key
  prior_state = PENDING_REVIEW
  next_state = ACCEPTED_TERMINAL
  referenced_pending_terminal_id
  referenced_review_id
  referenced_accepted_terminal_id
  disposition_sequence
  prior_disposition_id
  disposition_id
```

Once `TERMINAL_ACCEPTED` is the validated current disposition head:

```text
current state = ACCEPTED_TERMINAL
```

Historical blocked/pending/incomplete attempts do not affect current-state partition membership.

## 6.3 Partition invariants

The five current-state sets SHALL be pairwise disjoint:

```text
∀ i != j: S_i ∩ S_j = ∅
```

Their union SHALL equal exact Current86:

```text
S_ACCEPTED_TERMINAL
∪ S_PENDING_REVIEW
∪ S_IN_PROGRESS_OR_INCOMPLETE
∪ S_BLOCKED_ATTEMPT
∪ S_NOT_STARTED_FOR_ADJUDICATION
=
EXACT_CURRENT86_RAW_SET
```

Therefore:

```text
|S_ACCEPTED_TERMINAL|
+ |S_PENDING_REVIEW|
+ |S_IN_PROGRESS_OR_INCOMPLETE|
+ |S_BLOCKED_ATTEMPT|
+ |S_NOT_STARTED_FOR_ADJUDICATION|
= 86
```

These sets SHALL be reconstructed from the validated
`CURRENT86_CURRENT_DISPOSITION_HEAD_SET`, not inferred from historical row presence.

## 6.4 Accepted / pending / remaining compatibility view

If a compact accounting view retains:

```text
accepted + pending + remaining = 86
```

then it SHALL define:

```text
ACCEPTED = S_ACCEPTED_TERMINAL
PENDING  = S_PENDING_REVIEW

REMAINING =
EXACT_CURRENT86_RAW_SET
minus ACCEPTED
minus PENDING
```

which is exactly:

```text
REMAINING =
S_IN_PROGRESS_OR_INCOMPLETE
∪ S_BLOCKED_ATTEMPT
∪ S_NOT_STARTED_FOR_ADJUDICATION
```

Thus blocked or incomplete raws cannot disappear from accounting.

## 6.5 State transitions

Normal transitions include:

```text
NOT_STARTED_FOR_ADJUDICATION
→ IN_PROGRESS_OR_INCOMPLETE
→ PENDING_REVIEW
→ ACCEPTED_TERMINAL
```

Technical/integrity failure before a reviewable terminal exists:

```text
IN_PROGRESS_OR_INCOMPLETE
→ BLOCKED_ATTEMPT
```

Substantive rejection of a pending terminal:

```text
PENDING_REVIEW
→ PENDING_TERMINAL_INVALIDATED
→ BLOCKED_ATTEMPT
```

Reviewer/infrastructure failure without substantive terminal invalidation:

```text
PENDING_REVIEW
→ PENDING_REVIEW
+
GLOBAL_PAUSE
```

Controlled remediation:

```text
BLOCKED_ATTEMPT
→ REMEDIATION_RESTARTED
→ IN_PROGRESS_OR_INCOMPLETE
```

A valid semantic escalation still follows the normal candidate-terminal path and may become
`ACCEPTED_TERMINAL`; it is not `BLOCKED_ATTEMPT`.

`ACCEPTED_TERMINAL` is terminal under normal execution and SHALL NOT automatically transition back
to an adjudication state.

## 6.6 Resume token

Every P3 checkpoint PASS SHALL create a hash-bound resume token containing at least:

```text
active_authority_id
execution_contract_hash

current_disposition_head_set_hash
disposition_ledger_head_hash

accepted_raw_set_hash
pending_raw_set_hash
in_progress_or_incomplete_raw_set_hash
blocked_attempt_raw_set_hash
not_started_raw_set_hash

full_partition_object_hash

accepted_count
pending_count
in_progress_or_incomplete_count
blocked_attempt_count
not_started_count

last_checkpoint_id
accepted_ledger_head_hash
pending_ledger_head_hash
attempt_ledger_head_hash

resume_token_id
```

Resume SHALL:

1. validate every per-raw disposition chain;
2. reconstruct the exact current disposition head for all 86 raws;
3. recompute `current_disposition_head_set_hash`;
4. reconstruct all five current-state sets;
5. require exact equality with every partition-set hash and count bound by the resume token.

A stale pending-ledger row that is not referenced by the current authoritative disposition head SHALL
remain audit history but SHALL NOT be reconstructed into `S_PENDING_REVIEW`.

A simple statement such as “last raw = X” is insufficient.

---

# 7. Ledgers and exactly-once semantics

The execution SHALL separate:

```text
execution_attempt_ledger.jsonl
pending_terminal_ledger.jsonl
accepted_terminal_ledger.jsonl
```

## 7.1 Attempt ledger

Records all attempts, including failures. It is diagnostic/audit evidence, not the authoritative A2
terminal set.

## 7.2 Pending terminal ledger

The pending-terminal ledger is append-only historical evidence. It contains terminal candidates that
entered review, including candidates that may later be invalidated.

**Current** `S_PENDING_REVIEW` membership SHALL NOT be derived from historical row presence.

A pending-terminal row is current only when the validated current authoritative disposition head for
that raw is `PENDING_REVIEW` and references that exact `pending_terminal_id`.

After a substantive review rejection appends `PENDING_TERMINAL_INVALIDATED`, the old pending row
remains byte-preserved but is stale and excluded from current pending-state reconstruction.

## 7.3 Accepted terminal ledger

Contains only independently accepted A2 terminal records.

The authoritative Current86 A2 result set is derived only from the accepted terminal ledger.

## 7.4 Promotion

Independent review PASS SHALL create a deterministic promotion record that references but does not
rewrite the source terminal:

```text
source_terminal_record_id
source_terminal_record_hash
independent_review_id
independent_review_hash
promotion_sequence
promotion_record_id
```

The same atomic promotion transaction SHALL append the corresponding `TERMINAL_ACCEPTED`
authoritative disposition that moves the raw from current `PENDING_REVIEW` to current
`ACCEPTED_TERMINAL`.

Promotion is not re-adjudication.

If review substantively rejects the candidate terminal, no promotion is created; instead the exact
`PENDING_TERMINAL_INVALIDATED` disposition is appended.

If review infrastructure fails without substantively invalidating the terminal, neither promotion nor
invalidation is created and the current state remains `PENDING_REVIEW` under global pause.

## 7.5 Duplicate human-decision prevention

For an immutable human packet with an already captured qualifying normative USER event:

```text
SECOND_NORMATIVE_DECISION_REQUEST = PROHIBITED
```

A crash/restart SHALL first reconstruct the existing decision/provenance before issuing another
packet.

---

# 8. P3 stop / continue policy

## 8.1 Global pause conditions

The following are system/contract integrity failures and SHALL cause:

```text
SYSTEM_INTEGRITY_FAILURE = GLOBAL_PAUSE
```

Examples:

```text
ACTIVE_AUTHORITY_MISMATCH
CURRENT86_SCOPE_DRIFT
CANDIDATE_UNIVERSE_MISMATCH
SOURCE_PROVENANCE_FAILURE
EVIDENCE_ADMISSIBILITY_FAILURE
PROPOSER_VERIFIER_ISOLATION_FAILURE
HUMAN_PROVENANCE_CAPTURE_FAILURE
TERMINAL_SCHEMA_VIOLATION
LEDGER_CONSERVATION_FAILURE
EXECUTION_CONTRACT_HASH_DRIFT
SCORING_AUTHORITY_CHANGE_DETECTED
BINDING_AUTHORITY_CHANGE_DETECTED
DENOMINATOR_CHANGE_DETECTED
```

No next human packet may be issued while the global pause remains unresolved.

## 8.2 Legitimate raw semantic escalation

A legal raw-specific semantic outcome SHALL be:

```text
LEGITIMATE_SEMANTIC_ESCALATION = TERMINAL_AND_CONTINUE
```

Examples include authority-defined ambiguity, proposer/verifier disagreement, structure escalation,
scoring-authority referral, or human `NOT_SURE_ESCALATE`.

A legal escalation SHALL NOT automatically stop unrelated raws.

## 8.3 Critical distinction

```text
SYSTEM / CONTRACT INTEGRITY FAILURE
!=
LEGITIMATE SEMANTIC ESCALATION
```

A technical execution defect SHALL NOT be disguised as an accepted escalation terminal.

---

# 9. P4 — Current86 A2 final freeze

P4 begins only when:

```text
|S_ACCEPTED_TERMINAL| = 86
|S_PENDING_REVIEW| = 0
|S_IN_PROGRESS_OR_INCOMPLETE| = 0
|S_BLOCKED_ATTEMPT| = 0
|S_NOT_STARTED_FOR_ADJUDICATION| = 0
```

and accepted raw-set equality is exact.

P4 performs no new owner decision:

```text
P4_NEW_HUMAN_OWNER_DECISION_COUNT = 0
P4_RE_ADJUDICATION_COUNT = 0
```

## 9.1 Exactly one accepted terminal per raw

P4 SHALL verify:

```text
EXACTLY_ONE_ACCEPTED_A2_TERMINAL_PER_CURRENT86_RAW = YES
```

The accepted terminal set is partitioned into:

```text
OWNER_TERMINAL_SET
ESCALATION_TERMINAL_SET
```

They SHALL be disjoint and exhaustive:

```text
OWNER_TERMINAL_SET ∩ ESCALATION_TERMINAL_SET = ∅

OWNER_TERMINAL_SET ∪ ESCALATION_TERMINAL_SET
=
EXACT_CURRENT86_RAW_SET
```

Therefore:

```text
OWNER_COUNT + ESCALATION_COUNT = 86
```

## 9.2 Process completion versus owner resolution

This distinction is normative:

```text
A2_PROCESS_COMPLETE
!=
OWNER_RESOLUTION_COMPLETE
```

P4 SHALL report separately:

```text
A2_PROCESS_TERMINAL_COUNT = 86
A2_OWNER_RESOLVED_COUNT = X
A2_ESCALATION_UNRESOLVED_COUNT = Y
X + Y = 86
```

An escalation terminal counts toward process completion but not owner closure.

## 9.3 Final freeze is not publication

```text
P4_FREEZE
!=
BINDING_PUBLICATION
```

P4 SHALL NOT modify:

```text
PROJECT_SCORING_AUTHORITY
PROJECT_BINDING_AUTHORITY
PROJECT_ACCEPTED_BINDINGS
1796 denominator
```

and SHALL NOT execute B-SO-V/P automatically.

## 9.4 Two-layer P4 identity model

P4 SHALL separate the normative A2 result identity from full delivery/package integrity.

### 9.4.1 Workload-independent normative freeze identity

The normative manifest SHALL be:

```text
FINAL_FREEZE_NORMATIVE_MANIFEST.json
```

It MAY bind only authority-bearing / adjudication-bearing normative objects required to establish
the exact Current86 A2 result, including as applicable:

```text
active B-SO-A2 authority identity
activation transaction identity
exact Current86 scope identity
execution contract identity
set-ordering registry identity
current disposition head-set identity
accepted terminal ledger identity
accepted terminal raw-set identity
owner terminal-set identity
escalation terminal-set identity
terminal-lineage identity
final normative conservation snapshot identity
P3 scale-out release identity
last accepted checkpoint / resume-state identity needed for lineage
```

It SHALL explicitly exclude:

```text
workload_summary hash
decision-time telemetry
idle/session interruption telemetry
UI/presentation metrics
performance metrics
human packet character counts used only for workload analysis
candidate-universe expansion telemetry used only for workload analysis
other NON_AUTHORITATIVE_WORKLOAD_EVIDENCE
```

The normative final-freeze identity SHALL be:

```text
CURRENT86_A2_FINAL_FREEZE_ID =
CANONICAL_OBJECT_ID(
  FINAL_FREEZE_NORMATIVE_MANIFEST,
  "CURRENT86_A2_FINAL_FREEZE_ID"
)
```

Required invariant:

```text
changing only NON_AUTHORITATIVE_WORKLOAD_EVIDENCE
MUST NOT change
CURRENT86_A2_FINAL_FREEZE_ID
```

### 9.4.2 Full package/delivery integrity identity

The final delivery package MAY still contain workload evidence.

The package SHALL therefore have a separate:

```text
FINAL_FREEZE_PACKAGE_MANIFEST.json
```

containing the complete delivery inventory and exact-byte `RAW_FILE_SHA256` for all delivery members,
including:

```text
workload_summary.json
```

The package identity SHALL be:

```text
FINAL_FREEZE_PACKAGE_MANIFEST_ID =
CANONICAL_OBJECT_ID(
  FINAL_FREEZE_PACKAGE_MANIFEST,
  "FINAL_FREEZE_PACKAGE_MANIFEST_ID"
)
```

An implementation MAY additionally record the exact archive-byte:

```text
FINAL_FREEZE_PACKAGE_INTEGRITY_SHA256
```

if an archive handoff is produced.

Required separation:

```text
workload telemetry changes
→ FINAL_FREEZE_PACKAGE_MANIFEST_ID MAY change
→ exact archive SHA256 MAY change

but

workload telemetry changes
→ CURRENT86_A2_FINAL_FREEZE_ID MUST NOT change
```

### 9.4.3 Proposed P4 package

```text
FA1B2de_Current86_BSO_A2_Final_Freeze/
  FINAL_FREEZE_NORMATIVE_MANIFEST.json
  FINAL_FREEZE_PACKAGE_MANIFEST.json

  scope/
  execution/
  ledgers/
  owner_terminal_records/
  escalation_terminal_records/
  owner_projection.jsonl
  escalation_projection.jsonl
  terminal_lineage_records.jsonl
  final_normative_conservation_snapshot.json

  workload_summary.json

  FILE_LIST.txt
  SHA256SUMS.txt
```

The package manifest and checksum inventory protect complete delivery integrity. They do not redefine
the workload-independent normative freeze identity.

P4 materialization and fresh independent P4 verification SHALL remain separate.

---

# 10. B-SO-V boundary

After P4 fresh independent verification PASS, B-SO-V may receive a self-contained handoff derived
only from the verified final freeze.

Hard boundary:

```text
BSO_V_CURRENT86_A2_INPUT =
VERIFIED_CURRENT86_A2_FINAL_FREEZE_ONLY
```

The handoff SHALL expose both:

```text
CURRENT86_A2_FINAL_FREEZE_ID
```

for normative owner/adjudication identity, and:

```text
FINAL_FREEZE_PACKAGE_MANIFEST_ID
```

(and archive-byte SHA-256 if applicable) for package/delivery integrity.

B-SO-V MAY verify both identities, but owner/binding verification SHALL pin only the
workload-independent:

```text
CURRENT86_A2_FINAL_FREEZE_ID
```

as the normative A2 result identity.

A package-integrity change caused solely by non-authoritative workload telemetry SHALL NOT alter,
invalidate, or create a different normative owner/adjudication result so long as the normative
freeze identity remains unchanged and package contents authenticate correctly.

B-SO-V SHALL NOT use unverified pending/attempt artifacts as authority input.

B-SO-V:

```text
MUST_NOT_RE_ADJUDICATE_OWNER = YES
```

Its role is verification/promotion eligibility, not a second owner-selection stage.

For escalation raws:

```text
ESCALATION_COUNTS_AS_OWNER_CLOSURE = NO
ESCALATION_IS_PUBLISHABLE_BINDING = NO
```

No B-SO-V/P execution is authorized by this design document itself.

---

# 11. Human workload boundary

All workload measurements are:

```text
NON_AUTHORITATIVE_WORKLOAD_EVIDENCE
```

They SHALL NOT alter candidate filtering, owner selection, evidence admissibility, human authority,
terminal semantics, or scoring/binding semantics.

They also SHALL NOT alter the normative P4 result identity:

```text
NON_AUTHORITATIVE_WORKLOAD_EVIDENCE
NOT_IN
FINAL_FREEZE_NORMATIVE_MANIFEST

changing only workload telemetry
MUST NOT change
CURRENT86_A2_FINAL_FREEZE_ID
```

Workload files remain eligible for the separate full package/delivery integrity identity.

## 11.1 Decision-time measurement

For a human-path raw, define:

### Start event

```text
HUMAN_DECISION_TIME_START =
first machine-recorded HUMAN_PACKET_PRESENTED event
after:
  human_packet_hash is frozen,
  packet contents are immutable,
  packet is made available to the reviewer.
```

The start event SHALL bind:

```text
raw_key
human_packet_id
human_packet_hash
presentation_event_timestamp
session/run identity
```

### End event

```text
HUMAN_DECISION_TIME_END =
timestamp of the first qualifying native USER normative decision event
that is accepted as binding to that exact human_packet_hash.
```

The end event SHALL bind:

```text
raw_key
human_packet_hash
human_action
native_user_event_identity
decision_literal_hash
```

### Raw wall-clock metric

```text
decision_wall_clock_ms =
END_timestamp_ms - START_timestamp_ms
```

This is a wall-clock latency measurement only.

## 11.2 Idle/interruption limitation

Wall-clock duration SHALL NOT automatically be interpreted as reviewer cognitive effort.

Possible contamination includes:

```text
session left idle
browser/tab unfocused
network interruption
reviewer interruption
machine suspension
long pause before response
runtime/session reconnect
```

The workload record SHALL therefore include:

```text
session_continuity_status
known_interruption_events
known_pause_duration_ms if reliably measured
measurement_interpretation
```

If continuity is not demonstrably controlled, the metric SHALL be labeled:

```text
WALL_CLOCK_LATENCY_WITH_UNCONTROLLED_IDLE_RISK
```

and SHALL NOT be described as pure cognitive review time.

If an implementation later obtains reliable active-interaction telemetry, it may report a separate
non-authoritative active-review metric, but such telemetry MUST NOT become a requirement for
adjudication validity.

## 11.3 Additional workload metrics

P1/P3 may record:

```text
candidate_count
human_packet_character_count
visible_fact_count
full_candidate_universe_expanded
human_action

manual_candidate_id_copy_count
manual_relation_id_copy_count
manual_evidence_id_copy_count
manual_hash_copy_count

relation_level_manual_outcome_count
```

Design targets:

```text
manual_candidate_id_copy_count = 0
manual_relation_id_copy_count = 0
manual_evidence_id_copy_count = 0
manual_hash_copy_count = 0

relation_level_manual_outcome_count = 0
```

A single pilot may support feasibility evidence, not a population-level percentage claim about human
time reduction.

---

# 12. Invariant registry

| ID | Invariant | Class |
|---|---|---|
| INV-001 | `NEW_BSO_A2_AUTHORITY_STATUS=ACTIVE_FOR_EXACT_CURRENT86` | FACT / EXISTING AUTHORITY |
| INV-002 | `RETURN_TO_4161_RELATION_EQ=NO` | EXISTING AUTHORITY |
| INV-003 | `CONTINUE_OLD_44_RELATION_EQ_PILOT=NO` | EXISTING AUTHORITY |
| INV-004 | Complete candidate universe preserved for every raw | EXISTING AUTHORITY |
| INV-005 | Machine proposal is non-authoritative | EXISTING AUTHORITY |
| INV-006 | Hidden pruning/top-k normative truncation prohibited | EXISTING AUTHORITY |
| INV-007 | P0: `PREPARE_86=YES`, `ADJUDICATE_86=NO` | PROPOSED EXECUTION RULE |
| INV-008 | P1 pilot is real A2 adjudication | PROPOSED EXECUTION RULE |
| INV-009 | Pilot selection is deterministic and non-semantic | PROPOSED EXECUTION RULE |
| INV-010 | P2 is fresh/read-only/independent | PROPOSED EXECUTION RULE |
| INV-011 | `PILOT_RECORD_VALIDITY` and `PILOT_SCALE_OUT_ELIGIBILITY` are distinct | PROPOSED EXECUTION RULE |
| INV-012 | Human normative unit is one raw | EXISTING AUTHORITY |
| INV-013 | Only one active normative human packet at a time | PROPOSED EXECUTION RULE |
| INV-014 | No relation-level manual outcomes | EXISTING AUTHORITY / EXECUTION RULE |
| INV-015 | No manual evidence-ID/hash copying | PROPOSED EXECUTION RULE |
| INV-016 | System/contract integrity failure causes global pause | PROPOSED EXECUTION RULE |
| INV-017 | Legitimate semantic escalation is terminal-and-continue | PROPOSED EXECUTION RULE |
| INV-018 | Current86 raw state is an exact disjoint/exhaustive partition | PROPOSED EXECUTION RULE |
| INV-019 | Blocked/incomplete raws remain in exact accounting | PROPOSED EXECUTION RULE |
| INV-020 | Resume token binds exact state partition | PROPOSED EXECUTION RULE |
| INV-021 | Exactly one accepted A2 terminal per Current86 raw at P4 completion | PROPOSED EXECUTION RULE |
| INV-022 | Owner and escalation terminal sets are disjoint | EXISTING AUTHORITY / EXECUTION RULE |
| INV-023 | Owner count + escalation count = 86 at P4 completion | PROPOSED EXECUTION RULE |
| INV-024 | `A2_PROCESS_COMPLETE != OWNER_RESOLUTION_COMPLETE` | EXISTING AUTHORITY |
| INV-025 | `P4_FREEZE != BINDING_PUBLICATION` | EXISTING AUTHORITY |
| INV-026 | B-SO-V must not re-adjudicate owner | EXISTING AUTHORITY / HANDOFF RULE |
| INV-027 | Workload metrics are non-authoritative | PROPOSED EXECUTION RULE |
| INV-028 | Private chain-of-thought is not a normative artifact | PROPOSED EXECUTION RULE |
| INV-029 | All structured IDs use one canonicalization contract | PROPOSED EXECUTION RULE |
| INV-030 | Operational window/checkpoint sizes are non-normative | PROPOSED EXECUTION RULE |
| INV-031 | Current raw state is derived from the unique current authoritative disposition head, not historical row existence | PROPOSED EXECUTION RULE |
| INV-032 | Substantively rejected pending terminals are invalidated append-only and excluded from current `S_PENDING_REVIEW` | PROPOSED EXECUTION RULE |
| INV-033 | `CURRENT86_A2_FINAL_FREEZE_ID` excludes all non-authoritative workload telemetry | PROPOSED EXECUTION RULE |
| INV-034 | Full package integrity is a separate identity and may include workload telemetry | PROPOSED EXECUTION RULE |
| INV-035 | M1 `SET_ORDERING_REGISTRY` is mandatory before any runtime identity computation | MANDATORY_P0_MATERIALIZATION_REQUIREMENT |
| INV-036 | M2 verifier precommit readable set is mechanically isolated from primary private/commitment outputs | MANDATORY_P0_MATERIALIZATION_REQUIREMENT |

---

# 13. Artifact / hash / ID registry

Concrete runtime hashes for proposed artifacts are intentionally absent because no P0/P1 runtime
materialization is authorized in this consolidation turn.

`NOT_YET_MATERIALIZED` is a status, not a placeholder permission to invent a hash.

| Artifact / object | Role | Identity rule | Current state |
|---|---|---|---|
| Active B-SO-A2 candidate | Existing authority identity | existing verified candidate ID | `36831020...f9477` |
| H2 provenance evidence | Existing authority provenance | existing verified evidence ID | `939cc0c7...ff99e` |
| Activation transaction | Existing authority activation | existing verified transaction ID | `bf4569d2...b718f` |
| `SET_ORDERING_REGISTRY` | M1 identity-bearing set ordering contract | canonical object ID | `NOT_YET_MATERIALIZED` |
| `A2_VERIFIER_ISOLATION_ENFORCEMENT_CONTRACT` | M2 mechanical verifier visibility boundary | canonical object ID | `NOT_YET_MATERIALIZED` |
| `A2_COMPUTATIONAL_CONTRACT` primary | Proposer contract | canonical object ID | `NOT_YET_MATERIALIZED` |
| `A2_COMPUTATIONAL_CONTRACT` verifier | Verifier contract | canonical object ID | `NOT_YET_MATERIALIZED` |
| `current86_a2_execution_manifest.json` | P0 root manifest | canonical object ID | `NOT_YET_MATERIALIZED` |
| `a2_pilot_selection.json` | deterministic P1 selection | canonical object ID | `NOT_YET_MATERIALIZED` |
| raw execution unit | per-raw execution substrate | canonical object ID | `NOT_YET_MATERIALIZED` |
| complete candidate universe | per-raw exact candidate set | canonical object ID | `NOT_YET_MATERIALIZED` |
| source-fact bundle | admissible evidence set | canonical object ID + file hashes | `NOT_YET_MATERIALIZED` |
| proposal input bundle | common proposer/verifier input | canonical object ID | `NOT_YET_MATERIALIZED` |
| primary commitment | primary normative machine artifact | canonical object ID | `NOT_YET_MATERIALIZED` |
| verifier commitment | independent verifier artifact | canonical object ID | `NOT_YET_MATERIALIZED` |
| comparison record | commitment comparison | canonical object ID | `NOT_YET_MATERIALIZED` |
| human packet | immutable reviewer packet | canonical object ID/hash | `NOT_YET_MATERIALIZED` |
| human decision record | raw-level human normative event binding | canonical object ID | `NOT_YET_MATERIALIZED` |
| terminal candidate | owner/escalation candidate terminal | canonical object ID | `NOT_YET_MATERIALIZED` |
| execution attempt ledger | all execution attempts | exact bytes + entry IDs | `NOT_YET_MATERIALIZED` |
| pending terminal ledger | pending independent review | exact bytes + entry IDs | `NOT_YET_MATERIALIZED` |
| accepted terminal ledger | accepted A2 terminals | exact bytes + entry IDs | `NOT_YET_MATERIALIZED` |
| raw disposition ledger / current disposition heads | append-only current-state authority | exact bytes + disposition IDs / canonical head-set hash | `NOT_YET_MATERIALIZED` |
| `PENDING_TERMINAL_INVALIDATED` disposition | stale-pending invalidation and blocked-state transition | canonical object ID | `NOT_YET_MATERIALIZED` |
| ledger snapshot | state-set conservation snapshot | canonical object ID | `NOT_YET_MATERIALIZED` |
| resume token | restart contract | canonical object ID | `NOT_YET_MATERIALIZED` |
| checkpoint review | fresh read-only P3 review | canonical object ID + file hashes | `NOT_YET_MATERIALIZED` |
| `FINAL_FREEZE_NORMATIVE_MANIFEST` | workload-independent normative P4 result manifest | canonical object ID | `NOT_YET_MATERIALIZED` |
| `CURRENT86_A2_FINAL_FREEZE_ID` | workload-independent verified P4 normative identity | canonical object ID | `NOT_YET_MATERIALIZED` |
| `FINAL_FREEZE_PACKAGE_MANIFEST` | full delivery/package inventory including workload evidence | canonical object ID | `NOT_YET_MATERIALIZED` |
| `FINAL_FREEZE_PACKAGE_MANIFEST_ID` | delivery/package integrity identity | canonical object ID | `NOT_YET_MATERIALIZED` |
| B-SO-V handoff | verified-final-freeze handoff | exact archive bytes + manifest ID | `NOT_YET_MATERIALIZED` |

---

# 14. Fail-closed gate registry

The following gate registry is the consolidated minimum.

| Gate | Stage | Requirement | Failure disposition |
|---|---|---|---|
| G0 | P0/P1/P3 | Active B-SO-A2 authority exact | global block/pause |
| G1 | P0/P1/P3/P4 | Exact Current86 scope object/set equality | global block/pause |
| G2 | per raw | Canonical raw identity exact | raw blocked; global pause if systemic |
| G3 | per raw | Complete candidate universe exact | global pause |
| G4 | per raw | Source provenance/admissibility exact | raw block or global pause; never silent fallback |
| G5 | P1/P3 | Primary computational contract/input/output valid | raw blocked |
| G6 | P1/P3 | Verifier isolation and independent commitment valid | raw blocked / no human confirmation |
| G7 | P1/P3 | Proposer/verifier comparison recomputes | no human confirmation on mismatch |
| G8 | P1/P3 | Human packet exact and immutable | raw blocked |
| G9 | P1/P3 | Native human provenance valid when human path used | raw blocked |
| G10 | P1/P3 | Terminal schema/nullability/unresolved semantics valid | raw blocked |
| G11 | P1/P3 | Disposition-chain validity + ledger/state-partition conservation exact | global pause |
| G12 | P2 | Pilot review fresh/read-only/independent | no pilot promotion |
| G13 | P2 | Pilot record validity PASS | no accepted pilot terminal if fail |
| G14 | P2 | Human path exercised for scale-out | no P3 release if not exercised |
| G15 | P3 | Scale-out release binds exact unchanged execution contract | P3 blocked |
| G16 | P3 | Per-raw deterministic verification | terminal remains pending |
| G17 | P3 | Fresh checkpoint review PASS | no promotion for affected batch |
| G18 | P3 | Resume token exact disposition-head set + partition equality | resume blocked |
| G19 | P4 | Exactly one accepted terminal per raw | P4 blocked |
| G20 | P4 | Owner/escalation disjointness and exhaustiveness | P4 blocked |
| G21 | P4 | Terminal lineage complete and cross-raw consistent | P4 blocked |
| G22 | P4 | Human provenance conservation | P4 blocked |
| G23 | P4 | Complete candidate-universe conservation 86/86 | P4 blocked |
| G24 | P4 | Workload-independent normative final-freeze ID recomputation | P4 blocked |
| G25 | all | No scoring/binding/denominator/publication mutation | global block |
| G26 | P4 | Non-authoritative workload excluded from normative freeze identity; package identity verified separately | P4 blocked |

Fail-closed always means:

```text
NO OWNER FREEZE THROUGH FALLBACK
NO SILENT NEAREST-CANDIDATE SUBSTITUTION
NO DEFAULT APPROVAL
NO BINDING PUBLICATION
```

---

# 15. State machine

## 15.1 Phase-level state machine

```text
ACTIVE B-SO-A2 AUTHORITY
        |
        v
P0 PREPARE EXACT CURRENT86
        |
        | PREPARE_86=YES / ADJUDICATE_86=NO
        v
P1 DETERMINISTIC REAL PILOT
        |
        v
P2 FRESH INDEPENDENT PILOT REVIEW
        |
        +-------------------- BLOCKED --------------------+
        |                                                 |
        |                                      targeted remediation
        |                                                 |
        |                                                 v
        |                                               P1/P2
        |
        +-- PASS / human path not exercised
        |         |
        |         v
        |  deterministic pilot continuation
        |
        +-- PASS / human path exercised
                  |
                  v
          HUMAN P3 SCALE-OUT RELEASE
                  |
                  v
P3 REMAINING NON-TERMINAL RAWS
  one human raw at a time
  bounded machine preparation
  fresh checkpoint review
                  |
                  | accepted terminals = 86
                  v
STOP P3
                  |
                  v
P4 FINAL FREEZE MATERIALIZATION
                  |
                  v
FRESH P4 INDEPENDENT VERIFICATION
                  |
             +----+----+
             |         |
          BLOCKED     PASS
             |         |
             |         v
       remediation   VERIFIED CURRENT86 A2 FINAL FREEZE
                       |
                       v
                 PREPARE B-SO-V HANDOFF
                       |
                       v
                      STOP
```

## 15.2 Raw-level state machine

```text
NOT_STARTED_FOR_ADJUDICATION
        |
        | append legal start disposition
        v
IN_PROGRESS_OR_INCOMPLETE
        |
        +---- technical/integrity failure ----> BLOCKED_ATTEMPT
        |                                         |
        |                                         | append REMEDIATION_RESTARTED
        |                                         v
        |<----------------------------------------+
        |
        | reviewable owner/escalation terminal candidate
        v
PENDING_REVIEW
        |
        +---- review infrastructure failure
        |         without terminal invalidation
        |               |
        |               +----> remain PENDING_REVIEW + GLOBAL_PAUSE
        |
        +---- substantive review reject
        |               |
        |               v
        |     append PENDING_TERMINAL_INVALIDATED
        |               |
        |               v
        |        BLOCKED_ATTEMPT
        |
        +---- review PASS
        |               |
        |               v
        |       append TERMINAL_ACCEPTED
        v
ACCEPTED_TERMINAL
```

The raw's current state is determined only by the unique validated current authoritative disposition
head. Historical attempt/pending/blocked rows remain immutable audit history but do not independently
create current-state membership.

`ACCEPTED_TERMINAL` may contain either a valid owner terminal or a valid escalation terminal.

---

# 16. No new authority layer

This document is deliberately subordinate to the already-active B-SO-A2 authority.

It SHALL NOT create:

```text
H3
H4
another workflow architecture authority
another supersession authority
another scoring authority
another binding authority
```

If independent design review finds no genuine authority incompatibility, the intended governance path
is only:

```text
formal consolidated design
→ independent design review
→ one explicit human acceptance if required
→ P0/P1 execution-contract materialization
```

A new authority-transition layer is justified only if independent review identifies a real
incompatibility with the already-active authority that cannot be solved as subordinate execution
semantics.

---

# 17. Explicit non-actions of this design turn

This consolidation does not authorize or perform:

```text
P0 execution
P1 pilot execution
primary proposer execution
independent verifier execution
raw-level human decision
adjudication ledger writes
P2 execution
P3 execution
P4 execution
B-SO-V execution
B-SO-P execution

scoring authority mutation
binding authority mutation
binding publication
accepted binding change
1796 denominator change

replay
experiment
paper modification
```

---

# 18. Terminal design status

```text
R2_PATCH_STATUS = COMPLETE_DESIGN_ONLY

B1_CURRENT_STATE_DISPOSITION =
CLOSED_BY_DESIGN_PATCH

B2_NORMATIVE_FREEZE_IDENTITY_SEPARATION =
CLOSED_BY_DESIGN_PATCH

MANDATORY_P0_MATERIALIZATION_REQUIREMENT_M1 =
SET_ORDERING_REGISTRY_BEFORE_RUNTIME_ID_COMPUTATION

MANDATORY_P0_MATERIALIZATION_REQUIREMENT_M2 =
MECHANICALLY_ENFORCED_VERIFIER_PRECOMMIT_VISIBILITY_ISOLATION

DESIGN_STATUS = PROPOSED_NOT_EXECUTED

P0_EXECUTED = NO
P1_EXECUTED = NO
RAW_LEVEL_HUMAN_DECISIONS = 0

P2_EXECUTED = NO
P3_EXECUTED = NO
P4_EXECUTED = NO

BINDING_PUBLICATION = NO
BSO_V_EXECUTED = NO
BSO_P_EXECUTED = NO

SCORING_AUTHORITY_MUTATION = NO
BINDING_AUTHORITY_MUTATION = NO

RETURN_TO_4161_RELATION_EQ = NO
CONTINUE_OLD_44_RELATION_EQ_PILOT = NO

NEXT_ACTION =
TARGETED_INDEPENDENT_DESIGN_REVIEW_OF_TWO_R2_PATCHES_ONLY
```
