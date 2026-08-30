# E0-C Continuation — Authenticate Exact-1796 Raw Corpus and Build PROVX Replay Readiness

Continue the existing EXP-E0-C session. Do NOT restart the task from scratch.

## Newly established local facts

The authoritative raw source corpus is present at:

`/home/cph/experiment/APT数据集/playbooks`

Observed:
- JSON playbook files = 53
- playbook schema uses top-level `pipeline`
- each pipeline stage contains `actions`

An existing derived registry is present at:

`/home/cph/experiment-worktrees/full-action-protocol-binding/data/full_action/raw_action_registry.jsonl`

Observed:
- row count = 1796
- parse errors = 0
- unique `raw_action_key` count = 1796
- duplicate raw keys = 0
- invalid raw keys = 0
- first keys follow positional identity such as `6000002::S01::A001`

A historical protocol release is present at:

`/home/cph/experiment-worktrees/full-action-protocol-binding/data/full_action/protocol_release.json`

Its raw-side section records:
- protocol_id = `FULL_ACTION_PROTOCOL_V2`
- coverage_policy = `ALL_RAW_ACTIONS`
- raw corpus source file count = 53
- raw corpus playbooks root = `APT数据集/playbooks`
- raw corpus source commit = `a699ebe4fa14cf25768fd0e5475b994a72b60dec`
- raw corpus manifest SHA256 =
  `d52db285fc38deb0430ee32fad24b37e54e2f2b95f6f0ac35b96a42754725efa`

IMPORTANT:
The same historical protocol release records an old scoring snapshot:
- scoring_record_count = 1772
- scoring_commit = `0cc73de7c86cebb787e294a991984ef44ad4693e`

These scoring-side fields are historical/stale for the current project.
DO NOT use them as current scoring authority.
E0-C is raw-experiment preparation and must keep raw-side authority separate from current scoring/binding authority.

The current filesystem-level corpus SHA256SUMS file has:
- 53 entries
- SHA256SUMS file SHA256 =
  `57b8172ee5940a40448855349d23096a3385c4e27c36b6811efa3bf8a85f8605`

This checksum-list hash is evidence of the currently observed filesystem contents only.
Do not assume it equals the historical protocol `manifest_sha256`; determine the exact historical manifest construction before comparing them.

## Goal

Authenticate the exact 1796 raw population from source corpus and registry, then build the PROVX replay-readiness matrix only if the raw-side conservation checks pass.

Do not require a pre-existing "authoritative 1796 ledger" beyond the authenticated source corpus + mechanically verified derived registry.

---

## Phase C1 — Independently count the raw corpus from source JSON

Read all 53 files under:

`/home/cph/experiment/APT数据集/playbooks/*.json`

Use the actual schema:

- stages = top-level `pipeline`
- actions = each stage's `actions`

Mechanically compute:
- playbook count
- stage count
- raw action count
- per-playbook stage/action counts

Require:
- exactly 53 playbooks
- exact raw count = 1796
- unique positional raw keys = 1796

Construct positional raw keys strictly as:

`{playbook_id}::S{stage_index:02d}::A{action_index:03d}`

where stage/action indices are derived from exact source ordering, not UUID/VID sorting.

Do not guess or normalize missing stages/actions.

Record any malformed source object and fail closed.

---

## Phase C2 — Source-corpus identity verification

For each playbook source file:
- compute actual SHA256;
- compare it against every corresponding `source_file_sha256` value appearing in the derived registry;
- require all rows for the same source file to agree on one source SHA;
- require that SHA to equal the current source file bytes.

Verify the registry's `source_file` and `source_locator` point to the exact action from which each row is derived.

If the historical raw-corpus `manifest_sha256` construction is available in code or documentation, independently reproduce it and compare to:

`d52db285fc38deb0430ee32fad24b37e54e2f2b95f6f0ac35b96a42754725efa`

If its construction cannot be authenticated, report:

`HISTORICAL_RAW_MANIFEST_RECOMPUTATION = NOT_REPRODUCIBLE_FROM_AVAILABLE_RULE`

but continue only if per-file SHA and row-by-row source derivation are exact.

Do NOT substitute the checksum-list-file hash
`57b8172e...`
for the historical manifest hash unless the manifest rule explicitly defines that construction.

---

## Phase C3 — Independently verify derived raw-action registry

Read:

`/home/cph/experiment-worktrees/full-action-protocol-binding/data/full_action/raw_action_registry.jsonl`

For every one of the 1796 rows, independently recompute from the source corpus:

- `playbook_id`
- `stage_index`
- `action_index`
- `raw_action_key`
- `source_file`
- `source_file_sha256`
- source locator
- action name/description/type where mechanically derivable
- OS and ATT&CK fields only where represented in the source

Then compare source-derived values against the registry.

Require:

```text
SOURCE_DERIVED_RAW_COUNT = 1796
REGISTRY_ROW_COUNT = 1796
SOURCE_DERIVED_UNIQUE_RAW_KEYS = 1796
REGISTRY_UNIQUE_RAW_KEYS = 1796
MISSING_IN_REGISTRY = 0
EXTRA_IN_REGISTRY = 0
RAW_KEY_MISMATCH = 0
SOURCE_FILE_SHA_MISMATCH = 0
SOURCE_LOCATOR_MISMATCH = 0
```

Do not trust the registry merely because it has 1796 lines.

---

## Phase C4 — Raw-side authority decision

Only if C1-C3 pass, declare:

```text
EXP_E0_C_RAW_AUTHORITY =
AUTHENTICATED_SOURCE_CORPUS_PLUS_VERIFIED_DERIVED_REGISTRY

EXP_E0_C_CONSERVATION =
PASS_1796
```

The historical `protocol_release.json` may be cited only for its authenticated raw-side protocol metadata.

Explicitly record:

```text
HISTORICAL_PROTOCOL_SCORING_METADATA =
NOT_CURRENT_AUTHORITY
```

Do not use:
- historical `scoring_record_count = 1772`;
- historical `scoring_commit = 0cc73de...`;
- any historical scoring hashes

to alter the current project scoring/binding state.

---

## Phase C5 — Build full 1796 PROVX replay-readiness matrix

After C4 PASS, create exactly one record per authenticated raw action.

Outputs:

- `EXP_E0_C_1796_PROVX_REPLAY_READINESS.jsonl`
- `EXP_E0_C_1796_PROVX_REPLAY_READINESS.csv`

Each record must contain:

### Raw identity
- `raw_key`
- `playbook_id`
- `stage_index`
- `action_index`
- `action_name`
- `action_description`
- `action_type`
- `source_file`
- `source_file_sha256`
- `source_locator`

### Experiment requirements
- `source_node_role`
- `target_node_role`
- `required_os_or_host_class`
- `required_service_class`
- `required_protocol`
- `required_preconditions`
- `stimulus_class`
- `candidate_fidelity`:
  - NATIVE
  - EMULATED
  - SYNTHETIC
  - NOT_YET_EXECUTABLE
- `why_this_fidelity`
- `defensive_equivalence_requirements`
- `telemetry_equivalence_requirements`
- `action_success_criterion`
- `cleanup_reset_requirement`
- `repeatability_requirement`
- `environment_blockers`

If an experimental field cannot be mechanically determined from authenticated source/evidence, use `UNKNOWN` or an explicit blocker. Do not hallucinate implementation details.

### PROVX observation contract
- `provx_expected_entity_types`
- `provx_expected_causal_edge_classes`
- `provx_required_host_audit_events`
- `provx_expected_network_to_host_correlation`
- `provx_alert_subgraph_acquisition_requirement`
- `provx_phase1_observable`
- `provx_phase2_core_edge_localizable`
- `provx_real_enforcement_mapping_available`
- `provx_observation_blocker`

Do not fabricate provenance events merely to make a raw action "observable."

### Four separate result dimensions

Reserve fields for:
1. `attack_action_success`
2. `provx_phase1_detection`
3. `provx_phase2_core_edge_localization_or_model_flip`
4. `real_enforcement_prevention`

For this preparation task, these remain unexecuted/not observed.

Never equate:
`PROVX MER / prediction flip`
with:
`REAL PREVENTED/BLOCKED`.

### Authority/reference metadata
- `raw_authority_status = AUTHENTICATED`
- current binding/scoring references may be included only if a current authoritative source is explicitly available
- if not available, use `UNKNOWN_NOT_RESOLVED_IN_E0_C`
- never use the historical protocol's scoring snapshot as current authority

Set:
`formal_execution_authorized = false`

---

## Phase C6 — Conservation / blocker reports

Create:

- `EXP_E0_C_CONSERVATION_AUDIT.json`
- `EXP_E0_C_PROVX_OBSERVABILITY_SUMMARY.json`
- `EXP_E0_C_BLOCKER_SUMMARY.md`
- `EXP_E0_C_RAW_AUTHORITY_AUTHENTICATION_REPORT.md`

Required counts:

```text
RAW_RECORD_COUNT = 1796
UNIQUE_RAW_KEY_COUNT = 1796
MISSING_RAW_COUNT = 0
EXTRA_RAW_COUNT = 0
DUPLICATE_RAW_KEY_COUNT = 0
```

Also summarize by:
- playbook
- candidate fidelity
- OS/host requirement
- PROVX Phase-I observability
- PROVX Phase-II localizability
- environment blockers

No formal experiment execution occurs.

---

## Hard boundaries

DO NOT:

- execute any raw action;
- execute source-auth;
- execute Current86 P0/P1;
- make human binding decisions;
- mutate binding authority;
- mutate scoring authority;
- change accepted binding count;
- change denominator;
- rewrite historical protocol/scoring data;
- mutate Git refs;
- download/install experiment dependencies.

---

## Required terminal

```text
EXP_E0_C_RAW_AUTHORITY =
AUTHENTICATED_SOURCE_CORPUS_PLUS_VERIFIED_DERIVED_REGISTRY
|
BLOCKED

EXP_E0_C_CONSERVATION =
PASS_1796 | BLOCKED

RAW_RECORD_COUNT =
1796 | <actual if blocked>

UNIQUE_RAW_KEY_COUNT =
1796 | <actual if blocked>

HISTORICAL_PROTOCOL_SCORING_METADATA =
NOT_CURRENT_AUTHORITY

FORMAL_EXPERIMENT_EXECUTED = NO
BINDING_AUTHORITY_MUTATION = NO
SCORING_AUTHORITY_MUTATION = NO
DENOMINATOR_CHANGE = NO

NEXT_ACTION =
FRESH_REVIEW_OF_EXP_E0_C_1796_PROVX_REPLAY_READINESS
|
FIX_EXACT_RAW_AUTHORITY_DEFECT

STOP = true
```
