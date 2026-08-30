# Prompt 3 — EXP-E0-C Full-1796 PROVX Replay Readiness Matrix

You are preparing the FA1B2de formal experiment.

This task is **read-only replay/readiness modeling only**.

The experiment protocol denominator is:

```text
53 playbooks
1796 raw actions
1796 / 1796 protocol coverage required
```

Do not use an older 1758-action scoring/annotation snapshot as the raw-action denominator.

## Goal

Construct one experiment-readiness record for every one of the exact 1796 raw actions.

No raw action may disappear because:

- its binding is unresolved;
- multiple raws map to one scoring opportunity;
- the action is difficult to reproduce;
- the action requires downgraded fidelity.

## A. Authority first

Locate and authenticate the current authoritative 1796 raw-action population / raw ledger.

If exact 1796 authority cannot be found or authenticated:

```text
EXP_E0_C_CONSERVATION = BLOCKED
```

and stop rather than reconstructing 1796 from guesses.

Stable raw identity must remain:

`{playbook_id}::S{stage:02d}::A{action:03d}`

Do not replace positional identity with UUID/VID/scoring ID.

## B. Required record for every raw action

Create one record with at least:

### Identity

- `raw_key`
- `playbook_id`
- `stage_index`
- `action_index`
- authoritative raw action text/description
- ATT&CK fields only when authoritative

### Experiment roles

- `source_node_role`
- `target_node_role`
- `required_os_or_host_class`
- `required_service_class`
- `required_protocol`
- `required_preconditions`

### Replay design

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

Do not design uncontrolled real-world attack delivery. Stay within an isolated, controlled experiment design.

## C. PROVX-specific observation contract

The fixed defense system is PROVX.

For each raw record additionally derive:

- `provx_expected_entity_types`
  - PROCESS
  - FILE
  - SOCKET
  - OTHER
  - NONE
  - UNKNOWN
- `provx_expected_causal_edge_classes`
- `provx_required_host_audit_events`
- `provx_expected_network_to_host_correlation`
- `provx_alert_subgraph_acquisition_requirement`
- `provx_phase1_observable`
- `provx_phase2_core_edge_localizable`
- `provx_real_enforcement_mapping_available`
- `provx_observation_blocker`

Do not fabricate a process/file/socket edge merely to make an action visible to PROVX.

If an action is predominantly network-level and host provenance does not directly expose it, mark the observation gap explicitly.

## D. Keep four result dimensions separate

Every future formal run must distinguish:

1. `attack_action_success`
2. `provx_phase1_detection`
3. `provx_phase2_core_edge_localization_or_model_flip`
4. `real_enforcement_prevention`

Never convert:

`PROVX prediction flip / MER`

into:

`real PREVENTED/BLOCKED`

without a separately implemented and observed enforcement action.

## E. Evidence requirements

For every raw action specify required evidence such as:

- run manifest
- stdout/stderr if applicable
- process/event logs
- file audit records
- socket/connect records
- PCAP
- provenance graph fragment
- Phase-I alert output
- Phase-II core-edge output
- model-level intervention result
- enforcement result if separately implemented
- reset evidence.

## F. Binding/scoring references

You may include current binding/scoring linkage only as **reference metadata**.

Do NOT:

- infer missing binding decisions;
- publish bindings;
- change scoring IDs;
- change accepted binding count;
- drop unresolved raws.

## G. Conservation audit

Require:

```text
RAW_RECORD_COUNT = 1796
UNIQUE_RAW_KEY_COUNT = 1796
MISSING_RAW_COUNT = 0
EXTRA_RAW_COUNT = 0
DUPLICATE_RAW_KEY_COUNT = 0
```

Also produce breakdowns by:

- playbook
- stage
- candidate fidelity
- required OS/host class
- PROVX observability
- unresolved environment blocker.

## Required outputs

- `EXP_E0_C_1796_PROVX_REPLAY_READINESS.jsonl`
- `EXP_E0_C_1796_PROVX_REPLAY_READINESS.csv`
- `EXP_E0_C_CONSERVATION_AUDIT.json`
- `EXP_E0_C_PROVX_OBSERVABILITY_SUMMARY.json`
- `EXP_E0_C_BLOCKER_SUMMARY.md`

## Hard boundaries

DO NOT:

- execute any raw action;
- execute source-auth;
- execute P0/P1;
- make human binding decisions;
- publish binding changes;
- mutate scoring authority;
- change denominator;
- mutate Git refs.

Set on every record:

`formal_execution_authorized = false`

## Required terminal

```text
EXP_E0_C_CONSERVATION =
PASS_1796 | BLOCKED

RAW_RECORD_COUNT =
1796 | <actual if blocked>

FORMAL_EXPERIMENT_EXECUTED = NO
BINDING_AUTHORITY_MUTATION = NO
SCORING_AUTHORITY_MUTATION = NO
DENOMINATOR_CHANGE = NO

STOP = true
```
