# Prompt 4 — EXP-E0C-R1 Exact-1796 Execution-Archetype Enrichment

Continue from the accepted EXP-E0-C conservation result:

```text
RAW_AUTHORITY = AUTHENTICATED_SOURCE_CORPUS_PLUS_VERIFIED_DERIVED_REGISTRY
RAW_RECORD_COUNT = 1796
UNIQUE_RAW_KEY_COUNT = 1796
CONSERVATION = PASS_1796
```

Do not rebuild or change the denominator.

## Goal

Transform the conservation-only readiness matrix into an **evidence-bound execution-planning substrate** by grouping all 1796 raws into reproducible execution/prerequisite archetypes.

This is still preparation only.
Do not execute actions.

## 1. Inputs

Use:
- authenticated source playbooks;
- verified raw_action_registry;
- current E0-C 1796 readiness matrix;
- existing local experiment feasibility/run-plan artifacts if present.

Historical feasibility/run-plan data is reference evidence only. Do not treat old VM-specific implementation choices as mandatory for the new Mininet/PROVX experiment.

Do not use stale historical scoring metadata as current authority.

## 2. Exact source-evidenced enrichment

For every raw, populate only where explicitly supported by source fields:

- OS/platform hints;
- action type;
- ATT&CK IDs;
- tool/malware name where explicit;
- named protocol/service where explicit;
- network versus host/local behavior indicators;
- obvious input/output resource class;
- neighboring stage context only as context, not as invented action semantics.

For unsupported values use `UNKNOWN`.

Record provenance for every non-UNKNOWN derived planning field:
- source field/path;
- exact source wording/value;
- derivation rule ID.

## 3. Execution archetypes

Create deterministic planning archetypes such as structural classes, but derive the final catalog from the data rather than forcing this example list:

- process/command execution;
- file create/read/write/delete;
- network connect/beacon;
- HTTP/DNS/SMB/SSH/etc. service interaction where explicit;
- download/upload/transfer;
- credential-store access;
- persistence/configuration;
- discovery/enumeration;
- privilege/account action;
- archive/compress;
- registry/service/task action;
- mixed/composite action;
- unsupported/unknown.

A raw may have one primary archetype plus secondary prerequisite tags only when mechanically supported.

Do not split a raw into new scoring/binding units.

## 4. Mininet/PROVX planning dimensions

For each raw derive conservative planning flags:

- `requires_network_fabric`
- `requires_host_process_telemetry`
- `requires_file_telemetry`
- `requires_socket_telemetry`
- `requires_external_service_emulation`
- `requires_windows_semantics`
- `requires_linux_semantics`
- `requires_privileged_host_action`
- `provx_candidate_observation_surface`

These are requirements, not observed results.

Do not mark PROVX detectable/localizable until live/artifact evidence exists.

Keep:
- `provx_phase1_observable = UNKNOWN`
- `provx_phase2_core_edge_localizable = UNKNOWN`
unless a later authenticated PROVX artifact rule mechanically establishes otherwise.

## 5. Fidelity planning

Do not leave every row `NOT_YET_EXECUTABLE` if source evidence is sufficient to classify a **candidate planning mode**.

Use a separate field:

`candidate_execution_mode_for_design`

Allowed:
- `NATIVE_CANDIDATE`
- `EMULATED_CANDIDATE`
- `SYNTHETIC_CANDIDATE`
- `REQUIRES_MANUAL_DESIGN`
- `UNKNOWN`

This is not authorization and not final fidelity.

For any non-UNKNOWN candidate mode, include exact rationale and defensive/telemetry-equivalence constraints.

No unsafe real-world implementation detail is required in this task.

## 6. Adapter backlog

Aggregate the 1796 rows into a minimal implementation backlog:

For each adapter family report:
- exact raw count;
- playbooks covered;
- OS/service prerequisites;
- telemetry requirements;
- candidate execution modes;
- representative raw keys;
- unresolved design questions.

Create a prioritized order based on:
1. raw coverage;
2. reuse across playbooks;
3. compatibility with Mininet;
4. compatibility with future PROVX provenance collection;
5. implementation complexity.

Do not prioritize based on scoring weight.

## 7. Conservation

All enriched outputs must conserve exactly the same 1796 raw keys.

No binding/scoring changes.

## Outputs

- `EXP_E0C_R1_1796_ENRICHED_READINESS.jsonl`
- `EXP_E0C_R1_1796_ENRICHED_READINESS.csv`
- `EXP_E0C_R1_EXECUTION_ARCHETYPE_CATALOG.json`
- `EXP_E0C_R1_ADAPTER_BACKLOG.json`
- `EXP_E0C_R1_DERIVATION_RULES.json`
- `EXP_E0C_R1_CONSERVATION_AUDIT.json`
- `EXP_E0C_R1_PLANNING_REPORT.md`

## Hard boundaries

DO NOT:
- execute actions;
- assign formal benchmark outcomes;
- claim PROVX detection/localization;
- mutate binding/scoring authority;
- change denominator;
- mutate Git refs.

Every row remains:
`formal_execution_authorized = false`

## Terminal

```text
EXP_E0C_R1_CONSERVATION = PASS_1796 | BLOCKED
RAW_RECORD_COUNT = 1796
UNIQUE_RAW_KEY_COUNT = 1796

EXECUTION_ARCHETYPE_COUNT = <n>
REQUIRES_MANUAL_DESIGN_COUNT = <n>
UNKNOWN_PLANNING_COUNT = <n>

FORMAL_EXPERIMENT_EXECUTED = NO
DENOMINATOR_CHANGE = NO
BINDING_AUTHORITY_MUTATION = NO
SCORING_AUTHORITY_MUTATION = NO

NEXT_ACTION =
FRESH_REVIEW_OF_EXP_E0C_R1_EXECUTION_ARCHETYPE_ENRICHMENT

STOP = true
```
