# Prompt 4 — EXP-E0C-R2 High-Coverage Adapter Contract Design

Continue from accepted EXP-E0C-R1 planning substrate.

Frozen denominator:
`1796`

R1 planning facts:
- 13 archetypes;
- 589 `REQUIRES_MANUAL_DESIGN`;
- formal execution remains unauthorized.

## Goal

Design non-executable adapter contracts for the highest-coverage reusable families.

Do not implement or execute attack behavior yet.

Prioritize:

1. PROCESS_COMMAND_EXECUTION — 712 raws
2. NETWORK_SERVICE_INTERACTION — 232 raws
3. TRANSFER_DOWNLOAD_UPLOAD — 166 raws
4. EMAIL_DELIVERY — 105 raws
5. NETWORK_C2_BEACON — 103 raws

## 1. Exact member manifests

For each family:
- list exact raw keys;
- conserve counts to R1;
- list playbooks/stages;
- list source-derived OS/protocol/service prerequisites;
- list manual-design members separately.

## 2. Adapter contract schema

For each family define:

- adapter ID/version;
- applicable raw-key set commitment;
- input parameters;
- required source/target roles;
- preconditions;
- environment/service fixtures;
- execution result schema;
- run ID/raw key binding;
- cleanup/reset;
- evidence artifacts;
- timeout/error semantics;
- fail-closed behavior.

No command implementation is needed.

## 3. Defensive-equivalence contract

For Native/Emulated/Synthetic candidate modes define what must remain equivalent from the defense perspective:

- process ancestry where applicable;
- file/socket entity classes;
- network direction/protocol;
- timing/sequence constraints;
- observable causality;
- side effects required for the same defensive decision point;
- what may safely differ.

If equivalence cannot be stated, route to `MANUAL_DESIGN`.

## 4. PROVX telemetry contract

For each adapter family define future telemetry requirements:

- process events;
- file events;
- socket events;
- packets;
- logical-host attribution;
- provenance nodes/edges expected at adapter interface;
- reversible mapping to `raw_key/run_id`.

Do not claim Phase-I detection or Phase-II localization.

## 5. Mininet compatibility

Classify:

```text
PLAIN_MININET_CANDIDATE
REQUIRES_HOST_PROVENANCE_VALIDATION
REQUIRES_WINDOWS_OR_EXTERNAL_HOST_SEMANTICS
MANUAL_DESIGN
```

Do not select VM/container architecture yet.

## 6. Coverage accounting

Compute cumulative exact coverage addressable if contracts are later implemented.

Separate:
- contract-covered candidate rows;
- manual-design rows;
- unresolved prerequisites.

Do not call contract-covered rows executable.

## 7. Manual-design blocker taxonomy

For all 589 manual rows, classify source-supported blockers such as:
- missing exact command semantics;
- privileged action;
- credential-sensitive;
- destructive state;
- Windows-only semantics;
- service/environment absent;
- ambiguous source wording;
- multi-step/composite;
- other.

## Outputs

- `E0C_R2_ADAPTER_FAMILY_MANIFESTS.json`
- `E0C_R2_ADAPTER_CONTRACTS.json`
- `E0C_R2_DEFENSIVE_EQUIVALENCE_CONTRACTS.json`
- `E0C_R2_PROVX_TELEMETRY_CONTRACTS.json`
- `E0C_R2_MANUAL_DESIGN_BLOCKERS.json`
- `E0C_R2_COVERAGE_AUDIT.json`
- `E0C_R2_ADAPTER_DESIGN_REPORT.md`

## Hard boundaries

No attack execution, command implementation, formal benchmark outcome,
PROVX detectability claim, authority mutation, or denominator change.

## Terminal

```text
E0C_R2_ADAPTER_DESIGN =
PASS | BLOCKED

RAW_DENOMINATOR = 1796
TARGET_FAMILY_MEMBER_CONSERVATION = PASS | BLOCKED

CONTRACT_COVERED_CANDIDATE_ROWS = <n>
MANUAL_DESIGN_ROWS = <n>
UNRESOLVED_PREREQUISITE_ROWS = <n>

FORMAL_EXPERIMENT_EXECUTED = NO
DENOMINATOR_CHANGE = NO

NEXT_ACTION =
FRESH_REVIEW_OF_E0C_R2_ADAPTER_CONTRACTS

STOP = true
```
