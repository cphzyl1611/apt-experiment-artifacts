# EXP-E0C-R2 High-Coverage Adapter Contract Design

Non-executable adapter contracts derived from the accepted R1 exact-1,796 planning substrate.

## Terminal State

- `E0C_R2_ADAPTER_DESIGN = PASS`
- `RAW_DENOMINATOR = 1796`
- `TARGET_FAMILY_MEMBER_CONSERVATION = PASS`
- `CONTRACT_COVERED_CANDIDATE_ROWS = 945`
- `MANUAL_DESIGN_ROWS = 589`
- `UNRESOLVED_PREREQUISITE_ROWS = 4`
- `FORMAL_EXPERIMENT_EXECUTED = NO`
- `DENOMINATOR_CHANGE = NO`
- `BINDING_AUTHORITY_MUTATION = NO`
- `SCORING_AUTHORITY_MUTATION = NO`
- `NEXT_ACTION = FRESH_REVIEW_OF_E0C_R2_ADAPTER_CONTRACTS`
- `STOP = true`

## Scope and Boundaries

- Contracts are design interfaces only. No command implementation or attack behavior is present.
- Contract-covered candidate rows are not executable and retain `formal_execution_authorized = false` in R1.
- PROVX Phase-I/Phase-II observability and localization remain UNKNOWN; no benchmark result is assigned.
- Binding and scoring authority, including the 1,796 denominator, is unchanged.

## Target Families

| Family | Raw rows | Candidate rows | Manual rows | Playbooks | Mininet class |
|---|---:|---:|---:|---:|---|
| `PROCESS_COMMAND_EXECUTION` | 712 | 373 | 339 | 53 | REQUIRES_HOST_PROVENANCE_VALIDATION |
| `NETWORK_SERVICE_INTERACTION` | 232 | 232 | 0 | 45 | PLAIN_MININET_CANDIDATE |
| `TRANSFER_DOWNLOAD_UPLOAD` | 166 | 166 | 0 | 41 | PLAIN_MININET_CANDIDATE |
| `EMAIL_DELIVERY` | 105 | 105 | 0 | 40 | PLAIN_MININET_CANDIDATE |
| `NETWORK_C2_BEACON` | 103 | 69 | 34 | 44 | REQUIRES_HOST_PROVENANCE_VALIDATION |

## Coverage Accounting

The five target families contain 1318 exact R1 rows. The contracts cover 945 non-manual candidate rows; 941 currently have resolved prerequisites and 4 remain prerequisite-blocked. 373 target-family rows remain manual-design routes. The complete R1 matrix contains 589 manual-design rows; this design does not reclassify any of them.
Unresolved prerequisite rows under the stated policy: 4. They remain blocked and are not counted as executable until their required service/environment evidence is resolved.

## Manual-Design Blockers

All 589 R1 manual-design rows are listed in `E0C_R2_MANUAL_DESIGN_BLOCKERS.json` with one or more source-supported blocker labels and evidence paths. Labels are planning blockers, not execution instructions.

## PROVX Boundary

Telemetry contracts define future artifact interfaces and reversible `raw_key`/`run_id` mapping only. They do not claim Phase-I detection, Phase-II localization, causal-edge observation, or model flips.

STOP = true
