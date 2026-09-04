# Authoritative Semantic Evidence

## Authenticated Sources

- R2 design commit: `11a5692effd70ab5fbcf75b4574c7c27338e49af`.
- R2R1 baseline commit: `31bc08d3ddd0c836a4b610b53714cadea084172f`.
- R2R1 parent: `11a5692effd70ab5fbcf75b4574c7c27338e49af`.

## Field Meaning

1. `PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2/PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2.md:36-37` defines PCAP as provenance/authentication material and says it is never a graph-edge source.
2. `PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2R1/PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2R1.md:36-37` carries the same definition into R2R1.
3. `PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2/R6R3_RUNTIME_HANDOFF_SCHEMA_R2.json:670-682` defines `hardBoundaries`; the field `pcap_is_not_graph_edge_source` has `const: true`.
4. `PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2R1/R6R3_RUNTIME_HANDOFF_SCHEMA_R2R1.json:710-722` preserves that same authoritative schema requirement in R2R1.
5. `PROVX_R7R1_R6R3_RUNTIME_HANDOFF_CONTRACT_DESIGN_R2/r2_contract_validator.py:409-425` separately enforces the positive/negative pair: `provenance_only` is `true` and `used_as_graph_edge_source` is `false`.
6. The authenticated R2R1 baseline validator at commit `31bc08d3ddd0c836a4b610b53714cadea084172f`, `r2r1_contract_validator.py:1192-1198`, applied `false` to every hard-boundary value and therefore contradicted the schema's inverse guard.
7. The corrected validator at `r2r1_contract_validator.py:1192-1211` checks the seven positive operation/mutation flags for `false`, checks `pcap_is_not_graph_edge_source` for `true`, and retains `pcap_authentication.used_as_graph_edge_source == false`.

## Established Boolean Pattern

The same contract family uses the semantic form of each boolean, not a universal polarity:

| Boolean | Semantic form | Authoritative value | Evidence |
|---|---|---:|---|
| `r7r1_adapter_changed` | positive change occurrence | `false` | R2R1 schema `:715` |
| `frozen_32d_encoder_changed` | positive change occurrence | `false` | R2R1 schema `:716` |
| `detector_trained` | positive operation occurrence | `false` | R2R1 schema `:717` |
| `provx_inference_executed` | positive operation occurrence | `false` | R2R1 schema `:718` |
| `formal_experiment_executed` | positive operation occurrence | `false` | R2R1 schema `:719` |
| `privileged_commands_executed_by_e0b` | positive operation occurrence | `false` | R2R1 schema `:720` |
| `runtime_data_fabricated` | positive fabrication occurrence | `false` | R2R1 schema `:721` |
| `pcap_is_not_graph_edge_source` | inverse/guard assertion | `true` | R2R1 schema `:722`; prose `:36-37` |
| `pcap_authentication.used_as_graph_edge_source` | positive prohibited use occurrence | `false` | R2R1 schema `:523`; R2 validator `:423-424` |

The authoritative intent is therefore unique: `pcap_is_not_graph_edge_source = true`. The validator, not the schema or fixture, was the contradictory component.
