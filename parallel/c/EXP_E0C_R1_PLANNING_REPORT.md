# EXP-E0C-R1 Execution-Archetype Enrichment

Preparation-only planning substrate for the authenticated exact-1796 raw corpus.

## Terminal State

- `EXP_E0C_R1_CONSERVATION = PASS_1796`
- `RAW_RECORD_COUNT = 1796`
- `UNIQUE_RAW_KEY_COUNT = 1796`
- `EXECUTION_ARCHETYPE_COUNT = 13`
- `REQUIRES_MANUAL_DESIGN_COUNT = 589`
- `UNKNOWN_PLANNING_COUNT = 0`
- `FORMAL_EXPERIMENT_EXECUTED = NO`
- `DENOMINATOR_CHANGE = NO`
- `BINDING_AUTHORITY_MUTATION = NO`
- `SCORING_AUTHORITY_MUTATION = NO`
- `NEXT_ACTION = FRESH_REVIEW_OF_EXP_E0C_R1_EXECUTION_ARCHETYPE_ENRICHMENT`
- `STOP = true`

## Authority and Scope

- Raw authority remains `AUTHENTICATED_SOURCE_CORPUS_PLUS_VERIFIED_DERIVED_REGISTRY`.
- The accepted denominator remains 1,796; no scoring/binding identity or count was created.
- Historical feasibility/run-plan artifacts are listed as reference evidence only; old VM choices are not requirements for Mininet/PROVX.
- Every row retains `formal_execution_authorized = false`.

## Archetype Catalog

| Archetype | Raw count | Playbooks | Candidate modes |
|---|---:|---:|---|
| `ARCHIVE_COMPRESSION` | 9 | 8 | NATIVE_CANDIDATE:9 |
| `CREDENTIAL_STORE_ACCESS` | 67 | 31 | NATIVE_CANDIDATE:7, REQUIRES_MANUAL_DESIGN:60 |
| `DISCOVERY_ENUMERATION` | 90 | 39 | NATIVE_CANDIDATE:56, REQUIRES_MANUAL_DESIGN:34 |
| `DNS_INTERACTION` | 5 | 2 | EMULATED_CANDIDATE:5 |
| `EMAIL_DELIVERY` | 105 | 40 | SYNTHETIC_CANDIDATE:105 |
| `FILE_RESOURCE_OPERATION` | 64 | 33 | NATIVE_CANDIDATE:20, REQUIRES_MANUAL_DESIGN:44 |
| `NETWORK_C2_BEACON` | 103 | 44 | EMULATED_CANDIDATE:22, NATIVE_CANDIDATE:47, REQUIRES_MANUAL_DESIGN:34 |
| `NETWORK_SCAN_ENUMERATION` | 62 | 27 | EMULATED_CANDIDATE:62 |
| `NETWORK_SERVICE_INTERACTION` | 232 | 45 | EMULATED_CANDIDATE:232 |
| `PERSISTENCE_CONFIGURATION` | 101 | 45 | NATIVE_CANDIDATE:52, REQUIRES_MANUAL_DESIGN:49 |
| `PRIVILEGE_ACCOUNT_ACTION` | 80 | 36 | NATIVE_CANDIDATE:51, REQUIRES_MANUAL_DESIGN:29 |
| `PROCESS_COMMAND_EXECUTION` | 712 | 53 | NATIVE_CANDIDATE:373, REQUIRES_MANUAL_DESIGN:339 |
| `TRANSFER_DOWNLOAD_UPLOAD` | 166 | 41 | SYNTHETIC_CANDIDATE:166 |

## Adapter Backlog Priority

| Rank | Adapter family | Raw count | Playbooks | Manual rows |
|---:|---|---:|---:|---:|
| 1 | `adapter::process_command_execution` | 712 | 53 | 339 |
| 2 | `adapter::network_service_interaction` | 232 | 45 | 0 |
| 3 | `adapter::transfer_download_upload` | 166 | 41 | 0 |
| 4 | `adapter::email_delivery` | 105 | 40 | 0 |
| 5 | `adapter::network_c2_beacon` | 103 | 44 | 34 |
| 6 | `adapter::persistence_configuration` | 101 | 45 | 49 |
| 7 | `adapter::discovery_enumeration` | 90 | 39 | 34 |
| 8 | `adapter::privilege_account_action` | 80 | 36 | 29 |
| 9 | `adapter::credential_store_access` | 67 | 31 | 60 |
| 10 | `adapter::file_resource_operation` | 64 | 33 | 44 |
| 11 | `adapter::network_scan_enumeration` | 62 | 27 | 0 |
| 12 | `adapter::archive_compression` | 9 | 8 | 0 |
| 13 | `adapter::dns_interaction` | 5 | 2 | 0 |

Priority is based on raw coverage, playbook reuse, Mininet candidate compatibility, future PROVX candidate surface, and lower manual-design burden. It is not based on scoring weight.

## PROVX Boundary

Candidate observation surfaces are planning labels only. `provx_phase1_observable`, `provx_phase2_core_edge_localizable`, and all four result dimensions remain unchanged and unobserved. Network-only records retain an explicit metadata-only surface; no process/file/socket causal edge is fabricated.

## Reference Artifacts

- `/home/cph/experiment/data/feasibility/feasibility_labels.csv` SHA-256 `0d4a61e94f568b003ca078fece35fd7559f079e2910369013f0abd1eb6f46c79`; `REFERENCE_ONLY_NOT_CURRENT_AUTHORITY`.
- `/home/cph/experiment/data/run_plans/run_plan.csv` SHA-256 `9e555e62b57e11fc946877cbf4a6436dd5ff3c53cd3fbb1a0d5b36d44f0bf8b5`; `REFERENCE_ONLY_NOT_CURRENT_AUTHORITY`.
- `/home/cph/experiment/data/run_plans/run_plan_summary.md` SHA-256 `9c124842e6205e3347ad0c20242cd38df20b441539f691c855494755e5c844e0`; `REFERENCE_ONLY_NOT_CURRENT_AUTHORITY`.
- `/home/cph/experiment/data/reports/environment_requirements.csv` SHA-256 `b63e60db11a5a59ea80e27fc8c47fc1d290eacaed5dd7e812748ce1b8fca22a7`; `REFERENCE_ONLY_NOT_CURRENT_AUTHORITY`.

STOP = true
