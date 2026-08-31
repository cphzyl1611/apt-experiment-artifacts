# EXP-E0C-R3 — Full-13-Family Global Adapter Coverage Closure

Continue from E0C-R1/R2.

Frozen archetype denominator = 1796.

R2 covered five families:
PROCESS_COMMAND_EXECUTION 712
NETWORK_SERVICE_INTERACTION 232
TRANSFER_DOWNLOAD_UPLOAD 166
EMAIL_DELIVERY 105
NETWORK_C2_BEACON 103

These total 1318.

Remaining eight families total 478:
ARCHIVE_COMPRESSION 9
CREDENTIAL_STORE_ACCESS 67
DISCOVERY_ENUMERATION 90
DNS_INTERACTION 5
FILE_RESOURCE_OPERATION 64
NETWORK_SCAN_ENUMERATION 62
PERSISTENCE_CONFIGURATION 101
PRIVILEGE_ACCOUNT_ACTION 80

Reported `945 contract-covered`, `589 manual`, `4 unresolved` must NOT be assumed to be an exhaustive disjoint 1796 partition.

## Goal

1. Reconcile R2 accounting exactly.
2. Design equivalent non-executable contracts for the remaining eight archetypes.
3. Produce one mutually-exclusive global planning status for every one of 1796 raws.

## Required work

1. Authenticate R1 raw/archetype sets and all R2 family manifests/contracts/coverage audits.

2. For the five R2 families, explicitly distinguish:
   - contract exists for family/row
   - current implementation prerequisite status
   - manual-design status

   Explain reported 945/589/4 without double counting.

3. Design the same adapter-contract layers for all remaining eight families:
   exact member-set commitment, inputs/roles, prerequisites, fixtures,
   result/evidence schema, cleanup, fail-closed semantics,
   defensive-equivalence constraints, PROVX telemetry requirements,
   Mininet/OS compatibility.

4. Assign every raw exactly one global planning state:
   CONTRACT_DESIGNED_READY_FOR_IMPLEMENTATION_PLANNING
   MANUAL_DESIGN_REQUIRED
   BLOCKED_UNRESOLVED_PREREQUISITE

5. Require:
   CONTRACT_DESIGNED_COUNT
 + MANUAL_DESIGN_REQUIRED_COUNT
 + BLOCKED_UNRESOLVED_PREREQUISITE_COUNT
 = 1796

   GLOBAL_STATUS_OVERLAP = 0
   GLOBAL_STATUS_MISSING = 0

6. Preserve R1 candidate fidelity separately; do not overwrite NATIVE/EMULATED/SYNTHETIC/REQUIRES_MANUAL_DESIGN classifications.

7. Build an implementation-priority plan based on coverage, reuse, Mininet compatibility, OS/dependency availability, PROVX telemetry suitability, and manual burden—not scoring weight.

8. Mark each family dependency:
   CAN_IMPLEMENT_BEFORE_PROVX_COLLECTOR
   WAIT_FOR_PROVX_SCHEMA
   WAIT_FOR_MININET_PROVENANCE_COLLECTOR
   WAIT_FOR_WINDOWS_OR_SERVICE_ENVIRONMENT
   MANUAL_ONLY

## Outputs

- E0C_R3_R2_ACCOUNTING_RECONCILIATION.json
- E0C_R3_REMAINING_8_FAMILY_CONTRACTS.json
- E0C_R3_GLOBAL_1796_PLANNING_STATUS.jsonl
- E0C_R3_GLOBAL_COVERAGE_AUDIT.json
- E0C_R3_IMPLEMENTATION_PRIORITY.json
- E0C_R3_GLOBAL_ADAPTER_COVERAGE_REPORT.md

## Boundaries

No action execution, command implementation, formal results, PROVX detection claims, authority mutation, or denominator change.

## Terminal

E0C_R3_GLOBAL_ADAPTER_COVERAGE = PASS_1796 | BLOCKED
CONTRACT_DESIGNED_COUNT = <n>
MANUAL_DESIGN_REQUIRED_COUNT = <n>
BLOCKED_UNRESOLVED_PREREQUISITE_COUNT = <n>
GLOBAL_STATUS_SUM = 1796
GLOBAL_STATUS_OVERLAP = 0
GLOBAL_STATUS_MISSING = 0
FORMAL_EXPERIMENT_EXECUTED = NO
DENOMINATOR_CHANGE = NO
NEXT_ACTION = FRESH_REVIEW_OF_E0C_R3_GLOBAL_ADAPTER_COVERAGE
STOP = true
