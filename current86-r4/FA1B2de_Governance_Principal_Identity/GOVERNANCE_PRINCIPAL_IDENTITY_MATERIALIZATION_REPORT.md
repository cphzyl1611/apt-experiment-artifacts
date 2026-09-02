# Governance Principal Identity Materialization

## Terminal status

`BINDING_GOVERNANCE_PRINCIPAL_IDENTITY = PASS_READY_FOR_INDEPENDENT_PRINCIPAL_IDENTITY_AUTHENTICATION`

The project owner designation is materialized exactly as:

`GOVERNANCE_PRINCIPAL_ID = FA1B2DE_PROJECT_OWNER_GOVERNANCE_PRINCIPAL`

`GOVERNANCE_PRINCIPAL_ROLE = PROJECT_OWNER_AND_HUMAN_GOVERNANCE_PRINCIPAL`

`IDENTITY_SEMANTICS = PROJECT_INTERNAL_ROLE_BASED_PSEUDONYMOUS_IDENTITY`

`DESIGNATION_BASIS = EXPLICIT_CURRENT_HUMAN_SELF_DESIGNATION`

`DESIGNATION_SCOPE = FA1B2DE_PROJECT_GOVERNANCE`

`PROJECT_SCOPE = FA1B2de`

The identity is a stable project-internal, role-based pseudonymous reference. It does not claim or bind a real name, email address, GitHub identity, operating-system username, legal identity, institutional identity, or cryptographic public-key identity.

## Deterministic identity

The applicable frozen profile is `PROJECT_CANONICAL_JSON_V1` at `FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R5/01_canonicalization/PROJECT_CANONICAL_JSON_V1.json`. The identity basis contains exactly these stable semantic members:

`principal_id`, `principal_role`, `identity_semantics`, `designation_basis`, `designation_scope`, and `project_scope`.

Timestamp, local path, username, reviewer metadata, process ID, and random nonce are excluded. The canonical identity-basis JSON SHA-256 is:

`3e831ab556e624dd876fd489ffa709cc5edc014ffa04a76747bffcb51071d795`

The record identity is deterministic under that profile and is recomputed in `PRINCIPAL_IDENTITY_BASIS_RECOMPUTATION.json`.

## Continuity

Prior H1, H2, and R7 governance artifacts are listed only as optional immutable continuity references. They are not required to establish this initial principal designation, do not define personal identity, and do not grant authority to this record.

## Authority boundary

`PRINCIPAL_IDENTITY_DESIGNATED = YES` is the only new semantic fact. This package creates no new substantive governance decision and does not redo, replace, revoke, or reinterpret the approved `APPROVE_BOTH_G1_AND_G2` decision. No first-tranche scope is broadened.

Source authority remains inactive. Operative source-manifest entries, source-auth executions, mapping evidence, Stage A admissions, Stage B exposures, field pins, P0, P1, Binding publication, and the formal 1796 experiment remain at zero or `NO`. R1R1 is not modified.

## Independent authentication

The materialized identity remains pending independent authentication. The next gate is:

`INDEPENDENT_GOVERNANCE_PRINCIPAL_IDENTITY_AUTHENTICATION`

The independent reviewer must authenticate the exact principal bytes, exact semantic identity basis, canonicalization profile/hash, project-only scope, absence of personal identity fields, and zero operational effect.
