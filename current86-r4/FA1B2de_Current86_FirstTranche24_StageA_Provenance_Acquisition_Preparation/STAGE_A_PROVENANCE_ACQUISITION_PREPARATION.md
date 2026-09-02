# Stage A Provenance and Canonical Source Acquisition Preparation

> Status: preparation only. No source authority activation, source-auth execution, mappings, field pins, Stage A admission, Stage B exposure, R7/R8/R8R1 mutation, P0/P1, publication, formal experiment, commit, or push was performed.

## Frozen scope

The package covers the frozen first tranche of 24 targets in this exact order: `110, 273, 210, 98, 147, 277, 188, 301, 143, 250, 233, 287, 146, 293, 114, 284, 291, 215, 88, 182, 300, 218, 115, 148`.
The independently recomputed R1R1 crosswalk SHA-256 is `2c88f67ff154c5d6bfa2deb13dc51588b854e1c35ea74dc44749af8b537cb316`. The prior conservation review records 24 physical JSONL records, 24 unique target identities, zero mappings, zero field pins, and the frozen gate states `ADMISSION_NOT_READY_MISSING_PROVENANCE` and `FIELD_PIN_NOT_EXPOSED_GATED_ON_ADMISSION`.

## Cohort decision

All 24 targets are in primary cohort `CANONICAL_SOURCE_CLASS_IDENTIFIED_SOURCE_OBJECT_MISSING` and secondary cohort `SOURCE_OWNER_OR_GOVERNANCE_AUTHORIZATION_MISSING`. The eligible R1R1 class/fact type is `AUTHENTICATED_CANONICAL_INTRINSIC_SOURCE` / `PINNED_CANONICAL_INTRINSIC_FIELD`.

The project contains exact candidate scoring rows plus R5 wrapper objects and R8 candidate packets. Those artifacts are authenticated only for their noncanonical candidate/evidence roles. The recovery records for all 24 targets report `BLOCKED_MISSING_SOURCE_MANIFEST`, no canonical source-manifest entry, and no canonical object selection. They cannot be promoted by hash, ranking, pointer availability, semantic plausibility, or human prose.

## Per-target acquisition preparation

Each row in `FIRST_TRANCHE_24_PROVENANCE_GAP_MATRIX.jsonl` records the exact target identity, candidate references, missing canonical artifact/version/object/field evidence, owner/governance gaps, reusable cohort controls, and fail-closed disposition. The future source artifact/version, exact object locator/extractor, schema namespace, and RFC6901 pointer are intentionally unresolved rather than guessed.

The shared acquisition control is mechanically reusable across the 24: authenticate one governed source authority, obtain owner authorization, pin an immutable artifact/version, extract exactly one object by a deterministic rule, resolve the exact schema and RFC6901 field, recompute hashes and canonical identities, and independently verify the provenance graph. Artifact choice, object locator, extractor output, schema semantics, pointer, and conflict resolution remain target/source-specific.

## Gate and next action

The tranche remains `ADMISSION_NOT_READY_MISSING_PROVENANCE`; Stage B remains gated. The next bounded action is to obtain the explicit source-owner/governance authorization and canonical source-manifest entries, then acquire and authenticate the target-specific immutable source objects under the shared controls. This preparation package does not execute those actions.

## Generalization boundary

The workflow appears mechanically reusable for similarly structured unresolved Binding records, but no claim is made for all Current86 or all unresolved records. A Current86-wide applicability gate would require a complete target inventory, authenticated per-target source-manifest and owner status, independently recomputed classifications, exception analysis, and independent review of the wider package.

## Package contents

- `FIRST_TRANCHE_24_PROVENANCE_GAP_MATRIX.jsonl` - 24 target-level preparation records.
- `CANONICAL_SOURCE_COHORT_CLASSIFICATION.json` - primary/secondary cohort counts and membership.
- `SOURCE_AUTHORITY_AND_OWNER_GAP_REPORT.json` - missing authority, owner, manifest, and extraction controls.
- `ACQUISITION_EVIDENCE_REQUIREMENTS.json` - ordered future evidence requirements and reusable controls.
- `STAGE_A_APPLICABILITY_SUMMARY.json` - bounded applicability statement, gate state, and next action.
- `INDEPENDENT_PREPARATION_VERIFICATION.json` - independent recomputation results for this preparation package.
