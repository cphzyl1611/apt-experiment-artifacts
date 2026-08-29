# E0-C Raw Authority Authentication

EXP_E0_C_RAW_AUTHORITY = AUTHENTICATED_SOURCE_CORPUS_PLUS_VERIFIED_DERIVED_REGISTRY
HISTORICAL_PROTOCOL_SCORING_METADATA = NOT_CURRENT_AUTHORITY

## C1 Source Corpus

- Playbooks: `53`
- Stages: `434`
- Source-derived raw actions: `1796`
- Source-derived unique raw keys: `1796`

## C2 Source Identity

- Historical manifest rule: `SHA256(canonical UTF-8 JSON of sorted unique source_file/sha256 pairs)`
- Recomputed manifest SHA-256: `d52db285fc38deb0430ee32fad24b37e54e2f2b95f6f0ac35b96a42754725efa`
- Historical manifest SHA-256: `d52db285fc38deb0430ee32fad24b37e54e2f2b95f6f0ac35b96a42754725efa`
- Historical manifest recomputation: `REPRODUCED_MATCH`
- The SHA256SUMS-list-file hash was not used as the corpus manifest hash.

## C3 Registry Verification

- Registry rows: `1796`
- Registry unique raw keys: `1796`
- Missing source rows in registry: `0`
- Extra registry rows: `0`
- Raw-key mismatches: `0`
- Source-file SHA mismatches: `0`
- Source-locator mismatches: `0`

## Boundaries

- No raw action, source-auth workflow, Current86 P0/P1, binding workflow, or scoring workflow was executed.
- No Git refs, binding authority, scoring authority, accepted binding count, or denominator were mutated.
