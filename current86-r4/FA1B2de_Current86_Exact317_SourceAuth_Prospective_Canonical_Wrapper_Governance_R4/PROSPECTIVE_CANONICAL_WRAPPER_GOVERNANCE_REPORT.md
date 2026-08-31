# Prospective Canonical Source Wrapper Governance R4

This package is a design-only governance preparation for the authenticated Exact317 population. It does not execute source authentication, create active canonical source authority, select or pin fields, run P0/P1, publish bindings, mutate scoring or binding authority, modify GOV-R4 or EXEC-R4, or mutate Git refs.

## Authenticated scope

- Exact target manifest SHA256: `d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac`
- Scope: `34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306`
- Population: 317 targets = 86 RAW + 231 CANDIDATE
- R3 provenance recovery: 0 complete; 26 missing historical producer identity; 291 missing canonical source-manifest/extraction authority
- Reauthenticated inputs: GOV-R4, EXEC-R4, R2 packets, R3 roots/results, source class/fact registry, RAW registry, C0 evidence, and scoring snapshot

## Route evaluation

| Rule | Route | Exact targets | Result | Approval units |
|---|---|---:|---|---:|
| `R4_WRAPPER_RAW_LEGACY_26` | RAW playbook corpus | 26 | viable prospective wrapper | 1 |
| `R4_WRAPPER_C0_60` | immutable C0 evidence | 60 | viable prospective wrapper | 1 |
| `R4_WRAPPER_SCORING_231` | immutable scoring snapshot | 231 | viable prospective wrapper | 1 |

The RAW route is viable because all 53 Git-tracked source playbook files exist at an immutable commit/tree and every file hash matches the authenticated raw registry's `source_file_sha256`. The wrapper uses a stable positional key and exact stage/action locator. The missing historical registry producer is explicitly not recovered or claimed; the new manifest, checkpoint, and extractor are prospective identities.

The C0 route preserves the full C0 artifact identity, archive, producer, manifest, checkpoint, and exact recovered subset as evidence-only. It adds a new wrapper identity over immutable bytes and does not relabel historical C0.

The scoring route uses one exact scoring-ID row locator per target over the authenticated immutable snapshot. It creates no scoring-history or scoring-authority mutation.

## Governance minimization

`PROSPECTIVE_CORPUS_RULE_APPROVAL_UNITS = 3`. The three units are required because the routes have distinct immutable corpora, schemas, locators, and lineage obligations. Their committed sets are disjoint and conserve the Exact317 population exactly. Before any human approval, all 317 targets remain blocked. After wrapper approval, target-level field-pin governance remains unavoidable for all 317 targets.

Each route has exactly one pending human packet with no default action. The only decisions exposed are `APPROVE_EXACT_CANONICAL_WRAPPER_RULE`, `REJECT_KEEP_TARGETS_BLOCKED`, and `REQUEST_NARROWER_RULE_OR_MORE_EVIDENCE`.

## Fail-closed contract

Target-set mismatch, zero or multiple matches, duplicate/conflicting bytes or provenance, hash mismatch, missing extractor identity, stale or superseded artifacts, incomplete enumeration, or expansion-commitment mismatch blocks the affected route. No similarity, occupancy, ranking, semantic inference, historical relation result, or LLM assertion can resolve an ambiguity.

## Required terminal

```text
PROSPECTIVE_CANONICAL_WRAPPER_GOVERNANCE_R4 = READY_FOR_HUMAN_GOVERNANCE_REVIEW
TARGETS_TOTAL = 317
TARGET_CONSERVATION = PASS
PROSPECTIVE_CORPUS_RULE_APPROVAL_UNITS = 3
TARGETS_COVERED_BY_PROSPECTIVE_RULES = 317
TARGETS_STILL_BLOCKED_BEFORE_HUMAN_APPROVAL = 317
HUMAN_DECISIONS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO
NEXT_ACTION = FRESH_INDEPENDENT_REVIEW_OF_PROSPECTIVE_CANONICAL_WRAPPER_GOVERNANCE_R4
STOP = true
```
