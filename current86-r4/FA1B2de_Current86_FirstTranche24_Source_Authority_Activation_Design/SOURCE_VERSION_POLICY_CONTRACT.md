# FIRST_TRANCHE24 source-version policy contract

## Required representation

`source_version_policy` is mandatory in every future activation record. It has
one policy ID, policy version `V1`, one supported immutable form, one
non-empty immutable identifier, a lower-case SHA-256 content digest, lineage
evidence references, `floating_reference_allowed: false`, and
`update_policy: NEW_ACTIVATION_REQUIRED`.

Supported forms are:

| Form | Required immutable reference | Additional digest rule |
| --- | --- | --- |
| `CONTENT_DIGEST` | a content-addressed artifact identifier | identifier and `content_sha256` must agree |
| `GIT_COMMIT` | repository, full commit, and tree | commit/tree proof plus `content_sha256` |
| `RELEASE_TAG_WITH_DIGEST` | immutable release/tag identifier | release metadata plus `content_sha256` |

The exact conditional fields are closed by
`SOURCE_AUTHORITY_ACTIVATION_RECORD_SCHEMA.json`; unsupported keys are
rejected. The synthetic fixture uses `CONTENT_DIGEST` with a synthetic URI and
`SYNTHETIC_PASS` evidence solely to exercise structure.

## Immutable pin requirement

The future transaction must fail closed when the reference is a branch, a
mutable tag, `latest`, a version range, a date-only label, an unqualified
repository URL, or any other floating reference. A release/tag is acceptable
only when paired with its immutable content digest and lineage proof. A Git
reference is acceptable only with a full commit and tree (not a branch name).

## Authentication and lineage

The policy evidence must connect the selected authority descriptor to the
immutable identifier and content digest. The executor recomputes the digest
from supplied authenticated evidence, verifies commit/tree or release metadata
when applicable, and checks that every provenance item names the same policy
and authority candidate. Evidence from another candidate is a mismatch even if
its bytes happen to match.

## Updates and re-activation

An update is never an in-place edit. The new bytes, release, commit, or policy
parameters receive a new policy ID and a new composite authority ID, and a new
`FIRST_TRANCHE24_SOURCE_AUTHORITY_ACTIVATION` transaction is required. An exact
replay of an already committed transaction is idempotent; a same-key replay
with any changed policy field is rejected. A superseded or revoked candidate
cannot be reactivated under the old ID.

## Mismatch handling

Any ambiguity in the immutable identifier, digest, repository/tree, release
metadata, lineage, or policy form yields `FAIL_CLOSED_NO_ACTIVATION`. No
fallback to a nearby tag, branch, latest release, alternate locator, or
semantic match is permitted.

