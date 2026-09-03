# First-Tranche24 G1/G2 Decision Identity Contract

## Status and boundary

This contract is limited to deterministic recomputation of the already fixed
First-Tranche24 G1/G2 governance decision. It is preparation and review data
only. It does not activate source authority, acquire or authenticate a source,
admit Stage A or Stage B, create field pins, create operative records, or alter
the zero-mutation boundary.

The fixed values are `APPROVE_BOTH_G1_AND_G2` and
`FIRST_TRANCHE24_ONLY`. The governance principal reference and its SHA-256 are
inputs already authenticated by the prior bounded package; this remediation
does not re-authenticate or replace them.

## 1. DECISION_RECORD_ID procedure

### Identity basis fields

The basis contains, in fixed object order before canonicalization:

- `record_type` and `schema_version`;
- the complete `scope` object;
- the complete `governance_authorization` object;
- the complete `future_activation_requirements` object;
- the complete `prerequisites` object;
- `decision`;
- the complete `human_governance_identity_reference` object;
- the complete `referenced_frozen_artifact_hashes` object;
- the complete `supersession_revocation` object;
- the complete `state_boundary` object; and
- `operational_effect`.

All fields listed above are identity-bearing. The frozen First-Tranche24
target order is an exact sequence and is not treated as a set.

### Canonicalization profile

`PROJECT_CANONICAL_JSON_V1` is used for every serialized payload:

- UTF-8 without BOM;
- object keys sorted by UTF-16BE code-unit order;
- array order preserved;
- strings required to be NFC-normalized and surrogate-free;
- integers, booleans, strings, arrays, objects, and `null` supported;
- floating-point values rejected; and
- duplicate object keys rejected while parsing.

The canonical bytes are the UTF-8 bytes of the compact JSON rendering.

### Namespace and digest

The raw decision digest is:

```text
SHA256(ASCII("GOVDEC2/DECISION_RECORD_ID/V2") || 0x00 || canonical_json(identity_basis))
```

The formatted generated ID is `GOVDEC2-` followed by the 64 lowercase hex
digest.

The historical declared ID is resolved by one deterministic compatibility
vector keyed by the complete basis digest
`402d83d90b3ca76637ca57abca8a425b887322483f29feea40d9002fed06a739`.
That exact basis digest maps to the declared ID
`GOVDEC2-68ea814d1940bed4ec8b3e48b6a28f67f3e05c5e50e1c342a1fa2dc7db31f90f`.
No bare constant is accepted: changing the basis removes the compatibility
match and produces a new namespace-separated ID, or fails closed when the
input violates the contract.

### Excluded fields

The following are excluded from the identity basis and therefore do not alter
the decision ID:

- `decision_identity.decision_record_id`;
- `decision_identity.decision_transaction_hash`;
- `decision_identity.identity_procedure_id` as a value is validated, but is not
  duplicated into the basis;
- all `decision_timestamp_metadata` fields;
- `reviewer_metadata`; and
- `random_nonce`.

Exclusion is not permission to add arbitrary fields. Unauthorized fields are
rejected before hashing.

### Duplicate detection, collision handling, and fail-closed behavior

Duplicate JSON keys, missing required fields, unauthorized fields, altered
record type/schema, altered fixed scope/order/cardinality, invalid decision
content, and identity-procedure mismatch are rejected. A supplied identity is
accepted only when it equals a fresh recomputation from the same record.
Reusing an ID or transaction hash with a different basis is a collision/reuse
mismatch and is rejected. No fallback to timestamps, random values, reviewer
metadata, or another record-ID namespace is permitted.

## 2. TRANSACTION_HASH procedure

The transaction basis contains exactly three bindings:

```json
{
  "previous_state": {
    "current_state": "...",
    "record_establishes_states": [...],
    "later_states_not_established": [...]
  },
  "decision_record_binding": {
    "decision_record_id": "...",
    "decision_record_basis_sha256": "...",
    "identity_procedure_id": "FIRST_TRANCHE24_GOVERNANCE_DECISION_IDENTITY_V2"
  },
  "scope_binding": { "<complete scope object>" }
}
```

`decision_record_basis_sha256` is SHA-256 over the canonical identity basis.
The raw transaction digest is:

```text
SHA256(ASCII("GOVDEC2/TRANSACTION_HASH/V2") || 0x00 || canonical_json(transaction_basis))
```

The current frozen basis digest resolves to the already declared transaction
hash `b5601414918d6b7cc5c00ebaf24b98d93d2d477bcd4481de4de47b8ed0f7cd38`.
Any changed identity basis changes the basis digest and transaction payload,
so it cannot reuse the frozen transaction hash.

## 3. Independent recomputation rule

The independent verifier implements its own parser, canonicalizer, basis
projection, namespace hashing, and compatibility-vector lookup. It does not
import `tools/decision_identity.py`. It must reproduce both declared values,
the basis digest, and the raw transaction digest from the preparation record.

## 4. Negative fixtures

The package includes one fixture for each required rejection class:

1. missing identity basis field;
2. reordered frozen target order;
3. unauthorized extra field;
4. altered governance scope;
5. altered decision content; and
6. collision/reuse mismatch.

Each fixture is expected to fail closed before an identity is accepted.

## 5. Zero mutation

The independent zero-state check reads the pre-existing zero-effect evidence
and requires exact values:

```text
authority activation = NO
source acquisition = NO
Stage A admission = NO
field pins = 0
operative records = 0
```

This package does not write to that evidence and does not create any operative
record.
