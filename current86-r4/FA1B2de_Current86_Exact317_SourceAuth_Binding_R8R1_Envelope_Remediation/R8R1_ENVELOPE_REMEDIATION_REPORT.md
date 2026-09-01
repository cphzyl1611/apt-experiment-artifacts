# Binding R8R1 Envelope Inventory Remediation

This addendum records only `BINDING_R8R1_ENVELOPE_INVENTORY_REMEDIATION`. It does not revisit substantive R8 adjudication. It does not create a field pin or human decision, execute source-auth/P0/P1, publish a binding, or rewrite Git history. The historical blocked fresh-review report remains unchanged.

## Repository authentication

The session authenticated origin `https://github.com/cphzyl1611/apt-experiment-artifacts.git` and the requested pre-remediation HEAD `822079ec58e90f2d1a00fa967a8bd7f77ff9614d` exactly. During the shared-workspace run, concurrent commits advanced `main`; the final verification observed `f8d62fd36e40f3e0d0f8111022c4e43eb10bfc24`, a descendant of the authenticated expected commit. This remediation does not create a commit, so the terminal records `POST_REMEDIATION_HEAD = NOT_COMMITTED`.

## Defect reproduction and repair

Committed bytes at historical R8 materialization commit `2ff2b21cd313c5b91567adfe05691d3e25aabb87` reproduce the blocker: `FILE_LIST.txt` has 11 paths, `SHA256SUMS.txt` has the same paths plus `FILE_LIST.txt`, and all 12 recorded checksums otherwise match.

The producer's `write_envelope()` now creates one sorted final inventory from `OUTPUTS` plus `FILE_LIST.txt`, writes that exact inventory into `FILE_LIST.txt`, and hashes that same inventory into `SHA256SUMS.txt`. `SHA256SUMS.txt` is excluded from both inventories. A regression test asserts exact path-set equality and both self-binding rules.

Only the producer, regression test, R8 envelope, and this remediation addendum are in scope. `materialize()` was not called. The eight named substantive R8 artifact hashes are byte-for-byte identical to commit `2ff2b21c…`; their exact hashes are recorded in `R8R1_SUBSTANTIVE_ARTIFACT_NONREGRESSION.json`.

## Verification

- Targeted R8 tests: 5/5 passed.
- Supplied package-independent verifier, `tools/verify_r8.py`: passed.
- `sha256sum -c SHA256SUMS.txt`: all 12 paths passed.
- Exact inventory path-set equality: passed, 12 paths versus 12 paths.
- `FILE_LIST.txt`: self-listed and checksummed.
- `SHA256SUMS.txt`: neither self-listed nor self-checksummed.

## Terminal

```text
BINDING_R8R1_ENVELOPE_REMEDIATION =
PASS_READY_FOR_TARGETED_FRESH_REVIEW
PRE_REMEDIATION_HEAD = 822079ec58e90f2d1a00fa967a8bd7f77ff9614d
POST_REMEDIATION_HEAD = NOT_COMMITTED
ORIGINAL_BLOCKER_REPRODUCED = YES
FILE_LIST_PATH_COUNT = 12
SHA256SUMS_PATH_COUNT = 12
INVENTORY_PATH_SET_EQUALITY = PASS
FILE_LIST_SELF_LISTED = YES
FILE_LIST_CHECKSUMMED = YES
SHA256SUMS_SELF_LISTED = NO
SHA256SUMS_SELF_CHECKSUMMED = NO
SUBSTANTIVE_R8_ARTIFACT_BYTES_UNCHANGED = PASS
R8_TARGETED_TESTS = 5/5
R8_SUPPLIED_INDEPENDENT_VERIFIER = PASS
CHECKSUM_VERIFICATION = PASS
FIELD_PINS_CREATED = 0
SOURCE_AUTH_EXECUTED = NO
P0_EXECUTED = NO
P1_EXECUTED = NO
BINDING_PUBLICATION = NO
NEXT_ACTION = TARGETED_FRESH_REVIEW_OF_R8R1_ENVELOPE_REMEDIATION
STOP = true
```
