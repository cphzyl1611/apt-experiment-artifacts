# PROVX R7R1 / Mininet R6R2 Interface Compatibility Review

Review date: September 1, 2026.

## Decision

`PROVX_R7R1_R6R2_INTERFACE_COMPATIBILITY_REVIEW = PASS_INTERFACE_NEUTRAL_WAITING_FOR_AUTHENTICATED_R6_RUNTIME_INPUT`

The committed Mininet E1C-R6R2 change does not alter the authenticated runtime or normalized-event contract consumed by the recovered PROVX R7R1 adapter. It changes the pre-Mininet micro-probe from one interpreted `ausearch -i` lookup to bounded raw `ausearch --raw` polling and narrows the helper serial parser to raw numeric `msg=audit(<epoch>:<serial>)` syntax. The final Mininet raw collection, raw-group parser, normalized event builder, event class, evidence basis, watched-path semantics, audit rule, and raw-link fields are unchanged.

This is an interface review only. No runtime R6 evidence exists in the reviewed tree, and no runtime evidence was fabricated or synthesized.

## Authenticated Inputs

The authenticated source HEAD was `99f9c0d7fe8b4ecec896837b3991e8d23ebbb608`, matching remote `main` at review time. The required commits `cde75a82e7938db6d5903d16885bf35ceb17aa68`, `a471ee6ca09253a381d96a228ab58a1f652bd0b9`, and `ee28eb41220d080b225f1dbc752c114656ef2299` are ancestors.

The R7R1 adapter blob `3efd33f8aa37d5fdf150ff5b2fed433a471186bc` and remediation-test blob `a05564971d032e3727df184acaafec765942bc3f` are byte-identical at the remediation commit, the R6R2 materialization commit, the recovery commit, and the source HEAD. The recovered behavior remains:

- R5 FILE ID: `path:<path>`.
- Non-R5/R6 FILE ID: `host:<logical_host_id>|path:<path>`.
- Same path on `h1` and `h2`: distinct FILE nodes.

## R6R2 Delta

The direct parent of R6R2 is `674222444d6e675b50aba5d6194e9dd01015acbd`. The production delta replaces the micro-probe's `ausearch -i` query and broad serial regex with:

- `/usr/sbin/ausearch -k <exact_random_key> --raw`;
- raw numeric epoch/serial parsing returning an integer serial;
- exact key and path token checks;
- monotonic polling bounded to 2.0 seconds and an interval capped at 0.1 seconds;
- fail-closed `AUDIT_EVIDENCE_MISSING` timeout and additive micro-probe diagnostics.

The committed source proves that `EVENT_TYPE`, `EVIDENCE_BASIS`, the exact path/`perm=rw`/PID/key rule builder, inverse cleanup, raw-link verifier, raw-group parser, filesystem permission normalizer, and full normalized runtime event builder are byte-identical before and after R6R2. The final Mininet collection already used `ausearch --raw` in the parent and is unchanged.

Two R6R2 review-artifact statements are not accepted as provenance facts. Bounded polling was added, not preserved from the direct parent. Also, `R6R2_STATIC_BOUNDARY_AUDIT.json` names `cde75a82` as its current HEAD while recording hashes that match `a471ee6c`. These are non-blocking for this review because the implementation and test bytes were independently authenticated and the discrepancies do not change the consumer interface.

## Consumer Contract

R7R1 requires explicit descriptor paths and SHA-256 bindings for raw, normalized, join, coverage, runtime-review, pcap, and pcap-hash-source inputs. It rejects selected-file, run-ID, raw serial, decoded-byte/hash, and pcap authentication failures.

For `FILE_READ_OR_WRITE`, the normalized record must retain the common evidence and process identity fields plus exact `AUDIT_FILESYSTEM_PERMISSION_FILTER`, an absolute `watched_path` agreeing with `path` or `file_identity.paths`, `requested_access` in `r|w|rw`, and a non-empty `underlying_syscall`. A joined logical host, PID start time, and netns are required. The graph remains `PROCESS -> FILE`, the encoder class remains `write`, and non-R5 file identity remains host-scoped.

R6R2 adds no field R7R1 cannot consume, removes no required field, changes no required field meaning, and changes no identity, event mapping, raw-link, pcap, PID/netns, or fail-closed rule. The new micro-probe diagnostics are not normalized runtime event fields. The micro-probe serial helper is not the unchanged raw-group parser used to build final normalized events.

## Frozen Boundaries And Tests

The frozen encoder SHA-256 is `013d9b77297308843144ccfce4c3eec4b03dc3cc5172dabd6eb3320e7bc46547` at every required commit and at source HEAD. No detector checkpoint was loaded, no training or PROVX inference ran, no privileged command or Mininet run occurred, and no formal experiment was executed.

Fresh non-privileged results:

- R7R1 remediation tests: `12/12`.
- R7 adapter tests: `5/5`.
- Frozen encoder tests: `7/7`.
- Supplementary R6R2 harness tests: `33/33`.
- Review-package JSON validation: PASS.
- `git diff --check`: PASS.

The remaining gate is authenticated Mininet R6 runtime evidence. This review does not promote Stage-A full collector-adapter status.
