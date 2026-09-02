# PROVX R7R1 R6R3 Authenticated Runtime Handoff Contract Design

## Decision

This design introduces a machine-checkable handoff package at the E0-A/E0-B
seam. E0-A emits one package after a successful privileged R6R3 run. E0-B
authenticates that package independently, then returns one structured
pass/block decision to the later Stage A consumer.

The package is manifest-first and exact-path bound. It carries references and
hashes to runtime artifacts; it does not replace the raw audit or normalized
event files and it does not fabricate runtime data. The minimum-package JSON
in this directory is explicitly `NOT_RUNTIME_EVIDENCE` and cannot pass.

## Anchors and Scope

- R7R1 remediation: `cde75a82e7938db6d5903d16885bf35ceb17aa68`.
- Interface review: `13573a5a4c03261237a9b3553efb482b3eebd273`.
- E0-A R6R3 materialization: `6aec9e0ed113c17fd729f8ae359fd6d2c30fff0a`.
- Expected run ID: `e1c-r6-run-20260901T060350Z`.
- Expected producer: `mininet_e1c_r6_file_access_closure_smoke.py`.
- Exact privileged command:
  `sudo /usr/bin/python3 /home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/mininet_e1c_r6_file_access_closure_smoke.py --run-privileged`.

This task designs the handoff contract only. It does not run sudo, Mininet,
auditd, tcpdump, the adapter, the encoder, training, inference, or a formal
experiment. It does not push or mutate the artifact repository.

## Module and Interface

The handoff validator is a deep module at the E0-A/E0-B seam:

```text
E0-A runtime artifacts + exact manifest
                    |
                    v
        E0-B authenticated handoff result
                    |
                    v
        later Stage A consumption decision
```

Its external interface is intentionally small: one handoff object in, one
structured decision out. The implementation may use internal parsers and
recomputation helpers, but callers must not bypass manifest binding,
cross-file joins, or fail-closed rules.

## Producer Package

`R6R3_RUNTIME_HANDOFF_SCHEMA.json` describes the post-run package. It requires:

- run ID, collection window, topology, and logical-host identity;
- source commit, producer harness/test, pre-run contract, file-access
  semantics contract, design-document hashes, and artifact hashes;
- explicit human-invoked privileged execution with effective UID 0, exact
  command, exit code 0, successful micro-probe, and successful R6R3 result,
  all bound to one manifest-authenticated privileged-execution receipt;
- exact paths and SHA-256 values for raw audit, normalized events,
  PID/netns joins, coverage/loss, cleanup, result, report, and PCAP;
- exact `FILE_READ_OR_WRITE` evidence fields;
- identity-join and eight-class closure summaries;
- PCAP authentication and its provenance-only restriction;
- inverse-rule cleanup, loss/backlog, residue, and baseline restoration;
- a non-recursive package manifest hash and canonicalization profile.

The producer must preserve the exact raw bytes required for independent
verification. A reported PASS, coverage flag, or review statement cannot
substitute for those bytes or for E0-B recomputation.

The runtime artifacts must share the declared run root. Source-lineage and
contract-design files are authenticated as separate exact-path inputs and are
not required to be located under that runtime root.

## Exact File-Access Contract

Every `FILE_READ_OR_WRITE` row must carry:

```text
path
watched_path
file_identity_paths
raw_serial
raw_event_sha256
evidence_basis = AUDIT_FILESYSTEM_PERMISSION_FILTER
requested_access in {r, w, rw}
underlying_syscall
syscall_record_serial = raw_serial
path_record_serial = raw_serial
same_serial_linkage = PASS
```

The raw audit bundle identified by `raw_serial` must contain same-serial raw
`SYSCALL` and `PATH` records. The syscall must be supported, successful, and
carry the exact audit key. The PATH name must equal the exact watched path.
This closes the prior false-positive class where unrelated text, a key, or a
path on another serial could be treated as evidence.

The retained syscall is evidence about the underlying operation. E0-B does
not infer it from `perm=rw`; a permission-filter fact without a valid raw
bundle is blocked.

## Identity and Event Closure

Every normalized row must be tied to one logical host and exactly one
PID/start-time-ticks/netns join. The join key is:

```text
(run_id, logical_host_id, pid, pid_start_time_ticks, netns_inode, role)
```

The join must be unique, unambiguous, and `JOINED`. The namespace assertions
must prove that each child remains in its host namespace and that the two
logical hosts are distinct.

The required event classes are exactly:

1. `PROCESS_START_OR_EXEC`
2. `PROCESS_EXIT`
3. `FILE_CREATE_OR_OPEN`
4. `FILE_READ_OR_WRITE`
5. `FILE_DELETE`
6. `SOCKET_BIND`
7. `SOCKET_CONNECT`
8. `SOCKET_ACCEPT`

E0-B recomputes counts from normalized rows. Every class must occur at least
once, `FILE_READ_OR_WRITE` must be greater than zero, missing and unexpected
class lists must be empty, and audit loss, backlog, raw-link failures, and
duplicates must all be zero.

## PCAP and Cleanup

The PCAP is required because the closure includes socket classes. E0-B hashes
the exact PCAP bytes and compares that value with the PCAP hash in coverage
and post-cleanup evidence. PCAP is authentication/provenance metadata only;
it is never a graph-edge source and cannot repair missing audit evidence.

Cleanup must prove exact inverse removal of only successfully added transient
rules, unchanged persistent rule files, restored baseline hashes, zero audit
loss/backlog, no run-owned processes, no test interfaces or OVS residue, and
no tcpdump process residue. Global rule deletion, `mn -c`, external NAT, APT,
PROVX, training, inference, and formal experiment actions are forbidden.

## Hash and Canonicalization Contract

Artifact hashes are SHA-256 of exact file bytes. Raw and normalized event
hashes are SHA-256 of decoded base64 bytes. A normalized row joins to a raw
row by exact serial, and both decoded bytes and hashes must match.

The package manifest hash is:

```text
SHA256(canonical_utf8_json(package_manifest without manifest_sha256))
```

The privileged execution fact is not accepted from a claimed field alone.
E0-A must include one exact, manifest-bound `r6_privileged_execution_receipt`
with a single human-invoked reviewed command, effective UID `0`, exit code
`0`, and completed result. E0-B compares the receipt bytes and parsed fields
with `privileged_execution` before any Stage A decision.

Canonical JSON uses UTF-8, sorted object keys, compact `(',', ':')`
separators, `ensure_ascii=false`, LF line endings, no BOM, preserved array
order, and rejection of non-finite numbers. The manifest hash excludes only
its own field, so it is deterministic and non-circular.

## Fail-Closed Result

The validator must return `PASS_READY_FOR_STAGE_A_AUTHENTICATED_CONSUMPTION`
only after all blocking rules pass. Any duplicate, missing, inconsistent,
malformed, unverifiable, stale, or noncanonical record returns
`BLOCKED_HANDOFF_NOT_CONSUMABLE`. There is no partial promotion and no
best-effort continuation.

The current R7/R7R1 adapter remains unchanged. Its known R5-pinned input
route and remaining R6 `FILE_READ_OR_WRITE` integration work are recorded as
a later integration boundary. This handoff design does not redesign or
modify that adapter, the frozen 32D encoder, source authentication, binding,
or scoring.

## Independent Review Target

An independent reviewer should verify the JSON Schema, the ordered rule
inventory, the exact manifest hash scope, the eight-class closure, the
same-serial audit requirements, the PID/start-ticks/netns joins, the PCAP
role, and the cleanup assertions. Review should also confirm that this local
design package contains no runtime evidence and makes no adapter or
repository mutation.
