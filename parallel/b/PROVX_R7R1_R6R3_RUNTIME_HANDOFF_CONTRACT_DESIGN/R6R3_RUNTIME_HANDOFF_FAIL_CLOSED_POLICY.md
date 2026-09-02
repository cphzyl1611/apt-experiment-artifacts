# R6R3 Runtime Handoff Fail-Closed Policy

## Purpose

This policy defines the E0-A to E0-B handoff seam for one authenticated,
privileged R6R3 runtime. E0-A may emit a handoff only after the privileged
run and its cleanup have completed. E0-B must independently authenticate the
selected bytes and all cross-file relationships before Stage A consumption.

The handoff is a proof package, not a discovery mechanism. The consumer uses
only the exact paths and hashes in the package manifest. It does not search a
run directory, choose the newest run, substitute a basename, follow an
alternate R5 route, or infer missing facts.

## Blocking Rule

Any one of the following produces `BLOCKED_HANDOFF_NOT_CONSUMABLE` and stops
the handoff before Stage A:

- missing required field, artifact, hash, record, event class, or join;
- duplicate artifact ID, path, role, raw serial, normalized serial, event ID,
  or identity join key;
- malformed JSON, JSONL, base64, UTF-8, timestamp, path, serial, PID, start
  tick, netns, or SHA-256 value;
- a privileged-execution receipt that is absent, duplicated, stale, or does
  not prove one human-invoked exact command with effective UID 0 and exit code
  0;
- a declared hash that does not equal the hash of the exact selected bytes;
- a path that is relative, globbed, aliased, substituted, or not the exact
  manifest path used for the read;
- any run ID, host ID, PID, start-time tick, netns inode, event ID, serial,
  timestamp, or hash disagreement across records;
- an unjoined process identity, an ambiguous join, or a join captured after
  the process ceased to be live when the contract requires live capture;
- a normalized row whose raw serial, raw bytes, or raw-event hash cannot be
  linked one-to-one to the raw audit row;
- a `FILE_READ_OR_WRITE` row without exact permission-filter provenance,
  exact watched path, raw serial, raw hash, requested access, underlying
  syscall, and same-serial `SYSCALL`/`PATH` evidence;
- a same-serial audit bundle without a successful supported syscall, exact
  audit key, or exact watched path;
- any missing required event class, nonzero audit loss/backlog, raw-link
  failure, duplicate, or undeclared event class;
- absent, mismatched, or unbound PCAP authentication when socket classes are
  in the required closure;
- incomplete inverse-rule removal, residual topology/process state, changed
  persistent rules, or an unproved restored baseline;
- any use of a global rule delete, `mn -c`, external NAT attachment, APT
  action, PROVX execution, detector training, inference, formal experiment,
  adapter change, encoder change, or push in this design task;
- a package manifest hash that is missing, circularly computed, stale, or not
  reproducible under the canonicalization profile.

There is no warning-only state for these failures. A partial runtime is not a
consumable runtime. E0-B may record diagnostic failure codes, but it must not
pass any affected record downstream.

## Authentication Order

1. Validate the handoff object against `R6R3_RUNTIME_HANDOFF_SCHEMA.json`.
2. Recompute the package manifest hash after removing only
   `package_manifest.manifest_sha256`.
3. Require the exact required artifact IDs once each, with unique paths and
   hashes. Read only those paths and recompute exact-byte hashes and lengths.
4. Authenticate source commit, producer harness, producer tests, pre-run
   contract, file-access semantics contract, and the six design documents.
5. Authenticate the explicit privileged fact from the manifest-bound
   `r6_privileged_execution_receipt`: one human-invoked exact command,
   effective UID 0, exit code 0, completed result, successful R6R3
   classification, successful micro-probe, and exact probe cleanup state.
6. Parse all JSON documents and JSONL rows strictly. The parser must reject
   duplicate object keys; a parser that cannot detect duplicate keys is not a
   compliant validator. Also reject blank or malformed records, invalid
   base64, and non-finite numbers.
7. Require one run ID across the package, every runtime JSON document, and
   every JSONL row. Require the declared R6R3 run ID and one shared runtime
   artifact root. Source-lineage and contract-design paths are authenticated
   separately and are not incorrectly forced under that runtime root.
8. Recompute every raw row hash from decoded raw bytes. Require one raw row
   per serial.
9. Recompute every normalized raw-event hash from decoded bytes. Require one
   normalized row per event ID and raw serial.
10. Join normalized rows to raw rows by exact integer serial, then require
    byte equality and equal hashes. Do not accept a coverage boolean as a
    substitute for recomputation.
11. For each `FILE_READ_OR_WRITE` row, parse the raw bundle for that exact
    serial. Require raw `SYSCALL` and `PATH` records on that serial, a
    supported syscall with `success=yes`, the exact audit key, and the exact
    watched path. The syscall is retained as evidence; it is not inferred
    from the permission filter.
12. Join every normalized process-bearing row to exactly one PID/start-ticks/
    netns/logical-host row with `join_status=JOINED`. Recompute duplicate and
    ambiguity counts and the namespace assertions.
13. Recompute all eight class counts. Require each class at least once,
    `FILE_READ_OR_WRITE > 0`, empty missing/unexpected lists, zero loss, zero
    backlog, and zero link/duplicate failures.
14. Hash the exact PCAP bytes and require the same hash in the selected PCAP,
    coverage evidence, and post-cleanup evidence. PCAP authenticates runtime
    provenance only; it never creates graph nodes or edges.
15. Verify exact inverse removal of only successfully added transient rules,
    unchanged persistent rule files, zero residual processes/interfaces/OVS
    objects/tcpdump process, zero loss/backlog, and baseline hash restoration.
16. Recompute canonical serialization and the manifest hash once more after
    all reads. Pass only if no blocking rule remains.

## Producer Obligation

E0-A owns the factual runtime package. It must not fill a missing value with a
placeholder, an inferred syscall, a guessed host, a directory scan, or a
historical value. The minimum-package JSON in this directory is a shape
template only and explicitly carries `NOT_RUNTIME_EVIDENCE`; it cannot pass
this policy.

E0-A must preserve the raw audit bytes and the normalized raw-event bytes
needed for independent recomputation. It must preserve exact paths, exact
serials, and exact hashes in its manifest. It must emit cleanup and lineage
artifacts even when the runtime fails; a failed or partial run is then
blocked, never promoted by editing the result after the fact.

## Consumer Obligation

E0-B must return a structured decision with the run ID, authenticated manifest
hash, passed rule IDs, failed rule IDs, and failure codes. A pass means only
that the handoff is authenticated and eligible for the separately governed
Stage A adapter. It does not authorize training, inference, graph generation,
or a change to the R7/R7R1 adapter.

The current R7 adapter remains R5-pinned and lacks the final R6 selectable
runtime route and `FILE_READ_OR_WRITE` edge mapping. That is an integration
boundary for a later action, not an exception to this handoff policy and not a
reason to alter the adapter in E0-B.
