# R6R3 Runtime Handoff Hash Lineage

## Hash Domains

The handoff has four separate cryptographic hash domains plus one
privileged-execution binding. They must not be conflated.

1. **Source lineage hashes** identify the committed implementation and design
   inputs: the source commit, producer harness, producer tests, pre-run
   contract, file-access semantics contract, and contract-design documents.
2. **Artifact hashes** identify the exact bytes at every manifest path,
   including raw audit JSONL, normalized-event JSONL, PID/netns joins,
   coverage/loss, cleanup, result, report, and PCAP.
3. **Record hashes** identify raw audit bundles and normalized raw-event bytes.
4. **Package manifest hash** identifies the ordered manifest object under the
   canonical JSON profile.

The privileged-execution receipt is part of the artifact-hash domain, but it
also has a required semantic binding: its parsed one-invocation record must
agree with `privileged_execution`. A claimed UID or command without that
receipt is not authenticated.

No hash is evidence by itself. A hash is accepted only after the corresponding
path, run identity, record identity, and cross-file relationship pass.

## Source Lineage

The design is anchored to:

- R7R1 remediation commit:
  `cde75a82e7938db6d5903d16885bf35ceb17aa68`;
- interface review commit:
  `13573a5a4c03261237a9b3553efb482b3eebd273`;
- E0-A R6R3 materialization commit:
  `6aec9e0ed113c17fd729f8ae359fd6d2c30fff0a`.

The known R6R3 producer source hashes are recorded in the authentication
rules: harness `4202d3144974355881a398ffb58b28cb016d3add73e8fe7752012d1c76d06428`
and test `510a4339830a1641737fbefa152d231a45c98f2bca0f185e1e13d1cf473be14d`.
E0-B still recomputes every supplied source-file hash from exact bytes; the
known values are not a shortcut for path authentication.

## Artifact Hashes

For every `package_manifest.entries[]` item:

```text
entry.sha256 = SHA256(exact bytes opened from entry.path)
entry.byte_length = exact byte length opened from entry.path
```

The path in the manifest is absolute and exact. E0-B rejects globbing,
basename substitution, newest-file selection, alternate roots, symlink or
alias substitution, and any read that cannot be tied to the declared path.

Runtime artifact paths must share the declared run root. Source-lineage and
contract-design paths are separate authenticated inputs and are not required
to live below the runtime run root.

The raw and normalized JSONL files are hashed as emitted bytes. E0-B does not
re-serialize them before checking their artifact hash.

## Privileged Execution Lineage

`r6_privileged_execution_receipt` is a required manifest entry. Its exact
bytes must contain one and only one invocation record with the human-initiation
fact, effective UID `0`, the exact reviewed command, exit code `0`, and the
completed R6R3 result. E0-B hashes those bytes and compares the parsed values
with the structured `privileged_execution` object. A package field is never a
substitute for the receipt, and multiple invocation records fail closed.

## Raw-to-Normalized Lineage

For each raw audit row, R6R3 preserves a bundle grouped by one integer audit
serial:

```text
raw_row.raw_sha256 = SHA256(base64_decode(raw_row.raw_bytes_b64))
```

For each normalized row:

```text
normalized.raw_event_sha256 =
    SHA256(base64_decode(normalized.raw_event_bytes_b64))
```

E0-B joins the two rows by exact `raw_serial` and requires all of the
following:

- the serial exists exactly once in raw evidence;
- the serial exists exactly once in normalized evidence;
- decoded raw bytes are byte-identical;
- normalized and raw SHA-256 values are equal;
- the normalized row's run ID equals the handoff run ID.

The declared coverage boolean is advisory metadata. E0-B recomputes these
links and blocks on any failure or duplicate.

## FILE_READ_OR_WRITE Lineage

Each normalized `FILE_READ_OR_WRITE` row carries:

- `path` and `watched_path`, which must be equal and must equal one exact
  pre-created permission-filter path;
- `file_identity_paths`, which must contain that exact path;
- `raw_serial` and `raw_event_sha256` from the linked raw bundle;
- `evidence_basis= AUDIT_FILESYSTEM_PERMISSION_FILTER`;
- `requested_access` in `r`, `w`, or `rw`;
- the retained `underlying_syscall`;
- `syscall_record_serial` and `path_record_serial`, both equal to `raw_serial`.

The raw bundle for that serial must contain raw `SYSCALL` and `PATH` records.
The syscall must be supported, have `success=yes`, carry the exact audit key,
and be paired with a `PATH` whose name is the exact watched path. A matching
key or path on another serial is not evidence. A syscall inferred from a
permission filter without the raw bundle is not evidence.

## Identity Lineage

Every process-bearing normalized row joins to exactly one row keyed by:

```text
(run_id, logical_host_id, pid, pid_start_time_ticks, netns_inode, role)
```

The join must have `join_status=JOINED`. E0-B checks PID positivity,
process-start-time ticks, netns inode, host membership, uniqueness, and
ambiguity. It also checks the R6 namespace assertions: each child remains in
its host shell namespace, and the two logical hosts remain distinct.

## PCAP Lineage

Because the required closure contains `SOCKET_BIND`, `SOCKET_CONNECT`, and
`SOCKET_ACCEPT`, the PCAP is required for this handoff:

```text
pcap_authentication.sha256 = SHA256(exact bytes at pcap_authentication.path)
```

The same value must appear in the coverage/loss and post-cleanup evidence
sources. E0-B requires all source values to match. The PCAP is an
authentication/provenance artifact only. It cannot supply a missing audit
event, process join, file edge, or graph edge.

## Package Manifest Canonicalization

Canonical JSON is:

```python
json.dumps(
    value,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode("utf-8")
```

The manifest hash is computed over `package_manifest` after removing exactly
the `manifest_sha256` member:

```text
package_manifest.manifest_sha256 =
    SHA256(canonical_utf8_json(package_manifest_without_manifest_sha256))
```

The hash is therefore not recursive. Object keys are sorted, arrays retain
their declared order, UTF-8 has no BOM, and line-oriented artifacts use LF.
Non-finite numbers, invalid UTF-8, duplicate JSON object keys, and any
noncanonical serialization fail closed.

The final E0-B check repeats canonical serialization after all artifact reads
and requires the stored manifest hash to remain identical. A stale or
recomputed-after-edit manifest is blocked.
