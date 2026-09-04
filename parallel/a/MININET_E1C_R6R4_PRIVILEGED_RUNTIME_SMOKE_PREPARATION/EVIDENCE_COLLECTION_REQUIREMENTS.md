# Future Evidence Collection Requirements

These requirements constrain a future, separately authorized operator. They
are not instructions to execute work in this package.

## Receipt Root

The future receipt root must be new, immutable after collection, and separate
from this package. It must contain the eight receipt artifacts named in the
receipt schema. Every artifact is described by a relative path, byte count,
SHA-256, and the exact common `run_id`.

## Raw And Normalized Evidence

Raw audit JSONL must preserve each complete exact-serial record bundle, its
base64-encoded bytes, and SHA-256. Normalized JSONL must preserve the same
serial, the same decoded raw bytes, and the matching SHA-256. A future
reviewer must recompute all three relationships; a summary boolean alone is
not evidence.

For `FILE_READ_OR_WRITE`, acceptance requires the same serial bundle to
contain `SYSCALL` and `PATH`. The syscall must be supported, successful, and
carry the exact transient audit key. The path record must contain the exact
watched file path. The normalized event must name
`AUDIT_FILESYSTEM_PERMISSION_FILTER`, `watched_path`, `requested_access`, and
`underlying_syscall`; it must not infer a syscall or path.

## Identity And Coverage

Each normalized event must have exactly one matching `JOINED` PID/netns/logical
host record. The match includes the run ID, logical host ID, PID, process start
ticks, and netns inode. No identity is recovered from timing, filename, or
host-name guessing.

Coverage/loss output must make the `FILE_READ_OR_WRITE` count positive and
show zero audit loss and backlog. It must prove finite-time evidence collection
with no deadline expiry and a zero collector return code. Any late or failed
collection is rejected even when some records are visible.

## Packet Capture And Cleanup

PCAP bytes must have a separately declared PCAP hash-source artifact whose
`pcap_sha256` equals the PCAP's recomputed SHA-256. A reference in a review or
a filename does not authenticate the packet capture.

Post-cleanup proof must show that only rules from the same run were removed
and that the post-cleanup audit baseline hash exactly matches the pre-run
baseline hash. Missing cleanup proof or a non-restored baseline blocks the
receipt.

## Evidence Truthfulness

The preparation package must never be cited as runtime evidence. A receipt
must classify its own bytes as new runtime evidence and distinguish them from
synthetic schema fixtures, static reviews, and historical diagnostics.
