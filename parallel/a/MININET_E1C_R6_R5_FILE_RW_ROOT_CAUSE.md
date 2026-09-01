# Mininet E1C-R6 R5 FILE_READ_OR_WRITE root cause

`MININET_E1C_R5_AUDITD_COLLECTOR=PARTIAL_MISSING_REQUIRED_EVENT_CLASS`.
R5 accepted the ordinary open/read/write family, but the installed audit
userspace rejected `pread64` and `pwrite64` (`Syscall name unknown`). The run
then produced zero normalized `FILE_READ_OR_WRITE` events while all other
classes, cleanup assertions, namespace joins, and the TCP handshake passed.

The evidence supports this bounded diagnosis:

`R5_FILE_RW_ROOT_CAUSE = DIRECT_READ_WRITE_SYSCALL_RULE_STRATEGY_INSUFFICIENT_FOR_BOUNDED_FILE_ACCESS`.

The installed auditctl manual explains why: `perm` may be used without naming
a syscall, allowing the kernel to select syscalls satisfying the requested
permissions. Its filesystem-watch `r`/`w` permissions describe requested
access; direct read/write calls are omitted because they overwhelm logs and
open flags are inspected instead. The same manual says `path` is a full file
path, `dir` is recursive, and legacy `-w` watches are less expressive.

R6 therefore uses one pre-created exact file per logical host and a transient
syscall-form rule:

```text
-a always,exit -F arch=b64 -F path=<exact-file> -F perm=rw -F pid=<live-child> -k <R6-key>
```

This is a bounded filesystem permission filter, not a claim that every event
was caused by a raw `read(2)` or `write(2)` call. Normalized rows retain
`evidence_basis=AUDIT_FILESYSTEM_PERMISSION_FILTER`, `watched_path`,
`requested_access`, and the observed `underlying_syscall`.

The R5 evidence is preserved unchanged. Its historical boolean joined the
normalized `raw_event_sha256` field against a raw record's nonexistent
`raw_event_sha256` field instead of raw `raw_sha256`; independent serial and
decoded-byte hash recomputation was 28/28. R6 fixes the verifier and records a
RED reproduction in `MININET_E1C_R6_RAW_LINK_RED_EVIDENCE.json`.

## R6 implementation-gap finding

The pushed harness exposed a root-only branch in `main()` that called
`execute_reviewed_r6_path()`, but `_reviewed_mininet_smoke()` was an unconditional
`BLOCKED` placeholder. The existing reachability test injected a fake `smoke`
callback, so it proved only callback ordering, not the default runtime path.
The earlier preparation artifacts therefore overstated readiness. This was an
implementation-gap defect, not evidence about collector behavior.

R6 now routes the root branch through `execute_reviewed_r6_path()`: the exact
probe must pass, remove its inverse rule, and explicitly observe a clean
baseline (`RULE_REMOVED_BASELINE_RESTORED`) before `_reviewed_mininet_smoke()`
is reachable. A probe result that merely claims `AUDIT_EVIDENCE_PASS` cannot
open the smoke gate. The full smoke keeps the watched read/write inode
pre-created and uses a separate disposable inode for `FILE_DELETE`. The
regression test proves the former gate text is absent, the reviewed path is
entered only after the explicit restoration state, and cleanup handling is
preserved.
