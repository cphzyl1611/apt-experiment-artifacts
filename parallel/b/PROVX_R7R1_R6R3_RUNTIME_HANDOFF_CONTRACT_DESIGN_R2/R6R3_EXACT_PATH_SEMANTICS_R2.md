# R6R3 Exact Path Semantics R2

## Path Language

Every required runtime artifact path and runtime root is an absolute POSIX path
encoded as UTF-8 without NUL. The path is a literal path, never a glob, URI,
basename, directory selector, or path pattern. `.` and `..` components are
forbidden in the declared string, even when lexical normalization would place
the result below the root. The root comparison is component-wise, so
`/run/a2` is not beneath `/run/a`.

## Stable-Object Algorithm

An independent verifier must implement the following logical sequence for each
required artifact:

1. Validate the declared root and path syntax. Reject relative paths, dot
   segments, NUL, glob metacharacters, and an empty root.
2. Fix the exact declared runtime root before reading any artifact. The root
   itself must be opened/resolved with no-follow semantics and represented as
   a canonical component tuple.
3. Walk every path component from the opened root directory using an
   `openat`-equivalent operation with `O_NOFOLLOW` (or an equivalent API that
   rejects symlink traversal). Do not call a path-resolving API that silently
   follows a symlink.
4. Require the final object to be a regular file. Capture `lstat`/directory
   entry identity and then open it read-only with no-follow semantics.
5. Compare device and inode from the pre-open identity with `fstat` on the
   opened descriptor. A mismatch is a substitution/race failure.
6. Read exact bytes to EOF, compute SHA-256 and byte length, and compare with
   the manifest declaration.
7. `fstat` the still-open descriptor again. Device, inode, regular-file type,
   and expected size must still match. A changed object, short read, or
   replacement blocks.
8. Close the descriptor and optionally repeat the identity/hash check if the
   platform requires a post-close verification window. Any inability to prove
   stable identity blocks.

## Containment and Substitution Rules

- A canonical path must be under the one exact canonical runtime root after
  component resolution and must have a separator boundary.
- A symlink in any parent or final component is a hard failure, even if its
  target resolves inside the root.
- Bind mounts, aliases, hard-link substitution, device/inode changes, and
  path replacement races are rejected when they prevent the verifier from
  proving the declared object identity. Hard-link identity is accepted only
  when the captured device/inode and exact bytes remain stable throughout the
  read.
- The verifier never follows a path from an artifact's contents, a report, a
  basename, a `latest` pointer, or a directory scan.
- Source/design document paths are exact authenticated inputs but are a
  separate provenance domain; they are not runtime artifacts and are not
  silently treated as being under the runtime root.

## Failure Dispositions

`PATH_NOT_ABSOLUTE`, `PATH_DOT_SEGMENT`, `PATH_GLOB`, `PATH_SYMLINK`,
`PATH_CROSS_ROOT`, `PATH_OBJECT_REPLACED`, `PATH_DEVICE_INODE_MISMATCH`,
`PATH_NOT_REGULAR`, and `FILE_HASH_MISMATCH` are all blocking outcomes. There
is no fallback to a similar path or a second run.
