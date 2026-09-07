# MININET E1C R6R4 Privileged Runtime Smoke

## Terminal Disposition

```text
MININET_E1C_R6R4_PRIVILEGED_RUNTIME_SMOKE = BLOCKED
```

The frozen privileged runtime smoke **executed** on 2026-09-07 in a human-authorised
sudo window and ran to completion with no runtime error. It returned exit code 3
(`PARTIAL`, `PARTIAL_MISSING_REQUIRED_EVENT_CLASS`). The single unmet frozen
predicate is `missing_required_classes = ['FILE_READ_OR_WRITE']`.

## What executed

```text
sudo /usr/bin/python3 /home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/mininet_e1c_r6_file_access_closure_smoke.py --run-privileged
```

Start `2026-09-07T12:16:37.372772Z`, end `2026-09-07T12:16:51.762491Z`, exit `3`.
Harness bytes `8b0db6ea…` — byte-identical to the payload committed at `edee49c3`.

Reported states:

```text
CLEAN_BASELINE_VERIFIED, FILE_PRECREATED, RULE_ADDED, BENIGN_READ_WRITE_PERFORMED,
AUDIT_EVIDENCE_PASS, RULE_REMOVED_BASELINE_RESTORED, MININET_EXECUTED, CLEANUP,
BASELINE_RESTORED
```

## Pre-runtime baseline question, settled

The earlier blocked attempt recorded `observed_rule_dump_sha256 = e3b0c442…` and this
was read as evidence that the host renders an empty rule set as empty stdout. It did
not. That record had `returncode: null` and a Python `PermissionError`, so
`auditctl -l` never executed; `e3b0c442…` is `sha256(b"")`.

A direct observation with no Python in the path now settles it:

```text
returncode: 0
stdout_bytes: 9
stdout_sha256: 61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87
xxd: 4e6f 2072 756c 6573 0a   "No rules\n"
```

This is exactly the frozen `HISTORICAL_EMPTY_HASH`. The literal-hash predicate was
correct for this host and was never weakened.

## Why PARTIAL — exact unmet predicate

`classify()` took neither BLOCKED branch: `runtime_error` null, rules removed,
baseline restored, topology residue zero, child residue zero, namespace assertions
pass. It took the PARTIAL branch on one input:

| classify() input | value |
|---|---|
| `missing_required_classes` | `['FILE_READ_OR_WRITE']` |
| `pid_netns_join_failure_count` | 0 |
| `tcpdump.pcap_sha256` | present, hash-bound |

Normalized class counts: `PROCESS_START_OR_EXEC 10, PROCESS_EXIT 4,
FILE_CREATE_OR_OPEN 2, FILE_DELETE 2, SOCKET_BIND 4, SOCKET_CONNECT 1,
SOCKET_ACCEPT 1, FILE_READ_OR_WRITE 0` — 7 of 8 required classes present.

## Root cause: a defect in the frozen collector, not the runtime

`parse_raw_audit_event_bundles` zips two independently computed line lists:
`raw.splitlines()` over **bytes** and `text.splitlines()` over **str**.
`bytes.splitlines()` breaks only on `\r`, `\n`, `\r\n`; `str.splitlines()` also breaks
on `\x1d`. `ausearch --raw` embeds `\x1d` between each record body and its interpreted
suffix, so `zip()` truncates and misaligns.

Proof on raw serial 3879 (h1 `openat` on the watched path):

| | |
|---|---|
| `bytes.splitlines()` | 5 lines |
| `str.splitlines()` | 10 lines |
| `\x1d` occurrences | 5 |
| records captured by the frozen parser | `SYSCALL, CWD, PATH` |
| records actually present | `SYSCALL, CWD, PATH, PATH, PROCTITLE` |
| the captured `PATH` | `item=0 nametype=PARENT name=…/temp-events/` |
| the dropped `PATH` | `item=1 nametype=NORMAL name=…/temp-events/h1.txt` |

Losing the `item=1` record fails the `exact_path` check in
`_strict_raw_file_access_event`, so no strict permission event is registered; then
`normalize_audit_record` sees `permission_candidate=True` with no strict event and
returns `None`, dropping the record entirely. Running the same frozen function on the
same bytes with `\x1d` stripped captures all five records and yields the event.

## The runtime evidence does exist

Independent re-reading of the run's own raw bytes authenticates **6**
`FILE_READ_OR_WRITE` events across both logical hosts:

| serial | host | syscall | access | pid | join |
|---|---|---|---|---|---|
| 3869 | h2 | openat | w | 1375152 | JOINED |
| 3870 | h2 | openat | w | 1375152 | JOINED |
| 3871 | h2 | openat | r | 1375152 | JOINED |
| 3879 | h1 | openat | w | 1375151 | JOINED |
| 3880 | h1 | openat | w | 1375151 | JOINED |
| 3881 | h1 | openat | r | 1375151 | JOINED |

Every one carries same-serial `SYSCALL` + `PATH`, `success=yes`, the exact transient
audit key `e1c600493b1e40a2`, the exact watched path, a supported syscall, base64 raw
bytes that strict-decode to the recorded SHA-256, and one matching `JOINED` PID /
start-ticks / netns-inode / logical-host record.

**This does not make the receipt PASS.** The frozen schema locates closure in the
normalized evidence and the coverage count, both of which are zero. Promoting the
raw-byte proof into the receipt would mean regenerating normalized evidence outside
the frozen collector. That is forbidden, so the `PARTIAL` result stands and closure is
reported `NOT_PROVEN`.

## Receipt, cleanup and residual state

| Gate | Result |
|---|---|
| Receipt freshness / lineage | PASS |
| Artifacts present (8/8), hashes, run_id uniformity | PASS |
| Normalized↔raw links (92 serials, 0 duplicates, hashes) | PASS |
| PID/netns joins 4/4 JOINED, post-exec identity | PASS |
| Audit loss / backlog | 0 / 0 |
| PCAP hash vs both declared hash sources | PASS |
| Post-cleanup baseline before == after | PASS (`61501e69…`) |
| Rules removed | 62/62, all rc 0 |
| Residual objects | 0 children, 0 interfaces, 0 OVS objects, 0 tcpdump |
| `raw_audit_record.records` | **BLOCKED** — rows carry `record_types` |
| `FILE_READ_OR_WRITE` count | **BLOCKED** — 0 |

## Blocking findings

1. **F1** `parse_raw_audit_event_bundles` bytes/str `splitlines` misalignment — a
   harness/reporting defect that suppresses the required class.
2. **F2** `raw_audit_record.records` absent from the emitted raw JSONL; independent of
   F1 and would block the receipt on its own.

Non-blocking: **F3** open-flag radix (`int(a2, 0)` parses hex-rendered flags as
decimal; both radices agree on all six events here, so nothing is misreported).
**F4** an earlier preflight matrix was overwritten before preservation; remediated.

## Boundaries held

```text
FORMAL_1796_EXPERIMENT_EXECUTED = NO      PROVX_TRAINING = NO
PROVX_INFERENCE = NO                      SOURCE_AUTH_EXECUTED = NO
CURRENT86_P0_EXECUTED = NO                CURRENT86_P1_EXECUTED = NO
BINDING_PUBLICATION = NO                  GIT_COMMIT_CREATED = NO
GIT_PUSH_EXECUTED = NO                    GIT_REF_MUTATION = NO
FROZEN_HARNESS_MODIFIED = NO              RUNTIME_EVIDENCE_SYNTHESIZED = NO
```

## Next bounded action

A separate, separately reviewed **harness remediation cycle** for F1 and F2 against
`mininet_e1c_r6_file_access_closure_smoke.py`, followed by one re-run of the frozen
smoke. The harness is frozen and byte-authenticated at `edee49c3`; it was not modified
here, and re-running it unchanged would reproduce this same PARTIAL.
