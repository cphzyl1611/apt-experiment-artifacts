# Prompt 3 — MININET-E1A-R2 Privileged Attribution Harness Preparation

Continue from MININET-E1A.

Current verdict:
`BLOCKED_PRIVILEGED_EXECUTION_NOT_YET_PERFORMED`

Do not simply rerun the old harness.

## Goal

Prepare a corrected single-command benign privileged harness that can actually prove or disprove:

`event process -> exact logical Mininet host`

using process/netns metadata, socket evidence and concurrent packet capture.

Prepare and validate the harness unprivileged, then stop and ask the human user to run one exact sudo command.

## 1. Preserve previous evidence

Keep E1A R1 artifacts immutable.

Create:

`e1a-r2-run-<timestamp>/`

## 2. Correct descendant attribution

For h1 and h2:
- start benign child processes simultaneously;
- record exact child PID while alive;
- record child `/proc/<pid>/ns/net`;
- record child cgroup;
- record host shell PID/netns;
- prove child netns == owning host netns and != other host netns.

Use long enough benign sleep/socket windows to capture evidence reliably.

## 3. Correct socket attribution

Each child opens a benign TCP listening socket for several seconds.

While alive record:
- child PID;
- local address/port;
- host netns;
- `ss`/proc socket evidence if available;
- logical host mapping.

## 4. Integrate tcpdump into the same run

The privileged harness itself must:
- start bounded tcpdump after topology interfaces exist and before benign network traffic;
- capture only the test fabric/relevant loopback;
- run benign h1↔h2 ping or simple TCP exchange;
- stop tcpdump before teardown;
- hash the pcap.

Do not rely on a second sequential human tcpdump command.

## 5. File-event attribution limitation

Create/read/delete separate benign temp files.

Record which child PID performed each operation.

Do not claim filesystem isolation.

## 6. Cleanup

Use `net.stop()` and run-specific process termination.

Do not invoke broad `mn -c` unless the R2 run detects stale objects it cannot clean.
If broad cleanup becomes necessary, stop and request human approval first.

## 7. Preflight self-check

Before privileged execution:
- `python -m py_compile`;
- static check no NAT/external links;
- static check no APT commands;
- static check tcpdump filter is bounded;
- record harness SHA256.

Then STOP with:

```text
HUMAN_PRIVILEGED_RUN_REQUIRED = YES
```

and print exactly one command:

`sudo /usr/bin/python3 <absolute corrected_harness_path>`

Do not attempt sudo automatically.

## 8. After human run

When the user reports completion, resume the same session and:
- parse evidence;
- verify cleanup;
- decide:
  `PLAIN_MININET_ATTRIBUTION_FEASIBLE`
  or
  `MININET_CONTAINER_SUBSTRATE_REQUIRED`
  or
  `BLOCKED`.

## Outputs before human run

- corrected harness;
- `MININET_E1A_R2_PRE_RUN_CONTRACT.json`
- `MININET_E1A_R2_HARNESS_STATIC_AUDIT.json`
- exact human command.

## Hard boundaries

No package installation, APT actions, PROVX execution, formal scores,
external network/NAT, or authority mutation.

## Pre-human terminal

```text
MININET_E1A_R2_HARNESS_PREPARATION = PASS | BLOCKED
HUMAN_PRIVILEGED_RUN_REQUIRED = YES | NO
ATTACK_ACTIONS_EXECUTED = 0
FORMAL_EXPERIMENT_EXECUTED = NO

NEXT_ACTION =
HUMAN_RUN_EXACT_SUDO_COMMAND

STOP = true
```
