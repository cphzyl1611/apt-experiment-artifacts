#!/usr/bin/env python3
r"""Fail-closed gate predicates for the E0-A R6R4 pre-runtime prerequisite check.

Extracted so they can be tested without executing privileged commands.

Two remediations relative to the defective preflight preserved at
failed_preflight_evidence/e0a_r6r4_preflight.DEFECTIVE.py:

D1  audit status parsing.  The defective parser tokenised on "=" only and
    therefore returned {} for the `key value` form that auditctl 3.0.7 emits on
    this host, producing a false negative.  The replacement matches the FROZEN
    harness semantics exactly (mininet_e1c_r6_file_access_closure_smoke.py
    parse_audit_status uses rf"\b{key}\s+(\d+)"), and additionally accepts the
    deterministic `key=value` form.  Conflicting duplicate values are BLOCKED.

D3  non-executed commands.  The defective run() wrapper returned
    returncode=None when the subprocess raised, and predicates written as
    `returncode != 0` then scored a command that never ran as evidence of a
    clean host.  Every gate here requires proof of execution and fails closed.

The empty-audit-rule predicate is deliberately NOT relaxed.  The frozen,
byte-authenticated harness hard-requires the literal dump hash in
_audit_baseline_clean() and verify_clean_root_baseline()
(HISTORICAL_EMPTY_HASH = sha256(b"No rules\n")).  See
03A_PREFLIGHT_DEFECT_REPRODUCTION_AND_REMEDIATION.json.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

# sha256(b"No rules\n") -- identical to HISTORICAL_EMPTY_HASH in the frozen harness.
EXPECTED_EMPTY_RULE_HASH = "61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87"

AUDIT_STATUS_INT_KEYS = (
    "enabled", "failure", "pid", "rate_limit", "backlog_limit", "lost",
    "backlog", "backlog_wait_time", "backlog_wait_time_actual",
)


def command_executed(record: Mapping[str, Any] | None) -> bool:
    """True only when the subprocess actually ran and reported an exit status."""
    if not isinstance(record, Mapping):
        return False
    return isinstance(record.get("returncode"), int)


def parse_audit_status_text(text: Any) -> dict[str, int]:
    """Parse `auditctl -s` output.

    Accepts the space-delimited `key value` form emitted by auditd 3.x (the
    form the frozen harness parses) and the `key=value` form emitted by older
    auditctl builds.  A key is returned only when every occurrence agrees on
    one integer value; a conflict or a non-integer value drops the key so the
    dependent gate fails closed.
    """
    if not isinstance(text, str):
        return {}
    parsed: dict[str, int] = {}
    for key in AUDIT_STATUS_INT_KEYS:
        values: set[int] = set()
        for match in re.finditer(rf"\b{re.escape(key)}[ \t]*[= \t][ \t]*(-?\d+)\b", text):
            values.add(int(match.group(1)))
        if len(values) == 1:
            parsed[key] = values.pop()
    return parsed


def audit_status_gate(record: Mapping[str, Any] | None) -> tuple[str, dict[str, int]]:
    """PASS only on an executed, successful `auditctl -s` reporting lost=0 backlog=0."""
    if not command_executed(record) or record.get("returncode") != 0:
        return "BLOCKED", {}
    parsed = parse_audit_status_text(record.get("stdout"))
    if "lost" not in parsed or "backlog" not in parsed:
        return "BLOCKED", parsed
    return ("PASS" if parsed["lost"] == 0 and parsed["backlog"] == 0 else "BLOCKED"), parsed


def audit_rule_lines(stdout: Any) -> list[str]:
    """Rule lines, excluding the 'No rules' sentinel -- unchanged from the original."""
    if not isinstance(stdout, str):
        return []
    return [line for line in stdout.splitlines()
            if line.strip() and line.strip() != "No rules"]


def empty_rule_baseline_gate(record: Mapping[str, Any] | None) -> tuple[str, dict[str, Any]]:
    """PASS only on an executed, successful `auditctl -l` whose exact dump bytes
    hash to the frozen HISTORICAL_EMPTY_HASH and which carries no rule lines.

    The literal hash is the authority here because the frozen harness enforces
    exactly that constant before it will run.  A non-executed command, a
    nonzero exit, or any other rendering is BLOCKED, never 'clean'.
    """
    evidence: dict[str, Any] = {
        "expected_empty_rule_dump_sha256": EXPECTED_EMPTY_RULE_HASH,
        "executed": command_executed(record),
        "returncode": record.get("returncode") if isinstance(record, Mapping) else None,
        "observed_rule_dump_sha256": None,
        "observed_rule_lines": [],
        "blocked_reason": None,
    }
    if not evidence["executed"]:
        evidence["blocked_reason"] = "AUDITCTL_LIST_NOT_EXECUTED"
        return "BLOCKED", evidence
    stdout = record.get("stdout")
    evidence["observed_rule_dump_sha256"] = hashlib.sha256(
        (stdout if isinstance(stdout, str) else "").encode()).hexdigest()
    evidence["observed_rule_lines"] = audit_rule_lines(stdout)
    if record.get("returncode") != 0:
        evidence["blocked_reason"] = "AUDITCTL_LIST_NONZERO_RETURNCODE"
        return "BLOCKED", evidence
    if evidence["observed_rule_lines"]:
        evidence["blocked_reason"] = "PREEXISTING_AUDIT_RULES_PRESENT"
        return "BLOCKED", evidence
    if evidence["observed_rule_dump_sha256"] != EXPECTED_EMPTY_RULE_HASH:
        evidence["blocked_reason"] = "RULE_DUMP_HASH_NOT_FROZEN_EMPTY_BASELINE"
        return "BLOCKED", evidence
    return "PASS", evidence


def device_absent(record: Mapping[str, Any] | None) -> bool:
    """True only when `ip link show dev X` executed and reported the device missing."""
    return command_executed(record) and record.get("returncode") != 0


def ovs_bridge_absent(record: Mapping[str, Any] | None) -> bool:
    """True only when `ovs-vsctl br-exists s1` executed and reported absence."""
    return command_executed(record) and record.get("returncode") != 0
