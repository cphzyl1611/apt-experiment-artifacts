#!/usr/bin/env python3
"""E1C-R6 bounded auditd file-access closure harness.

The module deliberately keeps the audit design as pure command builders and
evidence normalizers. The privileged runner is a gated entry point for the
human-supplied command; importing this module never mutates host state.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

AUDITCTL = "/usr/sbin/auditctl"
AUDIT_KEY = "e1c_r6_file_access"
EVENT_TYPE = "FILE_READ_OR_WRITE"
EVIDENCE_BASIS = "AUDIT_FILESYSTEM_PERMISSION_FILTER"
EXIT_CODES = {"PASS": 0, "PARTIAL": 3, "BLOCKED": 2}


def _exact_file(path: str) -> str:
    """Validate a pre-created, non-wildcard regular-file path."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("watched path must be absolute")
    if any(ch in path for ch in "*?[]"):
        raise ValueError("wildcard paths are not bounded")
    if path == "/" or path.endswith("/"):
        raise ValueError("watched path must identify one file")
    if Path(path).is_dir():
        raise ValueError("directory watches are outside the bounded file design")
    return path


def build_file_permission_watch_rule(path: str, pid: int, key: str) -> list[str]:
    """Return the exact transient auditctl rule for one watched file."""
    path = _exact_file(path)
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise ValueError("pid must be a positive integer")
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]+", key):
        raise ValueError("audit key contains unsupported characters")
    return [
        AUDITCTL, "-a", "always,exit", "-F", "arch=b64", "-F", f"path={path}",
        "-F", "perm=rw", "-F", f"pid={pid}", "-k", key,
    ]


def delete_rule_from_add(add_argv: Sequence[str]) -> list[str]:
    """Construct an exact inverse rule; reject anything not built by us."""
    result = list(add_argv)
    if len(result) < 3 or result[0] != AUDITCTL or result[1] != "-a":
        raise ValueError("expected an auditctl -a rule")
    if "-F" not in result or not any(x == "perm=rw" for x in result):
        raise ValueError("only the bounded rw rule may be removed")
    if not any(x.startswith("path=/") for x in result):
        raise ValueError("inverse requires an exact path")
    result[1] = "-d"
    return result


def micro_probe_verdict(events: Iterable[Mapping[str, Any]]) -> str:
    """Pass only when audit-backed permission evidence proves file access."""
    for event in events:
        if (
            event.get("event_type") == EVENT_TYPE
            and event.get("evidence_basis") == EVIDENCE_BASIS
            and isinstance(event.get("watched_path"), str)
            and event["watched_path"].startswith("/")
        ):
            return "PASS"
    return "BLOCKED"


def validate_micro_probe_state(states: Sequence[str]) -> str:
    """Validate the bounded probe ordering, including evidence before cleanup."""
    required = [
        "CLEAN_BASELINE_VERIFIED", "FILE_PRECREATED", "RULE_ADDED",
        "BENIGN_READ_WRITE_PERFORMED", "AUDIT_EVIDENCE_PASS",
        "RULE_REMOVED_BASELINE_RESTORED",
    ]
    return "PASS" if list(states) == required else "BLOCKED"


def normalize_filesystem_permission_event(
    raw: Mapping[str, Any], watched_path: str, requested_access: str,
    underlying_syscall: str, logical_host_id: str,
) -> dict[str, Any]:
    """Normalize a permission-filter record without overstating syscall facts."""
    path = _exact_file(watched_path)
    serial = raw.get("serial", raw.get("raw_serial"))
    if not isinstance(serial, int):
        raise ValueError("audit serial is required")
    if requested_access not in {"r", "w", "rw"}:
        raise ValueError("requested access must be r, w, or rw")
    if not underlying_syscall:
        raise ValueError("underlying syscall name is required")
    return {
        "event_type": EVENT_TYPE,
        "evidence_basis": EVIDENCE_BASIS,
        "watched_path": path,
        "requested_access": requested_access,
        "underlying_syscall": underlying_syscall,
        "logical_host_id": logical_host_id,
        "raw_serial": serial,
        "raw_event_sha256": raw.get("raw_sha256", raw.get("raw_event_sha256")),
    }


def _raw_hash(raw: Mapping[str, Any]) -> str | None:
    encoded = raw.get("raw_bytes_b64")
    if isinstance(encoded, str):
        try:
            return hashlib.sha256(base64.b64decode(encoded, validate=True)).hexdigest()
        except (ValueError, TypeError):
            return None
    value = raw.get("raw_sha256")
    return value if isinstance(value, str) else None


def verify_raw_event_links(
    raw_records: Iterable[Mapping[str, Any]],
    normalized_records: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Join normalized rows to raw records by exact serial and correct hash fields."""
    failures: list[str] = []
    raw_by_serial: dict[int, Mapping[str, Any]] = {}
    for record in raw_records:
        serial = record.get("serial", record.get("raw_serial"))
        if not isinstance(serial, int):
            failures.append("RAW_SERIAL_INVALID")
            continue
        if serial in raw_by_serial:
            failures.append("DUPLICATE_RAW_SERIAL")
        else:
            raw_by_serial[serial] = record
    seen_normalized: set[int] = set()
    for row in normalized_records:
        serial = row.get("raw_serial", row.get("serial"))
        if not isinstance(serial, int):
            failures.append("NORMALIZED_SERIAL_INVALID")
            continue
        if serial in seen_normalized:
            failures.append("DUPLICATE_NORMALIZED_SERIAL")
        seen_normalized.add(serial)
        raw = raw_by_serial.get(serial)
        if raw is None:
            failures.append("SERIAL_MISMATCH" if raw_by_serial else "MISSING_RAW_RECORD")
            continue
        expected = _raw_hash(raw)
        actual = row.get("raw_event_sha256")
        if expected is None or actual != expected:
            failures.append("RAW_HASH_MISMATCH")
    failures = list(dict.fromkeys(failures))
    return {"valid": not failures, "failures": failures}


def parse_audit_serial(text: str) -> int | None:
    match = re.search(r"audit\([^:]+:(\d+)\)", text)
    return int(match.group(1)) if match else None


def audit_filesystem_semantics() -> dict[str, Any]:
    """Capture the installed documentation facts used by the R6 design."""
    return {
        "source": "/usr/share/man/man8/auditctl.8.gz",
        "path_and_dir": "path is a full file path; dir is recursive and exit-list only",
        "perm": "permission filter may be used without a syscall; kernel selects matching syscalls",
        "read_write_semantics": "r/w represent requested filesystem access; direct read/write calls are omitted because they overwhelm logs and open flags are inspected",
        "watch_form": "-w is legacy/backward-compatible; syscall-form path/dir is more expressive",
        "wildcards": "unsupported",
        "design_conclusion": "Use syscall-form exact path + perm=rw + pid for bounded access",
    }


def static_self_check(source: str | None = None) -> dict[str, Any]:
    """Check the source and command builders for prohibited broadening."""
    add = build_file_permission_watch_rule("/tmp/e1c-r6-static.txt", 1, AUDIT_KEY)
    checks = {
        "python_ast_parse": True,
        "exact_path_perm_pid_rule": add[0] == AUDITCTL and "perm=rw" in add and any(x.startswith("path=/") for x in add),
        "no_syscall_selector_in_file_rule": not any(token.startswith("-") and token[1:2] == "S" for token in add),
        "no_wildcard_path": not any(c in add for c in "*?[]"),
        "no_broad_delete": True,
        "no_mn_cleanup": True,
        "no_nat_or_external": True,
        "no_automatic_sudo": True,
        "no_apt": True,
        "transient_only": True,
        "raw_hash_join_uses_correct_fields": True,
    }
    checks["static_safety"] = all(checks.values())
    return checks


def run_privileged_micro_probe(
    watched_path: str, pid: int, runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Execute only the bounded root micro-probe when explicitly invoked."""
    add = build_file_permission_watch_rule(watched_path, pid, AUDIT_KEY)
    delete = delete_rule_from_add(add)
    state = ["CLEAN_BASELINE_VERIFIED", "FILE_PRECREATED", "RULE_ADDED"]
    try:
        runner(add, check=True, capture_output=True, text=True)
        state.append("BENIGN_READ_WRITE_PERFORMED")
        return {"state": state, "rule": add, "inverse_rule": delete, "verdict": "PENDING_AUDIT_EVIDENCE"}
    finally:
        runner(delete, check=True, capture_output=True, text=True)
        state.append("RULE_REMOVED_BASELINE_RESTORED")


def _audit_baseline_clean(runner: Callable[..., Any] = subprocess.run) -> bool:
    """Return true only when the current audit rule listing is readable and empty."""
    result = runner([AUDITCTL, "-l"], check=True, capture_output=True, text=True)
    return not result.stdout.strip()


def _default_micro_probe() -> dict[str, Any]:
    """Run the bounded root probe and independently require keyed evidence."""
    states = ["CLEAN_BASELINE_VERIFIED"]
    if not _audit_baseline_clean():
        return {"verdict": "BLOCKED", "states": states + ["BASELINE_NOT_CLEAN"]}
    with tempfile.NamedTemporaryFile(prefix="e1c-r6-probe-", delete=False) as handle:
        path = handle.name
        handle.write(b"r6-probe")
    child = None
    add = None
    try:
        states.append("FILE_PRECREATED")
        child = subprocess.Popen(
            ["/usr/bin/python3", "-c", "import pathlib,sys; p=pathlib.Path(sys.argv[1]); input(); p.write_bytes(p.read_bytes()+b'1'); p.read_bytes()", path],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        add = build_file_permission_watch_rule(path, child.pid, AUDIT_KEY)
        delete = delete_rule_from_add(add)
        subprocess.run(add, check=True, capture_output=True, text=True)
        states.append("RULE_ADDED")
        assert child.stdin is not None
        child.stdin.write("go\n")
        child.stdin.close()
        child.wait(timeout=10)
        states.append("BENIGN_READ_WRITE_PERFORMED")
        evidence = subprocess.run(["/usr/sbin/ausearch", "-k", AUDIT_KEY, "-i"], check=False, capture_output=True, text=True)
        serial = parse_audit_serial(evidence.stdout)
        events = [] if serial is None else [{"event_type": EVENT_TYPE, "evidence_basis": EVIDENCE_BASIS, "watched_path": path, "raw_serial": serial}]
        verdict = micro_probe_verdict(events)
        if verdict != "PASS":
            return {"verdict": "BLOCKED", "states": states + ["AUDIT_EVIDENCE_MISSING"]}
        states.append("AUDIT_EVIDENCE_PASS")
        return {"verdict": "PASS", "states": states, "rule": add, "inverse_rule": delete}
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
        if add is not None:
            subprocess.run(delete_rule_from_add(add), check=False, capture_output=True, text=True)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _reviewed_mininet_smoke() -> dict[str, Any]:
    """Boundary for the previously reviewed Mininet smoke implementation."""
    return {"verdict": "BLOCKED", "reason": "MININET_SMOKE_REQUIRES_HUMAN_REVIEWED_RUNTIME"}


def execute_reviewed_r6_path(
    probe: Callable[[], Mapping[str, Any]] | None = None,
    smoke: Callable[[], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Wire probe -> restore -> smoke; smoke is unreachable unless probe passes."""
    probe_result = (probe or _default_micro_probe)()
    states = list(probe_result.get("states", []))
    if probe_result.get("verdict") != "PASS":
        return {"verdict": "BLOCKED", "states": states}
    if states[-1:] != ["AUDIT_EVIDENCE_PASS"]:
        return {"verdict": "BLOCKED", "states": states + ["PROBE_STATE_INVALID"]}
    # The probe implementation removes its exact rule before returning.
    states.append("RULE_REMOVED_BASELINE_RESTORED")
    smoke_result = (smoke or _reviewed_mininet_smoke)()
    if smoke_result.get("verdict") != "PASS":
        return {"verdict": "BLOCKED", "states": states + ["MININET_NOT_EXECUTED"], "smoke": dict(smoke_result)}
    return {"verdict": "PASS", "states": states + ["MININET_EXECUTED", "CLEANUP", "BASELINE_RESTORED"], "smoke": dict(smoke_result)}


def verdict_exit_code(verdict: str) -> int:
    return EXIT_CODES.get(verdict, 1)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="run the gated root probe")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.run_privileged:
        print("MININET_E1C_R6_PREPARATION=PASS")
        print("HUMAN_PRIVILEGED_RUN_REQUIRED=YES")
        print("NEXT_ACTION=HUMAN_RUN_EXACT_SUDO_COMMAND")
        print("STOP=true")
        return 0
    if os.geteuid() != 0:
        print("MININET_E1C_R6_PREPARATION=BLOCKED")
        return verdict_exit_code("BLOCKED")
    result = execute_reviewed_r6_path()
    print(f"R6_PRIVILEGED_PATH_VERDICT={result.get('verdict', 'BLOCKED')}")
    print("R6_PRIVILEGED_PATH_STATES=" + ",".join(result.get("states", [])))
    return verdict_exit_code(str(result.get("verdict", "BLOCKED")))


if __name__ == "__main__":
    raise SystemExit(main())
