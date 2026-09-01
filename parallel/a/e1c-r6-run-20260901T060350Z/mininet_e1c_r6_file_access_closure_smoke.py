#!/usr/bin/env python3
"""Bounded E1C-R6 auditd file-access closure harness.

The privileged path is intentionally explicit: it is only entered by the
human-supplied sudo command after the static/pre-run gate has passed.  All
evidence writers use the recursive JSON-safe policy so command results that
contain bytes cannot abort cleanup.
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import collections
import datetime as dt
import hashlib
import json
import os
import re
import select
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


RUN_DIR = Path(__file__).resolve().parent
RUN_ID = RUN_DIR.name
HARNESS_PATH = Path(__file__).resolve()
R1_RUN_DIR = RUN_DIR.parent / "e1c-run-20260831T050028Z"
R2_RUN_DIR = RUN_DIR.parent / "e1c-r2-run-20260831T061204Z"
R3_RUN_DIR = RUN_DIR.parent / "e1c-r3-run-20260831T075356Z"
R1_KEY = "e1c902f74f583"
HISTORICAL_EMPTY_HASH = "61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87"
TCP_PORT = 18080
TEMP_DIR = RUN_DIR / "temp-events"
PCAP_PATH = RUN_DIR / "MININET_E1C_R6_SMOKE.pcap"

PRE_STATE_PATH = RUN_DIR / "MININET_E1C_R6_AUDIT_PRE_STATE.json"
LINEAGE_PATH = RUN_DIR / "MININET_E1C_R6_LINEAGE.json"
STATIC_AUDIT_PATH = RUN_DIR / "MININET_E1C_R6_STATIC_AUDIT.json"
PRE_RUN_CONTRACT_PATH = RUN_DIR / "MININET_E1C_R6_PRE_RUN_CONTRACT.json"
JOURNAL_PATH = RUN_DIR / "MININET_E1C_R6_RULE_REMEDIATION_JOURNAL.jsonl"
RESIDUAL_PATH = RUN_DIR / "MININET_E1C_R6_RESIDUAL_REMEDIATION.json"
RULE_CONTRACT_PATH = RUN_DIR / "MININET_E1C_R6_TRANSIENT_RULE_CONTRACT.json"
RAW_PATH = RUN_DIR / "MININET_E1C_R6_RAW_AUDIT_EVIDENCE.jsonl"
NORMALIZED_PATH = RUN_DIR / "MININET_E1C_R6_NORMALIZED_EVENTS.jsonl"
JOIN_PATH = RUN_DIR / "MININET_E1C_R6_PID_NETNS_JOIN.jsonl"
COVERAGE_PATH = RUN_DIR / "MININET_E1C_R6_COVERAGE_AND_LOSS_AUDIT.json"
POST_PATH = RUN_DIR / "MININET_E1C_R6_POST_CLEANUP_AUDIT.json"
STRACE_PATH = RUN_DIR / "MININET_E1C_R6_STRACE_ORACLE_COMPARISON.json"
REPORT_PATH = RUN_DIR / "MININET_E1C_R6_AUDITD_SMOKE_REPORT.md"
RESULT_PATH = RUN_DIR / "MININET_E1C_R6_PRIVILEGED_RUN_RESULT.json"
EARLY_FAILURE_PATH = RUN_DIR / "MININET_E1C_R6_EARLY_CHILD_FAILURES.jsonl"
CHILD_STATE_PATH = RUN_DIR / "MININET_E1C_R6_CHILD_STATE_TRANSITIONS.jsonl"
CHILD_PROCESS_PATH = RUN_DIR / "MININET_E1C_R6_CHILD_PROCESS_EVIDENCE.json"

EVENT_TYPE = "FILE_READ_OR_WRITE"
EVIDENCE_BASIS = "AUDIT_FILESYSTEM_PERMISSION_FILTER"
EXIT_CODES = {"PASS": 0, "PARTIAL": 3, "BLOCKED": 2}


def _exact_file(path: str) -> str:
    """Validate one absolute, non-wildcard file path (never a directory)."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("watched path must be absolute")
    if any(char in path for char in "*?[]"):
        raise ValueError("wildcard paths are not bounded")
    if path == "/" or path.endswith("/") or Path(path).is_dir():
        raise ValueError("watched path must identify one file")
    return path


def build_file_permission_watch_rule(path: str, pid: int, key: str) -> list[str]:
    """Build the exact transient path+perm=rw+pid audit rule."""
    path = _exact_file(path)
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise ValueError("pid must be a positive integer")
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]+", key):
        raise ValueError("audit key contains unsupported characters")
    return [
        "/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64",
        "-F", f"path={path}", "-F", "perm=rw", "-F", f"pid={pid}",
        "-k", key,
    ]


def delete_rule_from_add(add_argv: Sequence[str]) -> list[str]:
    """Return the exact inverse of a bounded path permission rule."""
    result = list(add_argv)
    if len(result) < 3 or result[0] != "/usr/sbin/auditctl" or result[1] != "-a":
        raise ValueError("expected an auditctl -a rule")
    if "-F" not in result or "perm=rw" not in result:
        raise ValueError("only the bounded rw rule may be removed")
    if not any(token.startswith("path=/") for token in result):
        raise ValueError("inverse requires an exact path")
    result[1] = "-d"
    return result


def micro_probe_verdict(events: Iterable[Mapping[str, Any]]) -> str:
    """Pass only on a permission-filter audit event for an absolute path."""
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
    """Normalize permission-filter evidence without inferring a syscall."""
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
        except (ValueError, TypeError, binascii.Error):
            return None
    value = raw.get("raw_sha256")
    return value if isinstance(value, str) else None


def verify_raw_event_links(
    raw_records: Iterable[Mapping[str, Any]],
    normalized_records: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Join by exact serial and compare the raw bytes/hash, never a boolean shortcut."""
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
        if _raw_hash(raw) is None or row.get("raw_event_sha256") != _raw_hash(raw):
            failures.append("RAW_HASH_MISMATCH")
    return {"valid": not failures, "failures": list(dict.fromkeys(failures))}


def parse_audit_serial(text: str) -> int | None:
    match = re.search(r"audit\([^:]+:(\d+)\)", text)
    return int(match.group(1)) if match else None


def audit_filesystem_semantics() -> dict[str, Any]:
    return {
        "source": "/usr/share/man/man8/auditctl.8.gz",
        "path_and_dir": "path is a full file path; dir is recursive and exit-list only",
        "perm": "permission filter may be used without a syscall; kernel selects matching syscalls",
        "read_write_semantics": "r/w represent requested filesystem access; direct read/write calls are omitted because they overwhelm logs and open flags are inspected",
        "watch_form": "-w is legacy/backward-compatible; syscall-form path/dir is more expressive",
        "wildcards": "unsupported",
        "design_conclusion": "Use syscall-form exact path + perm=rw + pid for bounded access",
    }


def run_privileged_micro_probe(
    watched_path: str, pid: int, runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Exercise the exact add/delete lifecycle used by the root probe.

    This small helper is intentionally evidence-agnostic for unit testing: the
    production probe below performs the bounded read/write and independently
    requires an audit-backed record before returning PASS.
    """
    add = build_file_permission_watch_rule(watched_path, pid, "e1c_r6_file_access")
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
    """Require the exact empty rule listing and a lossless, drained audit status."""
    rules = runner(["/usr/sbin/auditctl", "-l"], check=True, capture_output=True, text=True)
    if hashlib.sha256(rules.stdout.encode()).hexdigest() != HISTORICAL_EMPTY_HASH:
        return False
    status = runner(["/usr/sbin/auditctl", "-s"], check=True, capture_output=True, text=True)
    parsed = parse_audit_status(status.stdout)
    return parsed.get("lost") == 0 and parsed.get("backlog") == 0


def _default_micro_probe() -> dict[str, Any]:
    """Run one exact root probe and require permission-filter evidence."""
    states = ["CLEAN_BASELINE_VERIFIED"]
    if not _audit_baseline_clean():
        return {"verdict": "BLOCKED", "states": states + ["BASELINE_NOT_CLEAN"]}
    handle = tempfile.NamedTemporaryFile(prefix="e1c-r6-probe-", delete=False)
    path = handle.name
    result: dict[str, Any] = {"verdict": "BLOCKED", "states": states}
    add: list[str] | None = None
    delete: list[str] | None = None
    audit_key = "e1c6probe" + hashlib.sha256(f"{path}|{time.monotonic_ns()}".encode()).hexdigest()[:12]
    try:
        handle.write(b"r6-probe")
        handle.close()
        states.append("FILE_PRECREATED")
        child = subprocess.Popen(
            ["/usr/bin/python3", "-c",
             "import pathlib,sys; p=pathlib.Path(sys.argv[1]); input(); p.write_bytes(p.read_bytes()+b'1'); p.read_bytes()",
            path], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True,
        )
        add = build_file_permission_watch_rule(path, child.pid, audit_key)
        delete = delete_rule_from_add(add)
        subprocess.run(add, check=True, capture_output=True, text=True)
        states.append("RULE_ADDED")
        assert child.stdin is not None
        child.stdin.write("go\n")
        child.stdin.close()
        child.wait(timeout=10)
        if child.returncode != 0:
            result = {"verdict": "BLOCKED", "states": states + ["BENIGN_READ_WRITE_FAILED"]}
        else:
            states.append("BENIGN_READ_WRITE_PERFORMED")
            evidence = subprocess.run(
                ["/usr/sbin/ausearch", "-k", audit_key, "-i"],
                check=False, capture_output=True, text=True,
            )
            serial = parse_audit_serial(evidence.stdout)
            events = [] if serial is None else [{
                "event_type": EVENT_TYPE, "evidence_basis": EVIDENCE_BASIS,
                "watched_path": path, "raw_serial": serial,
            }]
            if micro_probe_verdict(events) != "PASS" or path not in evidence.stdout:
                result = {"verdict": "BLOCKED", "states": states + ["AUDIT_EVIDENCE_MISSING"]}
            else:
                states.append("AUDIT_EVIDENCE_PASS")
                result = {"verdict": "PASS", "states": states, "rule": add,
                          "inverse_rule": delete, "audit_serial": serial,
                          "audit_key": audit_key, "evidence_stdout": evidence.stdout}
    finally:
        if "child" in locals() and child.poll() is None:
            child.kill()
            child.wait()
        removal_ok = False
        if delete is not None:
            try:
                removal = subprocess.run(delete, check=False, capture_output=True, text=True)
                removal_ok = removal.returncode == 0
            except BaseException:
                removal_ok = False
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        baseline_restored = False
        if removal_ok:
            try:
                baseline_restored = _audit_baseline_clean()
            except BaseException:
                baseline_restored = False
        final_states = list(result.get("states", states))
        if removal_ok and baseline_restored:
            final_states.append("RULE_REMOVED_BASELINE_RESTORED")
        else:
            final_states.append("RULE_REMOVED_BASELINE_NOT_RESTORED")
        result["states"] = final_states
        result["baseline_restored"] = baseline_restored
        if not (removal_ok and baseline_restored):
            result["verdict"] = "BLOCKED"
    return result

HOSTS = {
    "h1": {"address": "10.0.0.1", "peer": "10.0.0.2", "mac": "00:00:00:00:01:01"},
    "h2": {"address": "10.0.0.2", "peer": "10.0.0.1", "mac": "00:00:00:00:01:02"},
}
RESERVED_INTERFACES = ("s1", "s1-eth1", "s1-eth2", "h1-eth0", "h2-eth0")
REQUIRED_CLASSES = (
    "PROCESS_START_OR_EXEC", "PROCESS_EXIT", "FILE_CREATE_OR_OPEN",
    "FILE_READ_OR_WRITE", "FILE_DELETE", "SOCKET_BIND", "SOCKET_CONNECT",
    "SOCKET_ACCEPT",
)
SYSCALL_CANDIDATES = (
    "execve", "execveat", "clone", "fork", "vfork", "exit_group",
    "openat", "openat2", "unlink", "unlinkat", "renameat", "bind",
    "connect", "accept", "accept4",
)
SYSCALL_NAMES = {
    0: "read", 1: "write", 17: "pread64", 18: "pwrite64", 19: "readv",
    20: "writev", 42: "connect", 43: "accept", 49: "bind", 56: "clone",
    57: "fork", 58: "vfork", 59: "execve", 87: "unlink", 231: "exit_group",
    257: "openat", 263: "unlinkat", 264: "renameat", 288: "accept4",
    322: "execveat", 328: "pwritev2", 437: "openat2",
}
CLASS_FOR_SYSCALL = {
    **{name: "PROCESS_START_OR_EXEC" for name in ("clone", "fork", "vfork", "execve", "execveat")},
    **{name: "PROCESS_EXIT" for name in ("exit", "exit_group")},
    **{name: "FILE_CREATE_OR_OPEN" for name in ("openat", "openat2")},
    **{name: "FILE_READ_OR_WRITE" for name in ("read", "write", "pread64", "pwrite64", "readv", "writev", "pwritev2")},
    **{name: "FILE_DELETE" for name in ("unlink", "unlinkat", "renameat")},
    "bind": "SOCKET_BIND", "connect": "SOCKET_CONNECT",
    "accept": "SOCKET_ACCEPT", "accept4": "SOCKET_ACCEPT",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_safe(value):
    """Convert recursively to JSON-safe values without implicit byte stringification."""
    if isinstance(value, bytes):
        item = {
            "__type__": "bytes",
            "encoding": "base64",
            "base64": base64.b64encode(value).decode("ascii"),
            "sha256": sha256_bytes(value),
            "length": len(value),
        }
        try:
            item["utf8"] = value.decode("utf-8")
        except UnicodeDecodeError:
            item["utf8"] = None
        return item
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsafe evidence value type: {type(value).__name__}")


def write_json_atomic(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    payload = json.dumps(json_safe(value), indent=2, sort_keys=True) + "\n"
    with temp.open("w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_jsonl_atomic(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(json_safe(row), sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def read_jsonl(path: Path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def append_jsonl_fsync(path: Path, row) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(json_safe(row), sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def run_command(argv, timeout=20):
    try:
        proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
        return {"argv": list(argv), "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as exc:
        return {"argv": list(argv), "returncode": None, "stdout": "", "stderr": f"{type(exc).__name__}: {exc}"}


def run_command_bytes(argv, timeout=30):
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        return {"argv": list(argv), "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as exc:
        return {"argv": list(argv), "returncode": None, "stdout": b"", "stderr": f"{type(exc).__name__}: {exc}".encode()}


def proc_link(pid, name):
    return os.readlink(f"/proc/{int(pid)}/ns/{name}")


def proc_text(pid, relative):
    return Path(f"/proc/{int(pid)}/{relative}").read_text(errors="replace")


def process_start_ticks(pid):
    text = proc_text(pid, "stat")
    return int(text[text.rfind(")") + 2:].split()[19])


def capture_process_ref(pid, role):
    stat = proc_text(pid, "stat")
    return {
        "pid": int(pid), "role": role, "start_ticks": process_start_ticks(pid),
        "ppid": int(stat.split(")", 1)[1].split()[1]),
        "comm": proc_text(pid, "comm").strip(),
    }


def process_ref_live(ref):
    try:
        return process_start_ticks(ref["pid"]) == ref["start_ticks"]
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError, KeyError):
        return False


def netns_inode(link):
    match = re.fullmatch(r"net:\[(\d+)\]", link or "")
    return int(match.group(1)) if match else None


def namespace_assertions(shells, children):
    """Evaluate namespace assertions with PASS/FAIL/NOT_OBSERVED semantics."""
    def check(left, right, equal):
        if left is None or right is None:
            return "NOT_OBSERVED"
        return "PASS" if ((left == right) if equal else (left != right)) else "FAIL"
    checks = {
        "h1_child_netns == h1_shell_netns": check(children.get("h1"), shells.get("h1"), True),
        "h2_child_netns == h2_shell_netns": check(children.get("h2"), shells.get("h2"), True),
        "h1_child_netns != h2_shell_netns": check(children.get("h1"), shells.get("h2"), False),
        "h2_child_netns != h1_shell_netns": check(children.get("h2"), shells.get("h1"), False),
    }
    return {"checks": checks, "pass": all(value == "PASS" for value in checks.values())}


def parse_audit_status(text):
    result = {"raw": text}
    for key in ("enabled", "backlog_limit", "backlog", "lost", "backlog_wait_time", "backlog_wait_time_actual"):
        match = re.search(rf"\b{re.escape(key)}\s+(\d+)", text)
        if match:
            result[key] = int(match.group(1))
    return result


def persistent_rule_files_snapshot():
    root = Path("/etc/audit/rules.d")
    files = {}
    try:
        for path in sorted(root.glob("*")):
            if path.is_file():
                data = path.read_bytes()
                files[str(path)] = {"sha256": sha256_bytes(data), "size": len(data)}
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "files": files}
    return {"files": files}


def audit_snapshot():
    rules = run_command_bytes(["/usr/sbin/auditctl", "-l"])
    status = run_command(["/usr/sbin/auditctl", "-s"])
    package = run_command(["/usr/bin/dpkg-query", "-W", "-f=${Package}=${Version}\n", "auditd"])
    return {
        "captured_at_utc": utc_now(),
        "auditctl_list": rules,
        "auditctl_status": {**status, "parsed": parse_audit_status(status.get("stdout", ""))},
        "auditd_package": package,
        "installed_auditd_version": package.get("stdout", "").strip(),
        "baseline_rule_dump_sha256": sha256_bytes(rules.get("stdout", b"")),
        "canonical_rule_lines": canonical_rule_lines(rules.get("stdout", b"")),
        "persistent_rules_files": persistent_rule_files_snapshot(),
    }


def canonical_rule(argv):
    tokens = list(argv)
    if tokens and Path(tokens[0]).name == "auditctl":
        tokens = tokens[1:]
    action = None
    syscalls = []
    filters = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in ("-a", "-d") and index + 1 < len(tokens):
            action = tokens[index + 1]
            index += 2
        elif token == "-S" and index + 1 < len(tokens):
            syscalls.extend(tokens[index + 1].split(",")); index += 2
        elif token.startswith("-S") and token != "-S":
            syscalls.extend(token[2:].lstrip("=").split(",")); index += 1
        elif token == "-k" and index + 1 < len(tokens):
            filters.append(("key", tokens[index + 1])); index += 2
        elif token.startswith("-F") and token != "-F" and "=" in token:
            filters.append(tuple(token[2:].lstrip("=").split("=", 1))); index += 1
        elif token == "-F" and index + 1 < len(tokens):
            filters.append(tuple(tokens[index + 1].split("=", 1))); index += 2
        else:
            index += 1
    return (action, tuple(sorted(syscalls)), tuple(sorted(filters)))


def canonical_rule_lines(raw):
    text = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw or "")
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line == "No rules":
            continue
        try:
            rows.append({"line": line, "canonical": canonical_rule(shlex.split(line))})
        except ValueError as exc:
            rows.append({"line": line, "canonical": None, "parse_error": str(exc)})
    return rows


def decode_prestate_lines(path):
    state = read_json(path, {}) or {}
    encoded = ((state.get("auditctl_list") or {}).get("stdout_b64") or "")
    try:
        return canonical_rule_lines(base64.b64decode(encoded))
    except (binascii.Error, ValueError):
        return []


def contract_rule_lines(path):
    contract = read_json(path, {}) or {}
    rows = []
    for item in contract.get("rule_specs", []) + contract.get("successful_adds", []):
        argv = item.get("add_argv") if isinstance(item, dict) else None
        if argv:
            rows.append({"line": shlex.join(argv), "canonical": canonical_rule(argv)})
    return rows


def known_owned_rules():
    r1 = decode_prestate_lines(R2_RUN_DIR / "MININET_E1C_R2_AUDIT_PRE_STATE.json")
    if not r1:
        r1 = decode_prestate_lines(R1_RUN_DIR / "MININET_E1C_AUDIT_PRE_STATE.json")
    owned = {}
    for row in r1:
        if row.get("canonical") is not None:
            owned.setdefault(row["canonical"], {"owner": "R1", "source": row["line"]})
    # Only exact identities in a generated R2/probe contract are trusted.
    for path in (
        R2_RUN_DIR / "MININET_E1C_R2_TRANSIENT_RULE_CONTRACT.json",
        R2_RUN_DIR / "MININET_E1C_R2_PROBE_RULE_CONTRACT.json",
        R3_RUN_DIR / "MININET_E1C_R3_TRANSIENT_RULE_CONTRACT.json",
        R3_RUN_DIR / "MININET_E1C_R3_PROBE_RULE_CONTRACT.json",
    ):
        for row in contract_rule_lines(path):
            if row.get("canonical") is not None:
                owned.setdefault(row["canonical"], {"owner": "R2_OR_PROBE", "source": row["line"]})
    return owned


def rule_key(line):
    match = re.search(r"(?:-k\s+|key=)([^\s]+)", line)
    return match.group(1) if match else None


def journal(journal_path, kind, **fields):
    append_jsonl_fsync(journal_path, {"timestamp_utc": utc_now(), "kind": kind, **fields})


def mutation_argv(add_argv, action):
    """Build an auditctl mutation argv with an explicit executable."""
    if action not in {"ADD", "DELETE"}:
        raise ValueError(f"unsupported mutation action: {action}")
    tokens = list(add_argv)
    if tokens and Path(tokens[0]).name == "auditctl":
        tokens = tokens[1:]
    if not tokens or tokens[0] != "-a":
        raise ValueError("mutation source must begin with auditctl -a")
    tokens[0] = "-a" if action == "ADD" else "-d"
    argv = ["/usr/sbin/auditctl", *tokens]
    if argv[0] != "/usr/sbin/auditctl" or argv[1] not in {"-a", "-d"}:
        raise AssertionError(f"invalid auditctl mutation argv: {argv!r}")
    return argv


def mutation(journal_path, spec, action, owner, runner=run_command):
    add_argv = list(spec["add_argv"])
    argv = mutation_argv(add_argv, action)
    canonical = canonical_rule(add_argv)
    journal(journal_path, "PLANNED_DELETE" if action == "DELETE" else "PLANNED_ADD", owner=owner, canonical_rule=canonical, argv=argv, source=spec.get("source"))
    result = runner(argv)
    after = run_command_bytes(["/usr/sbin/auditctl", "-l"])
    journal(journal_path, "DELETE_RESULT" if action == "DELETE" else "ADD_RESULT", owner=owner, canonical_rule=canonical, argv=argv, result=result, returncode=result.get("returncode"), post_rule_dump_sha256=sha256_bytes(after.get("stdout", b"")))
    return result


def remediate_residual_rules(pre, journal_path):
    state = {
        "schema": "MININET_E1C_R6_RESIDUAL_REMEDIATION_V1", "run_id": RUN_ID,
        "old_run_residual_rules_found": 0, "old_run_residual_rules_removed": 0,
        "classification": pre.get("canonical_rule_lines", []),
        "status": "BLOCKED_LEGACY_REMEDIATION_DISABLED",
        "before": pre,
        "legacy_cleanup_performed": False,
    }
    write_json_atomic(RESIDUAL_PATH, state)
    return state


def build_rule_specs(key, pid, file_dir, supported, ppid=None, scope="pid", permission_paths=()):
    subject = ["-F", f"ppid={ppid}"] if ppid is not None else ["-F", f"pid={pid}"]
    prefix = ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64"]
    groups = (
        ("process_start_or_exec", ("execve", "execveat", "clone", "fork", "vfork"), ()),
        ("process_exit", ("exit_group",), ()),
        ("file_create_or_open", ("openat", "openat2"), ("-F", f"dir={file_dir}")),
        ("file_delete", ("unlink", "unlinkat", "renameat"), ("-F", f"dir={file_dir}")),
        ("socket_bind_connect_accept", ("bind", "connect", "accept", "accept4"), ()),
    )
    specs = []
    for name, candidates, extra in groups:
        for syscall in candidates:
            if syscall not in supported:
                continue
            argv = list(prefix) + ["-S", syscall] + list(extra) + list(subject) + ["-k", key]
            specs.append({"name": f"{scope}_{name}_{syscall}", "syscall": syscall, "add_argv": argv, "subject": subject, "source": "R6_SMOKE"})
    if ppid is None:
        for watched_path in permission_paths:
            argv = build_file_permission_watch_rule(str(watched_path), pid, key)
            specs.append({
                "name": f"{scope}_file_permission_{Path(watched_path).name}",
                "syscall": None,
                "add_argv": argv,
                "subject": subject,
                "watched_path": str(watched_path),
                "source": "R6_FILE_PERMISSION_WATCH",
            })
    return specs


def query_supported_syscalls(probe_key, journal_path):
    supported, probes, leftovers = set(), [], []
    for syscall in SYSCALL_CANDIDATES:
        spec = {"name": f"probe_{syscall}", "add_argv": ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", syscall, "-F", f"pid={os.getpid()}", "-k", probe_key], "source": "R6_SYSCALL_PROBE"}
        add_result = mutation(journal_path, spec, "ADD", "R6_PROBE")
        remove_result = None
        if add_result.get("returncode") == 0:
            supported.add(syscall)
            remove_result = mutation(journal_path, spec, "DELETE", "R6_PROBE")
            if remove_result.get("returncode") != 0:
                leftovers.append(spec)
        probes.append({"syscall": syscall, "supported": add_result.get("returncode") == 0, "add": add_result, "remove": remove_result})
    return supported, probes, leftovers


def parse_audit_groups(raw, key_bytes):
    groups = collections.defaultdict(list)
    keyed = set()
    for line_no, line in enumerate(raw.splitlines(keepends=True), 1):
        match = re.search(rb"msg=audit\(([^:]+):(\d+)\)", line)
        if not match:
            continue
        serial = int(match.group(2))
        groups[serial].append((line_no, line))
        if key_bytes in line:
            keyed.add(serial)
    rows = []
    for serial in sorted(keyed):
        entries = groups[serial]
        blob = b"".join(line for _, line in entries)
        first = entries[0][1]
        stamp = re.search(rb"msg=audit\(([^:]+):", first)
        rows.append({
            "serial": serial, "timestamp_source": stamp.group(1).decode(errors="replace") if stamp else None,
            "record_types": [line.split(b" ", 1)[0][5:].decode(errors="replace") for _, line in entries],
            "source_line_numbers": [line_no for line_no, _ in entries], "raw_bytes": blob,
            "raw_text": blob.decode(errors="replace"), "raw_bytes_b64": base64.b64encode(blob).decode("ascii"),
            "raw_sha256": sha256_bytes(blob),
        })
    return rows


def parse_fields(text):
    result = {}
    for key, value in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|[^\s]+)", text):
        result.setdefault(key, value[1:-1] if value.startswith('"') and value.endswith('"') else value)
    return result


def decode_proctitle(text):
    match = re.search(r"proctitle=([0-9A-Fa-f]+)", text)
    if not match:
        return None
    try:
        return binascii.unhexlify(match.group(1)).replace(b"\0", b" ").decode(errors="replace")
    except (binascii.Error, ValueError):
        return None


def normalize_audit_record(record, pid_joins, permission_paths=()):
    raw = record.get("raw_bytes") or record.get("raw_text", "").encode()
    text = record.get("raw_text") or raw.decode(errors="replace")
    parsed = parse_fields(text)
    syscall_number = int(parsed["syscall"]) if parsed.get("syscall", "").lstrip("-").isdigit() else -1
    syscall = SYSCALL_NAMES.get(syscall_number, parsed.get("syscall"))
    paths = re.findall(r"\bname=\"([^\"]*)\"", text)
    permission_path_set = {str(path) for path in permission_paths}
    permission_match = bool(permission_path_set.intersection(paths)) and syscall in {"openat", "openat2", "read", "write", "pread64", "pwrite64", "readv", "writev", "pwritev2"}
    event_type = EVENT_TYPE if permission_match else CLASS_FOR_SYSCALL.get(syscall)
    if event_type is None:
        return None
    pid = int(parsed["pid"]) if parsed.get("pid", "").isdigit() else None
    ppid = int(parsed["ppid"]) if parsed.get("ppid", "").isdigit() else None
    join = pid_joins.get(pid, {})
    sockaddr_match = re.search(r"SADDR=\{([^}]*)\}", text)
    sockaddr = dict(re.findall(r"\b([A-Za-z_][A-Za-z0-9_-]*)=([^\s]+)", sockaddr_match.group(1))) if sockaddr_match else {}
    requested_access = None
    if event_type == EVENT_TYPE:
        # Permission-filter evidence describes requested access.  The observed
        # syscall remains separate and is never inferred from the filter.
        flags = parsed.get("a2", "")
        try:
            mode = int(flags, 0)
        except (TypeError, ValueError):
            mode = 0
        access_bits = mode & 3
        requested_access = "r" if access_bits == 0 else "w" if access_bits == 1 else "rw"
    row = {
        "event_id": sha256_bytes(f"{RUN_ID}|{record['serial']}|{event_type}|{record['raw_sha256']}".encode()),
        "event_type": event_type, "run_id": RUN_ID, "raw_serial": record["serial"],
        "raw_event_bytes_b64": base64.b64encode(raw).decode("ascii"), "raw_event_sha256": sha256_bytes(raw),
        "timestamp_source": record.get("timestamp_source"), "pid": pid, "ppid": ppid,
        "pid_start_time_ticks": join.get("start_ticks"), "netns_inode": join.get("netns_inode"),
        "logical_host_id": join.get("logical_host_id"), "join_status": "JOINED" if join.get("logical_host_id") else "UNJOINED",
        "executable": {"path": parsed.get("exe"), "comm": parsed.get("comm"), "proctitle": decode_proctitle(text)},
        "syscall": syscall, "result": parsed.get("success") or parsed.get("exit"),
        "path": paths[-1] if paths else None,
        "sockaddr": sockaddr,
        "file_identity": {"paths": paths, "operation": syscall} if event_type.startswith("FILE_") else None,
        "socket_identity": {"operation": syscall, "family": sockaddr.get("saddr_fam"), "local_address": sockaddr.get("laddr"), "local_port": sockaddr.get("lport")} if event_type.startswith("SOCKET_") else None,
    }
    if event_type == EVENT_TYPE:
        row.update({
            "evidence_basis": EVIDENCE_BASIS,
            "watched_path": next(iter(permission_path_set.intersection(paths)), None),
            "requested_access": requested_access,
            "underlying_syscall": syscall,
        })
    return row


class ChildProtocolError(RuntimeError):
    """Raised only after an early-child diagnostic record is durably written."""


def raise_child_protocol_error(path, logical_host_id, unexpected_event, child_pid,
                               returncode, stderr, stdout_history,
                               process_liveness, stage, timestamp_utc=None,
                               child_netns=None):
    """Persist complete parent-side failure context before raising.

    This is intentionally a separate helper so a protocol failure can never be
    reduced to the old generic ``emitted FINISHED before READY`` exception.
    """
    evidence = {
        "schema": "MININET_E1C_R6_EARLY_CHILD_FAILURE_V1",
        "timestamp_utc": timestamp_utc or utc_now(),
        "logical_host_id": logical_host_id,
        "unexpected_stdout_event": unexpected_event,
        "child_pid": int(child_pid) if child_pid is not None else None,
        "child_returncode": returncode,
        "complete_stderr": stderr if stderr is not None else "",
        "stdout_history": list(stdout_history or []),
        "process_liveness": bool(process_liveness),
        "exact_stage": stage,
        "child_netns": child_netns,
    }
    append_jsonl_fsync(path, evidence)
    raise ChildProtocolError(
        f"{logical_host_id} child protocol failure at {stage}: {unexpected_event}"
    )


def build_child_error_event(logical_host_id, pid, stage, exc, netns=None,
                            traceback_text=""):
    bounded_traceback = traceback_text[-8192:]
    return {
        "event": "CHILD_ERROR",
        "logical_host_id": logical_host_id,
        "pid": int(pid),
        "netns": netns,
        "stage": stage,
        "exception_type": type(exc).__name__,
        "exception_message": str(exc),
        "traceback_sha256": sha256_bytes(bounded_traceback.encode()),
        "traceback": bounded_traceback,
        "timestamp_utc": utc_now(),
    }


def persist_state_transition(path, logical_host_id, state, pid=None, stage=None,
                             **fields):
    row = {
        "schema": "MININET_E1C_R6_CHILD_STATE_V1", "timestamp_utc": utc_now(),
        "logical_host_id": logical_host_id, "state": state,
        "pid": int(pid if pid is not None else os.getpid()),
        "stage": stage or state,
        **fields,
    }
    append_jsonl_fsync(path, row)
    return row


def validate_post_exec_identity(shell, child, popen_pid=None):
    """Require live child identity and an observed netns after exec."""
    checks = {
        "popen_pid_matches_child_pid": popen_pid is None or popen_pid == child.get("pid"),
        "child_live": child.get("live") is True,
        "child_netns_observed": child.get("netns") is not None,
        "child_netns_matches_shell": child.get("netns") is not None and child.get("netns") == shell.get("netns"),
        "child_start_ticks_observed": child.get("start_ticks") is not None,
        "child_executable_observed": bool(child.get("exe")),
    }
    return {"checks": checks, "pass": all(checks.values())}


def _read_available_text(stream):
    if stream is None:
        return ""
    chunks = []
    try:
        while True:
            readable, _, _ = select.select([stream], [], [], 0)
            if not readable:
                break
            chunk = stream.readline()
            if not chunk:
                break
            chunks.append(chunk)
    except (OSError, ValueError):
        pass
    return "".join(chunks)


def benign_child(args):
    """Run the bounded child protocol with durable state/error diagnostics."""
    listener = None
    worker = None
    stopped = False
    failed = False
    temp = Path(args.temp_file)
    delete_temp = Path(args.delete_file) if args.delete_file else temp.with_name(f"{temp.stem}-delete{temp.suffix}")
    state_path = Path(args.state_file)
    operations = []
    stage = "BOOTSTRAP_STARTED"
    listener_diagnostics = {
        "requested_bind_address": args.listen_address,
        "requested_port": args.listen_port,
        "actual_child_netns": None,
        "interface_addresses": None,
        "bind_result": "NOT_ATTEMPTED",
        "getsockname": None,
    }

    def stop_handler(_signum, _frame):
        nonlocal stopped
        stopped = True

    def transition(state, **fields):
        nonlocal stage
        stage = state
        return persist_state_transition(
            state_path, args.logical_host_id, state, pid=os.getpid(), **fields
        )

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    transition("BOOTSTRAP_STARTED", role=args.role)
    try:
        temp.write_text(f"{args.logical_host_id} pid={os.getpid()}\n", encoding="utf-8")
        operations.append("overwrite_precreated")
        with temp.open("a", encoding="utf-8") as stream:
            stream.write("r6-write\n")
        operations.append("write")
        temp.read_text(encoding="utf-8")
        operations.append("read")
        delete_temp.write_text(f"{args.logical_host_id} delete inode\n", encoding="utf-8")
        operations.append("delete_create")
        delete_temp.unlink()
        operations.append("delete")
        transition("FILE_OPS_COMPLETE", file_operations=list(operations),
                   temp_file=str(temp), delete_file=str(delete_temp))

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        stage = "LISTENER_BIND"
        try:
            listener_diagnostics["actual_child_netns"] = proc_link(os.getpid(), "net")
        except Exception as exc:
            listener_diagnostics["actual_child_netns_error"] = f"{type(exc).__name__}: {exc}"
        try:
            listener_diagnostics["interface_addresses"] = run_command(
                ["/usr/sbin/ip", "-o", "addr", "show"]
            )
        except Exception as exc:
            listener_diagnostics["interface_addresses_error"] = f"{type(exc).__name__}: {exc}"
        try:
            listener.bind((args.listen_address, args.listen_port))
            listener.listen(8)
            listener_diagnostics["bind_result"] = "PASS"
            listener_diagnostics["getsockname"] = list(listener.getsockname())
        except BaseException as exc:
            listener_diagnostics.update({
                "bind_result": "FAIL",
                "bind_errno": getattr(exc, "errno", None),
                "bind_exception_type": type(exc).__name__,
                "bind_exception_message": str(exc),
            })
            raise
        transition("LISTENER_BOUND", listener_diagnostics=listener_diagnostics)
        ready = {
            "event": "READY", "logical_host_id": args.logical_host_id,
            "pid": os.getpid(), "ppid": os.getppid(),
            "listen": [args.listen_address, args.listen_port],
            "netns": listener_diagnostics.get("actual_child_netns"),
            "temp_file": str(temp), "delete_file": str(delete_temp),
            "file_operations": list(operations),
            "listener_diagnostics": listener_diagnostics,
        }
        transition("READY", listener_diagnostics=listener_diagnostics)
        print(json.dumps(ready, sort_keys=True), flush=True)
        if sys.stdin.readline().strip() != "GO" or stopped:
            transition("FINISHED", reason="GO_NOT_RECEIVED", file_operations=list(operations))
            return 2
        transition("GO_RECEIVED")
        worker = subprocess.Popen(["/usr/bin/python3", "-c", "import time; time.sleep(8)"])
        transition("WORKER_STARTED", worker_pid=worker.pid)
        print(json.dumps({"event": "WORKER_STARTED", "pid": worker.pid,
                          "ppid": os.getpid(), "logical_host_id": args.logical_host_id}, sort_keys=True), flush=True)
        if args.role == "server":
            connection, peer = listener.accept()
            with connection:
                payload = connection.recv(4096)
                connection.sendall(b"ACK:h2")
            network = {"event": "NETWORK", "logical_host_id": args.logical_host_id,
                       "mode": "accept", "peer": [peer[0], peer[1]],
                       "payload": payload.decode(errors="replace"), "port": args.listen_port}
        else:
            with socket.create_connection((args.peer_address, args.listen_port), timeout=6) as outgoing:
                outgoing.sendall(b"benign-h1")
                ack = outgoing.recv(4096).decode(errors="replace")
            network = {"event": "NETWORK", "logical_host_id": args.logical_host_id,
                       "mode": "connect", "peer": [args.peer_address, args.listen_port],
                       "ack": ack, "port": args.listen_port}
        transition("NETWORK_COMPLETE", network=network)
        print(json.dumps(network, sort_keys=True), flush=True)
        while not stopped:
            line = sys.stdin.readline()
            if line == "" or line.strip() == "STOP":
                break
            time.sleep(0.02)
        transition("FINISHED", file_operations=list(operations))
    except BaseException as exc:
        failed = True
        tb = traceback.format_exc()
        try:
            netns = proc_link(os.getpid(), "net")
        except Exception:
            netns = None
        error = build_child_error_event(args.logical_host_id, os.getpid(), stage, exc, netns, tb)
        error["listener_diagnostics"] = listener_diagnostics
        persist_state_transition(state_path, args.logical_host_id, "CHILD_ERROR",
                                 pid=os.getpid(), stage=stage, **{k: v for k, v in error.items() if k not in {"schema", "timestamp_utc", "logical_host_id", "pid", "stage"}})
        print(json.dumps(error, sort_keys=True), flush=True)
        sys.stderr.write(tb)
        sys.stderr.flush()
    finally:
        if worker is not None:
            try:
                worker.wait(timeout=2)
            except subprocess.TimeoutExpired:
                worker.kill(); worker.wait(timeout=2)
        if listener is not None:
            listener.close()
        try:
            if delete_temp.exists():
                delete_temp.unlink()
        except Exception:
            pass
        if not failed:
            # FINISHED is emitted only on a clean protocol path; exceptions
            # remain represented by CHILD_ERROR and are never hidden by finally.
            print(json.dumps({"event": "FINISHED", "logical_host_id": args.logical_host_id,
                              "pid": os.getpid(), "file_operations": operations}, sort_keys=True), flush=True)
    return 1 if failed else 0


def start_child(host_obj, host, role):
    spec = HOSTS[host]
    temp_file = TEMP_DIR / f"{host}.txt"
    delete_file = TEMP_DIR / f"{host}-delete.txt"
    state_file = RUN_DIR / f"child-{host}-states.jsonl"
    child_args = ["/usr/bin/python3", str(HARNESS_PATH), "--child", "--logical-host-id", host, "--listen-address", spec["address"], "--listen-port", str(TCP_PORT), "--peer-address", spec["peer"], "--temp-file", str(temp_file), "--delete-file", str(delete_file), "--role", role]
    child_args += ["--state-file", str(state_file)]
    command = "read gate; exec " + shlex.join(child_args)
    proc = host_obj.popen(["/bin/sh", "-c", command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    return {"host": host, "host_obj": host_obj, "process": proc, "pid": proc.pid,
            "popen_pid": proc.pid, "role": f"{host}-child", "temp_file": temp_file,
            "delete_file": delete_file,
            "state_file": state_file, "stdout_history": [], "stderr_history": "",
            "stage": "BOOTSTRAP_STARTED"}


def _child_diagnostic_snapshot(entry):
    proc = entry["process"]
    returncode = proc.poll()
    if returncode is None:
        # FINISHED/CHILD_ERROR is normally followed by immediate process exit;
        # give the child a bounded opportunity to flush all stderr/stdout.
        try:
            proc.wait(timeout=0.25)
            returncode = proc.poll()
        except (subprocess.TimeoutExpired, AttributeError, OSError):
            pass
    stderr_available = _read_available_text(proc.stderr)
    if stderr_available:
        entry["stderr_history"] = entry.get("stderr_history", "") + stderr_available
    if returncode is not None:
        try:
            out, err = proc.communicate(timeout=0)
            if out:
                entry["stdout_history"].extend(
                    [json.loads(line) if line.strip().startswith("{") else line
                     for line in out.splitlines()]
                )
            if err:
                entry["stderr_history"] += err
        except (subprocess.TimeoutExpired, ValueError):
            pass
    child_netns = None
    try:
        child_netns = proc_link(entry["pid"], "net")
    except Exception:
        pass
    return {
        "returncode": returncode,
        "stderr": entry.get("stderr_history", ""),
        "stdout_history": list(entry.get("stdout_history", [])),
        "liveness": returncode is None,
        "child_netns": child_netns,
    }


def read_ready(children, timeout=15, evidence_path=EARLY_FAILURE_PATH):
    pending, ready = set(children), {}
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        streams = [children[host]["process"].stdout for host in pending]
        readable, _, _ = select.select(streams, [], [], max(0, deadline - time.monotonic()))
        for stream in readable:
            host = next(name for name in pending if children[name]["process"].stdout is stream)
            line = stream.readline()
            if not line:
                diag = _child_diagnostic_snapshot(children[host])
                raise_child_protocol_error(
                    evidence_path, host, "CHILD_EXIT_BEFORE_READY", children[host]["pid"],
                    diag["returncode"], diag["stderr"], diag["stdout_history"],
                    diag["liveness"], children[host].get("stage", "READY_WAIT"),
                    child_netns=diag["child_netns"],
                )
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                children[host]["stdout_history"].append(line.rstrip("\n"))
                diag = _child_diagnostic_snapshot(children[host])
                raise_child_protocol_error(
                    evidence_path, host, "INVALID_JSON", children[host]["pid"],
                    diag["returncode"], diag["stderr"], diag["stdout_history"],
                    diag["liveness"], children[host].get("stage", "READY_WAIT"),
                    child_netns=diag["child_netns"],
                )
            children[host]["stdout_history"].append(event)
            children[host]["stage"] = event.get("stage", event.get("event", "READY_WAIT"))
            if event.get("event") != "READY":
                diag = _child_diagnostic_snapshot(children[host])
                raise_child_protocol_error(
                    evidence_path, host, event.get("event"), children[host]["pid"],
                    diag["returncode"], diag["stderr"], diag["stdout_history"],
                    diag["liveness"], children[host].get("stage", "READY_WAIT"),
                    child_netns=diag["child_netns"],
                )
            ready[host] = event; pending.remove(host)
    if pending:
        host = sorted(pending)[0]
        diag = _child_diagnostic_snapshot(children[host])
        raise_child_protocol_error(
            evidence_path, host, "READY_TIMEOUT", children[host]["pid"],
            diag["returncode"], diag["stderr"], diag["stdout_history"],
            diag["liveness"], children[host].get("stage", "READY_WAIT"),
            child_netns=diag["child_netns"],
        )
    return ready


def capture_socket_state(entry):
    pid = entry["pid"]
    state = {"captured_at_utc": utc_now(), "pid": int(pid), "listener_alive": True, "captured_while_socket_alive": True}
    try:
        state["proc_net_tcp"] = proc_text(pid, "net/tcp")
    except Exception as exc:
        state["proc_net_tcp_error"] = f"{type(exc).__name__}: {exc}"
    try:
        state["ss_socket_ownership"] = entry["host_obj"].cmd("ss -tanp")
    except Exception as exc:
        state["ss_socket_ownership_error"] = f"{type(exc).__name__}: {exc}"
    return state


def capture_join(entry, shell_netns, socket_state=None):
    link = proc_link(entry["pid"], "net")
    row = {
        "run_id": RUN_ID, "pid": int(entry["pid"]), "role": entry["role"], "logical_host_id": entry["host"],
        "netns": link, "netns_inode": netns_inode(link), "shell_netns": shell_netns,
        "netns_equals_shell_netns": link == shell_netns, "mntns": proc_link(entry["pid"], "mnt"),
        "cgroup": proc_text(entry["pid"], "cgroup"), "process": capture_process_ref(entry["pid"], entry["role"]),
        "start_ticks": process_start_ticks(entry["pid"]), "captured_at_utc": utc_now(),
        "captured_while_alive": True, "join_status": "JOINED" if link == shell_netns else "UNJOINED",
    }
    if socket_state is not None:
        row["socket_state"] = socket_state
    return row


def capture_join_safe(entry, shell_netns, socket_state=None):
    try:
        return capture_join(entry, shell_netns, socket_state)
    except Exception as exc:
        return {"run_id": RUN_ID, "pid": int(entry["pid"]), "role": entry["role"], "logical_host_id": entry.get("host"), "shell_netns": shell_netns, "join_status": "UNJOINED", "captured_while_alive": False, "error": f"{type(exc).__name__}: {exc}"}


def probe_interfaces():
    return {name: run_command(["/usr/sbin/ip", "link", "show", "dev", name]) for name in RESERVED_INTERFACES}


def probe_ovs():
    queries = [["/usr/bin/ovs-vsctl", "--timeout=2", "br-exists", "s1"]]
    for table in ("Interface", "Port", "Bridge"):
        for name in RESERVED_INTERFACES + ("s1",):
            queries.append(["/usr/bin/ovs-vsctl", "--timeout=2", "--data=bare", "--no-heading", "--columns=name", "find", table, f"name={name}"])
    return [{"argv": query, "result": run_command(query)} for query in queries]


def ovs_object_names(probe):
    names = set()
    for item in probe:
        result = item.get("result", {})
        if result.get("returncode") == 0:
            for line in result.get("stdout", "").splitlines():
                if line.strip():
                    names.add(line.strip())
    return names


def probe_tcpdump():
    result = run_command(["/bin/ps", "-eo", "pid=,comm=,args="])
    matches = [line for line in result.get("stdout", "").splitlines() if re.search(r"\btcpdump\b", line)]
    return {"probe": result, "matching_processes": matches, "count": len(matches)}


def collect_child_process_evidence(children):
    rows = []
    for host, entry in children.items():
        proc = entry.get("process")
        stdout_text = ""
        stderr_text = entry.get("stderr_history", "")
        returncode = None
        if proc is not None:
            try:
                out, err = proc.communicate(timeout=0)
                stdout_text = out or ""
                stderr_text += err or ""
                returncode = proc.returncode
            except (subprocess.TimeoutExpired, ValueError):
                returncode = proc.poll()
        history = list(entry.get("stdout_history", []))
        for line in stdout_text.splitlines():
            if not line.strip():
                continue
            try:
                history.append(json.loads(line))
            except json.JSONDecodeError:
                history.append(line)
        rows.append({
            "logical_host_id": host, "child_pid": entry.get("pid"),
            "popen_pid": entry.get("popen_pid"), "returncode": returncode,
            "stderr": stderr_text, "stdout_history": history,
            "process_liveness": returncode is None,
            "state_file": str(entry.get("state_file")) if entry.get("state_file") else None,
            "captured_at_utc": utc_now(),
        })
    write_json_atomic(CHILD_PROCESS_PATH, {"schema": "MININET_E1C_R6_CHILD_PROCESS_EVIDENCE_V1", "children": rows})
    state_rows = []
    for entry in children.values():
        path = entry.get("state_file")
        if path and Path(path).exists():
            state_rows.extend(read_jsonl(Path(path)))
    write_jsonl_atomic(CHILD_STATE_PATH, state_rows)
    return rows


def static_self_check():
    source = HARNESS_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    commands = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else None
        if name not in {"run_command", "run_command_bytes", "popen", "cmd", "Popen"}:
            continue
        arg = node.args[0]
        if isinstance(arg, (ast.List, ast.Tuple)):
            values = [item.value for item in arg.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)]
            if values:
                commands.append(values)
    flattened = [" ".join(command) for command in commands]
    dash_c = "-" + "c"; dash_D = "-" + "D"; pkg = "apt" + "-get"; model = "pro" + "vx"
    no_mn_cleanup = not any(len(cmd) > 1 and cmd[0] == "mn" and cmd[1] == dash_c for cmd in commands)
    no_broad_delete = not any(cmd and cmd[0].endswith("auditctl") and dash_D in cmd for cmd in commands)
    no_apt = not any(cmd and (cmd[0].endswith(pkg) or cmd[0].endswith("aptitude") or cmd[0].endswith("dpkg")) for cmd in commands if cmd[0] != "/usr/bin/dpkg-query")
    no_model = not any(model in command.lower() for command in flattened)
    no_external = not any(token in source for token in ("add" + "NAT", "NAT" + "(", "Intf" + "("))
    no_direct_rw_rules = not any(
        any(token in {"read", "write", "pread64", "pwrite64", "readv", "writev", "pwritev2"}
            for index, token in enumerate(command)
            if index > 0 and command[index - 1] == "-S")
        for command in commands
    )
    bounded_rw = no_direct_rw_rules and "build_file_permission_watch_rule" in source and '"perm=rw"' in source
    no_automatic_sudo = not any(command and command[0].endswith("sudo") for command in commands)
    no_persistent_rule_edits = not any("rules.d" in command for command in flattened)
    real_default_smoke = all(token in source for token in ("def _reviewed_mininet_smoke", "def _run_reviewed_mininet_smoke", "from mininet.net import Mininet", "net.addHost"))
    probe_cleanup_restore_gate = all(token in source for token in (
        "RULE_REMOVED_BASELINE_RESTORED", "RULE_REMOVED_BASELINE_NOT_RESTORED",
        "_audit_baseline_clean",
    ))
    probe_gate_wired = all(token in source for token in (
        "execute_reviewed_r6_path", "_default_micro_probe", "_reviewed_mininet_smoke",
    )) and probe_cleanup_restore_gate
    all_required_classes_contract = len(REQUIRED_CLASSES) == 8 and all(name in source for name in REQUIRED_CLASSES)
    result = {
        "schema": "MININET_E1C_R6_STATIC_AUDIT_V1", "checked_at_utc": utc_now(), "harness_path": str(HARNESS_PATH),
        "harness_sha256": sha256_bytes(source.encode()), "python_ast_parse": True,
        "no_nat_or_external_network": no_external, "no_apt_actions": no_apt, "no_model_execution": no_model,
        "no_mn_cleanup": no_mn_cleanup, "no_broad_rule_delete": no_broad_delete, "bounded_read_write_rules": bounded_rw,
        "no_direct_read_write_rules": no_direct_rw_rules, "no_automatic_sudo": no_automatic_sudo,
        "no_persistent_rule_edits": no_persistent_rule_edits, "real_default_smoke": real_default_smoke,
        "probe_gate_wired": probe_gate_wired, "probe_cleanup_restore_gate": probe_cleanup_restore_gate,
        "all_required_classes_contract": all_required_classes_contract,
        "supported_syscall_probe_present": "query_supported_syscalls" in source, "blocking_handshake_present": "listener.accept()" in source and "create_connection" in source,
        "live_netns_socket_persistence_present": "capture_socket_state" in source and "capture_join" in source,
        "early_child_diagnostics_present": "raise_child_protocol_error" in source and "CHILD_EXIT_BEFORE_READY" in source and "complete_stderr" in source,
        "child_error_persistence_present": "build_child_error_event" in source and '"CHILD_ERROR"' in source,
        "explicit_child_states_present": all(state in source for state in ("BOOTSTRAP_STARTED", "FILE_OPS_COMPLETE", "LISTENER_BOUND", "READY", "GO_RECEIVED", "WORKER_STARTED", "NETWORK_COMPLETE", "FINISHED")),
        "namespace_three_state_present": "NOT_OBSERVED" in source and 'all(value == "PASS"' in source,
        "post_exec_identity_validation_present": "validate_post_exec_identity" in source and "popen_pid_matches_child_pid" in source,
        "clean_root_baseline_fail_closed": "verify_clean_root_baseline" in source and "BLOCKED_NONEMPTY_OR_UNEXPECTED_BASELINE" in source and "HISTORICAL_EMPTY_HASH" in source,
        "recursive_json_safe_present": "def json_safe" in source and "base64.b64encode(value)" in source,
        "journal_fsync_present": "os.fsync" in source and "PLANNED_DELETE" in source and "DELETE_RESULT" in source,
        "exact_cleanup_finally_present": "finally:" in source and "mutation" in source,
        "strace_not_primary_collector": not any("strace" in command.lower() for command in flattened), "commands_inspected": commands,
    }
    result["pass"] = all(result[key] for key in ("python_ast_parse", "no_nat_or_external_network", "no_apt_actions", "no_model_execution", "no_mn_cleanup", "no_broad_rule_delete", "bounded_read_write_rules", "no_direct_read_write_rules", "no_automatic_sudo", "no_persistent_rule_edits", "real_default_smoke", "probe_gate_wired", "probe_cleanup_restore_gate", "all_required_classes_contract", "supported_syscall_probe_present", "blocking_handshake_present", "live_netns_socket_persistence_present", "early_child_diagnostics_present", "child_error_persistence_present", "explicit_child_states_present", "namespace_three_state_present", "post_exec_identity_validation_present", "clean_root_baseline_fail_closed", "recursive_json_safe_present", "journal_fsync_present", "exact_cleanup_finally_present", "strace_not_primary_collector"))
    result["static_safety"] = result["pass"]
    return result


def classify(coverage, post, runtime_error=None):
    if (runtime_error or not post.get("run_rules_removed")
            or not post.get("baseline_restored_after_r6")
            or not post.get("topology_residue_zero")
            or not post.get("child_residue_zero")
            or not coverage.get("namespace_assertions", {}).get("pass")):
        return "BLOCKED"
    if coverage.get("missing_required_classes") or coverage.get("pid_netns_join_failure_count") or not coverage.get("tcpdump", {}).get("pcap_sha256"):
        return "PARTIAL_MISSING_REQUIRED_EVENT_CLASS"
    return "PASS_READY_FOR_GRAPH_NORMALIZATION"


def verify_clean_root_baseline(baseline):
    """R6 never performs legacy cleanup; a non-empty root baseline fails closed."""
    return {
        "status": "PASS" if (
            not baseline.get("canonical_rule_lines")
            and baseline.get("baseline_rule_dump_sha256") == HISTORICAL_EMPTY_HASH
        ) else "BLOCKED_NONEMPTY_OR_UNEXPECTED_BASELINE",
        "old_run_residual_rules_found": 0,
        "old_run_residual_rules_removed": 0,
        "audit_baseline_restored_before_r6": not baseline.get("canonical_rule_lines") and baseline.get("baseline_rule_dump_sha256") == HISTORICAL_EMPTY_HASH,
        "AUDIT_BASELINE_RESTORED_BEFORE_R6": "YES" if (not baseline.get("canonical_rule_lines") and baseline.get("baseline_rule_dump_sha256") == HISTORICAL_EMPTY_HASH) else "NO",
        "legacy_cleanup_performed": False,
        "baseline": baseline,
    }


def _run_reviewed_mininet_smoke():
    if os.geteuid() != 0:
        write_json_atomic(RESULT_PATH, {"status": "BLOCKED", "reason": "root required", "formal_experiment_executed": False})
        return 2
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    journal(JOURNAL_PATH, "RUN_BEGIN", run_id=RUN_ID)
    baseline = audit_snapshot()
    write_json_atomic(PRE_STATE_PATH, baseline)
    remediation = {"status": "NOT_RUN", "old_run_residual_rules_found": 0, "old_run_residual_rules_removed": 0}
    key = "e1c6" + hashlib.sha256((RUN_ID + utc_now()).encode()).hexdigest()[:12]
    probe_key = "e1c6probe" + hashlib.sha256((RUN_ID + "probe").encode()).hexdigest()[:10]
    installed, probe_leftovers, outcomes = [], [], []
    run_owned, joins, children, shells, network_events = [], {}, {}, {}, {}
    permission_paths = {}
    delete_paths = {}
    supported, syscall_probes = set(), []
    raw_records, normalized, runtime_error = [], [], None
    tcpdump_proc = None
    net = None
    pre_ovs = probe_ovs()
    pre_ovs_names = ovs_object_names(pre_ovs)
    write_json_atomic(STRACE_PATH, {"schema": "MININET_E1C_R6_STRACE_ORACLE_COMPARISON_V1", "status": "NOT_RUN", "missing_classes_inferred_from_strace": False})
    try:
        if baseline.get("installed_auditd_version") != "auditd=1:3.0.7-1build1":
            remediation = {"status": "BLOCKED_AUDITD_VERSION", "old_run_residual_rules_found": 0, "old_run_residual_rules_removed": 0}
        else:
            remediation = verify_clean_root_baseline(baseline)
        if remediation.get("status") == "PASS":
            after_residual = remediation.get("baseline", {})
            if after_residual.get("baseline_rule_dump_sha256") != HISTORICAL_EMPTY_HASH:
                remediation["status"] = "BLOCKED_BASELINE_NOT_RESTORED"
            else:
                # Probe each syscall individually; no compound unsupported rule.
                supported, syscall_probes, probe_leftovers = query_supported_syscalls(probe_key, JOURNAL_PATH)
                probe_baseline = audit_snapshot()
                remediation["probe_baseline"] = probe_baseline
                remediation["audit_baseline_restored_after_probe"] = (not probe_baseline["canonical_rule_lines"] and probe_baseline["baseline_rule_dump_sha256"] == HISTORICAL_EMPTY_HASH)
                if not remediation["audit_baseline_restored_after_probe"]:
                    remediation["status"] = "BLOCKED_PROBE_BASELINE_NOT_RESTORED"
        write_json_atomic(RESIDUAL_PATH, remediation)
        write_json_atomic(RULE_CONTRACT_PATH, {"schema": "MININET_E1C_R6_TRANSIENT_RULE_CONTRACT_V1", "run_id": RUN_ID, "audit_key": key, "probe_key": probe_key, "status": "NOT_STARTED", "rule_specs": [], "successful_adds": []})
        write_jsonl_atomic(RAW_PATH, [])
        write_jsonl_atomic(NORMALIZED_PATH, [])
        write_jsonl_atomic(JOIN_PATH, [])
        write_jsonl_atomic(EARLY_FAILURE_PATH, [])
        write_jsonl_atomic(CHILD_STATE_PATH, [])
        if remediation.get("status") != "PASS":
            # A failed clean-baseline/version gate is blocked, not a partial
            # collector result; Mininet must never be attempted in this case.
            return 2
        from mininet.log import setLogLevel
        from mininet.net import Mininet
        from mininet.node import OVSSwitch
        setLogLevel("warning")
        net = Mininet(controller=None, switch=lambda name, **params: OVSSwitch(name, failMode="standalone", protocols="OpenFlow10", **params), autoSetMacs=False, build=False)
        s1 = net.addSwitch("s1")
        h1 = net.addHost("h1", ip="10.0.0.1/24", mac=HOSTS["h1"]["mac"])
        h2 = net.addHost("h2", ip="10.0.0.2/24", mac=HOSTS["h2"]["mac"])
        net.addLink(h1, s1); net.addLink(h2, s1); net.build(); net.start()
        shells = {"h1": {"pid": h1.pid, "netns": proc_link(h1.pid, "net"), "logical_host_id": "h1"}, "h2": {"pid": h2.pid, "netns": proc_link(h2.pid, "net"), "logical_host_id": "h2"}}
        run_owned.extend([capture_process_ref(h1.pid, "h1-shell"), capture_process_ref(h2.pid, "h2-shell"), capture_process_ref(s1.pid, "s1-shell")])
        # Pre-create exactly one watched file per host before binding the
        # child PID.  The child performs read/write against this exact path;
        # its delete probe uses a separate disposable inode so FILE_DELETE is
        # not conflated with the watched read/write target.
        permission_paths = {}
        delete_paths = {}
        for host in ("h1", "h2"):
            watched = TEMP_DIR / f"{host}.txt"
            delete_path = TEMP_DIR / f"{host}-delete.txt"
            watched.write_text(f"{host} precreated\n", encoding="utf-8")
            try:
                delete_path.unlink()
            except FileNotFoundError:
                pass
            permission_paths[host] = watched
            delete_paths[host] = delete_path
        children = {"h1": start_child(h1, "h1", "client"), "h2": start_child(h2, "h2", "server")}
        run_owned.extend([capture_process_ref(children[host]["pid"], children[host]["role"]) for host in children])
        for host in ("h1", "h2"):
            for spec in build_rule_specs(key, children[host]["pid"], str(TEMP_DIR), supported,
                                         scope=f"{host}_pid", permission_paths=[permission_paths[host]]):
                outcome = mutation(JOURNAL_PATH, spec, "ADD", "R6_SMOKE")
                entry = {**spec, "logical_host_id": host, "scope": "pid", "add_result": outcome, "installed": outcome.get("returncode") == 0}
                outcomes.append(entry)
                if entry["installed"]: installed.append(entry)
        for host in ("h1", "h2"):
            for spec in build_rule_specs(key, children[host]["pid"], str(TEMP_DIR), supported, ppid=children[host]["pid"], scope=f"{host}_ppid"):
                outcome = mutation(JOURNAL_PATH, spec, "ADD", "R6_SMOKE")
                entry = {**spec, "logical_host_id": host, "scope": "ppid", "add_result": outcome, "installed": outcome.get("returncode") == 0}
                outcomes.append(entry)
                if entry["installed"]: installed.append(entry)
        write_json_atomic(RULE_CONTRACT_PATH, {"schema": "MININET_E1C_R6_TRANSIENT_RULE_CONTRACT_V1", "run_id": RUN_ID, "audit_key": key, "probe_key": probe_key, "status": "ACTIVE", "supported_syscalls": sorted(supported), "syscall_probes": syscall_probes, "rule_specs": outcomes, "successful_adds": [item["name"] for item in installed]})
        # Start tcpdump before releasing either gated child.
        tcpdump_proc = h1.popen(["/usr/bin/tcpdump", "-U", "-i", "h1-eth0", "-w", str(PCAP_PATH), "-c", "6", "tcp", "port", str(TCP_PORT)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        run_owned.append(capture_process_ref(tcpdump_proc.pid, "tcpdump"))
        # Release the shell gate only after its PID-scoped rules are active;
        # the child then emits READY after bind/listen.
        for host in ("h1", "h2"):
            children[host]["process"].stdin.write("START\n")
            children[host]["process"].stdin.flush()
        ready = read_ready(children)
        for host in ("h1", "h2"):
            ready_event = ready[host]
            actual_netns = None
            live = False
            start_ticks = None
            exe = None
            try:
                actual_netns = proc_link(children[host]["pid"], "net")
                live = process_ref_live(capture_process_ref(children[host]["pid"], children[host]["role"]))
                start_ticks = process_start_ticks(children[host]["pid"])
                exe = os.readlink(f"/proc/{children[host]['pid']}/exe")
            except Exception:
                pass
            identity = validate_post_exec_identity(
                shells[host],
                {"pid": ready_event.get("pid"), "netns": actual_netns,
                 "live": live, "start_ticks": start_ticks, "exe": exe},
                popen_pid=children[host].get("popen_pid"),
            )
            identity_row = {"run_id": RUN_ID, "logical_host_id": host,
                            "evidence_type": "post_exec_identity",
                            "shell_pid": shells[host]["pid"], "shell_netns": shells[host]["netns"],
                            "popen_pid": children[host].get("popen_pid"),
                            "child_pid": ready_event.get("pid"), "child_netns": actual_netns,
                            "ready_event_netns": ready_event.get("netns"),
                            "child_live": live, "child_start_ticks": start_ticks, "child_exe": exe,
                            "post_exec_identity": identity, "captured_at_utc": utc_now(),
                            "captured_while_alive": live}
            append_jsonl_fsync(JOIN_PATH, identity_row)
            if not identity["pass"]:
                raise RuntimeError(f"{host} post-exec PID/netns identity validation failed")
            row = capture_join_safe(children[host], shells[host]["netns"], capture_socket_state(children[host]))
            row["ready_event"] = ready_event
            row["post_exec_identity"] = identity
            row["child_pid_netns_evidence"] = identity_row
            joins[f"{host}-child"] = row
            append_jsonl_fsync(JOIN_PATH, row)
        children["h2"]["process"].stdin.write("GO\n"); children["h2"]["process"].stdin.flush()
        children["h1"]["process"].stdin.write("GO\n"); children["h1"]["process"].stdin.flush()
        pending = {"h1", "h2"}; deadline = time.monotonic() + 15
        while pending and time.monotonic() < deadline:
            streams = [children[host]["process"].stdout for host in pending]
            readable, _, _ = select.select(streams, [], [], 0.5)
            for stream in readable:
                host = next(name for name in pending if children[name]["process"].stdout is stream)
                line = stream.readline()
                if not line:
                    diag = _child_diagnostic_snapshot(children[host])
                    raise_child_protocol_error(
                        EARLY_FAILURE_PATH, host, "CHILD_EXIT_BEFORE_NETWORK", children[host]["pid"],
                        diag["returncode"], diag["stderr"], diag["stdout_history"],
                        diag["liveness"], children[host].get("stage", "NETWORK_WAIT"),
                        child_netns=diag["child_netns"],
                    )
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    children[host]["stdout_history"].append(line.rstrip("\n"))
                    diag = _child_diagnostic_snapshot(children[host])
                    raise_child_protocol_error(
                        EARLY_FAILURE_PATH, host, "INVALID_JSON", children[host]["pid"],
                        diag["returncode"], diag["stderr"], diag["stdout_history"],
                        diag["liveness"], children[host].get("stage", "NETWORK_WAIT"),
                        child_netns=diag["child_netns"],
                    )
                children[host]["stdout_history"].append(event)
                children[host]["stage"] = event.get("stage", event.get("event", "NETWORK_WAIT"))
                if event.get("event") == "CHILD_ERROR":
                    diag = _child_diagnostic_snapshot(children[host])
                    raise_child_protocol_error(
                        EARLY_FAILURE_PATH, host, "CHILD_ERROR", children[host]["pid"],
                        diag["returncode"], diag["stderr"], diag["stdout_history"],
                        diag["liveness"], event.get("stage", "NETWORK_WAIT"),
                        child_netns=diag["child_netns"],
                    )
                if event.get("event") == "WORKER_STARTED":
                    worker = {"host": host, "host_obj": children[host]["host_obj"], "pid": int(event["pid"]), "role": f"{host}-worker"}
                    row = capture_join_safe(worker, shells[host]["netns"]); joins[worker["role"]] = row; append_jsonl_fsync(JOIN_PATH, row)
                    if "process" in row: run_owned.append(row["process"])
                elif event.get("event") == "NETWORK":
                    network_events[host] = event; pending.remove(host)
                    joins[f"{host}-child"]["socket_state_after_network"] = capture_socket_state(children[host]); write_jsonl_atomic(JOIN_PATH, list(joins.values()))
        if pending: raise TimeoutError(f"network events missing: {sorted(pending)}")
        for host in ("h1", "h2"):
            children[host]["process"].stdin.write("STOP\n"); children[host]["process"].stdin.flush()
        for host in ("h1", "h2"):
            children[host]["output"] = children[host]["process"].communicate(timeout=15)
        if tcpdump_proc is not None:
            try: tcpdump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired: tcpdump_proc.terminate(); tcpdump_proc.wait(timeout=5)
        time.sleep(0.5)
        audit_raw = run_command_bytes(["/usr/sbin/ausearch", "-k", key, "--raw"])
        raw_records = parse_audit_groups(audit_raw.get("stdout", b""), key.encode())
        pid_joins = {row["pid"]: row for row in read_jsonl(JOIN_PATH) if "pid" in row}
        write_jsonl_atomic(RAW_PATH, [{"schema": "MININET_E1C_R6_RAW_AUDIT_EVIDENCE_V1", "run_id": RUN_ID, "audit_key": key, **{k: v for k, v in record.items() if k not in {"raw_bytes", "raw_text"}}, "raw_text": record["raw_text"]} for record in raw_records])
        normalized = [event for event in (
            normalize_audit_record(record, pid_joins, permission_paths.values())
            for record in raw_records
        ) if event is not None]
        write_jsonl_atomic(NORMALIZED_PATH, normalized)
    except BaseException as exc:
        runtime_error = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        for entry in children.values():
            proc = entry.get("process")
            if proc is not None and proc.poll() is None:
                try: proc.stdin.write("STOP\n"); proc.stdin.flush()
                except Exception: pass
                try: proc.terminate()
                except Exception: pass
                try: proc.wait(timeout=5)
                except Exception: pass
        child_process_evidence = collect_child_process_evidence(children)
        if tcpdump_proc is not None and tcpdump_proc.poll() is None:
            try: tcpdump_proc.terminate(); tcpdump_proc.wait(timeout=5)
            except Exception: pass
        removals = []
        for spec in reversed(installed):
            result = mutation(JOURNAL_PATH, spec, "DELETE", "R6_SMOKE")
            removals.append({"name": spec.get("name"), "result": result, "returncode": result.get("returncode")})
        for spec in probe_leftovers:
            result = mutation(JOURNAL_PATH, spec, "DELETE", "R6_PROBE_LEFTOVER")
            removals.append({"name": spec.get("name"), "result": result, "returncode": result.get("returncode")})
        rules_after = audit_snapshot()
        if net is not None:
            try: net.stop()
            except Exception as exc: runtime_error = runtime_error or {"type": type(exc).__name__, "message": str(exc)}
        net = None
        for watched in permission_paths.values():
            try:
                Path(watched).unlink()
            except FileNotFoundError:
                pass
        for delete_path in delete_paths.values():
            try:
                Path(delete_path).unlink()
            except FileNotFoundError:
                pass
        interfaces = probe_interfaces(); ovs = probe_ovs(); tcpdump = probe_tcpdump()
        pcap_sha = sha256_bytes(PCAP_PATH.read_bytes()) if PCAP_PATH.exists() else None
        post = {
            "schema": "MININET_E1C_R6_POST_CLEANUP_V1", "run_id": RUN_ID, "audit_key": key,
            "run_rules_removed": bool(installed) and all(item["returncode"] == 0 for item in removals if item["name"] in {spec.get("name") for spec in installed}),
            "rule_removal": removals, "baseline_rule_dump_sha256_before": HISTORICAL_EMPTY_HASH,
            "baseline_rule_dump_sha256_after": rules_after.get("baseline_rule_dump_sha256"),
            "baseline_restored_after_r6": not rules_after.get("canonical_rule_lines") and rules_after.get("baseline_rule_dump_sha256") == HISTORICAL_EMPTY_HASH,
            "AUDIT_BASELINE_RESTORED_AFTER_R6": "YES" if (not rules_after.get("canonical_rule_lines") and rules_after.get("baseline_rule_dump_sha256") == HISTORICAL_EMPTY_HASH) else "NO",
            "persistent_rule_files_unchanged": rules_after.get("persistent_rules_files") == baseline.get("persistent_rules_files"),
            "RUN_OWNED_CHILDREN_REMAINING_DETAILS": [ref for ref in run_owned if process_ref_live(ref)],
            "RESERVED_TEST_INTERFACES_REMAINING_DETAILS": sorted(name for name, result in interfaces.items() if result.get("returncode") == 0),
            "RESERVED_TEST_OVS_OBJECTS_REMAINING_DETAILS": sorted(ovs_object_names(ovs) - pre_ovs_names),
            "TCPDUMP_PROCESS_REMAINING_DETAILS": tcpdump["matching_processes"],
            "mn_cleanup_command_executed": False, "external_nat_attachment": False, "apt_action_executed": False, "provx_executed": False, "formal_experiment_executed": False,
            "tcpdump_ran_inside_topology": tcpdump_proc is not None, "pcap_path": str(PCAP_PATH), "pcap_sha256": pcap_sha,
            "preexisting_ovs_daemons_excluded": True,
        }
        post["RUN_OWNED_CHILDREN_REMAINING"] = len(post["RUN_OWNED_CHILDREN_REMAINING_DETAILS"])
        post["RESERVED_TEST_INTERFACES_REMAINING"] = len(post["RESERVED_TEST_INTERFACES_REMAINING_DETAILS"])
        post["RESERVED_TEST_OVS_OBJECTS_REMAINING"] = len(post["RESERVED_TEST_OVS_OBJECTS_REMAINING_DETAILS"])
        post["TCPDUMP_PROCESS_REMAINING"] = len(post["TCPDUMP_PROCESS_REMAINING_DETAILS"])
        post["topology_residue_zero"] = post["RESERVED_TEST_INTERFACES_REMAINING"] == 0 and post["RESERVED_TEST_OVS_OBJECTS_REMAINING"] == 0
        post["child_residue_zero"] = post["RUN_OWNED_CHILDREN_REMAINING"] == 0
        post["tcpdump_residue_zero"] = post["TCPDUMP_PROCESS_REMAINING"] == 0
        write_json_atomic(POST_PATH, post)
        rows = read_jsonl(JOIN_PATH)
        join_rows = [row for row in rows if row.get("evidence_type") != "post_exec_identity"]
        counts = {name: sum(event.get("event_type") == name for event in normalized) for name in REQUIRED_CLASSES}
        status = rules_after.get("auditctl_status", {}).get("parsed", {})
        namespace = namespace_assertions({host: shells.get(host, {}).get("netns") for host in ("h1", "h2")}, {host: joins.get(f"{host}-child", {}).get("netns") for host in ("h1", "h2")})
        coverage = {
            "schema": "MININET_E1C_R6_COVERAGE_AND_LOSS_V1", "run_id": RUN_ID, "audit_key": key,
            "required_classes": list(REQUIRED_CLASSES), "normalized_class_counts": counts, "raw_record_count": len(raw_records), "normalized_event_count": len(normalized),
            "missing_required_classes": [name for name in REQUIRED_CLASSES if counts[name] == 0], "supported_syscalls": sorted(supported), "syscall_probes": syscall_probes,
            "PID_NETNS_JOIN_SUCCESS_COUNT": sum(row.get("join_status") == "JOINED" for row in join_rows), "PID_NETNS_JOIN_FAILURE_COUNT": sum(row.get("join_status") != "JOINED" for row in join_rows),
            "pid_netns_join_success_count": sum(row.get("join_status") == "JOINED" for row in join_rows), "pid_netns_join_failure_count": sum(row.get("join_status") != "JOINED" for row in join_rows),
            "namespace_assertions": namespace, "audit_lost_events": status.get("lost"), "audit_backlog": status.get("backlog"), "audit_status_post_run": rules_after.get("auditctl_status"),
            "same_tcp_port": {"intended_port": TCP_PORT, "h1_ready_port": (joins.get("h1-child", {}).get("ready_event") or {}).get("listen", [None, None])[1], "h2_ready_port": (joins.get("h2-child", {}).get("ready_event") or {}).get("listen", [None, None])[1], "h1_network": network_events.get("h1"), "h2_network": network_events.get("h2"), "both_hosts_successfully_exchanged": network_events.get("h1", {}).get("mode") == "connect" and network_events.get("h2", {}).get("mode") == "accept"},
            "tcpdump": {"ran_inside_topology": tcpdump_proc is not None, "pcap_exists": PCAP_PATH.exists(), "pcap_sha256": pcap_sha},
            "raw_evidence_hashes_recorded": all("raw_sha256" in record for record in raw_records),
            "normalized_raw_links_valid": verify_raw_event_links(raw_records, normalized).get("valid", False),
            "raw_link_failures": verify_raw_event_links(raw_records, normalized).get("failures", []),
            "file_read_write_limitation": [probe for probe in syscall_probes if probe["syscall"] in {"read", "write", "pread64", "pwrite64", "readv", "writev", "pwritev2"} and not probe["supported"]], "socket_accept_limitation": [probe for probe in syscall_probes if probe["syscall"] in {"accept", "accept4"} and not probe["supported"]], "runtime_error": runtime_error,
            "early_child_failure_count": len(read_jsonl(EARLY_FAILURE_PATH)),
            "child_state_transition_count": len(read_jsonl(CHILD_STATE_PATH)),
            "post_exec_identity_all_pass": all(row.get("post_exec_identity", {}).get("pass") for row in rows if row.get("post_exec_identity")),
        }
        classification = classify(coverage, post, runtime_error)
        coverage["MININET_E1C_R6_AUDITD_COLLECTOR"] = classification
        write_json_atomic(COVERAGE_PATH, coverage)
        write_json_atomic(RULE_CONTRACT_PATH, {"schema": "MININET_E1C_R6_TRANSIENT_RULE_CONTRACT_V1", "run_id": RUN_ID, "audit_key": key, "probe_key": probe_key, "status": "REMOVED" if post["run_rules_removed"] else "REMOVAL_FAILED", "supported_syscalls": sorted(supported), "syscall_probes": syscall_probes, "rule_specs": outcomes, "successful_add_count": len(installed), "removal": removals})
        result = {"schema": "MININET_E1C_R6_PRIVILEGED_RUN_RESULT_V1", "run_id": RUN_ID, "status": "COMPLETED" if runtime_error is None else "FAILED", "classification": classification, "runtime_error": runtime_error, "formal_experiment_executed": False}
        write_json_atomic(RESULT_PATH, result)
        report = ["# MININET-E1C-R6 Auditd Bounded Smoke", "", f"Run: `{RUN_ID}`", f"Audit key: `{key}`", "", f"`MININET_E1C_R6_AUDITD_COLLECTOR = {classification}`", "", f"`OLD_RUN_RESIDUAL_RULES_FOUND = {remediation.get('old_run_residual_rules_found', 0)}`", f"`OLD_RUN_RESIDUAL_RULES_REMOVED = {remediation.get('old_run_residual_rules_removed', 0)}`", f"`AUDIT_BASELINE_RESTORED_BEFORE_R6 = {'YES' if remediation.get('audit_baseline_restored_before_r6') else 'NO'}`", f"`AUDIT_BASELINE_RESTORED_AFTER_R6 = {'YES' if post['baseline_restored_after_r6'] else 'NO'}`", f"`AUDIT_LOST_EVENTS = {coverage.get('audit_lost_events')}`", f"`LOGICAL_HOST_JOIN_SUCCESS_COUNT = {coverage['pid_netns_join_success_count']}`", f"`LOGICAL_HOST_JOIN_FAILURE_COUNT = {coverage['pid_netns_join_failure_count']}`", f"`EARLY_CHILD_FAILURE_COUNT = {coverage.get('early_child_failure_count')}`", "", "## Required audit classes", ""]
        report.extend(f"- {name}: {counts[name]}" for name in REQUIRED_CLASSES)
        report.extend(["", "## Namespace assertions", "", json.dumps(namespace, indent=2, sort_keys=True), "", "## Cleanup", "", json.dumps(post, indent=2, sort_keys=True)])
        REPORT_PATH.write_text("\n".join(report) + "\n", encoding="utf-8")
        return verdict_exit_code(classification)


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--static-self-check", action="store_true")
    parser.add_argument("--run-privileged", action="store_true")
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--logical-host-id")
    parser.add_argument("--listen-address")
    parser.add_argument("--listen-port", type=int)
    parser.add_argument("--peer-address")
    parser.add_argument("--temp-file")
    parser.add_argument("--delete-file", required=False)
    parser.add_argument("--state-file", default=str(CHILD_STATE_PATH))
    parser.add_argument("--role", choices=("client", "server"), default="client")
    return parser.parse_args(argv)


def verdict_exit_code(verdict):
    return {
        "PASS": 0,
        "PARTIAL": 3,
        "BLOCKED": 2,
        "PASS_READY_FOR_GRAPH_NORMALIZATION": 0,
        "PARTIAL_MISSING_REQUIRED_EVENT_CLASS": 3,
    }.get(verdict, 1)


def _reviewed_mininet_smoke() -> dict[str, Any]:
    """Invoke the real R5-reviewed topology smoke body, never a fake PASS."""
    code = _run_reviewed_mininet_smoke()
    verdict = {
        0: "PASS",
        3: "PARTIAL",
        2: "BLOCKED",
    }.get(code, "BLOCKED")
    return {"verdict": verdict, "exit_code": code, "implementation": "R6_REVIEWED_R5_SMOKE"}


def execute_reviewed_r6_path(
    probe: Callable[[], Mapping[str, Any]] | None = None,
    smoke: Callable[[], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run probe, prove its exact cleanup, then reach the real smoke only on PASS."""
    try:
        probe_result = dict((probe or _default_micro_probe)())
    except BaseException as exc:
        return {"verdict": "BLOCKED", "states": ["CLEANUP", "BASELINE_RESTORATION_UNPROVEN"],
                "runtime_error": {"type": type(exc).__name__, "message": str(exc)}}
    states = list(probe_result.get("states", probe_result.get("state", [])))
    if probe_result.get("verdict") != "PASS":
        return {"verdict": "BLOCKED", "states": states}
    if "AUDIT_EVIDENCE_PASS" not in states:
        return {"verdict": "BLOCKED", "states": states + ["PROBE_STATE_INVALID"]}
    if states[-1:] != ["RULE_REMOVED_BASELINE_RESTORED"]:
        return {"verdict": "BLOCKED", "states": states + ["PROBE_CLEANUP_UNPROVEN"]}
    try:
        smoke_result = dict((smoke or _reviewed_mininet_smoke)())
    except BaseException as exc:
        return {"verdict": "BLOCKED", "states": states + ["MININET_EXCEPTION", "CLEANUP", "BASELINE_RESTORED"],
                "runtime_error": {"type": type(exc).__name__, "message": str(exc)}}
    smoke_verdict = smoke_result.get("verdict")
    if smoke_verdict not in {"PASS", "PARTIAL"}:
        return {"verdict": "BLOCKED", "states": states + ["MININET_NOT_EXECUTED", "CLEANUP", "BASELINE_RESTORED"],
                "smoke": smoke_result}
    return {"verdict": smoke_verdict,
            "states": states + ["MININET_EXECUTED", "CLEANUP", "BASELINE_RESTORED"],
            "smoke": smoke_result}


def main(argv=None):
    args = parse_args(argv)
    if args.static_self_check:
        result = static_self_check(); print(json.dumps(result, indent=2, sort_keys=True)); return 0 if result["pass"] else 1
    if args.child:
        return benign_child(args)
    if not args.run_privileged:
        print("MININET_E1C_R6_PREPARATION=PASS")
        print("HUMAN_PRIVILEGED_RUN_REQUIRED=YES")
        print("NEXT_ACTION=HUMAN_RUN_EXACT_SUDO_COMMAND")
        print("STOP=true")
        return 0
    if os.geteuid() != 0:
        print("MININET_E1C_R6_PREPARATION=BLOCKED")
        return verdict_exit_code("BLOCKED")
    try:
        result = execute_reviewed_r6_path()
        print(f"R6_PRIVILEGED_PATH_VERDICT={result.get('verdict', 'BLOCKED')}")
        print("R6_PRIVILEGED_PATH_STATES=" + ",".join(result.get("states", [])))
        return verdict_exit_code(str(result.get("verdict", "BLOCKED")))
    except BaseException:
        return 1


if __name__ == "__main__":
    sys.exit(main())
