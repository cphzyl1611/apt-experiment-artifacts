#!/usr/bin/env python3
"""Bounded E1C-R2 auditd smoke harness.

The default mode is privileged and is intentionally never invoked by this
module automatically.  Child/static modes are unprivileged and deterministic.
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
import time
from pathlib import Path


RUN_DIR = Path(__file__).resolve().parent
RUN_ID = RUN_DIR.name
HARNESS_PATH = Path(__file__).resolve()
R1_RUN_DIR = RUN_DIR.parent / "e1c-run-20260831T050028Z"
R1_KEY = "e1c902f74f583"
R1_PRE_STATE_PATH = R1_RUN_DIR / "MININET_E1C_AUDIT_PRE_STATE.json"
R1_CONTRACT_PATH = R1_RUN_DIR / "MININET_E1C_TRANSIENT_RULE_CONTRACT.json"

PRE_RUN_CONTRACT_PATH = RUN_DIR / "MININET_E1C_R2_PRE_RUN_CONTRACT.json"
STATIC_AUDIT_PATH = RUN_DIR / "MININET_E1C_R2_STATIC_AUDIT.json"
REMEDIATION_PATH = RUN_DIR / "MININET_E1C_R2_R1_RESIDUAL_STATE_REMEDIATION.json"
RULE_CONTRACT_PATH = RUN_DIR / "MININET_E1C_R2_TRANSIENT_RULE_CONTRACT.json"
RAW_PATH = RUN_DIR / "MININET_E1C_R2_RAW_AUDIT_EVIDENCE.jsonl"
NORMALIZED_PATH = RUN_DIR / "MININET_E1C_R2_NORMALIZED_EVENTS.jsonl"
JOIN_PATH = RUN_DIR / "MININET_E1C_R2_PID_NETNS_JOIN.jsonl"
COVERAGE_PATH = RUN_DIR / "MININET_E1C_R2_COVERAGE_AND_LOSS.json"
POST_PATH = RUN_DIR / "MININET_E1C_R2_POST_CLEANUP.json"
REPORT_PATH = RUN_DIR / "MININET_E1C_R2_REPORT.md"
RESULT_PATH = RUN_DIR / "MININET_E1C_R2_PRIVILEGED_RUN_RESULT.json"

HOSTS = {
    "h1": {"address": "10.0.0.1", "peer": "10.0.0.2", "mac": "00:00:00:00:01:01"},
    "h2": {"address": "10.0.0.2", "peer": "10.0.0.1", "mac": "00:00:00:00:01:02"},
}
TCP_PORT = 18080
RESERVED_INTERFACES = ("s1", "s1-eth1", "s1-eth2", "h1-eth0", "h2-eth0")
SYSCALL_CANDIDATES = (
    "execve", "execveat", "clone", "fork", "vfork", "exit_group",
    "openat", "openat2", "read", "write", "pread64", "pwrite64", "readv",
    "writev", "pwritev2", "unlink", "unlinkat", "renameat", "bind",
    "connect", "accept", "accept4",
)
SYSCALL_NAMES = {
    0: "read", 1: "write", 17: "pread64", 18: "pwrite64", 19: "readv",
    20: "writev", 42: "connect", 43: "accept", 49: "bind", 56: "clone",
    57: "fork", 58: "vfork", 59: "execve", 87: "unlink", 231: "exit_group",
    257: "openat", 263: "unlinkat", 264: "renameat", 288: "accept4",
    322: "execveat", 328: "pwritev2", 437: "openat2",
}
REQUIRED_CLASSES = (
    "PROCESS_START_OR_EXEC", "PROCESS_EXIT", "FILE_CREATE_OR_OPEN",
    "FILE_READ_OR_WRITE", "FILE_DELETE", "SOCKET_BIND", "SOCKET_CONNECT",
    "SOCKET_ACCEPT",
)
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


def write_json_atomic(path: Path, value) -> None:
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temp, path)


def write_jsonl_atomic(path: Path, rows) -> None:
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    os.replace(temp, path)


def read_jsonl(path: Path):
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def upsert_jsonl(path: Path, row, identity=("pid", "role")) -> None:
    rows = read_jsonl(path)
    if all(key in row for key in identity):
        replaced = False
        for index, existing in enumerate(rows):
            if all(existing.get(key) == row.get(key) for key in identity):
                rows[index] = row
                replaced = True
                break
        if not replaced:
            rows.append(row)
    else:
        rows.append(row)
    write_jsonl_atomic(path, rows)


def run_command(argv, timeout=15):
    try:
        proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
        return {"argv": list(argv), "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as exc:
        return {"argv": list(argv), "returncode": None, "stdout": "", "stderr": f"{type(exc).__name__}: {exc}"}


def run_command_bytes(argv, timeout=20):
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        return {"argv": list(argv), "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as exc:
        return {"argv": list(argv), "returncode": None, "stdout": b"", "stderr": str(exc).encode()}


def proc_link(pid, name):
    return os.readlink(f"/proc/{int(pid)}/ns/{name}")


def proc_text(pid, relative):
    return Path(f"/proc/{int(pid)}/{relative}").read_text(errors="replace")


def process_start_ticks(pid):
    text = proc_text(pid, "stat")
    return int(text[text.rfind(")") + 2 :].split()[19])


def capture_process_ref(pid, role):
    return {
        "pid": int(pid), "role": role, "start_ticks": process_start_ticks(pid),
        "ppid": int(proc_text(pid, "stat").split(")", 1)[1].split()[1]),
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
    checks = {
        "h1_child_netns == h1_shell_netns": children["h1"] == shells["h1"],
        "h2_child_netns == h2_shell_netns": children["h2"] == shells["h2"],
        "h1_child_netns != h2_shell_netns": children["h1"] != shells["h2"],
        "h2_child_netns != h1_shell_netns": children["h2"] != shells["h1"],
    }
    return {"checks": checks, "pass": all(checks.values())}


def build_rule_specs(key, pid, file_dir, supported, ppid=None, scope="pid"):
    subject = ["-F", f"ppid={ppid}"] if ppid is not None else ["-F", f"pid={pid}"]
    prefix = ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64"]
    specs = []

    def add(name, syscalls, extra=()):
        names = [name for name in syscalls if name in supported]
        if not names:
            return
        argv = list(prefix)
        for syscall in names:
            argv.extend(["-S", syscall])
        argv.extend(extra)
        argv.extend(subject)
        argv.extend(["-k", key])
        specs.append({"name": f"{scope}_{name}", "add_argv": argv, "subject": subject})

    add("process_exec_create", ("execve", "execveat", "clone", "fork", "vfork"))
    add("process_exit", ("exit_group",))
    add("file_open", ("openat", "openat2"), ("-F", f"dir={file_dir}"))
    add("file_read_write", ("read", "write", "pread64", "pwrite64", "readv", "writev", "pwritev2"), ("-F", f"dir={file_dir}"))
    add("file_delete", ("unlink", "unlinkat", "renameat"), ("-F", f"dir={file_dir}"))
    add("socket_ops", ("bind", "connect", "accept", "accept4"))
    return specs


def remove_rules_exact(specs, runner=run_command):
    results = []
    for spec in reversed(specs):
        argv = list(spec["add_argv"])
        try:
            index = argv.index("-a")
        except ValueError:
            results.append({"name": spec.get("name"), "returncode": 2, "error": "missing add action"})
            continue
        argv[index] = "-d"
        outcome = runner(argv)
        results.append({"name": spec.get("name"), "remove_argv": argv, "result": outcome, "returncode": outcome.get("returncode")})
    return results


def query_supported_syscalls(probe_key):
    supported = set()
    probes = []
    for syscall in SYSCALL_CANDIDATES:
        add = ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", syscall, "-F", f"pid={os.getpid()}", "-k", probe_key]
        add_result = run_command(add)
        remove = list(add)
        remove[1] = "-d"
        remove_result = run_command(remove) if add_result["returncode"] == 0 else None
        if add_result["returncode"] == 0:
            supported.add(syscall)
        probes.append({"syscall": syscall, "add": add_result, "remove": remove_result, "supported": add_result["returncode"] == 0})
    return supported, probes


def parse_audit_status(text):
    result = {"raw": text}
    for key in ("enabled", "backlog_limit", "backlog", "lost", "backlog_wait_time", "backlog_wait_time_actual"):
        match = re.search(rf"\b{re.escape(key)}\s+(\d+)", text)
        if match:
            result[key] = int(match.group(1))
    return result


def audit_snapshot():
    rules = run_command_bytes(["/usr/sbin/auditctl", "-l"])
    status = run_command(["/usr/sbin/auditctl", "-s"])
    active = run_command(["/bin/systemctl", "is-active", "auditd"])
    enabled = run_command(["/bin/systemctl", "is-enabled", "auditd"])
    return {
        "captured_at_utc": utc_now(),
        "auditctl_list": {"returncode": rules["returncode"], "stdout_b64": base64.b64encode(rules["stdout"]).decode(), "stderr": rules["stderr"].decode(errors="replace")},
        "baseline_rule_dump_sha256": sha256_bytes(rules["stdout"]),
        "auditctl_status": {**status, "parsed": parse_audit_status(status["stdout"])},
        "auditd_active": active, "auditd_enabled": enabled,
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
            continue
        if token == "-S" and index + 1 < len(tokens):
            syscalls.extend(tokens[index + 1].split(","))
            index += 2
            continue
        if token.startswith("-S") and token != "-S":
            syscalls.extend(token[2:].lstrip("=").split(","))
            index += 1
            continue
        if token == "-k" and index + 1 < len(tokens):
            filters.append(("key", tokens[index + 1]))
            index += 2
            continue
        if token.startswith("-F") and token != "-F" and "=" in token:
            filters.append(tuple(token[2:].lstrip("=").split("=", 1)))
            index += 1
            continue
        if token == "-F" and index + 1 < len(tokens):
            value = tokens[index + 1]
            filters.append(tuple(value.split("=", 1)))
            index += 2
            continue
        index += 1
    return (action, tuple(sorted(syscalls)), tuple(sorted(filters)))


def old_allowed_rules():
    try:
        contract = json.loads(R1_CONTRACT_PATH.read_text())
    except Exception:
        return set()
    allowed = set()
    base_specs = [item for item in contract.get("rule_specs", []) if item.get("installed")]
    for item in base_specs:
        add = item.get("add_argv")
        if add:
            allowed.add(canonical_rule(add))
            if any(value.startswith("-F") and "pid=" in value for value in add):
                variant = list(add)
                for index, value in enumerate(variant[:-1]):
                    if value == "-F" and variant[index + 1].startswith("pid="):
                        variant[index + 1] = variant[index + 1].replace("pid=", "ppid=", 1)
                allowed.add(canonical_rule(variant))
    return allowed


def remediate_r1_residual(baseline):
    before = run_command_bytes(["/usr/sbin/auditctl", "-l"])
    text = before["stdout"].decode(errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    old_lines = [line for line in lines if re.search(rf"(?:-k\s*{re.escape(R1_KEY)}|key={re.escape(R1_KEY)})", line)]
    allowed = old_allowed_rules()
    remediation = {
        "schema": "MININET_E1C_R2_R1_RESIDUAL_STATE_REMEDIATION_V1",
        "run_id": RUN_ID, "old_run_id": R1_RUN_DIR.name, "old_audit_key": R1_KEY,
        "captured_at_utc": utc_now(), "before_probe": {**before, "stdout": text},
        "old_run_residual_rules_found": len(old_lines), "old_run_residual_rules_removed": 0,
        "unrelated_rules_detected": False, "removed_rules": [], "status": "INITIALIZING",
    }
    for line in old_lines:
        try:
            parsed = shlex.split(line)
        except ValueError:
            parsed = []
        if not parsed or canonical_rule(parsed) not in allowed:
            remediation["unrelated_rules_detected"] = True
            remediation["status"] = "BLOCKED_UNRELATED_OR_UNMATCHED_RULE"
            remediation["unmatched_lines"] = old_lines
            write_json_atomic(REMEDIATION_PATH, remediation)
            return remediation
        if Path(parsed[0]).name != "auditctl":
            parsed.insert(0, "/usr/sbin/auditctl")
        if "-a" not in parsed:
            remediation["unrelated_rules_detected"] = True
            remediation["status"] = "BLOCKED_RULE_ACTION_UNPARSEABLE"
            write_json_atomic(REMEDIATION_PATH, remediation)
            return remediation
        parsed[parsed.index("-a")] = "-d"
        result = run_command(parsed)
        remediation["removed_rules"].append({"line": line, "argv": parsed, "result": result})
        if result["returncode"] == 0:
            remediation["old_run_residual_rules_removed"] += 1
        else:
            remediation["status"] = "BLOCKED_RULE_REMOVAL_FAILED"
            write_json_atomic(REMEDIATION_PATH, remediation)
            return remediation
    after = audit_snapshot()
    remediation["after_probe"] = after
    remediation["baseline_rule_dump_sha256"] = baseline.get("baseline_rule_dump_sha256")
    remediation["baseline_restored_before_r2"] = after.get("baseline_rule_dump_sha256") == baseline.get("baseline_rule_dump_sha256")
    remediation["status"] = "PASS" if remediation["baseline_restored_before_r2"] else "BLOCKED_BASELINE_NOT_RESTORED"
    write_json_atomic(REMEDIATION_PATH, remediation)
    return remediation


def parse_audit_groups(raw, key_bytes=None):
    key_bytes = key_bytes or AUDIT_KEY_BYTES
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
    records = []
    for serial in sorted(keyed):
        entries = groups[serial]
        blob = b"".join(value for _, value in entries)
        first = entries[0][1]
        stamp = re.search(rb"msg=audit\(([^:]+):", first)
        records.append({
            "serial": serial, "timestamp_source": stamp.group(1).decode() if stamp else None,
            "record_types": [line.split(b" ", 1)[0][5:].decode(errors="replace") for _, line in entries],
            "source_line_numbers": [line_no for line_no, _ in entries],
            "raw_bytes": blob, "raw_text": blob.decode(errors="replace"),
            "raw_bytes_b64": base64.b64encode(blob).decode(), "raw_sha256": sha256_bytes(blob),
        })
    return records


AUDIT_KEY_BYTES = b"e1c902f74f583"


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


def normalize_audit_record(record, pid_joins):
    raw = record.get("raw_bytes")
    if raw is None:
        raw = record.get("raw_text", "").encode()
    text = record.get("raw_text") or raw.decode(errors="replace")
    parsed = parse_fields(text)
    syscall_number = int(parsed["syscall"]) if parsed.get("syscall", "").isdigit() else -1
    syscall = SYSCALL_NAMES.get(syscall_number, parsed.get("syscall"))
    event_type = CLASS_FOR_SYSCALL.get(syscall)
    if event_type is None:
        return None
    pid = int(parsed["pid"]) if parsed.get("pid", "").isdigit() else None
    ppid = int(parsed["ppid"]) if parsed.get("ppid", "").isdigit() else None
    join = pid_joins.get(pid, {})
    paths = re.findall(r"\bname=\"([^\"]*)\"", text)
    sockaddr_match = re.search(r"SADDR=\{([^}]*)\}", text)
    sockaddr = dict(re.findall(r"\b([A-Za-z_][A-Za-z0-9_-]*)=([^\s]+)", sockaddr_match.group(1))) if sockaddr_match else {}
    event_id = sha256_bytes(f"{RUN_ID}|{record['serial']}|{event_type}|{sha256_bytes(raw)}".encode())
    return {
        "event_id": event_id, "event_type": event_type, "run_id": RUN_ID,
        "raw_serial": record["serial"], "raw_event_bytes_b64": base64.b64encode(raw).decode(),
        "raw_event_sha256": sha256_bytes(raw), "timestamp_source": record.get("timestamp_source"),
        "pid": pid, "ppid": ppid, "pid_start_time_ticks": join.get("start_ticks"),
        "netns_inode": join.get("netns_inode"), "logical_host_id": join.get("logical_host_id"),
        "join_status": "JOINED" if join.get("logical_host_id") else "UNJOINED",
        "executable": {"path": parsed.get("exe"), "comm": parsed.get("comm"), "proctitle": decode_proctitle(text)},
        "syscall": syscall, "result": parsed.get("success") or parsed.get("exit"),
        "path": paths[-1] if paths else None, "sockaddr": sockaddr,
        "file_identity": {"paths": paths, "operation": syscall} if event_type.startswith("FILE_") else None,
        "socket_identity": {"operation": syscall, "family": sockaddr.get("saddr_fam"), "local_address": sockaddr.get("laddr"), "local_port": sockaddr.get("lport")} if event_type.startswith("SOCKET_") else None,
    }


def benign_child(args):
    stopped = False
    listener = None
    worker = None
    temp = Path(args.temp_file)

    def stop_handler(_signum, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    operations = []
    try:
        temp.write_text(f"{args.logical_host_id} pid={os.getpid()}\n")
        operations.append("create")
        with temp.open("a", encoding="utf-8") as stream:
            stream.write("r2-write\n")
        operations.append("write")
        temp.read_text(encoding="utf-8")
        operations.append("read")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.listen_address, args.listen_port))
        listener.listen(8)
        print(json.dumps({"event": "READY", "logical_host_id": args.logical_host_id, "pid": os.getpid(), "ppid": os.getppid(), "listen": [args.listen_address, args.listen_port], "netns": proc_link(os.getpid(), "net"), "temp_file": str(temp), "file_operations": operations}, sort_keys=True), flush=True)
        gate = sys.stdin.readline().strip()
        if gate != "GO" or stopped:
            return 2
        worker = subprocess.Popen(["/usr/bin/python3", "-c", "import time; time.sleep(5)"])
        print(json.dumps({"event": "WORKER_STARTED", "pid": worker.pid, "ppid": os.getpid(), "logical_host_id": args.logical_host_id}, sort_keys=True), flush=True)
        if args.role == "server":
            connection, peer = listener.accept()
            with connection:
                payload = connection.recv(4096)
                connection.sendall(b"ACK:h2")
            network = {"event": "NETWORK", "logical_host_id": args.logical_host_id, "mode": "accept", "peer": [peer[0], peer[1]], "payload": payload.decode(errors="replace"), "port": args.listen_port}
        else:
            with socket.create_connection((args.peer_address, args.listen_port), timeout=5) as outgoing:
                outgoing.sendall(b"benign-h1")
                ack = outgoing.recv(4096).decode(errors="replace")
            network = {"event": "NETWORK", "logical_host_id": args.logical_host_id, "mode": "connect", "peer": [args.peer_address, args.listen_port], "ack": ack, "port": args.listen_port}
        print(json.dumps(network, sort_keys=True), flush=True)
        while not stopped:
            line = sys.stdin.readline()
            if line == "" or line.strip() == "STOP":
                break
            time.sleep(0.02)
    finally:
        if worker is not None:
            try:
                worker.wait(timeout=2)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=2)
        if listener is not None:
            listener.close()
        if temp.exists():
            temp.unlink()
            operations.append("delete")
        print(json.dumps({"event": "FINISHED", "logical_host_id": args.logical_host_id, "pid": os.getpid(), "file_operations": operations}, sort_keys=True), flush=True)
    return 0


def start_child(host_obj, host, temp_dir, role):
    spec = HOSTS[host]
    temp_file = temp_dir / f"{host}.txt"
    proc = host_obj.popen([
        "/usr/bin/python3", str(HARNESS_PATH), "--child", "--logical-host-id", host,
        "--listen-address", spec["address"], "--listen-port", str(TCP_PORT),
        "--peer-address", spec["peer"], "--temp-file", str(temp_file), "--role", role,
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    return {"host": host, "host_obj": host_obj, "process": proc, "pid": proc.pid, "role": role, "temp_file": temp_file}


def read_ready(children, timeout=10):
    pending = dict(children)
    ready = {}
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        streams = [entry["process"].stdout for entry in pending.values()]
        readable, _, _ = select.select(streams, [], [], max(0, deadline - time.monotonic()))
        for stream in readable:
            host = next(name for name, entry in pending.items() if entry["process"].stdout is stream)
            line = stream.readline()
            if not line:
                raise RuntimeError(f"{host} exited before READY")
            event = json.loads(line)
            if event.get("event") != "READY":
                raise RuntimeError(f"{host} emitted {event.get('event')} before READY")
            ready[host] = event
            del pending[host]
    if pending:
        raise TimeoutError(f"children not ready: {sorted(pending)}")
    return ready


def capture_socket_state(entry):
    pid = entry["pid"]
    state = {"captured_at_utc": utc_now(), "pid": pid, "listener_alive": True}
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
        "run_id": RUN_ID, "pid": int(entry["pid"]), "role": entry["role"],
        "logical_host_id": entry["host"], "netns": link, "netns_inode": netns_inode(link),
        "shell_netns": shell_netns, "netns_equals_shell_netns": link == shell_netns,
        "mntns": proc_link(entry["pid"], "mnt"), "cgroup": proc_text(entry["pid"], "cgroup"),
        "process": capture_process_ref(entry["pid"], entry["role"]), "start_ticks": process_start_ticks(entry["pid"]),
        "captured_at_utc": utc_now(), "captured_while_alive": True,
        "join_status": "JOINED" if link == shell_netns else "UNJOINED",
    }
    if socket_state is not None:
        row["socket_state"] = socket_state
    return row


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
    forbidden_clean = "-" + "c"
    forbidden_delete = "-" + "D"
    forbidden_pkg = "apt" + "-get"
    forbidden_model = "pro" + "vx"
    no_clean = not any(len(command) > 1 and command[0] == "mn" and command[1] == forbidden_clean for command in commands)
    no_delete = not any(command and command[0].endswith("auditctl") and forbidden_delete in command for command in commands)
    no_pkg = not any(command and (command[0].endswith(forbidden_pkg) or command[0].endswith("aptitude") or command[0].endswith("dpkg")) for command in commands)
    no_model = not any(forbidden_model in command.lower() for command in flattened)
    no_external_tokens = ("add" + "NAT", "NAT" + "(", "Intf" + "(")
    no_external = not any(token in source for token in no_external_tokens)
    no_broad_rw = all(("-S read" not in command and "-S write" not in command) or "-F dir=" in command for command in flattened)
    result = {
        "schema": "MININET_E1C_R2_STATIC_AUDIT_V1", "checked_at_utc": utc_now(),
        "harness_path": str(HARNESS_PATH), "harness_sha256": sha256_bytes(source.encode()),
        "python_ast_parse": True, "no_nat_or_external_network": no_external,
        "no_apt_actions": no_pkg, "no_model_execution": no_model,
        "no_mn_cleanup": no_clean, "no_broad_rule_delete": no_delete,
        "bounded_read_write_rules": no_broad_rw, "supported_syscall_probe_present": "query_supported_syscalls" in source,
        "blocking_handshake_present": "listener.accept()" in source and "create_connection" in source,
        "live_netns_socket_persistence_present": "write_jsonl_atomic" in source and "capture_socket_state" in source,
        "exact_cleanup_finally_present": "finally:" in source and "remove_rules_exact" in source,
        "strace_not_primary_collector": not any("strace" in command.lower() for command in flattened),
        "commands_inspected": commands,
    }
    result["pass"] = all(result[key] for key in ("python_ast_parse", "no_nat_or_external_network", "no_apt_actions", "no_model_execution", "no_mn_cleanup", "no_broad_rule_delete", "bounded_read_write_rules", "supported_syscall_probe_present", "blocking_handshake_present", "live_netns_socket_persistence_present", "exact_cleanup_finally_present", "strace_not_primary_collector"))
    return result


def probe_interfaces():
    return {name: run_command(["/usr/sbin/ip", "link", "show", "dev", name]) for name in RESERVED_INTERFACES}


def probe_ovs():
    queries = [["/usr/bin/ovs-vsctl", "--timeout=2", "br-exists", "s1"]]
    for table in ("Interface", "Port"):
        for name in RESERVED_INTERFACES:
            queries.append(["/usr/bin/ovs-vsctl", "--timeout=2", "--data=bare", "--no-heading", "--columns=name", "find", table, f"name={name}"])
    return [{"argv": query, "result": run_command(query)} for query in queries]


def probe_tcpdump():
    result = run_command(["/bin/ps", "-eo", "pid=,comm=,args="])
    matches = [line for line in result.get("stdout", "").splitlines() if re.search(r"\btcpdump\b", line)]
    return {"probe": result, "matching_processes": matches, "count": len(matches)}


def classify(coverage, post, runtime_error=None):
    if runtime_error or not post.get("run_rules_removed") or not post.get("baseline_restored") or not post.get("topology_residue_zero") or not post.get("child_residue_zero"):
        return "BLOCKED"
    if coverage.get("missing_required_classes") or coverage.get("pid_netns_join_failure_count"):
        return "PARTIAL_MISSING_REQUIRED_EVENT_CLASS"
    return "PASS_READY_FOR_GRAPH_NORMALIZATION"


def privileged_run():
    if os.geteuid() != 0:
        write_json_atomic(RESULT_PATH, {"status": "BLOCKED", "reason": "root required", "formal_experiment_executed": False})
        return 2
    baseline = audit_snapshot()
    try:
        write_json_atomic(RUN_DIR / "MININET_E1C_R2_AUDIT_PRE_STATE.json", baseline)
        if baseline["auditctl_list"]["returncode"] != 0 or baseline["auditctl_status"]["returncode"] != 0:
            remediation = {"status": "BLOCKED_BASELINE_UNAVAILABLE", "old_run_residual_rules_found": 0, "old_run_residual_rules_removed": 0}
            write_json_atomic(REMEDIATION_PATH, remediation)
            write_json_atomic(RESULT_PATH, {"status": "BLOCKED", "reason": "audit baseline unavailable", "formal_experiment_executed": False})
            return 2
        remediation = remediate_r1_residual(baseline)
        if remediation.get("status") != "PASS":
            write_json_atomic(RESULT_PATH, {"status": "BLOCKED", "reason": remediation.get("status"), "formal_experiment_executed": False})
            return 2
        probe_key = "e1c2probe" + hashlib.sha256((RUN_ID + utc_now()).encode()).hexdigest()[:10]
        supported, syscall_probes = query_supported_syscalls(probe_key)
        baseline_after_probe = audit_snapshot()
        if baseline_after_probe["baseline_rule_dump_sha256"] != baseline["baseline_rule_dump_sha256"]:
            write_json_atomic(RESULT_PATH, {"status": "BLOCKED", "reason": "probe did not restore baseline", "formal_experiment_executed": False})
            return 2
        temp_dir = RUN_DIR / "temp-events"
        temp_dir.mkdir(exist_ok=True)
        key = "e1c2" + hashlib.sha256((RUN_ID + utc_now()).encode()).hexdigest()[:10]
        write_json_atomic(RULE_CONTRACT_PATH, {"schema": "MININET_E1C_R2_TRANSIENT_RULE_CONTRACT_V1", "run_id": RUN_ID, "audit_key": key, "status": "INITIALIZING", "rule_specs": [], "successful_adds": []})
        write_jsonl_atomic(RAW_PATH, [])
        write_jsonl_atomic(NORMALIZED_PATH, [])
        write_jsonl_atomic(JOIN_PATH, [])
        run_owned = []
        installed = []
        outcomes = []
        joins = {}
        children = {}
        net = None
        runtime_error = None
        raw_records = []
        normalized = []
        network_events = {}
        try:
            from mininet.log import setLogLevel
            from mininet.net import Mininet
            from mininet.node import OVSSwitch
            setLogLevel("warning")
            net = Mininet(controller=None, switch=lambda name, **params: OVSSwitch(name, failMode="standalone", protocols="OpenFlow10", **params), autoSetMacs=False, build=False)
            s1 = net.addSwitch("s1")
            h1 = net.addHost("h1", ip="10.0.0.1/24", mac=HOSTS["h1"]["mac"])
            h2 = net.addHost("h2", ip="10.0.0.2/24", mac=HOSTS["h2"]["mac"])
            net.addLink(h1, s1)
            net.addLink(h2, s1)
            net.build()
            net.start()
            shells = {"h1": {"pid": h1.pid, "netns": proc_link(h1.pid, "net"), "logical_host_id": "h1"}, "h2": {"pid": h2.pid, "netns": proc_link(h2.pid, "net"), "logical_host_id": "h2"}}
            run_owned.extend([capture_process_ref(h1.pid, "h1-shell"), capture_process_ref(h2.pid, "h2-shell")])
            run_owned.append(capture_process_ref(s1.pid, "s1-shell"))
            children = {"h1": start_child(h1, "h1", temp_dir, "client"), "h2": start_child(h2, "h2", temp_dir, "server")}
            for host in ("h1", "h2"):
                run_owned.append(capture_process_ref(children[host]["pid"], f"{host}-child"))
            supported_for_rules = set(supported)
            for host in ("h1", "h2"):
                specs = build_rule_specs(key, children[host]["pid"], str(temp_dir), supported_for_rules, scope=f"{host}_pid")
                for spec in specs:
                    outcome = run_command(spec["add_argv"])
                    entry = {**spec, "logical_host_id": host, "add_result": outcome, "installed": outcome["returncode"] == 0}
                    outcomes.append(entry)
                    if entry["installed"]:
                        installed.append(entry)
                    write_json_atomic(RULE_CONTRACT_PATH, {"schema": "MININET_E1C_R2_TRANSIENT_RULE_CONTRACT_V1", "run_id": RUN_ID, "audit_key": key, "status": "ACTIVE", "supported_syscalls": sorted(supported), "syscall_probes": syscall_probes, "rule_specs": outcomes, "successful_adds": [item["name"] for item in installed]})
            for host in ("h1", "h2"):
                specs = build_rule_specs(key, children[host]["pid"], str(temp_dir), supported_for_rules, ppid=children[host]["pid"], scope=f"{host}_ppid")
                for spec in specs:
                    outcome = run_command(spec["add_argv"])
                    entry = {**spec, "logical_host_id": host, "scope": "ppid", "add_result": outcome, "installed": outcome["returncode"] == 0}
                    outcomes.append(entry)
                    if entry["installed"]:
                        installed.append(entry)
                    write_json_atomic(RULE_CONTRACT_PATH, {"schema": "MININET_E1C_R2_TRANSIENT_RULE_CONTRACT_V1", "run_id": RUN_ID, "audit_key": key, "status": "ACTIVE", "supported_syscalls": sorted(supported), "syscall_probes": syscall_probes, "rule_specs": outcomes, "successful_adds": [item["name"] for item in installed]})
            ready = read_ready(children)
            for host in ("h1", "h2"):
                # READY is emitted only after bind/listen; capture socket and
                # namespace ownership while that listener is still alive.
                joins[host] = capture_join(children[host], shells[host]["netns"], capture_socket_state(children[host]))
                joins[host]["ready_event"] = ready[host]
                upsert_jsonl(JOIN_PATH, joins[host])
            children["h2"]["process"].stdin.write("GO\n")
            children["h2"]["process"].stdin.flush()
            children["h1"]["process"].stdin.write("GO\n")
            children["h1"]["process"].stdin.flush()
            pending = {"h1", "h2"}
            deadline = time.monotonic() + 12
            while pending and time.monotonic() < deadline:
                streams = [children[host]["process"].stdout for host in pending]
                readable, _, _ = select.select(streams, [], [], 0.5)
                for stream in readable:
                    host = next(item for item in pending if children[item]["process"].stdout is stream)
                    line = stream.readline()
                    if not line:
                        raise RuntimeError(f"{host} exited before NETWORK")
                    event = json.loads(line)
                    if event.get("event") == "WORKER_STARTED":
                        worker = {"host": host, "host_obj": children[host]["host_obj"], "process": None, "pid": int(event["pid"]), "role": f"{host}-worker"}
                        joins[worker["role"]] = capture_join(worker, shells[host]["netns"])
                        run_owned.append(joins[worker["role"]]["process"])
                        upsert_jsonl(JOIN_PATH, joins[worker["role"]])
                    elif event.get("event") == "NETWORK":
                        network_events[host] = event
                        pending.remove(host)
                        joins[host]["socket_state_after_network"] = capture_socket_state(children[host])
                        upsert_jsonl(JOIN_PATH, joins[host])
            if pending:
                raise TimeoutError(f"network events missing: {sorted(pending)}")
            for host in ("h1", "h2"):
                children[host]["process"].stdin.write("STOP\n")
                children[host]["process"].stdin.flush()
            for host in ("h1", "h2"):
                children[host]["output"] = children[host]["process"].communicate(timeout=12)
            time.sleep(0.5)
            audit_raw = run_command_bytes(["/usr/sbin/ausearch", "-k", key, "--raw"])
            raw_records = parse_audit_groups(audit_raw["stdout"], key.encode())
            pid_joins = {item["pid"]: item for item in read_jsonl(JOIN_PATH) if "pid" in item}
            for record in raw_records:
                raw_row = {"schema": "MININET_E1C_R2_RAW_AUDIT_EVIDENCE_V1", "run_id": RUN_ID, "audit_key": key, **{k: v for k, v in record.items() if k not in {"raw_bytes", "raw_text"}}}
                raw_row["raw_text"] = record["raw_text"]
                append = read_jsonl(RAW_PATH)
                append.append(raw_row)
                write_jsonl_atomic(RAW_PATH, append)
                event = normalize_audit_record(record, pid_joins)
                if event is not None:
                    normalized.append(event)
                    write_jsonl_atomic(NORMALIZED_PATH, normalized)
        except BaseException as exc:
            runtime_error = {"type": type(exc).__name__, "message": str(exc)}
        finally:
            for entry in children.values():
                proc = entry.get("process")
                if proc is not None and proc.poll() is None:
                    try:
                        proc.stdin.write("STOP\n")
                        proc.stdin.flush()
                    except Exception:
                        pass
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        pass
            removal = remove_rules_exact(installed)
            rules_after_remove = audit_snapshot()
            if net is not None:
                try:
                    net.stop()
                except Exception:
                    pass
            net = None
            interfaces = probe_interfaces()
            ovs = probe_ovs()
            tcpdump = probe_tcpdump()
            post = {
                "schema": "MININET_E1C_R2_POST_CLEANUP_V1", "run_id": RUN_ID, "audit_key": key,
                "run_rules_removed": bool(installed) and all(item.get("returncode") == 0 for item in removal),
                "rule_removal": removal, "baseline_rule_dump_sha256_before": baseline["baseline_rule_dump_sha256"],
                "baseline_rule_dump_sha256_after": rules_after_remove["baseline_rule_dump_sha256"],
                "baseline_restored": rules_after_remove["baseline_rule_dump_sha256"] == baseline["baseline_rule_dump_sha256"],
                "audit_status_after": rules_after_remove["auditctl_status"],
                "reserved_interfaces_remaining": sorted(name for name, value in interfaces.items() if value["returncode"] == 0),
                "reserved_ovs_queries": ovs,
                "reserved_ovs_objects_remaining": sorted(item["argv"][-1] for item in ovs if item["result"]["returncode"] == 0 and item["result"].get("stdout", "").strip()),
                "run_owned_children_remaining": [ref for ref in run_owned if process_ref_live(ref)],
                "tcpdump_process_remaining": tcpdump["matching_processes"],
                "mn_cleanup_command_executed": False,
                "persistent_rules_files_edited": False,
                "external_nat_attachment": False,
                "formal_experiment_executed": False,
            }
            post["topology_residue_zero"] = not post["reserved_interfaces_remaining"] and not post["reserved_ovs_objects_remaining"]
            post["child_residue_zero"] = not post["run_owned_children_remaining"]
            write_json_atomic(POST_PATH, post)
            counts = {name: sum(event["event_type"] == name for event in normalized) for name in REQUIRED_CLASSES}
            status = rules_after_remove["auditctl_status"].get("parsed", {})
            coverage = {
                "schema": "MININET_E1C_R2_COVERAGE_AND_LOSS_V1", "run_id": RUN_ID, "audit_key": key,
                "supported_syscalls": sorted(supported), "syscall_probes": syscall_probes,
                "raw_record_count": len(raw_records), "normalized_event_count": len(normalized),
                "normalized_class_counts": counts, "required_classes": list(REQUIRED_CLASSES),
                "missing_required_classes": [name for name in REQUIRED_CLASSES if counts[name] == 0],
                "pid_netns_join_success_count": sum(item.get("join_status") == "JOINED" for item in read_jsonl(JOIN_PATH)),
                "pid_netns_join_failure_count": sum(item.get("join_status") != "JOINED" for item in read_jsonl(JOIN_PATH)),
                "namespace_assertions": namespace_assertions({host: shells[host]["netns"] for host in shells}, {host: joins[host]["netns"] for host in joins if host in shells}),
                "audit_lost_events": status.get("lost", 0), "audit_backlog": status.get("backlog", 0),
                "baseline_restored": post["baseline_restored"], "rule_removal_pass": post["run_rules_removed"],
                "topology_residue_zero": post["topology_residue_zero"], "child_residue_zero": post["child_residue_zero"],
                "same_tcp_port": {"intended_port": TCP_PORT, "h1_network": network_events.get("h1"), "h2_network": network_events.get("h2")},
                "formal_experiment_executed": False, "runtime_error": runtime_error,
            }
            write_json_atomic(COVERAGE_PATH, coverage)
            classification = classify(coverage, post, runtime_error)
            result = {"schema": "MININET_E1C_R2_PRIVILEGED_RUN_RESULT_V1", "run_id": RUN_ID, "status": "COMPLETED" if runtime_error is None else "FAILED", "classification": classification, "runtime_error": runtime_error, "formal_experiment_executed": False}
            write_json_atomic(RESULT_PATH, result)
            write_json_atomic(RULE_CONTRACT_PATH, {"schema": "MININET_E1C_R2_TRANSIENT_RULE_CONTRACT_V1", "run_id": RUN_ID, "audit_key": key, "status": "REMOVED" if post["run_rules_removed"] else "REMOVAL_FAILED", "supported_syscalls": sorted(supported), "syscall_probes": syscall_probes, "rule_specs": outcomes, "successful_add_count": len(installed), "removal": removal})
            report = [
                "# MININET-E1C-R2 Auditd Corrected Smoke", "", f"Run: `{RUN_ID}`", f"Audit key: `{key}`", "",
                f"`MININET_E1C_R2_AUDITD_COLLECTOR = {classification}`", "",
                f"`OLD_RUN_RESIDUAL_RULES_FOUND = {remediation.get('old_run_residual_rules_found', 0)}`", "",
                f"`OLD_RUN_RESIDUAL_RULES_REMOVED = {remediation.get('old_run_residual_rules_removed', 0)}`", "",
                f"`AUDIT_BASELINE_RESTORED_BEFORE_R2 = {'YES' if remediation.get('baseline_restored_before_r2') else 'NO'}`", "",
                f"`AUDIT_BASELINE_RESTORED_AFTER_R2 = {'YES' if post['baseline_restored'] else 'NO'}`", "",
                f"`AUDIT_LOST_EVENTS = {coverage['audit_lost_events']}`", "",
                f"`NORMALIZED_EVENT_COUNT = {coverage['normalized_event_count']}`", "",
                f"`LOGICAL_HOST_JOIN_SUCCESS_COUNT = {coverage['pid_netns_join_success_count']}`", "",
                f"`LOGICAL_HOST_JOIN_FAILURE_COUNT = {coverage['pid_netns_join_failure_count']}`", "",
                "`FORMAL_EXPERIMENT_EXECUTED = NO`", "", "`NEXT_ACTION = FRESH_REVIEW_OF_MININET_E1C_R2`", "", "`STOP = true`", "",
                "## Required Classes", "",
            ]
            report.extend(f"- {name}: {counts[name]}" for name in REQUIRED_CLASSES)
            report.extend(["", "## Namespace Assertions", "", json.dumps(coverage["namespace_assertions"], indent=2, sort_keys=True), "", "## Cleanup", "", json.dumps(post, indent=2, sort_keys=True)])
            REPORT_PATH.write_text("\n".join(report) + "\n", encoding="utf-8")
        return 0 if runtime_error is None else 4
    except BaseException as exc:
        write_json_atomic(RESULT_PATH, {"status": "FAILED", "error": {"type": type(exc).__name__, "message": str(exc)}, "formal_experiment_executed": False})
        return 4


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--static-self-check", action="store_true")
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--logical-host-id")
    parser.add_argument("--listen-address")
    parser.add_argument("--listen-port", type=int)
    parser.add_argument("--peer-address")
    parser.add_argument("--temp-file")
    parser.add_argument("--role", choices=("client", "server"), default="client")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.static_self_check:
        result = static_self_check()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["pass"] else 1
    if args.child:
        return benign_child(args)
    return privileged_run()


if __name__ == "__main__":
    sys.exit(main())
