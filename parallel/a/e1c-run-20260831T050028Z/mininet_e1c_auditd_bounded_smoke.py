#!/usr/bin/python3
"""Bounded auditd smoke for benign Mininet process/file/socket provenance.

Default mode is intentionally privileged and must be invoked by a human with
the exact sudo command supplied by the pre-run contract.  Child and static
self-check modes are unprivileged.
"""

import argparse
import ast
import base64
import hashlib
import json
import os
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


RUN_DIR = Path(__file__).resolve().parent
RUN_ID = RUN_DIR.name
HARNESS_PATH = Path(__file__).resolve()
AUDIT_PRE_STATE_PATH = RUN_DIR / "MININET_E1C_AUDIT_PRE_STATE.json"
RULE_CONTRACT_PATH = RUN_DIR / "MININET_E1C_TRANSIENT_RULE_CONTRACT.json"
RAW_AUDIT_PATH = RUN_DIR / "MININET_E1C_RAW_AUDIT_EVIDENCE.jsonl"
NORMALIZED_PATH = RUN_DIR / "MININET_E1C_NORMALIZED_EVENTS.jsonl"
JOIN_PATH = RUN_DIR / "MININET_E1C_PID_NETNS_JOIN.jsonl"
STRACE_PATH = RUN_DIR / "MININET_E1C_STRACE_ORACLE_COMPARISON.json"
COVERAGE_PATH = RUN_DIR / "MININET_E1C_COVERAGE_AND_LOSS_AUDIT.json"
POST_CLEANUP_PATH = RUN_DIR / "MININET_E1C_POST_CLEANUP_AUDIT.json"
REPORT_PATH = RUN_DIR / "MININET_E1C_AUDITD_SMOKE_REPORT.md"
RESULT_PATH = RUN_DIR / "MININET_E1C_PRIVILEGED_RUN_RESULT.json"

HOSTS = {
    "h1": {"address": "10.0.0.1", "ip": "10.0.0.1/24", "mac": "00:00:00:00:01:01", "peer": "10.0.0.2"},
    "h2": {"address": "10.0.0.2", "ip": "10.0.0.2/24", "mac": "00:00:00:00:01:02", "peer": "10.0.0.1"},
}
TCP_PORT = 18080
RESERVED_INTERFACES = ("s1", "s1-eth1", "s1-eth2", "h1-eth0", "h2-eth0")
REQUIRED_CLASSES = (
    "PROCESS_START_OR_EXEC",
    "PROCESS_EXIT",
    "FILE_CREATE_OR_OPEN",
    "FILE_READ_OR_WRITE",
    "FILE_DELETE",
    "SOCKET_BIND",
    "SOCKET_CONNECT",
    "SOCKET_ACCEPT",
)
REQUIRED_NAMESPACE_CHECKS = (
    "h1_child_netns == h1_shell_netns",
    "h2_child_netns == h2_shell_netns",
    "h1_child_netns != h2_shell_netns",
    "h2_child_netns != h1_shell_netns",
)
SYSCALL_NAMES = {
    0: "read", 1: "write", 17: "pread64", 18: "pwrite64", 19: "readv", 20: "writev",
    42: "connect", 43: "accept", 49: "bind", 56: "clone", 57: "fork", 58: "vfork",
    59: "execve", 60: "exit", 87: "unlink", 231: "exit_group", 257: "openat",
    263: "unlinkat", 264: "renameat", 288: "accept4", 322: "execveat", 328: "pwritev2",
    437: "openat2",
}
PROCESS_SYSCALLS = {"clone", "fork", "vfork", "execve", "execveat"}
EXIT_SYSCALLS = {"exit", "exit_group"}
OPEN_SYSCALLS = {"openat", "openat2"}
READ_WRITE_SYSCALLS = {"read", "write", "pread64", "pwrite64", "readv", "writev", "pwritev2"}
DELETE_SYSCALLS = {"unlink", "unlinkat", "renameat"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    return sha256_bytes(path.read_bytes())


def write_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def append_jsonl(path, value):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")


def run_command(argv, timeout=15):
    proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    return {"argv": list(argv), "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def run_command_bytes(argv, timeout=15):
    proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    return {"argv": list(argv), "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def process_start_ticks(pid):
    stat_text = Path(f"/proc/{int(pid)}/stat").read_text()
    return int(stat_text[stat_text.rfind(")") + 2 :].split()[19])


def capture_process_ref(pid, role):
    pid = int(pid)
    return {
        "pid": pid,
        "start_ticks": process_start_ticks(pid),
        "role": role,
        "ppid": int(Path(f"/proc/{pid}/stat").read_text().split(")", 1)[1].split()[1]),
        "comm": Path(f"/proc/{pid}/comm").read_text().strip(),
        "cmdline": Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip(),
    }


def process_ref_is_live(ref):
    try:
        return process_start_ticks(ref["pid"]) == ref["start_ticks"]
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError, KeyError):
        return False


def proc_link(pid, name):
    return os.readlink(f"/proc/{int(pid)}/ns/{name}")


def netns_inode(link):
    match = re.fullmatch(r"net:\[(\d+)\]", link)
    return int(match.group(1)) if match else None


def proc_text(pid, relative):
    return Path(f"/proc/{int(pid)}/{relative}").read_text(errors="replace")


def capture_pid_netns(pid, role, logical_host_id, shell_netns):
    link = proc_link(pid, "net")
    return {
        "pid": int(pid),
        "role": role,
        "logical_host_id": logical_host_id if link == shell_netns else None,
        "netns": link,
        "netns_inode": netns_inode(link),
        "shell_netns": shell_netns,
        "netns_equals_shell_netns": link == shell_netns,
        "mntns": proc_link(pid, "mnt"),
        "cgroup": proc_text(pid, "cgroup"),
        "process": capture_process_ref(pid, role),
        "captured_at_utc": utc_now(),
    }


def build_namespace_assertions(shells, children):
    checks = {
        "h1_child_netns == h1_shell_netns": children["h1"]["netns"] == shells["h1"]["netns"],
        "h2_child_netns == h2_shell_netns": children["h2"]["netns"] == shells["h2"]["netns"],
        "h1_child_netns != h2_shell_netns": children["h1"]["netns"] != shells["h2"]["netns"],
        "h2_child_netns != h1_shell_netns": children["h2"]["netns"] != shells["h1"]["netns"],
    }
    return {"checks": checks, "pass": tuple(checks) == REQUIRED_NAMESPACE_CHECKS and all(checks.values())}


def parse_audit_status(text):
    result = {"raw": text}
    for key in ("enabled", "backlog_limit", "backlog", "lost", "backlog_wait_time", "backlog_wait_time_actual"):
        match = re.search(rf"\b{re.escape(key)}\s+(\d+)", text)
        if match:
            result[key] = int(match.group(1))
    return result


def audit_baseline_snapshot():
    rules = run_command_bytes(["/usr/sbin/auditctl", "-l"])
    status = run_command(["/usr/sbin/auditctl", "-s"])
    active = run_command(["/bin/systemctl", "is-active", "auditd"])
    enabled = run_command(["/bin/systemctl", "is-enabled", "auditd"])
    config = {}
    for path in (Path("/etc/audit/auditd.conf"), Path("/etc/audit/audit.rules")):
        try:
            data = path.read_bytes()
        except (FileNotFoundError, PermissionError):
            config[str(path)] = {"present": False}
        else:
            config[str(path)] = {"present": True, "sha256": sha256_bytes(data), "size_bytes": len(data)}
    return {
        "captured_at_utc": utc_now(),
        "auditctl_list": {"returncode": rules["returncode"], "stdout_b64": base64.b64encode(rules["stdout"]).decode(), "stderr": rules["stderr"].decode(errors="replace")},
        "baseline_rule_dump_sha256": sha256_bytes(rules["stdout"]),
        "auditctl_status": {**status, "parsed": parse_audit_status(status["stdout"])},
        "auditd_active": active,
        "auditd_enabled": enabled,
        "config_files": config,
        "persistent_rules_files_edited": False,
    }


def rule_specs(key, pid, file_dir, ppid=None, scope="pid"):
    subject = ["-F", "pid=" + str(pid)] if ppid is None else ["-F", "ppid=" + str(ppid)]
    return [
        {"name": f"{scope}_process_exec_create", "add": ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", "execve", "-S", "execveat", "-S", "clone", "-S", "fork", "-S", "vfork", *subject, "-k", key], "remove_mode": "always,exit"},
        {"name": f"{scope}_process_exit", "add": ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", "exit_group", *subject, "-k", key], "remove_mode": "always,exit"},
        {"name": f"{scope}_file_open", "add": ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", "openat", "-S", "openat2", "-F", "dir=" + str(file_dir), *subject, "-k", key], "remove_mode": "always,exit"},
        {"name": f"{scope}_file_read_write", "add": ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", "read", "-S", "write", "-S", "pread64", "-S", "pwrite64", "-S", "readv", "-S", "writev", "-S", "pwritev2", "-F", "dir=" + str(file_dir), *subject, "-k", key], "remove_mode": "always,exit"},
        {"name": f"{scope}_file_delete", "add": ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", "unlink", "-S", "unlinkat", "-S", "renameat", "-F", "dir=" + str(file_dir), *subject, "-k", key], "remove_mode": "always,exit"},
        {"name": f"{scope}_socket_ops", "add": ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", "bind", "-S", "connect", "-S", "accept", "-S", "accept4", *subject, "-k", key], "remove_mode": "always,exit"},
    ]


def remove_argv(add_argv):
    argv = list(add_argv)
    argv[1] = "-d"
    return argv


def install_rules(specs):
    outcomes = []
    installed = []
    for spec in specs:
        outcome = run_command(spec["add"])
        entry = {"name": spec["name"], "add_argv": spec["add"], "add_result": outcome, "remove_argv": remove_argv(spec["add"])}
        if outcome["returncode"] == 0:
            installed.append(spec)
            entry["installed"] = True
        else:
            entry["installed"] = False
        outcomes.append(entry)
    return installed, outcomes


def remove_rules(installed, outcomes):
    by_name = {item["name"]: item for item in outcomes}
    removal = []
    for spec in reversed(installed):
        outcome = run_command(by_name[spec["name"]]["remove_argv"])
        by_name[spec["name"]]["remove_result"] = outcome
        removal.append({"name": spec["name"], "returncode": outcome["returncode"]})
    return removal


def parse_audit_groups(raw):
    text = raw.decode(errors="replace")
    groups = {}
    malformed = []
    for line in text.splitlines(keepends=True):
        match = re.search(r"msg=audit\(([^:]+):(\d+)\)", line)
        if not match or not line.startswith("type="):
            if line.strip() and not line.startswith("----"):
                malformed.append(line.rstrip("\n"))
            continue
        serial = int(match.group(2))
        groups.setdefault(serial, []).append(line)
    records = []
    for serial, lines in sorted(groups.items()):
        raw_record = "".join(lines).encode()
        header = lines[0]
        stamp_match = re.search(r"msg=audit\(([^:]+):", header)
        records.append({
            "serial": serial,
            "timestamp_source": stamp_match.group(1) if stamp_match else None,
            "record_types": [line.split(" ", 1)[0][5:] for line in lines],
            "raw_bytes_b64": base64.b64encode(raw_record).decode(),
            "raw_sha256": sha256_bytes(raw_record),
            "raw_text": raw_record.decode(errors="replace"),
        })
    return records, malformed


def parse_fields(raw_text):
    fields = {}
    for key, value in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|[^\s]+)", raw_text):
        fields.setdefault(key, value.strip('"'))
    return fields


def normalize_audit_record(record, run_id, pid_joins):
    fields = parse_fields(record["raw_text"])
    try:
        syscall_num = int(fields.get("syscall", "-1"))
    except ValueError:
        syscall_num = -1
    syscall = SYSCALL_NAMES.get(syscall_num, fields.get("syscall"))
    if syscall in PROCESS_SYSCALLS:
        event_type = "PROCESS_START_OR_EXEC"
    elif syscall in EXIT_SYSCALLS:
        event_type = "PROCESS_EXIT"
    elif syscall in OPEN_SYSCALLS:
        event_type = "FILE_CREATE_OR_OPEN"
    elif syscall in READ_WRITE_SYSCALLS:
        event_type = "FILE_READ_OR_WRITE"
    elif syscall in DELETE_SYSCALLS:
        event_type = "FILE_DELETE"
    elif syscall == "bind":
        event_type = "SOCKET_BIND"
    elif syscall == "connect":
        event_type = "SOCKET_CONNECT"
    elif syscall in {"accept", "accept4"}:
        event_type = "SOCKET_ACCEPT"
    else:
        return None
    pid = int(fields["pid"]) if fields.get("pid", "").isdigit() else None
    join = pid_joins.get(pid, {})
    event_id = sha256_bytes(f"{run_id}|{record['serial']}|{event_type}|{record['raw_sha256']}".encode())
    return {
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": {"source": record["timestamp_source"], "normalized_utc": None, "monotonic_ns": None},
        "pid": pid,
        "ppid": int(fields["ppid"]) if fields.get("ppid", "").isdigit() else None,
        "executable": {"path": fields.get("exe"), "comm": fields.get("comm"), "proctitle": fields.get("proctitle")},
        "file_identity": {"path": fields.get("name") or fields.get("path"), "device": fields.get("dev"), "inode": fields.get("ino"), "operation": syscall} if event_type.startswith("FILE_") else None,
        "socket_identity": {"socket_inode": fields.get("inode"), "family": fields.get("family"), "local_address": fields.get("saddr"), "operation": syscall} if event_type.startswith("SOCKET_") else None,
        "netns_inode": join.get("netns_inode"),
        "logical_host_id": join.get("logical_host_id"),
        "run_id": run_id,
        "raw_serial": record["serial"],
        "syscall": syscall,
        "path": fields.get("name") or fields.get("path"),
        "sockaddr": fields.get("saddr") or fields.get("sockaddr"),
        "result": fields.get("success") or fields.get("exit"),
        "raw_event_bytes_b64": record["raw_bytes_b64"],
        "raw_event_sha256": record["raw_sha256"],
        "join_status": join.get("join_status", "UNJOINED"),
    }


def existing_reserved_interfaces():
    return [name for name in RESERVED_INTERFACES if run_command(["/usr/sbin/ip", "link", "show", "dev", name])["returncode"] == 0]


def reserved_ovs_queries():
    queries = [{"label": "bridge:s1", "argv": ["/usr/bin/ovs-vsctl", "--timeout=2", "br-exists", "s1"]}]
    for table in ("Interface", "Port"):
        for name in RESERVED_INTERFACES:
            queries.append({"label": f"{table.lower()}:{name}", "argv": ["/usr/bin/ovs-vsctl", "--timeout=2", "--data=bare", "--no-heading", "--columns=name", "find", table, f"name={name}"]})
    return queries


def existing_reserved_ovs_objects():
    found = []
    for query in reserved_ovs_queries():
        result = run_command(query["argv"])
        if result["returncode"] == 0 and (query["label"] == "bridge:s1" or result["stdout"].strip()):
            found.append(query["label"])
    return sorted(found)


def child_mode(args):
    stop = {"value": False}

    def stop_handler(_signum, _frame):
        stop["value"] = True

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    operations = []
    listener = None
    worker = None
    temp_path = Path(args.temp_file)
    started = time.monotonic()
    try:
        temp_path.write_text(f"{args.logical_host_id} pid={os.getpid()}\n")
        operations.append("create")
        with temp_path.open("a") as stream:
            stream.write("auditd-smoke-write\n")
        operations.append("write")
        _ = temp_path.read_text()
        operations.append("read")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.listen_address, args.listen_port))
        listener.listen(4)
        listener.settimeout(0.2)
        print(json.dumps({"event": "READY", "logical_host_id": args.logical_host_id, "pid": os.getpid(), "ppid": os.getppid(), "listen_address": args.listen_address, "listen_port": listener.getsockname()[1], "temp_file": str(temp_path), "file_operations": list(operations), "netns": proc_link(os.getpid(), "net"), "ready_at_utc": utc_now()}, sort_keys=True), flush=True)
        if sys.stdin.readline() == "" and not stop["value"]:
            raise RuntimeError("control gate closed before GO")
        worker = subprocess.Popen(["/usr/bin/python3", "-c", "import time; time.sleep(1.2)"])
        print(json.dumps({"event": "WORKER_STARTED", "pid": worker.pid, "ppid": os.getpid(), "logical_host_id": args.logical_host_id}, sort_keys=True), flush=True)
        with socket.create_connection((args.peer_address, args.listen_port), timeout=3) as outgoing:
            outgoing.sendall(("benign-" + args.logical_host_id).encode())
            ack = outgoing.recv(4096).decode(errors="replace")
        connection, peer = listener.accept()
        with connection:
            payload = connection.recv(4096)
            connection.sendall(("ACK:" + args.logical_host_id).encode())
        print(json.dumps({"event": "NETWORK", "logical_host_id": args.logical_host_id, "connect_peer": [args.peer_address, args.listen_port], "connect_ack": ack, "accept_peer": [peer[0], peer[1]], "payload": payload.decode(errors="replace")}, sort_keys=True), flush=True)
        deadline = time.monotonic() + args.window_seconds
        while time.monotonic() < deadline and not stop["value"]:
            time.sleep(0.05)
    finally:
        if worker is not None:
            try:
                worker.wait(timeout=2)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=2)
        if listener is not None:
            listener.close()
        if temp_path.exists():
            temp_path.unlink()
            operations.append("delete")
        print(json.dumps({"event": "FINISHED", "logical_host_id": args.logical_host_id, "pid": os.getpid(), "file_operations": operations, "elapsed_seconds": round(time.monotonic() - started, 6), "finished_at_utc": utc_now()}, sort_keys=True), flush=True)
    return 0


def command_literals_from_ast(tree):
    names = {"Popen", "run", "check_output", "check_call", "run_command", "run_command_bytes", "popen", "pexec", "cmd"}
    values = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else None
        if name not in names or not node.args:
            continue
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            values.append(arg.value)
        elif isinstance(arg, (ast.List, ast.Tuple)):
            parts = [item.value for item in arg.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)]
            if parts:
                values.append(" ".join(parts))
    return values


def static_self_check():
    source = HARNESS_PATH.read_text()
    tree = ast.parse(source)
    attrs = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    names = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    commands = command_literals_from_ast(tree)
    heads = {Path(item.split()[0]).name for item in commands if item.split()}
    required_tokens = ["execve", "execveat", "openat", "openat2", "read", "write", "unlink", "unlinkat", "bind", "connect", "accept", "accept4", "exit_group", "auditctl", "ausearch"]
    result = {
        "checked_at_utc": utc_now(),
        "harness_path": str(HARNESS_PATH),
        "harness_sha256": sha256_file(HARNESS_PATH),
        "python_ast_parse": True,
        "no_nat_or_external_links": not bool({"addNAT", "addIntf", "attach"} & attrs or {"NAT", "Intf"} & names),
        "no_apt_commands": not bool(heads & {"apt", "apt-get", "aptitude", "dpkg"}),
        "no_automatic_sudo": "sudo" not in heads,
        "no_mn_c": not any(item.split()[:2] == ["mn", "-c"] for item in commands),
        "no_provx_or_formal_benchmark_execution": not bool(heads & {"provx", "benchmark-runner"}),
        "transient_audit_rules_only": "auditctl" in heads and all(
            not ("auditctl" in item and "/etc/audit" in item and "-a" not in item and "-d" not in item)
            for item in commands
        ),
        "bounded_file_rules": "-F dir=" in source and "-S read" in source and "-S write" in source,
        "pid_or_ppid_filtered_rules": "-F pid=" in source and "-F ppid=" in source,
        "required_syscall_families_present": all(token in source for token in required_tokens),
        "raw_audit_preserved_and_hashed": "raw_bytes_b64" in source and "raw_sha256" in source,
        "baseline_hash_restore_present": "baseline_rule_dump_sha256" in source and "baseline_restored" in source,
        "no_broad_delete_rule": "auditctl\\\" , \\\"-D" not in source,
        "command_executables_inspected": sorted(heads),
        "command_literals_inspected": commands,
    }
    result["pass"] = all(result[key] for key in ("python_ast_parse", "no_nat_or_external_links", "no_apt_commands", "no_automatic_sudo", "no_mn_c", "no_provx_or_formal_benchmark_execution", "transient_audit_rules_only", "bounded_file_rules", "pid_or_ppid_filtered_rules", "required_syscall_families_present", "raw_audit_preserved_and_hashed", "baseline_hash_restore_present", "no_broad_delete_rule"))
    return result


def start_child(host, host_obj, temp_dir):
    spec = HOSTS[host]
    temp_path = temp_dir / f"{host}.txt"
    proc = host_obj.popen(["/bin/sh", "-c", "read gate; exec /usr/bin/python3 %s --child --logical-host-id %s --listen-address %s --listen-port %s --peer-address %s --temp-file %s --window-seconds 5" % (HARNESS_PATH, host, spec["address"], TCP_PORT, spec["peer"], temp_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return {"process": proc, "pid": proc.pid, "temp_path": temp_path, "started_at_utc": utc_now(), "host": host}


def read_ready(children, timeout=8):
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
            message = json.loads(line)
            if message.get("event") != "READY":
                raise RuntimeError(f"{host} emitted {message.get('event')} before READY")
            ready[host] = message
            del pending[host]
    if pending:
        raise TimeoutError(f"children not ready: {sorted(pending)}")
    return ready


def collect_remaining_output(entry):
    stdout_tail, stderr = entry["process"].communicate(timeout=10)
    events = [json.loads(line) for line in stdout_tail.splitlines() if line.strip()]
    return {"returncode": entry["process"].returncode, "events": events, "stdout": stdout_tail, "stderr": stderr}


def privileged_run():
    if os.geteuid() != 0:
        return blocked_result("HUMAN_PRIVILEGED_RUN_REQUIRED", "EUID 0 is required; do not invoke sudo automatically")
    baseline = audit_baseline_snapshot()
    write_json(AUDIT_PRE_STATE_PATH, baseline)
    if baseline["auditctl_list"]["returncode"] != 0 or baseline["auditctl_status"]["returncode"] != 0:
        return blocked_result("AUDITCTL_BASELINE_UNAVAILABLE", "auditctl baseline probes failed")
    stale_interfaces = existing_reserved_interfaces()
    stale_ovs = existing_reserved_ovs_objects()
    if stale_interfaces or stale_ovs:
        return blocked_result("STALE_TOPOLOGY_STATE", "reserved topology objects already exist; no cleanup attempted")
    static = static_self_check()
    if not static["pass"]:
        return blocked_result("STATIC_SELF_CHECK_FAILED", "static boundary checks failed")
    key = "e1c" + hashlib.sha256((RUN_ID + utc_now()).encode()).hexdigest()[:10]
    temp_dir = RUN_DIR / "temp-events"
    temp_dir.mkdir(exist_ok=True)
    write_json(RULE_CONTRACT_PATH, {"schema": "MININET_E1C_TRANSIENT_RULE_CONTRACT_V1", "run_id": RUN_ID, "audit_key": key, "file_rule_directory": str(temp_dir), "persistent_rules_files_edited": False, "bounded_rule_policy": "per-PID/PPID for process/socket and unique run directory for file syscalls", "rule_specs": [], "status": "INITIALIZING"})
    RAW_AUDIT_PATH.write_text("")
    NORMALIZED_PATH.write_text("")
    JOIN_PATH.write_text("")
    net = None
    children = {}
    shells = {}
    run_owned = []
    installed = []
    outcomes = []
    child_joins = {}
    worker_joins = {}
    all_output = {}
    error = None
    try:
        from mininet.log import setLogLevel
        from mininet.net import Mininet
        from mininet.node import OVSSwitch
        setLogLevel("warning")
        net = Mininet(controller=None, switch=lambda name, **params: OVSSwitch(name, failMode="standalone", protocols="OpenFlow10", **params), autoSetMacs=False, build=False)
        s1 = net.addSwitch("s1")
        h1 = net.addHost("h1", ip=HOSTS["h1"]["ip"], mac=HOSTS["h1"]["mac"])
        h2 = net.addHost("h2", ip=HOSTS["h2"]["ip"], mac=HOSTS["h2"]["mac"])
        net.addLink(h1, s1)
        net.addLink(h2, s1)
        net.build()
        net.start()
        shells = {"h1": {"pid": h1.pid, "netns": proc_link(h1.pid, "net"), "logical_host_id": "h1"}, "h2": {"pid": h2.pid, "netns": proc_link(h2.pid, "net"), "logical_host_id": "h2"}}
        children = {"h1": start_child("h1", h1, temp_dir), "h2": start_child("h2", h2, temp_dir)}
        run_owned.extend([capture_process_ref(h1.pid, "h1-shell"), capture_process_ref(h2.pid, "h2-shell"), capture_process_ref(s1.pid, "s1-shell"), capture_process_ref(children["h1"]["pid"], "h1-child-wrapper"), capture_process_ref(children["h2"]["pid"], "h2-child-wrapper")])
        for host in ("h1", "h2"):
            specs = rule_specs(key, children[host]["pid"], temp_dir, scope=f"{host}_pid")
            host_installed, host_outcomes = install_rules(specs)
            installed.extend(host_installed)
            outcomes.extend([{**entry, "logical_host_id": host} for entry in host_outcomes])
            child_joins[host] = capture_pid_netns(children[host]["pid"], f"{host}-child", host, shells[host]["netns"])
        write_json(RULE_CONTRACT_PATH, {"schema": "MININET_E1C_TRANSIENT_RULE_CONTRACT_V1", "run_id": RUN_ID, "audit_key": key, "file_rule_directory": str(temp_dir), "persistent_rules_files_edited": False, "bounded_rule_policy": "per-PID/PPID for process/socket and unique run directory for file syscalls", "rule_specs": outcomes, "installed_rule_count": len(installed), "status": "ACTIVE"})
        for host in ("h1", "h2"):
            children[host]["process"].stdin.write("\n")
            children[host]["process"].stdin.flush()
        ready = read_ready(children)
        for host in ("h1", "h2"):
            if ready[host]["pid"] != children[host]["pid"]:
                child_joins[host]["wrapper_pid_matches_ready_pid"] = False
            else:
                child_joins[host]["wrapper_pid_matches_ready_pid"] = True
            ppid_specs = rule_specs(key, children[host]["pid"], temp_dir, ppid=children[host]["pid"], scope=f"{host}_ppid")
            ppid_installed, ppid_outcomes = install_rules(ppid_specs)
            installed.extend(ppid_installed)
            outcomes.extend([{**entry, "logical_host_id": host, "scope": "child_ppid"} for entry in ppid_outcomes])
            child_joins[host]["ready_event"] = ready[host]
        # Re-open gate for the post-READY worker/network actions.
        for host in ("h1", "h2"):
            children[host]["process"].stdin.write("\n")
            children[host]["process"].stdin.flush()
        for host in ("h1", "h2"):
            output = collect_remaining_output(children[host])
            all_output[host] = output
            for event in output["events"]:
                if event.get("event") == "WORKER_STARTED":
                    worker_joins[str(event["pid"])] = capture_pid_netns(event["pid"], f"{host}-worker", host, shells[host]["netns"])
                    run_owned.append(capture_process_ref(event["pid"], f"{host}-worker"))
        # Ensure the child itself receives a clean exit event before rule removal.
        time.sleep(0.5)
        audit_raw = run_command_bytes(["/usr/sbin/ausearch", "-k", key, "--raw"])
        raw_records, malformed = parse_audit_groups(audit_raw["stdout"])
        pid_joins = {int(item["pid"]): item for item in child_joins.values()}
        pid_joins.update({int(pid): item for pid, item in worker_joins.items()})
        namespace = build_namespace_assertions(shells, child_joins)
        for item in list(child_joins.values()) + list(worker_joins.values()):
            append_jsonl(JOIN_PATH, item)
        normalized = []
        duplicate_serials = []
        seen = set()
        for record in raw_records:
            if record["serial"] in seen:
                duplicate_serials.append(record["serial"])
            seen.add(record["serial"])
            append_jsonl(RAW_AUDIT_PATH, {"run_id": RUN_ID, "audit_key": key, **{k: v for k, v in record.items() if k != "raw_text"}})
            event = normalize_audit_record(record, RUN_ID, pid_joins)
            if event is not None:
                normalized.append(event)
                append_jsonl(NORMALIZED_PATH, event)
        baseline_after_events = audit_baseline_snapshot()
        removal = remove_rules(installed, outcomes)
        if net is not None:
            net.stop()
        net = None
        post_rules = audit_baseline_snapshot()
        baseline_restored = post_rules["baseline_rule_dump_sha256"] == baseline["baseline_rule_dump_sha256"]
        post_cleanup = {"captured_at_utc": utc_now(), "run_rules_removed": all(item["returncode"] == 0 for item in removal), "rule_removal": removal, "baseline_rule_dump_sha256_before": baseline["baseline_rule_dump_sha256"], "baseline_rule_dump_sha256_after": post_rules["baseline_rule_dump_sha256"], "baseline_restored": baseline_restored, "reserved_interfaces_remaining": existing_reserved_interfaces(), "reserved_ovs_objects_remaining": existing_reserved_ovs_objects(), "run_owned_children_remaining": [ref for ref in run_owned if process_ref_is_live(ref)], "mn_dash_c_executed": False, "persistent_rules_files_edited": False}
        post_cleanup["topology_residue_zero"] = not post_cleanup["reserved_interfaces_remaining"] and not post_cleanup["reserved_ovs_objects_remaining"]
        post_cleanup["child_residue_zero"] = not post_cleanup["run_owned_children_remaining"]
        write_json(POST_CLEANUP_PATH, post_cleanup)
        counts = {name: sum(event["event_type"] == name for event in normalized) for name in REQUIRED_CLASSES}
        status_after = post_rules["auditctl_status"].get("parsed", {})
        coverage = {"run_id": RUN_ID, "audit_key": key, "raw_record_count": len(raw_records), "normalized_event_count": len(normalized), "normalized_class_counts": counts, "required_classes": list(REQUIRED_CLASSES), "missing_required_classes": [name for name, count in counts.items() if not count], "joined_event_count": sum(event.get("join_status") == "JOINED" for event in normalized), "unjoined_event_count": sum(event.get("join_status") != "JOINED" for event in normalized), "pid_netns_join_success_count": sum(item.get("logical_host_id") in {"h1", "h2"} for item in list(child_joins.values()) + list(worker_joins.values())), "pid_netns_join_failure_count": sum(item.get("logical_host_id") not in {"h1", "h2"} for item in list(child_joins.values()) + list(worker_joins.values())), "audit_lost_events": status_after.get("lost", 0), "audit_backlog": status_after.get("backlog", 0), "malformed_records": len(malformed), "duplicate_serial_count": len(duplicate_serials), "baseline_restored": baseline_restored, "rule_removal_pass": post_cleanup["run_rules_removed"], "topology_residue_zero": post_cleanup["topology_residue_zero"], "child_residue_zero": post_cleanup["child_residue_zero"], "formal_experiment_executed": False}
        write_json(COVERAGE_PATH, coverage)
        write_json(STRACE_PATH, {"schema": "MININET_E1C_STRACE_ORACLE_COMPARISON_V1", "run_id": RUN_ID, "status": "NOT_RUN", "role": "validation_oracle_only", "formal_collector": False, "reason": "Auditd smoke was kept isolated; strace remains available for a separate bounded parser-validation run."})
        result = {"run_id": RUN_ID, "status": "COMPLETED", "audit_key": key, "namespace_assertions": namespace, "baseline": baseline, "coverage": coverage, "post_cleanup": post_cleanup, "child_output": all_output, "audit_raw_returncode": audit_raw["returncode"], "static_self_check": static, "formal_experiment_executed": False}
        write_json(RESULT_PATH, result)
        write_json(RULE_CONTRACT_PATH, {"schema": "MININET_E1C_TRANSIENT_RULE_CONTRACT_V1", "run_id": RUN_ID, "audit_key": key, "file_rule_directory": str(temp_dir), "persistent_rules_files_edited": False, "bounded_rule_policy": "per-PID/PPID for process/socket and unique run directory for file syscalls", "rule_specs": outcomes, "installed_rule_count": len(installed), "removal": removal, "status": "REMOVED"})
        REPORT_PATH.write_text(build_report(result, coverage, post_cleanup, namespace))
        return 0 if coverage["missing_required_classes"] == [] and coverage["audit_lost_events"] == 0 and coverage["unjoined_event_count"] == 0 and post_cleanup["baseline_restored"] and post_cleanup["topology_residue_zero"] and post_cleanup["child_residue_zero"] else 4
    except BaseException as exc:
        error = {"type": type(exc).__name__, "message": str(exc)}
        if net is not None:
            try:
                net.stop()
            except BaseException:
                pass
        for entry in children.values():
            try:
                entry["process"].terminate()
            except BaseException:
                pass
        write_json(RESULT_PATH, {"run_id": RUN_ID, "status": "FAILED", "error": error, "formal_experiment_executed": False})
        return 4


def build_report(result, coverage, cleanup, namespace):
    counts = "\n".join(f"- {name}: {coverage['normalized_class_counts'][name]}" for name in REQUIRED_CLASSES)
    return f"""# MININET-E1C Auditd Bounded Benign Smoke\n\nRun: `{RUN_ID}`\n\n## Terminal\n\n`MININET_E1C_AUDITD_COLLECTOR = {'PASS_READY_FOR_GRAPH_NORMALIZATION' if not coverage['missing_required_classes'] and coverage['audit_lost_events'] == 0 and coverage['unjoined_event_count'] == 0 and cleanup['baseline_restored'] else 'PARTIAL_MISSING_REQUIRED_EVENT_CLASS'}`\n\n`AUDIT_LOST_EVENTS = {coverage['audit_lost_events']}`\n\n`NORMALIZED_EVENT_COUNT = {coverage['normalized_event_count']}`\n\n`LOGICAL_HOST_JOIN_SUCCESS_COUNT = {coverage['pid_netns_join_success_count']}`\n\n`LOGICAL_HOST_JOIN_FAILURE_COUNT = {coverage['pid_netns_join_failure_count']}`\n\n`FORMAL_EXPERIMENT_EXECUTED = NO`\n\n`NEXT_ACTION = FRESH_REVIEW_OF_MININET_E1C_AUDITD_SMOKE`\n\n`STOP = true`\n\n## Namespace Assertions\n\n```json\n{json.dumps(namespace, indent=2, sort_keys=True)}\n```\n\n## Normalized Classes\n\n{counts}\n\n## Cleanup\n\n```json\n{json.dumps(cleanup, indent=2, sort_keys=True)}\n```\n\nRaw audit records, normalized events, PID/netns joins, coverage, loss, and the strace oracle status are stored as adjacent JSON/JSONL artifacts. Persistent audit rule files were not edited; only transient rules under the unique run key were used.\n"""


def blocked_result(status, error):
    write_json(AUDIT_PRE_STATE_PATH, {"status": status, "error": error, "captured_at_utc": utc_now(), "formal_experiment_executed": False})
    write_json(RESULT_PATH, {"status": status, "error": error, "formal_experiment_executed": False})
    return 2


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static-self-check", action="store_true")
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--logical-host-id")
    parser.add_argument("--listen-address")
    parser.add_argument("--listen-port", type=int)
    parser.add_argument("--peer-address")
    parser.add_argument("--temp-file")
    parser.add_argument("--window-seconds", type=float, default=5.0)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.static_self_check:
        result = static_self_check()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["pass"] else 1
    if args.child:
        required = (args.logical_host_id, args.listen_address, args.listen_port is not None, args.peer_address, args.temp_file)
        if not all(required):
            raise SystemExit("child mode requires host, address, port, peer, and temp file")
        return child_mode(args)
    return privileged_run()


if __name__ == "__main__":
    sys.exit(main())
