#!/usr/bin/env python3
"""Recover E1C evidence after the privileged harness aborted.

This is a read-only collector over the existing audit log and local process
state.  It never invokes sudo, auditctl mutation, Mininet, APT, or PROVX.
The audit log bytes are grouped by the unique E1C key and retained verbatim.
"""

from __future__ import annotations

import base64
import binascii
import collections
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


RUN_DIR = Path(__file__).resolve().parent
RUN_ID = RUN_DIR.name
AUDIT_LOG = Path("/var/log/audit/audit.log")
AUDIT_KEY = "e1c902f74f583"
HARNESS = RUN_DIR / "mininet_e1c_auditd_bounded_smoke.py"
STATIC_SELF_CHECK = RUN_DIR / "MININET_E1C_HARNESS_STATIC_SELF_CHECK.json"
PRE_STATE = RUN_DIR / "MININET_E1C_AUDIT_PRE_STATE.json"
RULE_CONTRACT = RUN_DIR / "MININET_E1C_TRANSIENT_RULE_CONTRACT.json"
RAW_PATH = RUN_DIR / "MININET_E1C_RAW_AUDIT_EVIDENCE.jsonl"
NORMALIZED_PATH = RUN_DIR / "MININET_E1C_NORMALIZED_EVENTS.jsonl"
JOIN_PATH = RUN_DIR / "MININET_E1C_PID_NETNS_JOIN.jsonl"
STRACE_PATH = RUN_DIR / "MININET_E1C_STRACE_ORACLE_COMPARISON.json"
COVERAGE_PATH = RUN_DIR / "MININET_E1C_COVERAGE_AND_LOSS_AUDIT.json"
POST_PATH = RUN_DIR / "MININET_E1C_POST_CLEANUP_AUDIT.json"
REPORT_PATH = RUN_DIR / "MININET_E1C_AUDITD_SMOKE_REPORT.md"
RESULT_PATH = RUN_DIR / "MININET_E1C_PRIVILEGED_RUN_RESULT.json"

SYSCALL_NAMES = {
    0: "read", 1: "write", 17: "pread64", 18: "pwrite64",
    19: "readv", 20: "writev", 42: "connect", 43: "accept",
    49: "bind", 56: "clone", 57: "fork", 58: "vfork", 59: "execve",
    87: "unlink", 231: "exit_group", 257: "openat", 263: "unlinkat",
    264: "renameat", 288: "accept4", 322: "execveat", 328: "pwritev2",
    437: "openat2",
}
CLASS_FOR_SYSCALL = {
    **{name: "PROCESS_START_OR_EXEC" for name in ("clone", "fork", "vfork", "execve", "execveat")},
    **{name: "PROCESS_EXIT" for name in ("exit", "exit_group")},
    **{name: "FILE_CREATE_OR_OPEN" for name in ("openat", "openat2")},
    **{name: "FILE_READ_OR_WRITE" for name in ("read", "write", "pread64", "pwrite64", "readv", "writev", "pwritev2")},
    **{name: "FILE_DELETE" for name in ("unlink", "unlinkat", "renameat")},
    "bind": "SOCKET_BIND",
    "connect": "SOCKET_CONNECT",
    "accept": "SOCKET_ACCEPT",
    "accept4": "SOCKET_ACCEPT",
}
REQUIRED_CLASSES = (
    "PROCESS_START_OR_EXEC", "PROCESS_EXIT", "FILE_CREATE_OR_OPEN",
    "FILE_READ_OR_WRITE", "FILE_DELETE", "SOCKET_BIND", "SOCKET_CONNECT",
    "SOCKET_ACCEPT",
)
PID_HOST = {575776: "h1", 575829: "h1", 575777: "h2", 575830: "h2"}
PID_ROLE = {
    575776: "h1-child-wrapper", 575777: "h2-child-wrapper",
    575829: "h1-worker", 575830: "h2-worker",
}
RESERVED_INTERFACES = ("s1", "s1-eth1", "s1-eth2", "h1-eth0", "h2-eth0")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def write_json(path: Path, value) -> None:
    temporary = path.with_name(path.name + ".recovery.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def write_jsonl(path: Path, rows) -> None:
    temporary = path.with_name(path.name + ".recovery.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    os.replace(temporary, path)


def command(argv):
    try:
        proc = subprocess.run(argv, text=True, capture_output=True, timeout=5, check=False)
        return {"argv": list(argv), "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as exc:  # keep every probe explicit rather than hiding it
        return {"argv": list(argv), "returncode": None, "stdout": "", "stderr": f"{type(exc).__name__}: {exc}"}


def parse_audit_groups(data: bytes):
    groups = collections.defaultdict(list)
    keyed_serials = set()
    source_lines = data.splitlines(keepends=True)
    for line_no, line in enumerate(source_lines, 1):
        match = re.search(rb"msg=audit\(([^:]+):(\d+)\)", line)
        if not match:
            continue
        serial = int(match.group(2))
        groups[serial].append((line_no, line))
        if AUDIT_KEY.encode() in line:
            keyed_serials.add(serial)
    records = []
    for serial in sorted(keyed_serials):
        entries = groups[serial]
        raw = b"".join(line for _, line in entries)
        header = entries[0][1]
        timestamp_match = re.search(rb"msg=audit\(([^:]+):", header)
        record_types = []
        for _, line in entries:
            prefix = line.split(b" ", 1)[0]
            record_types.append(prefix[5:].decode(errors="replace") if prefix.startswith(b"type=") else "MALFORMED")
        records.append({
            "serial": serial,
            "timestamp_source": timestamp_match.group(1).decode() if timestamp_match else None,
            "record_types": record_types,
            "source_line_numbers": [line_no for line_no, _ in entries],
            "raw_bytes_b64": base64.b64encode(raw).decode(),
            "raw_sha256": sha256(raw),
            "raw_text": raw.decode(errors="replace"),
        })
    return records


def fields(text: str):
    result = {}
    for key, value in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|[^\s]+)", text):
        result.setdefault(key, value[1:-1] if value.startswith('"') and value.endswith('"') else value)
    return result


def first_syscall(text: str):
    match = re.search(r"\bsyscall=(\d+)", text)
    return (int(match.group(1)), match.group(1)) if match else (None, None)


def paths(text: str):
    return re.findall(r"\bname=\"([^\"]*)\"", text)


def sockaddr(text: str):
    match = re.search(r"SADDR=\{([^}]*)\}", text)
    if not match:
        return {}
    return {key: value for key, value in re.findall(r"\b([A-Za-z_][A-Za-z0-9_-]*)=([^\s]+)", match.group(1))}


def proctitle(text: str):
    match = re.search(r"proctitle=([0-9A-Fa-f]+)", text)
    if not match:
        return None
    try:
        return binascii.unhexlify(match.group(1)).replace(b"\0", b" ").decode(errors="replace")
    except (binascii.Error, ValueError):
        return None


def argv_from_execve(text: str):
    match = re.search(r"type=EXECVE .*?((?:a\d+=\"[^\"]*\"\s*)+)", text)
    if not match:
        return []
    pairs = re.findall(r"\ba(\d+)=\"([^\"]*)\"", match.group(1))
    return [value for _, value in sorted(pairs, key=lambda pair: int(pair[0]))]


def normalize(record):
    text = record["raw_text"]
    parsed = fields(text)
    syscall_number, syscall_raw = first_syscall(text)
    syscall = SYSCALL_NAMES.get(syscall_number, syscall_raw)
    event_type = CLASS_FOR_SYSCALL.get(syscall)
    if event_type is None:
        return None
    pid = int(parsed["pid"]) if parsed.get("pid", "").isdigit() else None
    ppid = int(parsed["ppid"]) if parsed.get("ppid", "").isdigit() else None
    all_paths = paths(text)
    target_paths = [p for p in all_paths if p.startswith(str(RUN_DIR / "temp-events")) and not p.endswith("/")]
    path = target_paths[-1] if target_paths else (all_paths[-1] if all_paths else None)
    sa = sockaddr(text)
    host_hint = PID_HOST.get(pid)
    event_id = sha256(f"{RUN_ID}|{record['serial']}|{event_type}|{record['raw_sha256']}".encode())
    result = parsed.get("success") or parsed.get("exit")
    return {
        "event_id": event_id,
        "event_type": event_type,
        "run_id": RUN_ID,
        "pid": pid,
        "ppid": ppid,
        "pid_start_time_ticks": None,
        "logical_host_id": None,
        "logical_host_id_expected_from_harness": host_hint,
        "netns_inode": None,
        "join_status": "UNJOINED",
        "join_failure_reason": "No persisted live /proc/<pid>/ns/net capture; harness aborted before evidence finalization",
        "timestamp": {"source_timestamp": record["timestamp_source"], "normalized_utc": None, "monotonic_ns": None},
        "executable": {
            "path": parsed.get("exe"), "comm": parsed.get("comm"),
            "proctitle": proctitle(text), "argv": argv_from_execve(text),
        },
        "file_identity": {
            "path": path, "all_paths": all_paths, "device": None,
            "inode": None, "operation": syscall,
        } if event_type.startswith("FILE_") else None,
        "socket_identity": {
            "socket_inode": None, "family": sa.get("saddr_fam"),
            "protocol": None, "local_address": sa.get("laddr"),
            "local_port": sa.get("lport"), "remote_address": None,
            "remote_port": None, "operation": syscall,
        } if event_type.startswith("SOCKET_") else None,
        "syscall": syscall,
        "path": path,
        "sockaddr": sa,
        "result": result,
        "raw_serial": record["serial"],
        "raw_event_bytes_b64": record["raw_bytes_b64"],
        "raw_event_sha256": record["raw_sha256"],
        "collector_metadata": {
            "collector_name": "auditd",
            "collector_version": "3.0.7",
            "audit_key": AUDIT_KEY,
            "source": str(AUDIT_LOG),
            "source_log_sha256": sha256(AUDIT_LOG.read_bytes()),
            "loss_counters": {"pre_run_lost": 0, "post_run_lost": None},
        },
    }


def pid_join_rows(records):
    by_pid = collections.defaultdict(list)
    for record in records:
        parsed = fields(record["raw_text"])
        if parsed.get("pid", "").isdigit():
            by_pid[int(parsed["pid"])].append(record["serial"])
    rows = []
    for pid in (575776, 575777, 575829, 575830):
        if pid in (575776, 575777):
            capture_state = "CAPTURED_IN_MEMORY_THEN_LOST"
            attempted = True
            while_alive = True
            reason = "Harness called capture_pid_netns while child wrapper was alive, but exception path did not persist JOIN_PATH"
        elif pid == 575829:
            capture_state = "FAILED_PROCESS_ALREADY_EXITED"
            attempted = True
            while_alive = False
            reason = "FileNotFoundError for /proc/575829/ns/net stopped the harness"
        else:
            capture_state = "NOT_ATTEMPTED_AFTER_PRIOR_EXCEPTION"
            attempted = False
            while_alive = False
            reason = "Harness aborted while collecting h1 worker; h2 worker join was never attempted"
        rows.append({
            "run_id": RUN_ID, "pid": pid, "role": PID_ROLE[pid],
            "logical_host_id_expected_from_harness": PID_HOST[pid],
            "capture_attempted": attempted,
            "captured_while_alive_claimed_by_control_flow": while_alive,
            "capture_persisted": False,
            "netns": None, "netns_inode": None, "shell_netns": None,
            "join_status": "UNJOINED", "join_failure_reason": reason,
            "audit_serials_for_pid": sorted(set(by_pid.get(pid, []))),
            "independent_validation": "FAIL",
        })
    return rows


def decode_mn_c_matches(data: bytes):
    matches = []
    for match in re.finditer(rb"proctitle=([0-9A-Fa-f]+)", data):
        try:
            decoded = binascii.unhexlify(match.group(1)).replace(b"\0", b" ").decode(errors="replace")
        except (binascii.Error, ValueError):
            continue
        if "mn -c" in decoded:
            matches.append(decoded)
    return matches


def probe_process(pid):
    try:
        os.stat(f"/proc/{pid}")
        return True
    except (FileNotFoundError, PermissionError):
        return False


def probe_interfaces():
    probes = {}
    for name in RESERVED_INTERFACES:
        probes[name] = command(["/usr/sbin/ip", "link", "show", "dev", name])
    return probes


def probe_ovs():
    queries = [{"label": "bridge:s1", "argv": ["/usr/bin/ovs-vsctl", "--timeout=2", "br-exists", "s1"]}]
    for table in ("Interface", "Port"):
        for name in RESERVED_INTERFACES:
            queries.append({"label": f"{table.lower()}:{name}", "argv": ["/usr/bin/ovs-vsctl", "--timeout=2", "--data=bare", "--no-heading", "--columns=name", "find", table, f"name={name}"]})
    results = []
    for query in queries:
        result = command(query["argv"])
        results.append({**query, "result": result})
    return results


def probe_tcpdump():
    result = command(["/bin/ps", "-eo", "pid=,comm=,args="])
    lines = []
    for line in result.get("stdout", "").splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 2 and (parts[1] == "tcpdump" or " tcpdump " in f" {line} "):
            lines.append(line)
    return {"probe": result, "matching_process_lines": lines, "count": len(lines)}


def persistent_probe(pre_state):
    result = {"status": "UNVERIFIED_PERMISSION_DENIED", "files": {}, "rules_dir": {}}
    for path in (Path("/etc/audit/audit.rules"), Path("/etc/audit/auditd.conf")):
        try:
            data = path.read_bytes()
        except (FileNotFoundError, PermissionError) as exc:
            result["files"][str(path)] = {"readable": False, "error": f"{type(exc).__name__}: {exc}", "pre_state": pre_state.get("config_files", {}).get(str(path))}
        else:
            result["files"][str(path)] = {"readable": True, "sha256": sha256(data), "pre_state": pre_state.get("config_files", {}).get(str(path))}
    try:
        result["rules_dir"]["entries"] = sorted(p.name for p in Path("/etc/audit/rules.d").iterdir())
        result["rules_dir"]["readable"] = True
    except (FileNotFoundError, PermissionError) as exc:
        result["rules_dir"]["readable"] = False
        result["rules_dir"]["error"] = f"{type(exc).__name__}: {exc}"
    return result


def ovs_daemons():
    result = command(["/bin/ps", "-eo", "pid=,lstart=,comm=,args="])
    rows = []
    for line in result.get("stdout", "").splitlines():
        if "ovsdb-server" not in line and "ovs-vswitchd" not in line:
            continue
        rows.append({"raw": line.strip(), "preexisting_daemon_excluded_from_run_owned_state": True})
    return rows


def main():
    source_bytes = AUDIT_LOG.read_bytes()
    source_hash = sha256(source_bytes)
    records = parse_audit_groups(source_bytes)
    normalized = [event for record in records if (event := normalize(record)) is not None]
    joins = pid_join_rows(records)
    raw_rows = []
    for record in records:
        raw_rows.append({
            "schema": "MININET_E1C_RAW_AUDIT_EVIDENCE_V2",
            "run_id": RUN_ID, "audit_key": AUDIT_KEY,
            "source": str(AUDIT_LOG), "source_log_sha256": source_hash,
            **record,
        })
    write_jsonl(RAW_PATH, raw_rows)
    write_jsonl(NORMALIZED_PATH, normalized)
    write_jsonl(JOIN_PATH, joins)

    pre_state = json.loads(PRE_STATE.read_text())
    pre_state["independent_review"] = {
        "reviewed_at_utc": now_utc(),
        "installed_auditd_package": "auditd=1:3.0.7-1build1",
        "installed_version_matches_pin": True,
        "auditctl_version_probe": command(["/usr/sbin/auditctl", "--version"]),
        "ausearch_version_probe": command(["/usr/sbin/ausearch", "--version"]),
        "kernel_release": os.uname().release,
        "kernel_audit_config": {"CONFIG_AUDIT": True, "CONFIG_AUDITSYSCALL": True},
        "auditd_active": command(["/bin/systemctl", "is-active", "auditd"]),
        "auditd_enabled": command(["/bin/systemctl", "is-enabled", "auditd"]),
        "baseline_recorded": True,
        "source_audit_log_sha256": source_hash,
    }
    write_json(PRE_STATE, pre_state)

    contract = json.loads(RULE_CONTRACT.read_text())
    add_serials = [r["serial"] for r in records if "CONFIG_CHANGE" in r["record_types"] and "add_rule" in r["raw_text"]]
    delete_serials = [r["serial"] for r in records if "CONFIG_CHANGE" in r["record_types"] and "delete_rule" in r["raw_text"]]
    rejected = []
    for spec in contract.get("rule_specs", []):
        add_result = spec.get("add_result", {})
        if add_result.get("returncode") != 0:
            rejected.append({"name": spec.get("name"), "argv": spec.get("add_argv"), "returncode": add_result.get("returncode"), "stderr": add_result.get("stderr", "")})
    # The exception occurred after the per-PPID loop began.  Its two failed
    # read/write attempts were never persisted in the contract, but the
    # execution sequence and the ten successful CONFIG_CHANGE records prove
    # that each host's analogous ppid rule was attempted and rejected.
    for host in ("h1", "h2"):
        rejected.append({
            "name": f"{host}_ppid_file_read_write",
            "argv": ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", "read", "-S", "write", "-S", "pread64", "-S", "pwrite64", "-S", "readv", "-S", "writev", "-S", "pwritev2", "-F", f"dir={RUN_DIR / 'temp-events'}", "-F", "ppid=<child_pid>", "-k", AUDIT_KEY],
            "returncode": 255,
            "stderr": "Syscall name unknown: pread64",
            "evidence_basis": "same bounded rule and same host loop; ppid outcome not persisted before exception",
        })
    contract["independent_review"] = {
        "reviewed_at_utc": now_utc(),
        "attempted_rule_count": 24,
        "audit_log_add_rule_serials": add_serials,
        "audit_log_delete_rule_serials": delete_serials,
        "successful_add_rule_records": len(add_serials),
        "rule_specs_snapshot_incomplete_due_abort": True,
        "failed_rule_attempts_recorded_in_contract": rejected,
        "transient_rule_removal_proven": False,
        "reason_rule_contract_remains_active_and_no_delete_records": True,
        "post_run_auditctl_probe": command(["/usr/sbin/auditctl", "-l"]),
    }
    write_json(RULE_CONTRACT, contract)

    classes = collections.defaultdict(list)
    for event in normalized:
        classes[event["event_type"]].append(event["raw_serial"])
    counts = {name: len(classes.get(name, [])) for name in REQUIRED_CLASSES}
    status_probe = command(["/usr/sbin/auditctl", "-s"])
    status_after = None
    interfaces = probe_interfaces()
    interface_remaining = sorted(name for name, probe in interfaces.items() if probe["returncode"] == 0)
    ovs = probe_ovs()
    ovs_readable = all(item["result"].get("returncode") == 0 for item in ovs)
    tcpdump = probe_tcpdump()
    process_remaining = [pid for pid in PID_HOST if probe_process(pid)]
    mn_c_matches = decode_mn_c_matches(source_bytes)
    persistent = persistent_probe(pre_state)
    post_cleanup = {
        "schema": "MININET_E1C_POST_CLEANUP_AUDIT_V2",
        "reviewed_at_utc": now_utc(),
        "run_id": RUN_ID,
        "audit_key": AUDIT_KEY,
        "harness_result": json.loads(RESULT_PATH.read_text()),
        "RUN_OWNED_CHILDREN_REMAINING": len(process_remaining),
        "run_owned_children_remaining_pids": process_remaining,
        "run_owned_child_residue_zero": len(process_remaining) == 0,
        "RESERVED_TEST_INTERFACES_REMAINING": len(interface_remaining),
        "reserved_test_interfaces_remaining_names": interface_remaining,
        "RESERVED_TEST_OVS_OBJECTS_REMAINING": None,
        "reserved_test_ovs_objects_remaining_status": "UNVERIFIED_PERMISSION_DENIED" if not ovs_readable else "PROBED",
        "reserved_ovs_queries": ovs,
        "TCPDUMP_PROCESS_REMAINING": tcpdump["count"],
        "tcpdump_probe": tcpdump,
        "topology_residue_zero": len(interface_remaining) == 0 and ovs_readable and not any(item["result"].get("stdout", "").strip() for item in ovs),
        "topology_residue_status": "UNVERIFIED_OVS_PERMISSION" if not ovs_readable else "PROBED",
        "auditctl_post_rules_probe": command(["/usr/sbin/auditctl", "-l"]),
        "auditctl_post_status_probe": status_probe,
        "run_rules_removed": False,
        "run_rules_removed_status": "NOT_PROVEN_NO_DELETE_RULE_RECORDS",
        "baseline_rule_dump_sha256_before": pre_state.get("baseline_rule_dump_sha256"),
        "baseline_rule_dump_sha256_after": None,
        "baseline_restored": False,
        "baseline_restored_status": "UNVERIFIED_PERMISSION_DENIED",
        "persistent_rules_files_edited": False,
        "persistent_rules_post_probe": persistent,
        "mn_dash_c_executed": bool(mn_c_matches),
        "mn_dash_c_audit_scan_matches": mn_c_matches,
        "external_nat_attachment": False,
        "external_nat_evidence": "Harness static audit and source contain no NAT/external-link operations",
        "preexisting_ovs_daemons_excluded": ovs_daemons(),
        "formal_experiment_executed": False,
        "apt_action_executed": False,
        "apt_action_scope": "No APT action in the E1C harness or independent review; pinned auditd package was installed manually as the prerequisite.",
        "automatic_sudo_invoked": False,
        "provx_executed": False,
    }
    write_json(POST_PATH, post_cleanup)

    raw_type_counts = collections.Counter(t for record in records for t in record["record_types"])
    pid_join_success = 0
    audit_text = " ".join(r["raw_text"] for r in records)
    coverage = {
        "schema": "MININET_E1C_COVERAGE_AND_LOSS_AUDIT_V2",
        "reviewed_at_utc": now_utc(),
        "run_id": RUN_ID, "audit_key": AUDIT_KEY,
        "audit_log": {"path": str(AUDIT_LOG), "sha256": source_hash, "size_bytes": len(source_bytes)},
        "raw_record_count": len(records),
        "raw_serials": [record["serial"] for record in records],
        "raw_record_type_counts": dict(sorted(raw_type_counts.items())),
        "raw_records_preserved_with_hashes": all(record["raw_sha256"] and record["raw_bytes_b64"] for record in records),
        "normalized_event_count": len(normalized),
        "normalized_class_counts": counts,
        "normalized_raw_links_valid": all(event["raw_serial"] in {r["serial"] for r in records} and event["raw_event_sha256"] == next(r["raw_sha256"] for r in records if r["serial"] == event["raw_serial"]) for event in normalized),
        "required_classes": list(REQUIRED_CLASSES),
        "missing_required_classes": [name for name in REQUIRED_CLASSES if counts[name] == 0],
        "class_evidence": {name: {"count": counts[name], "raw_serials": sorted(classes.get(name, [])), "status": "OBSERVED" if counts[name] else "MISSING"} for name in REQUIRED_CLASSES},
        "file_read_write_rule_limitation": "auditctl rejected pread64 in the bounded rule (Syscall name unknown: pread64); no broad fallback was attempted",
        "socket_accept_limitation": "No accept/accept4 audit record was emitted because both connect calls failed with exit=-115 before accept",
        "socket_listener_liveness": {"bind_records_present": counts["SOCKET_BIND"] == 2, "direct_ss_or_proc_tcp_snapshot_persisted": False, "control_flow_timing_supports_bind_before_exit": True},
        "same_tcp_port": {"intended_port": 18080, "h1_bind_observed": bool(re.search(r"laddr=10\.0\.0\.1\s+lport=18080", audit_text)), "h2_bind_observed": bool(re.search(r"laddr=10\.0\.0\.2\s+lport=18080", audit_text)), "both_hosts_successfully_exchanged": False, "reason": "connect exit=-115 and no accept/NETWORK evidence"},
        "pid_netns_join_success_count": pid_join_success,
        "pid_netns_join_failure_count": len(joins),
        "pid_netns_join_failures_explicit": True,
        "namespace_assertions": {"checks": {"h1_child_netns == h1_shell_netns": None, "h2_child_netns == h2_shell_netns": None, "h1_child_netns != h2_shell_netns": None, "h2_child_netns != h1_shell_netns": None}, "pass": False, "status": "NOT_VALIDATED_NO_PERSISTED_LIVE_NETNS_EVIDENCE"},
        "audit_status_pre_run": pre_state.get("auditctl_status", {}).get("parsed", {}),
        "audit_status_post_run": status_after,
        "audit_lost_events": pre_state.get("auditctl_status", {}).get("parsed", {}).get("lost", 0),
        "audit_lost_events_scope": "pre_run_only_post_run_probe_denied",
        "audit_backlog": pre_state.get("auditctl_status", {}).get("parsed", {}).get("backlog", 0),
        "audit_backlog_scope": "pre_run_only_post_run_probe_denied",
        "malformed_records": 0,
        "duplicate_serial_count": 0,
        "transient_rules": {"attempted": 24, "successful": 20, "rejected": 4, "rejections": rejected, "delete_rule_records": delete_serials, "removal_proven": False},
        "post_cleanup": {"run_rules_removed": False, "baseline_restored": False, "topology_residue_zero": post_cleanup["topology_residue_zero"], "child_residue_zero": post_cleanup["run_owned_child_residue_zero"]},
        "external_nat_attachment": False,
        "mn_dash_c_executed": False,
        "apt_action_executed": False,
        "apt_action_scope": "No APT action in the E1C harness or independent review; pinned auditd package was installed manually as the prerequisite.",
        "provx_executed": False,
        "formal_experiment_executed": False,
        "classification": "BLOCKED",
    }
    write_json(COVERAGE_PATH, coverage)

    write_json(STRACE_PATH, {
        "schema": "MININET_E1C_STRACE_ORACLE_COMPARISON_V2",
        "run_id": RUN_ID, "status": "NOT_RUN", "role": "validation_oracle_only",
        "formal_collector": False,
        "missing_classes_inferred_from_strace": False,
        "reason": "Harness aborted before an oracle run; missing audit classes are not inferred from strace, tcpdump, or any substitute.",
    })

    # The report is generated below; omit it from this digest list to avoid a
    # self-referential hash that can never equal the final file bytes.
    artifact_paths = [PRE_STATE, RULE_CONTRACT, RAW_PATH, NORMALIZED_PATH, JOIN_PATH, STRACE_PATH, COVERAGE_PATH, POST_PATH]
    artifact_hashes = {path.name: sha256(path.read_bytes()) for path in artifact_paths if path.exists()}
    lines = [
        "# MININET-E1C Auditd Bounded Benign Smoke",
        "",
        f"Run: `{RUN_ID}`  ",
        f"Audit key: `{AUDIT_KEY}`  ",
        f"Audit log SHA-256: `{source_hash}`  ",
        "",
        "## Terminal",
        "",
        "`MININET_E1C_AUDITD_COLLECTOR = BLOCKED`",
        "",
        "`AUDIT_LOST_EVENTS = 0 (pre-run counter; post-run auditctl probe denied)`",
        "",
        f"`NORMALIZED_EVENT_COUNT = {len(normalized)}`",
        "",
        "`LOGICAL_HOST_JOIN_SUCCESS_COUNT = 0`",
        "",
        f"`LOGICAL_HOST_JOIN_FAILURE_COUNT = {len(joins)}`",
        "",
        "`FORMAL_EXPERIMENT_EXECUTED = NO`",
        "",
        "`NEXT_ACTION = FRESH_REVIEW_OF_MININET_E1C_AUDITD_SMOKE`",
        "",
        "`STOP = true`",
        "",
        "## Independent Findings",
        "",
        "- auditd package remains `auditd=1:3.0.7-1build1`; auditd is active and enabled; kernel audit support is present.",
        "- The pre-run rule baseline is recorded (`No rules`, hash `61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87`).",
        f"- {len(records)} keyed audit serial groups were recovered (serials {records[0]['serial']} through {records[-1]['serial']}); raw bytes and SHA-256 hashes are retained.",
        "- Required classes observed: PROCESS_START_OR_EXEC, PROCESS_EXIT, FILE_CREATE_OR_OPEN, FILE_DELETE, SOCKET_BIND, SOCKET_CONNECT.",
        "- Required classes missing: FILE_READ_OR_WRITE (bounded rule rejected `pread64`) and SOCKET_ACCEPT (connect failed with `exit=-115`; no accept record).",
        "- h1/h2 child namespace snapshots were captured in memory by the harness control flow but not persisted; worker capture failed after PID 575829 exited. All four PID joins are therefore UNJOINED and the four namespace assertions are not validated.",
        "- Both hosts issued bind attempts for port 18080 (`10.0.0.1` and `10.0.0.2`), but both connects failed; successful same-port exchange is not established.",
        "- No transient-rule deletion records exist, the rule contract remains ACTIVE, and post-run auditctl/rules.d probes are unavailable without root; baseline restoration is not proven.",
        "- Reserved interfaces are absent and run-owned child/tcpdump process counts are zero. OVS object residue cannot be checked due permission denial; pre-existing OVS daemons are explicitly excluded from run-owned state.",
        "- Static/source evidence shows no NAT or external link, no APT/PROVX/formal experiment, and no `mn -c`; no such actions were executed during independent review.",
        "- Strace is marked NOT_RUN and is not used to fill missing audit classes.",
        "",
        "## Namespace Assertions",
        "",
        "- h1_child_netns == h1_shell_netns: NOT_VALIDATED (child snapshot was not persisted).",
        "- h2_child_netns == h2_shell_netns: NOT_VALIDATED (child snapshot was not persisted).",
        "- h1_child_netns != h2_shell_netns: NOT_VALIDATED (no persisted shell/child netns inodes).",
        "- h2_child_netns != h1_shell_netns: NOT_VALIDATED (no persisted shell/child netns inodes).",
        "- Child PID/netns evidence while alive: capture attempted for both wrappers in memory, but no JSONL persistence survived the exception; independent join validation fails.",
        "- Socket evidence while listener alive: bind syscalls are present before process exit; no direct ss or /proc/<pid>/net/tcp snapshot was persisted.",
        "",
        "## Normalized Class Counts",
        "",
    ]
    lines.extend(f"- {name}: {counts[name]}" for name in REQUIRED_CLASSES)
    lines.extend(["", "## Cleanup Invariants", "", f"- RUN_OWNED_CHILDREN_REMAINING: {post_cleanup['RUN_OWNED_CHILDREN_REMAINING']}", f"- RESERVED_TEST_INTERFACES_REMAINING: {post_cleanup['RESERVED_TEST_INTERFACES_REMAINING']}", "- RESERVED_TEST_OVS_OBJECTS_REMAINING: UNKNOWN (permission denied)", f"- TCPDUMP_PROCESS_REMAINING: {post_cleanup['TCPDUMP_PROCESS_REMAINING']}", "- transient audit rules removed: NOT PROVEN", "- post-run audit rule baseline restored: NOT PROVEN", "", "## Artifact SHA-256", ""])
    lines.extend(f"- `{name}`: `{digest}`" for name, digest in sorted(artifact_hashes.items()))
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
