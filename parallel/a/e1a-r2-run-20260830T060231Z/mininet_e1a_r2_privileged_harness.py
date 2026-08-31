#!/usr/bin/python3
"""Single-command benign MININET-E1A-R2 attribution harness.

Default mode requires EUID 0 and performs one isolated two-host Mininet run.
Child and static-self-check modes are deliberately unprivileged so this file
can be tested before the human-authorized run.
"""

import argparse
import ast
import hashlib
import json
import os
import select
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


RUN_DIR = Path(__file__).resolve().parent
RUN_ID = RUN_DIR.name
HARNESS_PATH = Path(__file__).resolve()
RESULT_PATH = RUN_DIR / "MININET_E1A_R2_PRIVILEGED_RUN_RESULT.json"
ATTRIBUTION_PATH = RUN_DIR / "MININET_E1A_R2_LIVE_ATTRIBUTION.jsonl"
PCAP_PATH = RUN_DIR / "MININET_E1A_R2_BENIGN_TRAFFIC.pcap"
TCPDUMP_LOG_PATH = RUN_DIR / "MININET_E1A_R2_TCPDUMP.log"

TEST_NETWORK = "10.0.0.0/24"
TCP_PORT = 18080
TCPDUMP_FILTER = (
    "(icmp and net 10.0.0.0/24) or "
    "(tcp and net 10.0.0.0/24 and port 18080)"
)
MIN_CAPTURE_WINDOW_SECONDS = 5.0
CHILD_MAX_WINDOW_SECONDS = 12.0

HOSTS = {
    "h1": {"ip": "10.0.0.1/24", "address": "10.0.0.1", "mac": "00:00:00:00:01:01"},
    "h2": {"ip": "10.0.0.2/24", "address": "10.0.0.2", "mac": "00:00:00:00:01:02"},
}
RESERVED_INTERFACES = ("s1", "s1-eth1", "s1-eth2", "h1-eth0", "h2-eth0")
REQUIRED_NAMESPACE_CHECKS = (
    "h1_child_netns == h1_shell_netns",
    "h2_child_netns == h2_shell_netns",
    "h1_child_netns != h2_shell_netns",
    "h2_child_netns != h1_shell_netns",
)
REQUIRED_CLEANUP_CHECKS = (
    "RUN_OWNED_CHILDREN_REMAINING",
    "RESERVED_TEST_INTERFACES_REMAINING",
    "RESERVED_TEST_OVS_OBJECTS_REMAINING",
    "TCPDUMP_PROCESS_REMAINING",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def append_jsonl(path, value):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_command(argv, timeout=10):
    proc = subprocess.run(
        argv,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return {
        "argv": list(argv),
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def process_start_ticks(pid):
    stat_text = Path(f"/proc/{int(pid)}/stat").read_text()
    after_comm = stat_text[stat_text.rfind(")") + 2 :].split()
    return int(after_comm[19])


def capture_process_ref(pid, role):
    pid = int(pid)
    return {
        "pid": pid,
        "start_ticks": process_start_ticks(pid),
        "role": role,
        "comm": Path(f"/proc/{pid}/comm").read_text().strip(),
        "cmdline": Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip(),
    }


def process_ref_is_live(ref):
    if not ref:
        return False
    try:
        return process_start_ticks(ref["pid"]) == ref["start_ticks"]
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
        return False


def same_process_ref(left, right):
    return bool(
        left
        and right
        and left.get("pid") == right.get("pid")
        and left.get("start_ticks") == right.get("start_ticks")
    )


def proc_link(pid, namespace):
    return os.readlink(f"/proc/{int(pid)}/ns/{namespace}")


def proc_text(pid, relative_path):
    return Path(f"/proc/{int(pid)}/{relative_path}").read_text(errors="replace")


def socket_fd_inodes(pid):
    sockets = []
    for fd_path in Path(f"/proc/{int(pid)}/fd").iterdir():
        try:
            target = os.readlink(fd_path)
        except FileNotFoundError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            sockets.append({"fd": int(fd_path.name), "inode": int(target[8:-1])})
    return sorted(sockets, key=lambda item: item["fd"])


def parse_proc_net_tcp(text):
    records = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local_hex, remote_hex = parts[1], parts[2]
        local_address_hex, local_port_hex = local_hex.split(":")
        remote_address_hex, remote_port_hex = remote_hex.split(":")
        records.append(
            {
                "slot": parts[0].rstrip(":"),
                "local_address_hex": local_address_hex,
                "local_port": int(local_port_hex, 16),
                "remote_address_hex": remote_address_hex,
                "remote_port": int(remote_port_hex, 16),
                "state_hex": parts[3],
                "inode": int(parts[9]),
                "raw": line,
            }
        )
    return records


def capture_process_evidence(pid, role):
    tcp_text = proc_text(pid, "net/tcp")
    tcp_records = parse_proc_net_tcp(tcp_text)
    fd_sockets = socket_fd_inodes(pid)
    fd_inodes = {entry["inode"] for entry in fd_sockets}
    owned_listeners = [
        entry for entry in tcp_records if entry["state_hex"] == "0A" and entry["inode"] in fd_inodes
    ]
    return {
        "process": capture_process_ref(pid, role),
        "netns": proc_link(pid, "net"),
        "mntns": proc_link(pid, "mnt"),
        "pidns": proc_link(pid, "pid"),
        "cgroup": proc_text(pid, "cgroup"),
        "status": proc_text(pid, "status"),
        "proc_net_tcp_raw": tcp_text,
        "proc_net_tcp_records": tcp_records,
        "socket_fds": fd_sockets,
        "owned_listening_sockets": owned_listeners,
    }


def build_attribution_assertions(
    h1_shell_netns,
    h2_shell_netns,
    h1_child_netns,
    h2_child_netns,
):
    checks = {
        "h1_child_netns == h1_shell_netns": h1_child_netns == h1_shell_netns,
        "h2_child_netns == h2_shell_netns": h2_child_netns == h2_shell_netns,
        "h1_child_netns != h2_shell_netns": h1_child_netns != h2_shell_netns,
        "h2_child_netns != h1_shell_netns": h2_child_netns != h1_shell_netns,
    }
    return {"checks": checks, "pass": all(checks.values()) and tuple(checks) == REQUIRED_NAMESPACE_CHECKS}


def build_cleanup_assertions(
    run_owned_process_refs,
    live_process_refs,
    tcpdump_process_ref,
    reserved_interfaces_remaining,
    reserved_ovs_objects_remaining,
):
    remaining_children = [
        owned
        for owned in run_owned_process_refs
        if any(same_process_ref(owned, live) for live in live_process_refs)
    ]
    tcpdump_remaining = int(
        bool(tcpdump_process_ref)
        and any(same_process_ref(tcpdump_process_ref, live) for live in live_process_refs)
    )
    result = {
        "RUN_OWNED_CHILDREN_REMAINING": len(remaining_children),
        "RESERVED_TEST_INTERFACES_REMAINING": len(reserved_interfaces_remaining),
        "RESERVED_TEST_OVS_OBJECTS_REMAINING": len(reserved_ovs_objects_remaining),
        "TCPDUMP_PROCESS_REMAINING": tcpdump_remaining,
        "run_owned_children_remaining_detail": remaining_children,
        "reserved_test_interfaces_remaining_detail": list(reserved_interfaces_remaining),
        "reserved_test_ovs_objects_remaining_detail": list(reserved_ovs_objects_remaining),
    }
    result["pass"] = all(result[key] == 0 for key in REQUIRED_CLEANUP_CHECKS)
    return result


def validate_tcpdump_filter(capture_filter):
    expected = (
        "(icmp and net 10.0.0.0/24) or "
        "(tcp and net 10.0.0.0/24 and port 18080)"
    )
    result = {
        "filter": capture_filter,
        "network": TEST_NETWORK,
        "tcp_port": TCP_PORT,
        "icmp_bounded": "icmp and net 10.0.0.0/24" in capture_filter,
        "tcp_bounded": "tcp and net 10.0.0.0/24 and port 18080" in capture_filter,
        "exact_match": capture_filter == expected,
    }
    result["pass"] = result["icmp_bounded"] and result["tcp_bounded"] and result["exact_match"]
    return result


def child_mode(args):
    stop_requested = {"value": False}

    def request_stop(_signum, _frame):
        stop_requested["value"] = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    started = time.monotonic()
    operations = []
    network_events = []
    temp_path = Path(args.temp_file)
    listener = None
    try:
        temp_path.write_text(f"{args.logical_host_id} pid={os.getpid()}\n")
        operations.append("create")
        file_content = temp_path.read_text()
        operations.append("read")

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.listen_address, args.listen_port))
        listener.listen(4)
        listener.settimeout(0.25)
        address, port = listener.getsockname()
        print(
            json.dumps(
                {
                    "event": "READY",
                    "logical_host_id": args.logical_host_id,
                    "pid": os.getpid(),
                    "listen_address": address,
                    "listen_port": port,
                    "temp_file": str(temp_path),
                    "file_content": file_content,
                    "file_operations": list(operations),
                    "ready_at_utc": utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )

        deadline = started + args.window_seconds
        while time.monotonic() < deadline and not stop_requested["value"]:
            try:
                connection, peer = listener.accept()
            except socket.timeout:
                continue
            with connection:
                payload = connection.recv(4096)
                connection.sendall(("ACK:" + args.logical_host_id).encode())
                network_events.append(
                    {
                        "peer": [peer[0], peer[1]],
                        "payload_utf8": payload.decode(errors="replace"),
                        "accepted_at_utc": utc_now(),
                    }
                )
    finally:
        if listener is not None:
            listener.close()
        if temp_path.exists():
            temp_path.unlink()
            operations.append("delete")
        print(
            json.dumps(
                {
                    "event": "FINISHED",
                    "logical_host_id": args.logical_host_id,
                    "pid": os.getpid(),
                    "file_operations": operations,
                    "network_events": network_events,
                    "elapsed_seconds": round(time.monotonic() - started, 6),
                    "finished_at_utc": utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
    return 0


def command_literals_from_ast(tree):
    command_method_names = {
        "Popen",
        "run",
        "check_output",
        "check_call",
        "run_command",
        "popen",
        "pexec",
        "cmd",
    }
    literals = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = None
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name not in command_method_names or not node.args:
            continue
        value = node.args[0]
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            literals.append(value.value)
        elif isinstance(value, (ast.List, ast.Tuple)):
            items = [item.value for item in value.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)]
            if items:
                literals.append(" ".join(items))
    return literals


def static_self_check():
    source = HARNESS_PATH.read_text()
    tree = ast.parse(source)
    call_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    commands = command_literals_from_ast(tree)
    command_heads = {Path(command.split()[0]).name for command in commands if command.split()}
    forbidden_package_commands = {"apt", "apt-get", "pip", "pip3", "conda"}
    forbidden_experiment_commands = {"provx", "benchmark-runner"}

    result = {
        "checked_at_utc": utc_now(),
        "harness_path": str(HARNESS_PATH),
        "harness_sha256": sha256_file(HARNESS_PATH),
        "python_ast_parse": True,
        "no_nat_or_external_links": not bool(
            {"addNAT", "addIntf", "attach"} & call_attributes or {"Intf", "NAT"} & called_names
        ),
        "no_apt_commands": not bool(command_heads & forbidden_package_commands),
        "no_provx_or_formal_benchmark_execution": not bool(command_heads & forbidden_experiment_commands),
        "no_mn_c": not any(command.split()[:2] == ["mn", "-c"] for command in commands),
        "no_automatic_sudo": "sudo" not in command_heads,
        "bounded_tcpdump_filter": validate_tcpdump_filter(TCPDUMP_FILTER),
        "required_namespace_assertions": len(REQUIRED_NAMESPACE_CHECKS),
        "required_namespace_assertion_names": list(REQUIRED_NAMESPACE_CHECKS),
        "required_cleanup_zero_assertions": len(REQUIRED_CLEANUP_CHECKS),
        "required_cleanup_zero_assertion_names": list(REQUIRED_CLEANUP_CHECKS),
        "command_literals_inspected": commands,
        "command_executables_inspected": sorted(command_heads),
    }
    result["pass"] = all(
        (
            result["python_ast_parse"],
            result["no_nat_or_external_links"],
            result["no_apt_commands"],
            result["no_provx_or_formal_benchmark_execution"],
            result["no_mn_c"],
            result["no_automatic_sudo"],
            result["bounded_tcpdump_filter"]["pass"],
            result["required_namespace_assertions"] == 4,
            result["required_cleanup_zero_assertions"] == 4,
        )
    )
    return result


def existing_reserved_interfaces():
    remaining = []
    for name in RESERVED_INTERFACES:
        if run_command(["/usr/sbin/ip", "link", "show", "dev", name])["returncode"] == 0:
            remaining.append(name)
    return remaining


def reserved_ovs_find_queries():
    queries = []
    for table in ("Interface", "Port"):
        for name in RESERVED_INTERFACES:
            queries.append(
                {
                    "object_label": f"{table.lower()}:{name}",
                    "argv": [
                        "/usr/bin/ovs-vsctl",
                        "--timeout=2",
                        "--data=bare",
                        "--no-heading",
                        "--columns=name",
                        "find",
                        table,
                        f"name={name}",
                    ],
                }
            )
    return queries


def existing_reserved_ovs_objects():
    objects = []
    bridge = run_command(["/usr/bin/ovs-vsctl", "--timeout=2", "br-exists", "s1"])
    if bridge["returncode"] == 0:
        objects.append("bridge:s1")
    for query in reserved_ovs_find_queries():
        observed = run_command(query["argv"])
        if observed["returncode"] == 0 and observed["stdout"].strip():
            objects.append(query["object_label"])
    return sorted(set(objects))


def capture_host_shell(host):
    return {
        "logical_host_id": host.name,
        "shell": capture_process_evidence(host.pid, f"{host.name}-shell"),
        "interfaces": [
            {"name": intf.name, "ip": intf.IP(), "mac": intf.MAC()} for intf in host.intfList()
        ],
    }


def wait_for_child_ready(children, timeout_seconds=6.0):
    pending = dict(children)
    ready = {}
    deadline = time.monotonic() + timeout_seconds
    while pending and time.monotonic() < deadline:
        streams = [entry["process"].stdout for entry in pending.values()]
        readable, _, _ = select.select(streams, [], [], max(0.0, deadline - time.monotonic()))
        if not readable:
            break
        for stream in readable:
            owner = next(name for name, entry in pending.items() if entry["process"].stdout is stream)
            line = stream.readline()
            if not line:
                raise RuntimeError(f"{owner} child exited before READY")
            message = json.loads(line)
            if message.get("event") != "READY":
                raise RuntimeError(f"{owner} emitted unexpected first event: {message}")
            ready[owner] = message
            del pending[owner]
    if pending:
        raise TimeoutError(f"children did not become ready: {sorted(pending)}")
    return ready


def stop_process(proc, graceful_signal=signal.SIGTERM, timeout=5.0):
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(graceful_signal)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=timeout)


def start_tcpdump():
    log_stream = TCPDUMP_LOG_PATH.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            "/usr/bin/tcpdump",
            "-i",
            "any",
            "-nn",
            "-U",
            "-s",
            "0",
            "-w",
            str(PCAP_PATH),
            TCPDUMP_FILTER,
        ],
        stdout=subprocess.DEVNULL,
        stderr=log_stream,
        text=True,
    )
    time.sleep(1.0)
    if proc.poll() is not None:
        log_stream.flush()
        raise RuntimeError(f"tcpdump exited during startup with status {proc.returncode}")
    return proc, log_stream, capture_process_ref(proc.pid, "tcpdump")


def start_benign_child(host):
    spec = HOSTS[host.name]
    temp_path = Path("/tmp") / f"mininet-e1a-r2-{RUN_ID}-{host.name}.txt"
    proc = host.popen(
        [
            "/usr/bin/python3",
            str(HARNESS_PATH),
            "--child",
            "--logical-host-id",
            host.name,
            "--listen-address",
            spec["address"],
            "--listen-port",
            str(TCP_PORT),
            "--temp-file",
            str(temp_path),
            "--window-seconds",
            str(CHILD_MAX_WINDOW_SECONDS),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        "process": proc,
        "process_ref": capture_process_ref(proc.pid, f"{host.name}-benign-server-child"),
        "temp_path": temp_path,
        "started_monotonic_ns": time.monotonic_ns(),
    }


def capture_socket_evidence(host, child_entry, ready):
    proc = child_entry["process"]
    identity = capture_process_evidence(proc.pid, f"{host.name}-benign-server-child")
    ss_result = host.pexec("ss", "-H", "-ltnp", "sport", "=", f":{TCP_PORT}")
    ss_evidence = {"stdout": ss_result[0], "stderr": ss_result[1], "returncode": ss_result[2]}
    port_listeners = [
        item for item in identity["owned_listening_sockets"] if item["local_port"] == TCP_PORT
    ]
    ownership_checks = {
        "child_still_alive": proc.poll() is None,
        "ready_pid_matches_exact_child_pid": ready["pid"] == proc.pid,
        "ready_address_matches_logical_host": ready["listen_address"] == HOSTS[host.name]["address"],
        "ready_port_matches_reserved_test_port": ready["listen_port"] == TCP_PORT,
        "proc_child_net_tcp_has_owned_listener": bool(port_listeners),
        "ss_reports_reserved_test_port": str(TCP_PORT) in ss_result[0],
        "ss_reports_exact_child_pid": f"pid={proc.pid}" in ss_result[0],
    }
    return {
        "logical_host_id": host.name,
        "captured_at_utc": utc_now(),
        "child": identity,
        "ready_event": ready,
        "ss_socket_ownership": ss_evidence,
        "port_owned_listeners": port_listeners,
        "ownership_checks": ownership_checks,
        "pass": all(ownership_checks.values()),
    }


def start_tcp_client(host, destination, payload):
    client_code = (
        "import socket,sys; "
        "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),3); "
        "s.sendall(sys.argv[3].encode()); "
        "print(s.recv(4096).decode(),flush=True); s.close()"
    )
    proc = host.popen(
        [
            "/usr/bin/python3",
            "-c",
            client_code,
            destination,
            str(TCP_PORT),
            payload,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc, capture_process_ref(proc.pid, f"{host.name}-benign-tcp-client")


def capture_environment_snapshot():
    interfaces = run_command(["/usr/sbin/ip", "-j", "address", "show"])
    netns = run_command(["/usr/sbin/ip", "netns", "list"])
    bridges = run_command(["/usr/bin/ovs-vsctl", "--timeout=2", "list-br"])
    ovs_daemons = []
    for daemon in ("ovsdb-server", "ovs-vswitchd"):
        pgrep = run_command(["/usr/bin/pgrep", "-x", daemon])
        for value in pgrep["stdout"].split():
            try:
                ovs_daemons.append(capture_process_ref(int(value), f"pre-existing-{daemon}"))
            except (FileNotFoundError, ProcessLookupError):
                continue
    return {
        "captured_at_utc": utc_now(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "interfaces": json.loads(interfaces["stdout"]) if interfaces["returncode"] == 0 else interfaces,
        "named_netns": netns,
        "ovs_bridges": bridges,
        "pre_existing_ovs_daemons_excluded_from_run_owned_state": ovs_daemons,
    }


def privileged_run():
    result = {
        "run_id": RUN_ID,
        "started_at_utc": utc_now(),
        "status": "INITIALIZING",
        "topology_contract": {
            "switch": "s1",
            "hosts": HOSTS,
            "controller": None,
            "nat": False,
            "external_links": False,
        },
        "attack_actions_executed": 0,
        "provx_executed": False,
        "formal_experiment_executed": False,
        "broad_cleanup_executed": False,
    }
    if os.geteuid() != 0:
        result["status"] = "BLOCKED_ROOT_REQUIRED"
        result["error"] = "EUID 0 is required for the human-authorized Mininet run"
        write_json(RESULT_PATH, result)
        return 2

    result["pre_state"] = capture_environment_snapshot()
    stale_interfaces = existing_reserved_interfaces()
    stale_ovs = existing_reserved_ovs_objects()
    result["reserved_state_preflight"] = {
        "interfaces": stale_interfaces,
        "ovs_objects": stale_ovs,
        "pass": not stale_interfaces and not stale_ovs,
    }
    if stale_interfaces or stale_ovs:
        result["status"] = "BLOCKED_STALE_RESERVED_STATE"
        result["error"] = "Reserved topology objects already exist; no cleanup was attempted"
        write_json(RESULT_PATH, result)
        return 3

    static_audit = static_self_check()
    result["static_self_check"] = static_audit
    if not static_audit["pass"]:
        result["status"] = "BLOCKED_STATIC_SELF_CHECK"
        write_json(RESULT_PATH, result)
        return 3

    ATTRIBUTION_PATH.write_text("")
    if PCAP_PATH.exists():
        PCAP_PATH.unlink()

    net = None
    net_stopped = False
    tcpdump_proc = None
    tcpdump_ref = None
    tcpdump_log = None
    children = {}
    run_owned_refs = []
    child_outputs = {}
    error = None
    attribution = None
    socket_evidence = {}
    try:
        from mininet.log import setLogLevel
        from mininet.net import Mininet
        from mininet.node import OVSSwitch

        setLogLevel("warning")
        net = Mininet(
            controller=None,
            switch=lambda name, **params: OVSSwitch(
                name,
                failMode="standalone",
                protocols="OpenFlow10",
                **params,
            ),
            autoSetMacs=False,
            build=False,
        )
        s1 = net.addSwitch("s1")
        run_owned_refs.append(capture_process_ref(s1.pid, "s1-mininet-shell"))
        h1 = net.addHost("h1", ip=HOSTS["h1"]["ip"], mac=HOSTS["h1"]["mac"])
        run_owned_refs.append(capture_process_ref(h1.pid, "h1-mininet-shell"))
        h2 = net.addHost("h2", ip=HOSTS["h2"]["ip"], mac=HOSTS["h2"]["mac"])
        run_owned_refs.append(capture_process_ref(h2.pid, "h2-mininet-shell"))
        net.addLink(h1, s1)
        net.addLink(h2, s1)
        net.build()
        net.start()
        result["status"] = "TOPOLOGY_STARTED"
        result["host_shell_evidence"] = {
            "h1": capture_host_shell(h1),
            "h2": capture_host_shell(h2),
        }

        tcpdump_proc, tcpdump_log, tcpdump_ref = start_tcpdump()
        result["tcpdump"] = {
            "process": tcpdump_ref,
            "filter": TCPDUMP_FILTER,
            "path": str(PCAP_PATH),
            "started_before_benign_traffic": True,
        }

        children["h1"] = start_benign_child(h1)
        children["h2"] = start_benign_child(h2)
        run_owned_refs.extend([children["h1"]["process_ref"], children["h2"]["process_ref"]])
        ready = wait_for_child_ready(children)
        result["simultaneous_child_start_delta_ns"] = abs(
            children["h1"]["started_monotonic_ns"] - children["h2"]["started_monotonic_ns"]
        )

        socket_evidence["h1"] = capture_socket_evidence(h1, children["h1"], ready["h1"])
        socket_evidence["h2"] = capture_socket_evidence(h2, children["h2"], ready["h2"])
        attribution = build_attribution_assertions(
            h1_shell_netns=result["host_shell_evidence"]["h1"]["shell"]["netns"],
            h2_shell_netns=result["host_shell_evidence"]["h2"]["shell"]["netns"],
            h1_child_netns=socket_evidence["h1"]["child"]["netns"],
            h2_child_netns=socket_evidence["h2"]["child"]["netns"],
        )
        result["attribution_assertions"] = attribution
        result["socket_evidence"] = socket_evidence
        for host_name in ("h1", "h2"):
            temp_path = children[host_name]["temp_path"]
            file_evidence = {
                "logical_host_id": host_name,
                "exact_child_pid": children[host_name]["process"].pid,
                "path": str(temp_path),
                "exists_while_child_alive": temp_path.exists(),
                "content_while_child_alive": temp_path.read_text() if temp_path.exists() else None,
                "filesystem_isolation_claimed": False,
            }
            append_jsonl(
                ATTRIBUTION_PATH,
                {
                    "run_id": RUN_ID,
                    "captured_at_utc": utc_now(),
                    "logical_host_id": host_name,
                    "host_shell": result["host_shell_evidence"][host_name],
                    "child_socket_process": socket_evidence[host_name],
                    "file_event_attribution": file_evidence,
                },
            )
            result.setdefault("file_event_evidence", {})[host_name] = file_evidence

        if not attribution["pass"]:
            raise RuntimeError("mandatory process/netns attribution assertions failed")
        if not all(item["pass"] for item in socket_evidence.values()):
            raise RuntimeError("live socket ownership evidence was incomplete")

        result["ping"] = {
            "h1_to_h2": dict(
                zip(
                    ("stdout", "stderr", "returncode"),
                    h1.pexec("ping", "-c", "2", "-W", "1", HOSTS["h2"]["address"]),
                )
            ),
            "h2_to_h1": dict(
                zip(
                    ("stdout", "stderr", "returncode"),
                    h2.pexec("ping", "-c", "2", "-W", "1", HOSTS["h1"]["address"]),
                )
            ),
        }

        clients = []
        for owner, host, destination in (
            ("h1", h1, HOSTS["h2"]["address"]),
            ("h2", h2, HOSTS["h1"]["address"]),
        ):
            client, client_ref = start_tcp_client(host, destination, f"benign-{owner}-to-peer")
            clients.append((owner, client, client_ref))
            run_owned_refs.append(client_ref)
        result["tcp_exchange"] = {}
        for owner, client, _client_ref in clients:
            stdout, stderr = client.communicate(timeout=6)
            result["tcp_exchange"][owner] = {
                "pid": client.pid,
                "returncode": client.returncode,
                "stdout": stdout,
                "stderr": stderr,
            }

        earliest_start = min(entry["started_monotonic_ns"] for entry in children.values()) / 1_000_000_000
        remaining_window = MIN_CAPTURE_WINDOW_SECONDS - (time.monotonic() - earliest_start)
        if remaining_window > 0:
            time.sleep(remaining_window)
        for host_name, entry in children.items():
            stop_process(entry["process"], signal.SIGTERM, timeout=4)
            stdout_tail, stderr = entry["process"].communicate(timeout=2)
            finished = json.loads(stdout_tail.strip().splitlines()[-1]) if stdout_tail.strip() else None
            child_outputs[host_name] = {
                "returncode": entry["process"].returncode,
                "stdout_after_ready": stdout_tail,
                "stderr": stderr,
                "finished_event": finished,
                "temp_file_exists_after_child_exit": entry["temp_path"].exists(),
            }

        stop_process(tcpdump_proc, signal.SIGINT, timeout=5)
        tcpdump_log.flush()
        result["tcpdump"].update(
            {
                "returncode": tcpdump_proc.returncode,
                "log": TCPDUMP_LOG_PATH.read_text(errors="replace"),
                "pcap_exists": PCAP_PATH.exists(),
                "pcap_size_bytes": PCAP_PATH.stat().st_size if PCAP_PATH.exists() else 0,
                "pcap_sha256": sha256_file(PCAP_PATH) if PCAP_PATH.exists() else None,
                "stopped_before_topology_teardown": True,
            }
        )
        result["child_outputs"] = child_outputs
        net.stop()
        net_stopped = True
        result["status"] = "EVIDENCE_CAPTURED"
    except BaseException as exc:  # preserve evidence and always enter run-scoped cleanup
        error = {"type": type(exc).__name__, "message": str(exc)}
        result["error"] = error
        result["status"] = "FAILED_DURING_PRIVILEGED_RUN"
    finally:
        if tcpdump_proc is not None:
            try:
                stop_process(tcpdump_proc, signal.SIGINT, timeout=3)
            except BaseException as exc:
                result.setdefault("cleanup_errors", []).append(
                    {"component": "tcpdump", "type": type(exc).__name__, "message": str(exc)}
                )
        if tcpdump_log is not None:
            tcpdump_log.close()
        for host_name, entry in children.items():
            try:
                stop_process(entry["process"], signal.SIGTERM, timeout=3)
            except BaseException as exc:
                result.setdefault("cleanup_errors", []).append(
                    {"component": host_name, "type": type(exc).__name__, "message": str(exc)}
                )
        if net is not None and not net_stopped:
            try:
                net.stop()
                net_stopped = True
            except BaseException as exc:
                result.setdefault("cleanup_errors", []).append(
                    {"component": "net.stop", "type": type(exc).__name__, "message": str(exc)}
                )

        time.sleep(0.5)
        live_refs = []
        for ref in run_owned_refs + ([tcpdump_ref] if tcpdump_ref else []):
            if process_ref_is_live(ref):
                live_refs.append(capture_process_ref(ref["pid"], ref["role"]))
        remaining_interfaces = existing_reserved_interfaces()
        remaining_ovs = existing_reserved_ovs_objects()
        cleanup = build_cleanup_assertions(
            run_owned_process_refs=run_owned_refs,
            live_process_refs=live_refs,
            tcpdump_process_ref=tcpdump_ref,
            reserved_interfaces_remaining=remaining_interfaces,
            reserved_ovs_objects_remaining=remaining_ovs,
        )
        cleanup.update(
            {
                "net_stop_called": net_stopped,
                "broad_cleanup_executed": False,
                "pre_existing_ovs_daemons_were_run_owned": False,
                "captured_at_utc": utc_now(),
            }
        )
        result["post_cleanup_assertions"] = cleanup
        result["post_state"] = capture_environment_snapshot()
        result["finished_at_utc"] = utc_now()

        evidence_pass = bool(
            not error
            and attribution
            and attribution["pass"]
            and socket_evidence
            and all(item["pass"] for item in socket_evidence.values())
            and result.get("tcpdump", {}).get("pcap_sha256")
            and result.get("ping", {}).get("h1_to_h2", {}).get("returncode") == 0
            and result.get("ping", {}).get("h2_to_h1", {}).get("returncode") == 0
            and cleanup["pass"]
        )
        result["evidence_contract_pass"] = evidence_pass
        result["status"] = "COMPLETED_PASS" if evidence_pass else result["status"]
        write_json(RESULT_PATH, result)
    return 0 if result.get("evidence_contract_pass") else 4


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static-self-check", action="store_true")
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--logical-host-id")
    parser.add_argument("--listen-address")
    parser.add_argument("--listen-port", type=int)
    parser.add_argument("--temp-file")
    parser.add_argument("--window-seconds", type=float)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.static_self_check:
        result = static_self_check()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["pass"] else 1
    if args.child:
        required = (
            args.logical_host_id,
            args.listen_address,
            args.listen_port is not None,
            args.temp_file,
            args.window_seconds is not None,
        )
        if not all(required):
            raise SystemExit("child mode requires logical host, address, port, temp file, and window")
        return child_mode(args)
    return privileged_run()


if __name__ == "__main__":
    sys.exit(main())
