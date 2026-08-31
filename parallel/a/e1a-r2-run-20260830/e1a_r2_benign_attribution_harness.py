#!/usr/bin/env python3
"""MININET-E1A-R2 bounded benign logical-host attribution harness.

This file is intentionally a preparation artifact. It contains no attack
actions, external links, NAT, package installation, or broad cleanup.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch


RUN_DIR = Path(__file__).resolve().parent
RUN_ID = RUN_DIR.name
PCAP = RUN_DIR / "benign_fabric.pcap"
MANIFEST = RUN_DIR / "MININET_E1A_R2_RUN_MANIFEST.json"
CLEANUP = RUN_DIR / "MININET_E1A_R2_CLEANUP_AUDIT.json"


def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def proc_value(pid: int, item: str) -> str:
    try:
        return os.readlink(f"/proc/{pid}/ns/{item}")
    except Exception as exc:  # noqa: BLE001 - preserve evidence of a race
        return f"ERROR:{type(exc).__name__}:{exc}"


def cgroup_value(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        return f"ERROR:{type(exc).__name__}:{exc}"


def command_capture(argv: list[str], timeout: float = 3.0) -> dict[str, object]:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return {"argv": argv, "returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
    except Exception as exc:  # noqa: BLE001
        return {"argv": argv, "error": f"{type(exc).__name__}: {exc}"}


def child_observation(host_name: str, host, other_host, proc, port: int | None = None) -> dict[str, object]:
    child_pid = int(proc.pid)
    host_pid = int(host.pid)
    other_pid = int(other_host.pid)
    child_netns = proc_value(child_pid, "net")
    host_netns = proc_value(host_pid, "net")
    other_netns = proc_value(other_pid, "net")
    return {
        "host": host_name,
        "child_pid": child_pid,
        "child_netns": child_netns,
        "child_cgroup": cgroup_value(child_pid),
        "host_shell_pid": host_pid,
        "host_shell_netns": host_netns,
        "host_shell_cgroup": cgroup_value(host_pid),
        "other_host_shell_pid": other_pid,
        "other_host_shell_netns": other_netns,
        "child_netns_equals_owning_host": child_netns == host_netns,
        "child_netns_differs_from_other_host": child_netns != other_netns,
        "listener_port": port,
        "socket_evidence": host.cmd("ss -H -ltnp 2>&1"),
        "proc_tcp_evidence": host.cmd("cat /proc/net/tcp 2>&1"),
    }


def host_shell_observation(host_name: str, host) -> dict[str, object]:
    pid = int(host.pid)
    return {
        "host": host_name,
        "shell_pid": pid,
        "shell_netns": proc_value(pid, "net"),
        "shell_cgroup": cgroup_value(pid),
        "interfaces": [{"name": intf.name, "ip": intf.IP(), "mac": intf.MAC()} for intf in host.intfList()],
    }


def benign_child_script(marker: str) -> str:
    return (
        "import json, os, socket, time; "
        "path='/tmp/mininet-e1a-r2-' + " + repr(marker) + "; "
        "open(path,'w',encoding='utf-8').write(str(os.getpid())+'\\n'); "
        "open(path,encoding='utf-8').read(); "
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
        "s.bind(('0.0.0.0',0)); s.listen(4); "
        "print(json.dumps({'pid':os.getpid(),'port':s.getsockname()[1],'marker':" + repr(marker) + "},sort_keys=True),flush=True); "
        "time.sleep(5); s.close(); os.unlink(path)"
    )


def main() -> int:
    setLogLevel("warning")
    result: dict[str, object] = {
        "schema": "MININET_E1A_R2_RUN_MANIFEST_V1",
        "run_id": RUN_ID,
        "status": "not_started",
        "attack_actions_executed": 0,
        "formal_experiment_executed": False,
        "topology": {
            "switches": [{"name": "s1", "type": "OVSSwitch", "fail_mode": "standalone"}],
            "hosts": [
                {"name": "h1", "ip": "10.0.0.1/24", "mac": "00:00:00:00:01:01"},
                {"name": "h2", "ip": "10.0.0.2/24", "mac": "00:00:00:00:01:02"},
            ],
            "links": ["h1-s1", "h2-s1"],
            "nat_or_external_attachment": False,
        },
        "events": [],
    }
    net = None
    hosts = []
    children = []
    tcpdump = None
    cleanup: dict[str, object] = {"child_processes_terminated": [], "net_stop": "not_attempted", "broad_cleanup_invoked": False}
    try:
        net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=False, build=False)
        s1 = net.addSwitch("s1", failMode="standalone", protocols="OpenFlow10")
        h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:01:01")
        h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:01:02")
        hosts = [h1, h2]
        net.addLink(h1, s1)
        net.addLink(h2, s1)
        net.build()
        net.start()
        result["status"] = "topology_started"
        result["events"].append({"phase": "topology_started", "host_shells": [host_shell_observation("h1", h1), host_shell_observation("h2", h2)]})

        tcpdump = subprocess.Popen(
            ["tcpdump", "-i", "any", "-w", str(PCAP), "-U", "net", "10.0.0.0/24", "and", "(icmp or tcp)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        result["tcpdump"] = {"argv": ["tcpdump", "-i", "any", "-w", str(PCAP), "-U", "net", "10.0.0.0/24", "and", "(icmp or tcp)"], "pid": tcpdump.pid}

        p1 = h1.popen(["python3", "-c", benign_child_script("h1")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        p2 = h2.popen(["python3", "-c", benign_child_script("h2")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children = [p1, p2]
        line1 = p1.stdout.readline().strip()
        line2 = p2.stdout.readline().strip()
        info1 = json.loads(line1)
        info2 = json.loads(line2)
        result["events"].append({"phase": "children_alive", "observations": [child_observation("h1", h1, h2, p1, int(info1["port"])), child_observation("h2", h2, h1, p2, int(info2["port"]))]})
        result["events"].append({"phase": "file_events", "events": [{"host": "h1", "pid": int(info1["pid"]), "operation": "create_read_delete", "path": "/tmp/mininet-e1a-r2-h1"}, {"host": "h2", "pid": int(info2["pid"]), "operation": "create_read_delete", "path": "/tmp/mininet-e1a-r2-h2"}], "filesystem_isolation_claimed": False})

        # Benign cross-host traffic is bounded to the private test fabric.
        result["ping"] = net.pingAll()
        result["tcp_exchange"] = h2.cmd("python3 -c 'import socket; s=socket.create_connection((\"10.0.0.1\",%d),2); s.close()'" % int(info1["port"]))
        result["events"].append({"phase": "traffic_complete", "socket_ownership": [child_observation("h1", h1, h2, p1, int(info1["port"])), child_observation("h2", h2, h1, p2, int(info2["port"]))]})
        result["status"] = "completed"
    except Exception as exc:  # noqa: BLE001 - preserve privileged-run blocker
        result["status"] = "blocked_or_failed"
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        for proc in children:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=3)
                cleanup["child_processes_terminated"].append({"pid": proc.pid, "returncode": proc.returncode})
            except Exception as exc:  # noqa: BLE001
                cleanup["child_processes_terminated"].append({"pid": proc.pid, "error": f"{type(exc).__name__}: {exc}"})
        if tcpdump is not None:
            try:
                if tcpdump.poll() is None:
                    tcpdump.send_signal(signal.SIGINT)
                    tcpdump.wait(timeout=5)
                cleanup["tcpdump_returncode"] = tcpdump.returncode
            except Exception as exc:  # noqa: BLE001
                cleanup["tcpdump_error"] = f"{type(exc).__name__}: {exc}"
        for host, marker in zip(hosts, ("h1", "h2")):
            try:
                host.cmd("rm -f /tmp/mininet-e1a-r2-" + marker)
            except Exception as exc:  # noqa: BLE001
                cleanup.setdefault("temp_file_cleanup_errors", []).append(f"{marker}:{type(exc).__name__}: {exc}")
        if net is not None:
            try:
                net.stop()
                cleanup["net_stop"] = "completed"
            except Exception as exc:  # noqa: BLE001
                cleanup["net_stop"] = f"ERROR:{type(exc).__name__}:{exc}"
        result["pcap_sha256"] = hashlib.sha256(PCAP.read_bytes()).hexdigest() if PCAP.exists() else None
        result["cleanup"] = cleanup
        atomic_json(CLEANUP, cleanup)
        atomic_json(MANIFEST, result)
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    sys.exit(main())
