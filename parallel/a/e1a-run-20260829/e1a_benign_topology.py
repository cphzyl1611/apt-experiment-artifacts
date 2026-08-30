#!/usr/bin/python3
"""Bounded, benign Mininet E1A attribution smoke test.

The harness deliberately avoids a controller, NAT, external links, attack
actions, and broad cleanup. It records host shell/process namespace metadata,
attempts a same-subnet ping, creates a local temporary file per host, and
creates a loopback TCP socket per host. It is expected to require root for
network namespace/link/OVS operations.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch


OUT = Path(__file__).resolve().parent


def ns_value(pid, name):
    try:
        return os.readlink(f"/proc/{pid}/ns/{name}")
    except Exception as exc:  # noqa: BLE001 - preserve observable failure
        return f"ERROR:{type(exc).__name__}:{exc}"


def cgroup_value(pid):
    try:
        return Path(f"/proc/{pid}/cgroup").read_text()
    except Exception as exc:  # noqa: BLE001
        return f"ERROR:{type(exc).__name__}:{exc}"


def host_identity(host):
    pid = getattr(host, "pid", None)
    interfaces = []
    try:
        for intf in host.intfList():
            interfaces.append({
                "name": intf.name,
                "ip": intf.IP(),
                "mac": intf.MAC(),
            })
    except Exception as exc:  # noqa: BLE001
        interfaces = [f"ERROR:{type(exc).__name__}:{exc}"]
    if not pid:
        return {"host": host.name, "shell_pid": None, "interfaces": interfaces}
    return {
        "host": host.name,
        "shell_pid": pid,
        "netns": ns_value(pid, "net"),
        "mntns": ns_value(pid, "mnt"),
        "pidns": ns_value(pid, "pid"),
        "utsns": ns_value(pid, "uts"),
        "ipcns": ns_value(pid, "ipc"),
        "cgroup": cgroup_value(pid),
        "interfaces": interfaces,
    }


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run_benign(host, marker):
    # One shell descendant creates/reads/removes a host-labelled temp file,
    # then opens a loopback TCP listener long enough for socket inspection.
    script = (
        "set -eu; "
        "f=/tmp/mininet-e1a-%s; "
        "printf '%s\\n' '$$' > \"$f\"; "
        "cat \"$f\"; "
        "python3 -c 'import socket,time; s=socket.socket(); s.bind((\"127.0.0.1\",0)); s.listen(1); print(s.getsockname()[1], flush=True); time.sleep(1); s.close()'; "
        "rm -f \"$f\""
    ) % (marker, marker)
    proc = host.popen(["sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc


def main():
    setLogLevel("warning")
    result = {
        "run_id": "e1a-run-20260829",
        "topology": {
            "switches": ["s1"],
            "hosts": ["h1", "h2"],
            "ips": {"h1": "10.0.0.1/24", "h2": "10.0.0.2/24"},
            "macs": {"h1": "00:00:00:00:01:01", "h2": "00:00:00:00:01:02"},
            "controller": None,
            "nat_or_external_attachment": False,
            "actions": ["echo", "temp-file create/read/delete", "ping", "loopback TCP socket"],
        },
        "status": "not_started",
        "events": [],
    }
    net = None
    try:
        net = Mininet(
            controller=None,
            switch=lambda name, **params: OVSSwitch(
                name, failMode="standalone", protocols="OpenFlow10", **params
            ),
            autoSetMacs=False,
            build=False,
        )
        s1 = net.addSwitch("s1")
        h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:01:01")
        h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:01:02")
        net.addLink(h1, s1)
        net.addLink(h2, s1)
        net.build()
        net.start()
        result["status"] = "topology_started"
        result["events"].append({"phase": "during", "identities": [host_identity(h1), host_identity(h2)]})

        p1 = run_benign(h1, "h1")
        p2 = run_benign(h2, "h2")
        result["events"].append({"phase": "simultaneous", "identities": [host_identity(h1), host_identity(h2)]})
        out1, err1 = p1.communicate(timeout=10)
        out2, err2 = p2.communicate(timeout=10)
        result["benign_commands"] = {
            "h1": {"returncode": p1.returncode, "stdout": out1, "stderr": err1},
            "h2": {"returncode": p2.returncode, "stdout": out2, "stderr": err2},
        }
        result["ping_loss_percent"] = net.pingAll()
        result["events"].append({"phase": "after", "identities": [host_identity(h1), host_identity(h2)]})
        result["status"] = "completed"
    except Exception as exc:  # noqa: BLE001 - preserve root/namespace failure
        result["status"] = "blocked_or_failed"
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if net is not None:
            try:
                net.stop()
                result["cleanup"] = "net.stop completed"
            except Exception as exc:  # noqa: BLE001
                result["cleanup"] = {"type": type(exc).__name__, "message": str(exc)}
        write_json(OUT / "topology_harness_result.json", result)
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    sys.exit(main())
