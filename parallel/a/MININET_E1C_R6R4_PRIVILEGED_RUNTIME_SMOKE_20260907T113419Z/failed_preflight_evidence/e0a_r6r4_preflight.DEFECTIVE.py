#!/usr/bin/env python3
"""Pre-runtime prerequisite gate for MININET_E1C_R6R4_PRIVILEGED_RUNTIME_SMOKE.

Derived byte-for-byte in logic from the prior blocked attempt's preflight
(/tmp/e0a_preflight_current.py, schema MININET_E1C_R6R4_PRE_RUNTIME_PREREQUISITES_V1);
only the output path and a small set of explicitly-flagged additional bounded
read-only checks differ.  Root checks use `sudo -n` against a credential the
human operator cached interactively; no password is read, stored, or logged.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PACKAGE = Path(sys.argv[1])
RUN_DIR = Path("/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z")
EXPECTED_EMPTY_RULE_HASH = "61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87"
EXPECTED_AUDITD_VERSION = "auditd=1:3.0.7-1build1"
EXPECTED_HARNESS_SHA256 = "8b0db6eab7c2a9d720a9a9d0624ebbe4ba93859f2151fc338f0e0303321e78cc"
RESERVED = ("s1", "s1-eth1", "s1-eth2", "h1-eth0", "h2-eth0")
TCP_PORT = 18080


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(argv: list[str], root: bool = False, timeout: float = 15.0) -> dict:
    actual = (["sudo", "-n"] if root else []) + argv
    try:
        proc = subprocess.run(actual, capture_output=True, timeout=timeout, check=False)
        stdout = proc.stdout or b""
        stderr = proc.stderr or b""
        return {
            "argv": actual, "privileged": root, "returncode": proc.returncode,
            "stdout": stdout.decode(errors="replace"), "stderr": stderr.decode(errors="replace"),
            "stdout_sha256": sha256(stdout), "stdout_bytes": len(stdout),
            "stderr_sha256": sha256(stderr), "stderr_bytes": len(stderr),
        }
    except Exception as exc:
        return {
            "argv": actual, "privileged": root, "returncode": None, "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "stdout_sha256": sha256(b""), "stdout_bytes": 0,
            "stderr_sha256": None, "stderr_bytes": None,
        }


def command_available(path: str) -> bool:
    return Path(path).is_file() and os.access(path, os.X_OK)


started = now()
commands: dict = {}
for name, path in {
    "mininet": "/usr/bin/mn",
    "ovs_vsctl": "/usr/bin/ovs-vsctl",
    "tcpdump": "/usr/bin/tcpdump",
    "auditctl": "/usr/sbin/auditctl",
    "ausearch": "/usr/sbin/ausearch",
    "python3": "/usr/bin/python3",
}.items():
    commands[name] = {"path": path, "available": command_available(path)}

commands["mininet_import"] = run([
    "/usr/bin/python3", "-c",
    "from mininet.net import Mininet; from mininet.node import OVSSwitch; print('MININET_IMPORT_OK')",
])
commands["sudo_uid"] = run(["/usr/bin/id", "-u"], root=True)
commands["audit_rules"] = run(["/usr/sbin/auditctl", "-l"], root=True)
commands["audit_status"] = run(["/usr/sbin/auditctl", "-s"], root=True)
commands["auditd_version"] = run([
    "/usr/bin/dpkg-query", "-W", "-f=${Package}=${Version}\\n", "auditd",
], root=True)
commands["reserved_interfaces"] = {
    name: run(["/usr/sbin/ip", "link", "show", "dev", name], root=True)
    for name in RESERVED
}
commands["ovs_bridge"] = run([
    "/usr/bin/ovs-vsctl", "--timeout=2", "br-exists", "s1",
], root=True)
commands["tcpdump_processes"] = run(["/bin/ps", "-eo", "pid=,comm=,args="], root=True)
# --- additional bounded read-only checks (not present in the prior preflight) ---
commands["ovs_bridge_list"] = run(["/usr/bin/ovs-vsctl", "--timeout=2", "list-br"], root=True)
commands["listening_port"] = run(
    ["/usr/bin/ss", "-Hltnp", f"sport = :{TCP_PORT}"], root=True)
commands["netns_list"] = run(["/usr/sbin/ip", "netns", "list"], root=True)
commands["audit_key_residue"] = run(
    ["/usr/sbin/ausearch", "-k", "e1c_r6_file_access", "--raw"], root=True)

rules = commands["audit_rules"]
rule_hash = rules["stdout_sha256"]
rule_lines = [line for line in rules["stdout"].splitlines()
              if line.strip() and line.strip() != "No rules"]
tcpdump_lines = [line for line in commands["tcpdump_processes"]["stdout"].splitlines()
                 if "tcpdump" in line]
interfaces_clean = all(result["returncode"] != 0
                       for result in commands["reserved_interfaces"].values())
mininet_ok = (commands["mininet_import"]["returncode"] == 0
              and "MININET_IMPORT_OK" in commands["mininet_import"]["stdout"])
privileges_ok = (commands["sudo_uid"]["returncode"] == 0
                 and commands["sudo_uid"]["stdout"].strip() == "0")
audit_tools_ok = all(commands[name]["available"] for name in ("auditctl", "ausearch"))
runtime_binaries_ok = all(commands[name]["available"]
                          for name in ("mininet", "ovs_vsctl", "tcpdump", "python3"))
clean_baseline = rule_hash == EXPECTED_EMPTY_RULE_HASH and not rule_lines
clean_ovs = commands["ovs_bridge"]["returncode"] != 0
clean_tcpdump = not tcpdump_lines
clean_run_dir = sorted(path.name for path in RUN_DIR.iterdir()) == [
    "mininet_e1c_r6_file_access_closure_smoke.py",
    "test_e1c_r6_harness.py",
]
# additional gates
auditd_version_ok = commands["auditd_version"]["stdout"].strip() == EXPECTED_AUDITD_VERSION
harness_bytes = (RUN_DIR / "mininet_e1c_r6_file_access_closure_smoke.py").read_bytes()
harness_sha = sha256(harness_bytes)
harness_lineage_ok = harness_sha == EXPECTED_HARNESS_SHA256
port_free = not commands["listening_port"]["stdout"].strip()
status_parsed = {}
for token in commands["audit_status"]["stdout"].split():
    if "=" in token:
        k, _, v = token.partition("=")
        status_parsed[k] = v
loss_ok = status_parsed.get("lost") == "0" and status_parsed.get("backlog") == "0"

clean_state = (clean_baseline and interfaces_clean and clean_ovs
               and clean_tcpdump and clean_run_dir and port_free)
prerequisites = (mininet_ok and audit_tools_ok and runtime_binaries_ok
                 and privileges_ok and clean_state and auditd_version_ok
                 and harness_lineage_ok and loss_ok)
ended = now()

result = {
    "schema": "MININET_E1C_R6R4_PRE_RUNTIME_PREREQUISITES_V1",
    "task_id": "MININET_E1C_R6R4_PRIVILEGED_RUNTIME_SMOKE",
    "captured_at_utc": {"start": started, "end": ended},
    "runtime_output_dir": str(PACKAGE),
    "MININET_AVAILABLE": "PASS" if mininet_ok else "BLOCKED",
    "AUDIT_TOOLING_AVAILABLE": "PASS" if audit_tools_ok else "BLOCKED",
    "RUNTIME_BINARIES_AVAILABLE": "PASS" if runtime_binaries_ok else "BLOCKED",
    "REQUIRED_PRIVILEGES_AVAILABLE": "PASS" if privileges_ok else "BLOCKED",
    "AUDITD_VERSION_EXACT": "PASS" if auditd_version_ok else "BLOCKED",
    "HARNESS_LINEAGE_AUTHENTICATED": "PASS" if harness_lineage_ok else "BLOCKED",
    "AUDIT_LOSS_AND_BACKLOG_ZERO_PRE_RUN": "PASS" if loss_ok else "BLOCKED",
    "TCP_PORT_18080_FREE": "PASS" if port_free else "BLOCKED",
    "CLEAN_PRE_RUNTIME_STATE": "PASS" if clean_state else "BLOCKED",
    "PRE_RUNTIME_PREREQUISITES": "PASS" if prerequisites else "BLOCKED",
    "expected_empty_rule_dump_sha256": EXPECTED_EMPTY_RULE_HASH,
    "observed_empty_rule_dump_sha256": rule_hash,
    "observed_rule_lines": rule_lines,
    "expected_auditd_version": EXPECTED_AUDITD_VERSION,
    "observed_auditd_version": commands["auditd_version"]["stdout"].strip(),
    "expected_harness_sha256": EXPECTED_HARNESS_SHA256,
    "observed_harness_sha256": harness_sha,
    "audit_status_parsed_pre_run": status_parsed,
    "reserved_interfaces_clean": interfaces_clean,
    "ovs_bridge_s1_absent": clean_ovs,
    "ovs_bridges_pre_run": commands["ovs_bridge_list"]["stdout"].split(),
    "netns_list_pre_run": commands["netns_list"]["stdout"].split(),
    "tcp_port_18080_listeners": commands["listening_port"]["stdout"].splitlines(),
    "prior_audit_key_residue_bytes": commands["audit_key_residue"]["stdout_bytes"],
    "tcpdump_processes": tcpdump_lines,
    "runtime_source_dir_clean": clean_run_dir,
    "runtime_source_dir_entries": sorted(path.name for path in RUN_DIR.iterdir()),
    "commands": commands,
    "preparation_commit": "9128e772cb727852b7fb37a3bcdd4778fbd84939",
    "fresh_review_materialization_commit": "edee49c3a1eb84b040e4734ad9e58f8490882dc0",
    "provx_training": "NO",
    "provx_inference": "NO",
    "formal_1796_experiment_executed": "NO",
}
PACKAGE.mkdir(parents=True, exist_ok=True)
(PACKAGE / "03_PRE_RUNTIME_PREREQUISITE_MATRIX.json").write_text(
    json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print("PRE_RUNTIME_PREREQUISITES=" + result["PRE_RUNTIME_PREREQUISITES"])
for gate in ("MININET_AVAILABLE", "AUDIT_TOOLING_AVAILABLE", "RUNTIME_BINARIES_AVAILABLE",
             "REQUIRED_PRIVILEGES_AVAILABLE", "AUDITD_VERSION_EXACT",
             "HARNESS_LINEAGE_AUTHENTICATED", "AUDIT_LOSS_AND_BACKLOG_ZERO_PRE_RUN",
             "TCP_PORT_18080_FREE", "CLEAN_PRE_RUNTIME_STATE"):
    print(f"  {gate}={result[gate]}")
sys.exit(0 if prerequisites else 2)
