#!/usr/bin/python3
"""Unprivileged contract tests for the E1A-R2 privileged harness."""

import importlib.util
import json
import os
import select
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


RUN_DIR = Path(__file__).resolve().parent
HARNESS_PATH = RUN_DIR / "mininet_e1a_r2_privileged_harness.py"


def load_harness():
    spec = importlib.util.spec_from_file_location("e1a_r2_harness", HARNESS_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HarnessContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = load_harness()

    def test_attribution_requires_all_four_owner_and_cross_host_relations(self):
        result = self.harness.build_attribution_assertions(
            h1_shell_netns="net:[101]",
            h2_shell_netns="net:[202]",
            h1_child_netns="net:[101]",
            h2_child_netns="net:[202]",
        )

        self.assertEqual(
            result["checks"],
            {
                "h1_child_netns == h1_shell_netns": True,
                "h2_child_netns == h2_shell_netns": True,
                "h1_child_netns != h2_shell_netns": True,
                "h2_child_netns != h1_shell_netns": True,
            },
        )
        self.assertTrue(result["pass"])

    def test_attribution_fails_if_child_is_in_other_host_namespace(self):
        result = self.harness.build_attribution_assertions(
            h1_shell_netns="net:[101]",
            h2_shell_netns="net:[202]",
            h1_child_netns="net:[202]",
            h2_child_netns="net:[202]",
        )

        self.assertFalse(result["checks"]["h1_child_netns == h1_shell_netns"])
        self.assertFalse(result["checks"]["h1_child_netns != h2_shell_netns"])
        self.assertFalse(result["pass"])

    def test_cleanup_contract_counts_only_run_owned_or_reserved_state(self):
        result = self.harness.build_cleanup_assertions(
            run_owned_process_refs=[{"pid": 300, "start_ticks": 10}, {"pid": 301, "start_ticks": 11}],
            live_process_refs=[{"pid": 841, "start_ticks": 1}, {"pid": 907, "start_ticks": 2}],
            tcpdump_process_ref={"pid": 302, "start_ticks": 12},
            reserved_interfaces_remaining=[],
            reserved_ovs_objects_remaining=[],
        )

        self.assertEqual(result["RUN_OWNED_CHILDREN_REMAINING"], 0)
        self.assertEqual(result["RESERVED_TEST_INTERFACES_REMAINING"], 0)
        self.assertEqual(result["RESERVED_TEST_OVS_OBJECTS_REMAINING"], 0)
        self.assertEqual(result["TCPDUMP_PROCESS_REMAINING"], 0)
        self.assertTrue(result["pass"])

    def test_cleanup_contract_fails_on_matching_run_process_identity(self):
        result = self.harness.build_cleanup_assertions(
            run_owned_process_refs=[{"pid": 300, "start_ticks": 10}],
            live_process_refs=[{"pid": 300, "start_ticks": 10}, {"pid": 841, "start_ticks": 1}],
            tcpdump_process_ref={"pid": 302, "start_ticks": 12},
            reserved_interfaces_remaining=["s1-eth1"],
            reserved_ovs_objects_remaining=["bridge:s1"],
        )

        self.assertEqual(result["RUN_OWNED_CHILDREN_REMAINING"], 1)
        self.assertEqual(result["RESERVED_TEST_INTERFACES_REMAINING"], 1)
        self.assertEqual(result["RESERVED_TEST_OVS_OBJECTS_REMAINING"], 1)
        self.assertFalse(result["pass"])

    def test_tcpdump_filter_is_exactly_bounded_to_test_network_and_port(self):
        result = self.harness.validate_tcpdump_filter(self.harness.TCPDUMP_FILTER)

        self.assertEqual(result["network"], "10.0.0.0/24")
        self.assertEqual(result["tcp_port"], 18080)
        self.assertTrue(result["icmp_bounded"])
        self.assertTrue(result["tcp_bounded"])
        self.assertTrue(result["pass"])

    def test_tcpdump_filter_rejects_unbounded_capture(self):
        result = self.harness.validate_tcpdump_filter("icmp or tcp")

        self.assertFalse(result["pass"])

    def test_process_reference_includes_pid_start_time_and_detects_identity(self):
        ref = self.harness.capture_process_ref(os.getpid(), role="unit-test")

        self.assertEqual(ref["pid"], os.getpid())
        self.assertIsInstance(ref["start_ticks"], int)
        self.assertTrue(self.harness.process_ref_is_live(ref))
        self.assertFalse(
            self.harness.process_ref_is_live({"pid": os.getpid(), "start_ticks": ref["start_ticks"] + 1})
        )

    def test_reserved_ovs_query_plan_covers_interface_and_port_rows(self):
        queries = self.harness.reserved_ovs_find_queries()

        self.assertEqual(len(queries), 10)
        self.assertIn(
            {
                "object_label": "interface:s1-eth1",
                "argv": [
                    "/usr/bin/ovs-vsctl",
                    "--timeout=2",
                    "--data=bare",
                    "--no-heading",
                    "--columns=name",
                    "find",
                    "Interface",
                    "name=s1-eth1",
                ],
            },
            queries,
        )
        self.assertIn(
            {
                "object_label": "port:s1-eth1",
                "argv": [
                    "/usr/bin/ovs-vsctl",
                    "--timeout=2",
                    "--data=bare",
                    "--no-heading",
                    "--columns=name",
                    "find",
                    "Port",
                    "name=s1-eth1",
                ],
            },
            queries,
        )

    def test_child_mode_exposes_socket_and_temp_file_while_alive_then_deletes_file(self):
        with tempfile.TemporaryDirectory(prefix="e1a-r2-test-") as tmp:
            temp_path = Path(tmp) / "child-marker.txt"
            proc = subprocess.Popen(
                [
                    "/usr/bin/python3",
                    str(HARNESS_PATH),
                    "--child",
                    "--logical-host-id",
                    "test-host",
                    "--listen-address",
                    "127.0.0.1",
                    "--listen-port",
                    "0",
                    "--temp-file",
                    str(temp_path),
                    "--window-seconds",
                    "1.5",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            ready_streams, _, _ = select.select([proc.stdout], [], [], 3)
            self.assertTrue(ready_streams, "child did not emit READY evidence")
            ready = json.loads(proc.stdout.readline())

            self.assertEqual(ready["event"], "READY")
            self.assertEqual(ready["pid"], proc.pid)
            self.assertGreater(ready["listen_port"], 0)
            self.assertTrue(temp_path.exists())
            self.assertTrue(Path(f"/proc/{proc.pid}/net/tcp").read_text().startswith("  sl"))

            stdout_tail, stderr = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 0, stderr)
            finished = json.loads(stdout_tail.strip().splitlines()[-1])
            self.assertEqual(finished["event"], "FINISHED")
            self.assertEqual(finished["file_operations"], ["create", "read", "delete"])
            self.assertFalse(temp_path.exists())

    def test_static_self_check_runs_without_root_and_reports_all_guards(self):
        proc = subprocess.run(
            ["/usr/bin/python3", str(HARNESS_PATH), "--static-self-check"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertTrue(result["pass"])
        self.assertTrue(result["no_nat_or_external_links"])
        self.assertTrue(result["no_apt_commands"])
        self.assertTrue(result["no_provx_or_formal_benchmark_execution"])
        self.assertTrue(result["no_mn_c"])
        self.assertTrue(result["no_automatic_sudo"])
        self.assertTrue(result["bounded_tcpdump_filter"]["pass"])
        self.assertEqual(result["required_namespace_assertions"], 4)
        self.assertEqual(result["required_cleanup_zero_assertions"], 4)
        self.assertTrue(
            {"ip", "ovs-vsctl", "pgrep", "tcpdump", "python3", "ss", "ping"}.issubset(
                set(result["command_executables_inspected"])
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
