# MININET-E1C-R3 Auditd Bounded Smoke

Run: `e1c-r3-run-20260831T075356Z`
Audit key: `e1c30cd510e09357`

`MININET_E1C_R3_AUDITD_COLLECTOR = BLOCKED`

`OLD_RUN_RESIDUAL_RULES_FOUND = 10`
`OLD_RUN_RESIDUAL_RULES_REMOVED = 0`
`AUDIT_BASELINE_RESTORED_BEFORE_R3 = NO`
`AUDIT_BASELINE_RESTORED_AFTER_R3 = NO`
`AUDIT_LOST_EVENTS = 0`
`LOGICAL_HOST_JOIN_SUCCESS_COUNT = 0`
`LOGICAL_HOST_JOIN_FAILURE_COUNT = 0`

## Required audit classes

- PROCESS_START_OR_EXEC: 0
- PROCESS_EXIT: 0
- FILE_CREATE_OR_OPEN: 0
- FILE_READ_OR_WRITE: 0
- FILE_DELETE: 0
- SOCKET_BIND: 0
- SOCKET_CONNECT: 0
- SOCKET_ACCEPT: 0

## Namespace assertions

{
  "checks": {
    "h1_child_netns != h2_shell_netns": false,
    "h1_child_netns == h1_shell_netns": true,
    "h2_child_netns != h1_shell_netns": false,
    "h2_child_netns == h2_shell_netns": true
  },
  "pass": false
}

## Cleanup

{
  "RESERVED_TEST_INTERFACES_REMAINING": [],
  "RESERVED_TEST_OVS_OBJECTS_REMAINING": [],
  "RUN_OWNED_CHILDREN_REMAINING": [],
  "TCPDUMP_PROCESS_REMAINING": [],
  "apt_action_executed": false,
  "audit_key": "e1c30cd510e09357",
  "baseline_restored_after_r3": false,
  "baseline_rule_dump_sha256_after": "1fb44fe1092e290e878f5e437fd5d2961803b551f52a656d4e4e93956ac95ad0",
  "baseline_rule_dump_sha256_before": "61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87",
  "child_residue_zero": true,
  "external_nat_attachment": false,
  "formal_experiment_executed": false,
  "mn_cleanup_command_executed": false,
  "pcap_path": "/home/cph/experiment-parallel/e0-a/e1c-r3-run-20260831T075356Z/MININET_E1C_R3_SMOKE.pcap",
  "pcap_sha256": null,
  "persistent_rule_files_unchanged": true,
  "preexisting_ovs_daemons_excluded": true,
  "provx_executed": false,
  "rule_removal": [],
  "run_id": "e1c-r3-run-20260831T075356Z",
  "run_rules_removed": false,
  "schema": "MININET_E1C_R3_POST_CLEANUP_V1",
  "tcpdump_ran_inside_topology": false,
  "topology_residue_zero": true
}
