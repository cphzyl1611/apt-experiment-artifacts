# MININET-E1C-R6 Auditd Bounded Smoke

Run: `e1c-r6-run-20260901T060350Z`
Audit key: `e1c600493b1e40a2`

`MININET_E1C_R6_AUDITD_COLLECTOR = PARTIAL_MISSING_REQUIRED_EVENT_CLASS`

`OLD_RUN_RESIDUAL_RULES_FOUND = 0`
`OLD_RUN_RESIDUAL_RULES_REMOVED = 0`
`AUDIT_BASELINE_RESTORED_BEFORE_R6 = YES`
`AUDIT_BASELINE_RESTORED_AFTER_R6 = YES`
`AUDIT_LOST_EVENTS = 0`
`LOGICAL_HOST_JOIN_SUCCESS_COUNT = 4`
`LOGICAL_HOST_JOIN_FAILURE_COUNT = 0`
`EARLY_CHILD_FAILURE_COUNT = 0`

## Required audit classes

- PROCESS_START_OR_EXEC: 10
- PROCESS_EXIT: 4
- FILE_CREATE_OR_OPEN: 2
- FILE_READ_OR_WRITE: 0
- FILE_DELETE: 2
- SOCKET_BIND: 4
- SOCKET_CONNECT: 1
- SOCKET_ACCEPT: 1

## Namespace assertions

{
  "checks": {
    "h1_child_netns != h2_shell_netns": "PASS",
    "h1_child_netns == h1_shell_netns": "PASS",
    "h2_child_netns != h1_shell_netns": "PASS",
    "h2_child_netns == h2_shell_netns": "PASS"
  },
  "pass": true
}

## Cleanup

{
  "AUDIT_BASELINE_RESTORED_AFTER_R6": "YES",
  "RESERVED_TEST_INTERFACES_REMAINING": 0,
  "RESERVED_TEST_INTERFACES_REMAINING_DETAILS": [],
  "RESERVED_TEST_OVS_OBJECTS_REMAINING": 0,
  "RESERVED_TEST_OVS_OBJECTS_REMAINING_DETAILS": [],
  "RUN_OWNED_CHILDREN_REMAINING": 0,
  "RUN_OWNED_CHILDREN_REMAINING_DETAILS": [],
  "TCPDUMP_PROCESS_REMAINING": 0,
  "TCPDUMP_PROCESS_REMAINING_DETAILS": [],
  "apt_action_executed": false,
  "audit_key": "e1c600493b1e40a2",
  "baseline_restored_after_r6": true,
  "baseline_rule_dump_sha256_after": "61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87",
  "baseline_rule_dump_sha256_before": "61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87",
  "child_residue_zero": true,
  "external_nat_attachment": false,
  "formal_experiment_executed": false,
  "mn_cleanup_command_executed": false,
  "pcap_path": "/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/MININET_E1C_R6_SMOKE.pcap",
  "pcap_sha256": "f2993a2f9e75e9fb5299af71d3cebe7b798300262e7e94adbe2abc54ddc9ed89",
  "persistent_rule_files_unchanged": true,
  "preexisting_ovs_daemons_excluded": true,
  "provx_executed": false,
  "rule_removal": [
    {
      "name": "h2_ppid_socket_bind_connect_accept_accept4",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "accept4",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_socket_bind_connect_accept_accept",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "accept",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_socket_bind_connect_accept_connect",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "connect",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_socket_bind_connect_accept_bind",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "bind",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_file_delete_renameat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "renameat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_file_delete_unlinkat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "unlinkat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_file_delete_unlink",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "unlink",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_file_create_or_open_openat2",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "openat2",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_file_create_or_open_openat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "openat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_process_exit_exit_group",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "exit_group",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_process_start_or_exec_vfork",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "vfork",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_process_start_or_exec_fork",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "fork",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_process_start_or_exec_clone",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "clone",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_process_start_or_exec_execveat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "execveat",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_ppid_process_start_or_exec_execve",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "execve",
          "-F",
          "ppid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_socket_bind_connect_accept_accept4",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "accept4",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_socket_bind_connect_accept_accept",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "accept",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_socket_bind_connect_accept_connect",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "connect",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_socket_bind_connect_accept_bind",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "bind",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_file_delete_renameat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "renameat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_file_delete_unlinkat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "unlinkat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_file_delete_unlink",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "unlink",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_file_create_or_open_openat2",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "openat2",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_file_create_or_open_openat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "openat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_process_exit_exit_group",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "exit_group",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_process_start_or_exec_vfork",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "vfork",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_process_start_or_exec_fork",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "fork",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_process_start_or_exec_clone",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "clone",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_process_start_or_exec_execveat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "execveat",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_ppid_process_start_or_exec_execve",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "execve",
          "-F",
          "ppid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_file_permission_h2.txt",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-F",
          "path=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events/h2.txt",
          "-F",
          "perm=rw",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_socket_bind_connect_accept_accept4",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "accept4",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_socket_bind_connect_accept_accept",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "accept",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_socket_bind_connect_accept_connect",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "connect",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_socket_bind_connect_accept_bind",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "bind",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_file_delete_renameat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "renameat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_file_delete_unlinkat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "unlinkat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_file_delete_unlink",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "unlink",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_file_create_or_open_openat2",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "openat2",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_file_create_or_open_openat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "openat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_process_exit_exit_group",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "exit_group",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_process_start_or_exec_vfork",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "vfork",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_process_start_or_exec_fork",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "fork",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_process_start_or_exec_clone",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "clone",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_process_start_or_exec_execveat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "execveat",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h2_pid_process_start_or_exec_execve",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "execve",
          "-F",
          "pid=1375152",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_file_permission_h1.txt",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-F",
          "path=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events/h1.txt",
          "-F",
          "perm=rw",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_socket_bind_connect_accept_accept4",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "accept4",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_socket_bind_connect_accept_accept",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "accept",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_socket_bind_connect_accept_connect",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "connect",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_socket_bind_connect_accept_bind",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "bind",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_file_delete_renameat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "renameat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_file_delete_unlinkat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "unlinkat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_file_delete_unlink",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "unlink",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_file_create_or_open_openat2",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "openat2",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_file_create_or_open_openat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "openat",
          "-F",
          "dir=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/temp-events",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_process_exit_exit_group",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "exit_group",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_process_start_or_exec_vfork",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "vfork",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_process_start_or_exec_fork",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "fork",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_process_start_or_exec_clone",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "clone",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_process_start_or_exec_execveat",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "execveat",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    },
    {
      "name": "h1_pid_process_start_or_exec_execve",
      "result": {
        "argv": [
          "/usr/sbin/auditctl",
          "-d",
          "always,exit",
          "-F",
          "arch=b64",
          "-S",
          "execve",
          "-F",
          "pid=1375151",
          "-k",
          "e1c600493b1e40a2"
        ],
        "returncode": 0,
        "stderr": "",
        "stdout": ""
      },
      "returncode": 0
    }
  ],
  "run_id": "e1c-r6-run-20260901T060350Z",
  "run_rules_removed": true,
  "schema": "MININET_E1C_R6_POST_CLEANUP_V1",
  "tcpdump_ran_inside_topology": true,
  "tcpdump_residue_zero": true,
  "topology_residue_zero": true
}
