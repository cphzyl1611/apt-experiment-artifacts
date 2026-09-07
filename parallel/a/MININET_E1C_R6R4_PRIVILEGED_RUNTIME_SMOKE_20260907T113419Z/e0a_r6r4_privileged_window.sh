#!/usr/bin/env bash
# MININET_E1C_R6R4_PRIVILEGED_RUNTIME_SMOKE -- human sudo window (remediated preflight).
# Run this from a REAL TERMINAL on this machine. sudo prompts on your tty.
# The password is never read by, passed to, or stored by any part of this script.
set -u

PKG="/home/cph/experiment-parallel/e0-a/MININET_E1C_R6R4_PRIVILEGED_RUNTIME_SMOKE_20260907T113419Z"
SP="/tmp/claude-1000/-home-cph-experiment-parallel-e0-a/8ffd76de-29d9-4174-bd53-8fcd383546b8/scratchpad"
EXEC_DIR="$PKG/execution"
HARNESS=/home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z/mininet_e1c_r6_file_access_closure_smoke.py
RUNSTAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$EXEC_DIR"

stamp() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }

echo "== E0-A MININET_E1C_R6R4 PRIVILEGED RUNTIME SMOKE =="
echo "Receipt root: $PKG"
echo "Run stamp:    $RUNSTAMP"
echo

# ---- Step 5: interactive sudo acquisition (normal password entry only) ----
ACQ_START=$(stamp)
echo "[1/5] sudo -v  (enter your password at the prompt)"
sudo -v
ACQ_RC=$?
ACQ_END=$(stamp)
if [ "$ACQ_RC" -ne 0 ]; then
  echo "REQUIRED_PRIVILEGES_AVAILABLE=BLOCKED (sudo -v returned $ACQ_RC)"
  exit 2
fi
VERIFY_START=$(stamp)
sudo -n true
VERIFY_RC=$?
VERIFY_END=$(stamp)
SUDO_UID=$(sudo -n /usr/bin/id -u 2>/dev/null)
if [ "$VERIFY_RC" -ne 0 ] || [ "$SUDO_UID" != "0" ]; then
  echo "REQUIRED_PRIVILEGES_AVAILABLE=BLOCKED (sudo -n true rc=$VERIFY_RC uid=$SUDO_UID)"
  exit 2
fi
printf '{"schema":"MININET_E1C_R6R4_PRIVILEGE_ACQUISITION_V1","run_stamp":"%s","method":"interactive_sudo_v","sudo_dash_S_used":false,"password_read_by_script":false,"password_stored":false,"sudo_v_returncode":%s,"sudo_v_start_utc":"%s","sudo_v_end_utc":"%s","sudo_n_true_returncode":%s,"sudo_n_true_start_utc":"%s","sudo_n_true_end_utc":"%s","sudo_n_id_u":"%s","required_privileges_available":"PASS"}\n' \
  "$RUNSTAMP" "$ACQ_RC" "$ACQ_START" "$ACQ_END" "$VERIFY_RC" "$VERIFY_START" "$VERIFY_END" "$SUDO_UID" \
  > "$EXEC_DIR/privilege_acquisition.$RUNSTAMP.json"
cp -f "$EXEC_DIR/privilege_acquisition.$RUNSTAMP.json" "$EXEC_DIR/privilege_acquisition.json"
echo "    REQUIRED_PRIVILEGES_AVAILABLE=PASS (sudo -n id -u => $SUDO_UID)"
echo

# ---- Step 5b: direct raw observation of auditctl -l (settles the D2 open question) ----
echo "[2/5] raw auditctl -l observation (no Python in the path)"
OBS="$EXEC_DIR/auditctl_l_raw_observation.$RUNSTAMP"
sudo -n /usr/sbin/auditctl -l > "$OBS.stdout" 2> "$OBS.stderr"
LIST_RC=$?
LIST_SHA=$(sha256sum < "$OBS.stdout" | cut -d' ' -f1)
LIST_BYTES=$(wc -c < "$OBS.stdout")
{
  echo "returncode: $LIST_RC"
  echo "stdout_bytes: $LIST_BYTES"
  echo "stdout_sha256: $LIST_SHA"
  echo "frozen_expected_sha256: 61501e69a61dbbc1a41605ea15c34807e6b1d3992bee195dde36a7ebdd95dd87  (= sha256 of 'No rules\\n')"
  echo "--- stdout, cat -A ---"; cat -A "$OBS.stdout"
  echo "--- stdout, xxd ---";    xxd "$OBS.stdout"
  echo "--- stderr ---";         cat "$OBS.stderr"
} > "$OBS.report.txt" 2>&1
cat "$OBS.report.txt"
echo

echo "[3/5] raw auditctl -s observation"
sudo -n /usr/sbin/auditctl -s > "$EXEC_DIR/auditctl_s_raw_observation.$RUNSTAMP.stdout" 2>&1
cat "$EXEC_DIR/auditctl_s_raw_observation.$RUNSTAMP.stdout"
echo

# ---- Step 6: remediated pre-runtime prerequisite gate (fails closed) ----
echo "[4/5] remediated pre-runtime prerequisite gate"
PRE_START=$(stamp)
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 "$SP/e0a_r6r4_preflight.py" "$PKG" \
  > "$EXEC_DIR/preflight_stdout.$RUNSTAMP.log" 2> "$EXEC_DIR/preflight_stderr.$RUNSTAMP.log"
PRE_RC=$?
PRE_END=$(stamp)
cat "$EXEC_DIR/preflight_stdout.$RUNSTAMP.log"
[ -s "$EXEC_DIR/preflight_stderr.$RUNSTAMP.log" ] && cat "$EXEC_DIR/preflight_stderr.$RUNSTAMP.log"
printf '{"run_stamp":"%s","start_utc":"%s","end_utc":"%s","returncode":%s}\n' \
  "$RUNSTAMP" "$PRE_START" "$PRE_END" "$PRE_RC" > "$EXEC_DIR/preflight_timing.$RUNSTAMP.json"
if [ "$PRE_RC" -ne 0 ]; then
  echo
  echo "PRE_RUNTIME_PREREQUISITES=BLOCKED -- the frozen smoke was NOT executed."
  echo "Evidence: $EXEC_DIR (run stamp $RUNSTAMP)"
  exit 2
fi
echo

# ---- Step 7: the exact frozen privileged runtime smoke ----
echo "[5/5] executing the exact frozen R6R4 smoke command"
echo "      sudo /usr/bin/python3 $HARNESS --run-privileged"
SMOKE_START=$(stamp)
sudo /usr/bin/python3 "$HARNESS" --run-privileged \
  > "$EXEC_DIR/smoke_stdout.log" 2> "$EXEC_DIR/smoke_stderr.log"
SMOKE_RC=$?
SMOKE_END=$(stamp)
printf '{"run_stamp":"%s","exact_command":"sudo /usr/bin/python3 %s --run-privileged","start_utc":"%s","end_utc":"%s","returncode":%s}\n' \
  "$RUNSTAMP" "$HARNESS" "$SMOKE_START" "$SMOKE_END" "$SMOKE_RC" > "$EXEC_DIR/smoke_timing.json"
echo "      exit=$SMOKE_RC"
sed -n '1,40p' "$EXEC_DIR/smoke_stdout.log"
echo

echo "post-runtime privileged residual observation"
{
  echo "### auditctl -l"; sudo -n /usr/sbin/auditctl -l 2>&1
  echo "### auditctl -s"; sudo -n /usr/sbin/auditctl -s 2>&1
  echo "### ovs-vsctl list-br"; sudo -n /usr/bin/ovs-vsctl --timeout=2 list-br 2>&1
  echo "### ip link show"; sudo -n /usr/sbin/ip -o link show 2>&1
  echo "### ip netns list"; sudo -n /usr/sbin/ip netns list 2>&1
  echo "### ps"; sudo -n /bin/ps -eo pid=,comm=,args= 2>&1
  echo "### ss -Hltnp"; sudo -n /usr/bin/ss -Hltnp 2>&1
} > "$EXEC_DIR/post_runtime_privileged_observation.log" 2>&1
sudo -n /bin/chown -R "$(id -u):$(id -g)" /home/cph/experiment-parallel/e0-a/e1c-r6-run-20260901T060350Z
echo "    done"
echo
echo "PRIVILEGED_WINDOW_COMPLETE smoke_exit=$SMOKE_RC"
exit "$SMOKE_RC"
