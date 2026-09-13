#!/usr/bin/env bash

set -Eeuo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: mac_isolation_test.sh TELEGRAMD_APP EVIDENCE_DIR" >&2
	exit 2
fi

APP_PATH="$1"
EVIDENCE_DIR="$2"
PARSER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check_mac_fs_usage.py"
OFFICIAL_DMG_URL="https://td.telegram.org/mac/td-setup-mac-7.2.8.dmg"
OFFICIAL_DMG_SHA256="5883217d4f6f25d147ee8bf9997c984a38b3fecef3d5ab6630a1fc22d212a6bb"
RUN_ROOT=""
HOME_ROOT=""
OFFICIAL_APP=""
OFFICIAL_EXE=""
FORK_APP=""
FORK_EXE=""
LAUNCHED_PID=""
CONTROL_HELPER_PID=""
CONTROL_DTRACE_PID=""
CONTROL_READY=""
CONTROL_RELEASE=""
CONTROL_RESULT=""
CONTROL_PID=""
CONTROL_CHILD_PID=""
CONTROL_TRACE=""
OBSERVER_LAUNCH_PID=""
PYTHON3=""
SPAWN_CONTROL_HELPER_PID=""
SPAWN_CONTROL_OBSERVER_PID=""
SPAWN_CONTROL_PID=""
SPAWN_CONTROL_READY=""
SPAWN_CONTROL_RELEASE=""
SPAWN_CONTROL_RESULT=""
SPAWN_CONTROL_PARENT_PID=""
SPAWN_CONTROL_CHILD_PID=""
SPAWN_CONTROL_TRACE=""
OFFICIAL_PID=""
FORK_PID=""
SECOND_PID=""
QUIT_PID=""
RELAUNCH_PID=""
TRACKER_PID=""
OBSERVER_MANAGER_PID=""
OBSERVER_STOP_FILE=""
OBSERVER_MANAGER_FAILURE_FILE=""
OBSERVER_STOP_RESULT_FILE=""
PID_ROOTS_FILE=""
PID_FILE=""
PID_LOCK_DIR=""
TRACK_STOP_FILE=""
TARGET_TRACE_DIR=""
TARGET_EXEC_DIR=""
TARGET_FORK_DIR=""
TARGET_OBSERVER_FILE=""
MOUNT_PATH=""
MOUNTED=0
TRACE_STOPPED=0
OBSERVER_SHUTDOWN_FILE="$EVIDENCE_DIR/observer-shutdown.txt"
RESULT="FAIL"
LAST_ERROR_COMMAND=""
LAST_ERROR_LINE=""

mkdir -p "$EVIDENCE_DIR"
: > "$OBSERVER_SHUTDOWN_FILE"

record() {
	printf '%s\n' "$*" >> "$EVIDENCE_DIR/events.txt"
}

fail() {
	local criterion="$1"
	shift
	local detail="${*:-assertion failed}"
	printf 'FAIL: criterion=%s detail=%s\n' "$criterion" "$detail" | tee "$EVIDENCE_DIR/status.txt" >&2
	record "failure criterion=$criterion detail=$detail"
	exit 1
}

unavailable() {
	local detail="$*"
	printf 'UNAVAILABLE: %s\n' "$detail" | tee "$EVIDENCE_DIR/status.txt" >&2
	record "unavailable detail=$detail"
	exit 2
}

canonical_path() {
	python3 - "$1" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
}

process_command() {
	ps -p "$1" -o command= 2>/dev/null | sed -e 's/^[[:space:]]*//'
}

process_alive() {
	local state
	[ -n "$1" ] && kill -0 "$1" 2>/dev/null || return 1
	state="$(ps -p "$1" -o state= 2>/dev/null | tr -d '[:space:]' || true)"
	case "$state" in
		Z*) return 1 ;;
	esac
}

process_present() {
	local state
	[ -n "$1" ] || return 1
	state="$(ps -p "$1" -o state= 2>/dev/null | tr -d '[:space:]' || true)"
	case "$state" in
		""|Z*) return 1 ;;
	esac
}

start_privileged_observer() {
	local executable="$1"
	shift
	sudo -n "$PYTHON3" -c '
import os
import signal
import sys

signal.signal(signal.SIGINT, signal.SIG_DFL)
os.execv(sys.argv[1], sys.argv[1:])
' "$executable" "$@" &
	OBSERVER_LAUNCH_PID=$!
}

wait_for_process() {
	local pid="$1"
	local seconds="$2"
	local i
	for i in $(seq 1 "$seconds"); do
		if process_alive "$pid"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

wait_for_exit() {
	local pid="$1"
	local seconds="$2"
	local i
	if ! process_alive "$pid"; then
		return 0
	fi
	for i in $(seq 1 "$seconds"); do
		if ! process_alive "$pid"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

wait_for_observer_exit() {
	local owner_pid="$1"
	local tracer_pid="$2"
	local seconds="$3"
	local i
	for i in $(seq 1 $((seconds * 10))); do
		if ! process_alive "$owner_pid" && ! process_present "$tracer_pid"; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

wait_for_file() {
	local path="$1"
	local seconds="$2"
	local i
	for i in $(seq 1 "$seconds"); do
		if [ -e "$path" ]; then
			return 0
		fi
		sleep 1
	done
	return 1
}

wait_for_trace_marker() {
	local pid="$1"
	local path="$2"
	local marker="$3"
	local seconds="$4"
	local i
	for i in $(seq 1 $((seconds * 10))); do
		if grep -F -- "$marker" "$path" >/dev/null 2>&1; then
			return 0
		fi
		if ! process_alive "$pid"; then
			return 1
		fi
		sleep 0.1
	done
	return 1
}

focus_application_process() {
	local pid="$1"
	local output="$2"
	local seconds="$3"
	local i
	: > "$output"
	for i in $(seq 1 "$seconds"); do
		if ! process_alive "$pid"; then
			printf 'attempt=%s result=FAIL detail=process-exited\n' "$i" >> "$output"
			return 1
		fi
		if osascript -e "tell application \"System Events\" to set frontmost of (first application process whose unix id is $pid) to true" >> "$output" 2>&1; then
			printf 'attempt=%s result=PASS\n' "$i" >> "$output"
			return 0
		fi
		sleep 1
	done
	printf 'attempts=%s result=FAIL detail=process-never-became-focusable\n' "$seconds" >> "$output"
	return 1
}

wait_for_stopped() {
	local pid="$1"
	local seconds="$2"
	local state
	local i
	for i in $(seq 1 $((seconds * 10))); do
		state="$(ps -p "$pid" -o state= 2>/dev/null | tr -d '[:space:]' || true)"
		case "$state" in
			T*) return 0 ;;
			"") return 1 ;;
		esac
		sleep 0.1
	done
	return 1
}

launch_suspended() {
	local output="$1"
	shift
	env HOME="$HOME_ROOT" /bin/sh -c 'kill -STOP $$; exec "$@"' telegramd-launcher "$FORK_EXE" "$@" > "$output" 2>&1 &
	LAUNCHED_PID=$!
	wait_for_stopped "$LAUNCHED_PID" 10 || fail "suspended Telegramd launch" "pid=$LAUNCHED_PID did not stop before observation"
}

stop_observer_process() {
	local label="$1"
	local pid="$2"
	local expected_fragment="$3"
	local trace_path="${4:-}"
	local signal_pid="$pid"
	local tracer_pid="$pid"
	local child_pid
	local child_command
	local command
	local tracer_found=0
	local signal_result=FAIL
	local flush_result=FAIL
	local forced_kill=0
	local wait_status=0
	local result=PASS
	local detail=clean

	if [ -z "$pid" ]; then
		printf 'label=%s pid=missing forced_kill=0 wait_status=none result=FAIL detail=missing-pid\n' \
			"$label" >> "$OBSERVER_SHUTDOWN_FILE"
		return 1
	fi
	if ! process_alive "$pid"; then
		printf 'label=%s pid=%s forced_kill=0 wait_status=none result=FAIL detail=exited-before-intentional-shutdown\n' \
			"$label" "$pid" >> "$OBSERVER_SHUTDOWN_FILE"
		return 1
	fi
	command="$(process_command "$pid")"
	case "$command" in
		*"$expected_fragment"*)
			;;
		*)
			record "cleanup refused observer label=$label pid=$pid command=$command expected=$expected_fragment"
			printf 'label=%s pid=%s forced_kill=0 wait_status=none result=FAIL detail=unexpected-command command=%s\n' \
				"$label" "$pid" "$command" >> "$OBSERVER_SHUTDOWN_FILE"
			return 1
			;;
	esac
	while read -r child_pid; do
		[ -n "$child_pid" ] || continue
		child_command="$(process_command "$child_pid")"
		if [ -n "$child_command" ] && [[ "$child_command" == *"$expected_fragment"* ]]; then
			signal_pid="$child_pid"
			tracer_pid="$child_pid"
			tracer_found=1
			break
		fi
	done < <(ps -axo pid=,ppid= | awk -v parent="$pid" '$2 == parent { print $1 }')
	if [ "$tracer_found" -eq 0 ]; then
		result=FAIL
		detail=tracer-not-found
		forced_kill=1
	fi
	if [ "$tracer_found" -eq 1 ] && (sudo -n kill -INT "$signal_pid" 2>/dev/null || kill -INT "$signal_pid" 2>/dev/null); then
		signal_result=PASS
		if ! wait_for_observer_exit "$pid" "$tracer_pid" 10; then
			forced_kill=1
			result=FAIL
			detail=forced-kill-after-interrupt-timeout
			if ! sudo -n kill -KILL "$signal_pid" 2>/dev/null && ! kill -KILL "$signal_pid" 2>/dev/null; then
				detail=interrupt-timeout-and-kill-failed
			elif ! wait_for_observer_exit "$pid" "$tracer_pid" 5; then
				detail=interrupt-timeout-and-process-still-alive
			fi
		fi
	else
		result=FAIL
		[ "$tracer_found" -eq 1 ] && detail=interrupt-failed
		forced_kill=1
		if ! sudo -n kill -KILL "$signal_pid" 2>/dev/null && ! kill -KILL "$signal_pid" 2>/dev/null; then
			detail=interrupt-and-kill-failed
		elif ! wait_for_observer_exit "$pid" "$tracer_pid" 5; then
			detail=interrupt-failed-and-process-still-alive
		fi
	fi
	if process_alive "$pid"; then
		wait_status=still-alive
	else
		if wait "$pid" 2>/dev/null; then
			wait_status=0
		else
			wait_status=$?
		fi
	fi
	case "$wait_status" in
		0|130)
			;;
		*)
			result=FAIL
			detail="unexpected-wait-status-$wait_status"
			;;
	esac
	if [ "$forced_kill" -eq 1 ]; then
		result=FAIL
	fi
	if [ "$tracer_pid" != "$pid" ] && process_present "$tracer_pid"; then
		forced_kill=1
		result=FAIL
		detail=tracer-still-alive-after-interrupt
		if ! sudo -n kill -KILL "$tracer_pid" 2>/dev/null && ! kill -KILL "$tracer_pid" 2>/dev/null; then
			detail=tracer-still-alive-and-kill-failed
		elif ! wait_for_observer_exit "$pid" "$tracer_pid" 5; then
			detail=tracer-still-alive-after-kill
		fi
	fi
	if [ "$forced_kill" -eq 0 ] && [ "$signal_result" = PASS ] && \
		! process_alive "$pid" && ! process_present "$tracer_pid"; then
		if [ -z "$trace_path" ] || {
			[ -e "$trace_path" ] &&
			! grep -Ei '^dtrace: (failed|error)' "$trace_path" >/dev/null 2>&1;
		}; then
			flush_result=PASS
		else
			result=FAIL
			detail=trace-incomplete-or-observer-error
		fi
	fi
	if [ "$flush_result" != PASS ]; then
		result=FAIL
	fi
	printf 'label=%s owner_pid=%s tracer_pid=%s signal=SIGINT forced_kill=%s wait_status=%s flush_result=%s result=%s detail=%s\n' \
		"$label" "$pid" "$tracer_pid" "$forced_kill" "$wait_status" "$flush_result" "$result" "$detail" >> "$OBSERVER_SHUTDOWN_FILE"
	[ "$result" = PASS ]
}

stop_helper_process() {
	local label="$1"
	local pid="$2"
	local expected_fragment="$3"
	local command
	local forced_kill=0
	local wait_status=0
	local result=PASS
	local detail=clean

	[ -n "$pid" ] || return 0
	if ! process_alive "$pid"; then
		return 0
	fi
	command="$(process_command "$pid")"
	case "$command" in
		*"$expected_fragment"*)
			;;
		*)
			record "cleanup refused helper label=$label pid=$pid command=$command expected=$expected_fragment"
			return 1
			;;
	esac
	if ! kill -TERM "$pid" 2>/dev/null; then
		result=FAIL
		detail=terminate-failed
		forced_kill=1
		if ! kill -KILL "$pid" 2>/dev/null; then
			detail=terminate-and-kill-failed
		elif ! wait_for_exit "$pid" 5; then
			detail=terminate-failed-and-process-still-alive
		fi
	else
		if ! wait_for_exit "$pid" 10; then
			forced_kill=1
			result=FAIL
			detail=forced-kill-after-terminate-timeout
			if ! kill -KILL "$pid" 2>/dev/null; then
				detail=terminate-timeout-and-kill-failed
			elif ! wait_for_exit "$pid" 5; then
				detail=terminate-timeout-and-process-still-alive
			fi
		fi
	fi
	if process_alive "$pid"; then
		wait_status=still-alive
	else
		if wait "$pid" 2>/dev/null; then
			wait_status=0
		else
			wait_status=$?
		fi
	fi
	case "$wait_status" in
		0|130|143)
			;;
		*)
			result=FAIL
			detail="unexpected-wait-status-$wait_status"
			;;
	esac
	if [ "$forced_kill" -eq 1 ]; then
		result=FAIL
	fi
	printf 'label=%s pid=%s forced_kill=%s wait_status=%s result=%s detail=%s\n' \
		"$label" "$pid" "$forced_kill" "$wait_status" "$result" "$detail" >> "$OBSERVER_SHUTDOWN_FILE"
	[ "$result" = PASS ]
}

stop_lifecycle_observer_control() {
	local stop_failed=0
	if [ -n "$CONTROL_DTRACE_PID" ]; then
		stop_observer_process "lifecycle-dtrace" "$CONTROL_DTRACE_PID" "dtrace" "$CONTROL_TRACE" || stop_failed=1
	fi
	stop_helper_process "lifecycle-control" "$CONTROL_HELPER_PID" "python" || stop_failed=1
	CONTROL_DTRACE_PID=""
	CONTROL_HELPER_PID=""
	return "$stop_failed"
}

stop_spawn_observer_control() {
	local stop_failed=0
	if [ -n "$SPAWN_CONTROL_OBSERVER_PID" ]; then
		stop_observer_process "spawn-dtrace" "$SPAWN_CONTROL_OBSERVER_PID" "dtrace" "$SPAWN_CONTROL_TRACE" || stop_failed=1
	fi
	stop_helper_process "spawn-control-child" "$SPAWN_CONTROL_CHILD_PID" "sleep" || stop_failed=1
	stop_helper_process "spawn-control" "$SPAWN_CONTROL_HELPER_PID" "python" || stop_failed=1
	SPAWN_CONTROL_OBSERVER_PID=""
	SPAWN_CONTROL_HELPER_PID=""
	return "$stop_failed"
}

control_observer_unavailable() {
	local detail="$*"
	if [ -n "$CONTROL_RELEASE" ]; then
		touch "$CONTROL_RELEASE"
	fi
	stop_lifecycle_observer_control || true
	unavailable "$detail; see lifecycle-observer-control.txt and lifecycle-observer-control-trace.txt"
}

run_lifecycle_observer_control() {
	local control_log="$EVIDENCE_DIR/lifecycle-observer-control-helper.log"
	local dtrace_program
	local helper_status=0
	local child_pid
	CONTROL_READY="$RUN_ROOT/observer-control-ready"
	CONTROL_RELEASE="$RUN_ROOT/observer-control-release"
	CONTROL_RESULT="$RUN_ROOT/observer-control-result"
	CONTROL_TRACE="$EVIDENCE_DIR/lifecycle-observer-control-trace.txt"
	rm -f "$CONTROL_READY" "$CONTROL_RELEASE" "$CONTROL_RESULT" "$CONTROL_TRACE"
	{
		echo "observer=dtrace syscall write readiness and fork:return"
		echo "control=python os.fork child os._exit without exec"
		echo "result=NOT_RUN"
	} > "$EVIDENCE_DIR/lifecycle-observer-control.txt"
	if [ ! -x /usr/sbin/dtrace ]; then
		control_observer_unavailable "/usr/sbin/dtrace is unavailable"
	fi
	python3 - "$CONTROL_READY" "$CONTROL_RELEASE" "$CONTROL_RESULT" > "$control_log" 2>&1 <<'PY' &
import os
import sys
import time

ready_path, release_path, result_path = sys.argv[1:]
with open(ready_path, "w", encoding="utf-8") as ready:
    ready.write(str(os.getpid()) + "\n")
    ready.flush()
while not os.path.exists(release_path):
    os.write(1, b"observer-heartbeat\n")
    time.sleep(0.01)
child_pid = os.fork()
if child_pid == 0:
    os._exit(0)
with open(result_path, "w", encoding="utf-8") as result:
    result.write(str(child_pid) + "\n")
_, status = os.waitpid(child_pid, 0)
if status != 0:
    raise SystemExit(1)
PY
	CONTROL_HELPER_PID=$!
	if ! wait_for_file "$CONTROL_READY" 10; then
		control_observer_unavailable "fork observer control helper did not become ready"
	fi
	CONTROL_PID="$(tr -d '[:space:]' < "$CONTROL_READY")"
	if ! [[ "$CONTROL_PID" =~ ^[0-9]+$ ]]; then
		control_observer_unavailable "fork observer control reported an invalid parent pid"
	fi
	dtrace_program="BEGIN { printf(\"observer-ready\\n\"); } syscall::write:entry /pid == $CONTROL_PID/ { printf(\"observer-ready\\n\"); } syscall::*fork*:return /pid == $CONTROL_PID && arg1 > 0/ { printf(\"fork parent=%d child=%d\\n\", pid, arg1); }"
	{
		echo "parent_pid=$CONTROL_PID"
		echo "dtrace_program=$dtrace_program"
	} >> "$EVIDENCE_DIR/lifecycle-observer-control.txt"
	start_privileged_observer /usr/sbin/dtrace -q -n "$dtrace_program" > "$CONTROL_TRACE" 2>&1
	CONTROL_DTRACE_PID=$OBSERVER_LAUNCH_PID
	if ! wait_for_trace_marker "$CONTROL_DTRACE_PID" "$CONTROL_TRACE" "observer-ready" 10; then
		control_observer_unavailable "fork observer control did not report dtrace readiness"
	fi
	touch "$CONTROL_RELEASE"
	if ! wait_for_file "$CONTROL_RESULT" 10; then
		control_observer_unavailable "fork observer control child result did not appear"
	fi
	child_pid="$(tr -d '[:space:]' < "$CONTROL_RESULT")"
	if ! [[ "$child_pid" =~ ^[0-9]+$ ]]; then
		control_observer_unavailable "fork observer control reported an invalid child pid"
	fi
	if ! wait_for_exit "$CONTROL_HELPER_PID" 10; then
		control_observer_unavailable "fork observer control helper did not exit"
	fi
	wait "$CONTROL_HELPER_PID" || helper_status=$?
	if [ "$helper_status" -ne 0 ]; then
		control_observer_unavailable "fork observer control helper failed"
	fi
	wait_for_trace_marker "$CONTROL_DTRACE_PID" "$CONTROL_TRACE" \
		"fork parent=$CONTROL_PID child=$child_pid" 10 || true
	if ! stop_lifecycle_observer_control; then
		control_observer_unavailable "fork observer shutdown or flush failed"
	fi
	if ! grep -F -- "observer-ready" "$CONTROL_TRACE" >/dev/null 2>&1 || \
		! grep -F -- "fork parent=$CONTROL_PID child=$child_pid" "$CONTROL_TRACE" >/dev/null 2>&1; then
		control_observer_unavailable "fork observer missed a short-lived fork-only child"
	fi
	{
		echo "child_pid=$child_pid"
		echo "detected=fork parent=$CONTROL_PID child=$child_pid"
		echo "result=PASS"
	} >> "$EVIDENCE_DIR/lifecycle-observer-control.txt"
}

spawn_observer_unavailable() {
	local detail="$*"
	if [ -n "$SPAWN_CONTROL_RELEASE" ]; then
		touch "$SPAWN_CONTROL_RELEASE"
	fi
	stop_spawn_observer_control || true
	unavailable "$detail; see spawn-observer-control.txt and spawn-observer-control-trace.txt"
}

run_spawn_observer_control() {
	local control_log="$EVIDENCE_DIR/spawn-observer-control-helper.log"
	local dtrace_program
	local helper_status=0
	local child_ppid
	SPAWN_CONTROL_READY="$RUN_ROOT/spawn-observer-ready"
	SPAWN_CONTROL_RELEASE="$RUN_ROOT/spawn-observer-release"
	SPAWN_CONTROL_RESULT="$RUN_ROOT/spawn-observer-result"
	SPAWN_CONTROL_TRACE="$EVIDENCE_DIR/spawn-observer-control-trace.txt"
	rm -f "$SPAWN_CONTROL_READY" "$SPAWN_CONTROL_RELEASE" "$SPAWN_CONTROL_RESULT" "$SPAWN_CONTROL_TRACE"
	{
		echo "observer=dtrace syscall write readiness and posix_spawn"
		echo "control=python os.posix_spawn /bin/sleep"
		echo "result=NOT_RUN"
	} > "$EVIDENCE_DIR/spawn-observer-control.txt"
	if [ ! -x /usr/sbin/dtrace ]; then
		spawn_observer_unavailable "/usr/sbin/dtrace is unavailable"
	fi
	python3 - "$SPAWN_CONTROL_READY" "$SPAWN_CONTROL_RELEASE" "$SPAWN_CONTROL_RESULT" > "$control_log" 2>&1 <<'PY' &
import os
import sys
import time

ready_path, release_path, result_path = sys.argv[1:]
parent_pid = os.getpid()
with open(ready_path, "w", encoding="utf-8") as ready:
    ready.write(str(parent_pid) + "\n")
    ready.flush()
while not os.path.exists(release_path):
    os.write(1, b"observer-heartbeat\n")
    time.sleep(0.01)
child_pid = os.posix_spawn("/bin/sleep", ["sleep", "3"], os.environ.copy())
with open(result_path, "w", encoding="utf-8") as result:
    result.write("%d %d\n" % (parent_pid, child_pid))
    result.flush()
_, status = os.waitpid(child_pid, 0)
if status != 0:
    raise SystemExit(1)
PY
	SPAWN_CONTROL_HELPER_PID=$!
	if ! wait_for_file "$SPAWN_CONTROL_READY" 10; then
		spawn_observer_unavailable "exec observer control helper did not become ready"
	fi
	SPAWN_CONTROL_PID="$(tr -d '[:space:]' < "$SPAWN_CONTROL_READY")"
	if ! [[ "$SPAWN_CONTROL_PID" =~ ^[0-9]+$ ]]; then
		spawn_observer_unavailable "exec observer control reported an invalid parent pid"
	fi
	if [ "$SPAWN_CONTROL_PID" != "$SPAWN_CONTROL_HELPER_PID" ]; then
		spawn_observer_unavailable "exec observer control parent pid changed"
	fi
	dtrace_program="BEGIN { printf(\"observer-ready\\n\"); } syscall::write:entry /pid == $SPAWN_CONTROL_PID/ { printf(\"observer-ready\\n\"); } syscall::posix_spawn:entry /pid == $SPAWN_CONTROL_PID/ { printf(\"posix_spawn parent=%d\\n\", pid); }"
	{
		echo "parent_pid=$SPAWN_CONTROL_PID"
		echo "dtrace_program=$dtrace_program"
	} >> "$EVIDENCE_DIR/spawn-observer-control.txt"
	start_privileged_observer /usr/sbin/dtrace -q -n "$dtrace_program" > "$SPAWN_CONTROL_TRACE" 2>&1
	SPAWN_CONTROL_OBSERVER_PID=$OBSERVER_LAUNCH_PID
	if ! wait_for_trace_marker "$SPAWN_CONTROL_OBSERVER_PID" "$SPAWN_CONTROL_TRACE" "observer-ready" 10; then
		spawn_observer_unavailable "exec observer control did not report dtrace readiness"
	fi
	touch "$SPAWN_CONTROL_RELEASE"
	if ! wait_for_file "$SPAWN_CONTROL_RESULT" 10; then
		spawn_observer_unavailable "exec observer control child result did not appear"
	fi
	if ! read -r SPAWN_CONTROL_PARENT_PID SPAWN_CONTROL_CHILD_PID < "$SPAWN_CONTROL_RESULT"; then
		spawn_observer_unavailable "exec observer control result could not be read"
	fi
	if ! [[ "$SPAWN_CONTROL_PARENT_PID" =~ ^[0-9]+$ ]] || ! [[ "$SPAWN_CONTROL_CHILD_PID" =~ ^[0-9]+$ ]]; then
		spawn_observer_unavailable "exec observer control reported invalid parent or child pid"
	fi
	if [ "$SPAWN_CONTROL_PARENT_PID" != "$SPAWN_CONTROL_PID" ] || [ "$SPAWN_CONTROL_CHILD_PID" = "$SPAWN_CONTROL_PARENT_PID" ]; then
		spawn_observer_unavailable "exec observer control parent-child attribution is inconsistent"
	fi
	if ! child_ppid="$(ps -p "$SPAWN_CONTROL_CHILD_PID" -o ppid= 2>/dev/null | tr -d '[:space:]')"; then
		spawn_observer_unavailable "exec observer control could not inspect child pid=$SPAWN_CONTROL_CHILD_PID"
	fi
	if [ "$child_ppid" != "$SPAWN_CONTROL_PARENT_PID" ]; then
		spawn_observer_unavailable "exec observer control child pid=$SPAWN_CONTROL_CHILD_PID has ppid=$child_ppid expected=$SPAWN_CONTROL_PARENT_PID"
	fi
	if ! wait_for_trace_marker "$SPAWN_CONTROL_OBSERVER_PID" "$SPAWN_CONTROL_TRACE" \
		"posix_spawn parent=$SPAWN_CONTROL_PARENT_PID" 10; then
		spawn_observer_unavailable "exec observer control missed the parent posix_spawn event"
	fi
	if ! wait_for_exit "$SPAWN_CONTROL_HELPER_PID" 10; then
		spawn_observer_unavailable "exec observer control helper did not exit"
	fi
	wait "$SPAWN_CONTROL_HELPER_PID" || helper_status=$?
	if [ "$helper_status" -ne 0 ]; then
		spawn_observer_unavailable "exec observer control helper failed"
	fi
	if ! process_alive "$SPAWN_CONTROL_OBSERVER_PID"; then
		spawn_observer_unavailable "exec observer control dtrace exited before intentional shutdown"
	fi
	if ! stop_spawn_observer_control; then
		spawn_observer_unavailable "exec observer shutdown or flush failed"
	fi
	grep -F -- "posix_spawn parent=$SPAWN_CONTROL_PARENT_PID" "$SPAWN_CONTROL_TRACE" > "$EVIDENCE_DIR/spawn-observer-control-events.txt" ||
		spawn_observer_unavailable "exec observer control missed the parent posix_spawn event"
	{
		echo "parent_pid=$SPAWN_CONTROL_PARENT_PID"
		echo "child_pid=$SPAWN_CONTROL_CHILD_PID"
		echo "child_ppid=$child_ppid"
		echo "detected=posix_spawn parent=$SPAWN_CONTROL_PARENT_PID child=$SPAWN_CONTROL_CHILD_PID"
		echo "attribution=posix_spawn parent=$SPAWN_CONTROL_PARENT_PID child=$SPAWN_CONTROL_CHILD_PID child_ppid=$child_ppid"
		cat "$EVIDENCE_DIR/spawn-observer-control-events.txt"
		echo "result=PASS"
	} >> "$EVIDENCE_DIR/spawn-observer-control.txt"
}

start_pid_observer() {
	local target_pid="$1"
	local trace="$TARGET_TRACE_DIR/$target_pid.txt"
	local exec_trace="$TARGET_EXEC_DIR/$target_pid.txt"
	local fork_trace="$TARGET_FORK_DIR/$target_pid.txt"
	local observer_pid
	local exec_observer_pid
	local fork_observer_pid
	local fork_program
	if ! [[ "$target_pid" =~ ^[0-9]+$ ]]; then
		record "PID-filtered lifecycle observer received an invalid pid=$target_pid"
		return 1
	fi
	if grep -E "^${target_pid} " "$TARGET_OBSERVER_FILE" >/dev/null 2>&1; then
		return 0
	fi
	if ! process_alive "$target_pid"; then
		record "PID-filtered lifecycle observer could not attach to exited pid=$target_pid"
		return 1
	fi
	start_privileged_observer /usr/bin/fs_usage -w -F -f filesys "$target_pid" > "$trace" 2>&1
	observer_pid=$OBSERVER_LAUNCH_PID
	start_privileged_observer /usr/bin/fs_usage -w -F -f exec "$target_pid" > "$exec_trace" 2>&1
	exec_observer_pid=$OBSERVER_LAUNCH_PID
	fork_program="syscall::*fork*:return /pid == $target_pid && arg1 > 0/ { printf(\"fork parent=%d child=%d\\n\", pid, arg1); }"
	start_privileged_observer /usr/sbin/dtrace -q -n "$fork_program" > "$fork_trace" 2>&1
	fork_observer_pid=$OBSERVER_LAUNCH_PID
	if ! printf '%s %s %s %s\n' "$target_pid" "$observer_pid" "$exec_observer_pid" "$fork_observer_pid" >> "$TARGET_OBSERVER_FILE"; then
		record "PID-filtered lifecycle observer could not record pid=$target_pid"
		return 1
	fi
	{
		echo "target_pid=$target_pid"
		echo "filesystem_observer_pid=$observer_pid"
		echo "exec_observer_pid=$exec_observer_pid"
		echo "fork_observer_pid=$fork_observer_pid"
		echo "filesystem_filter=/usr/bin/fs_usage -w -F -f filesys $target_pid"
		echo "exec_filter=/usr/bin/fs_usage -w -F -f exec $target_pid"
		echo "fork_filter=/usr/sbin/dtrace -q -n $fork_program"
	} >> "$EVIDENCE_DIR/observer-commands.txt"
	sleep 1
	if ! process_alive "$observer_pid" || ! process_alive "$exec_observer_pid" || ! process_alive "$fork_observer_pid"; then
		record "PID-filtered lifecycle observer failed to stay alive for pid=$target_pid"
		return 1
	fi
}

ensure_observer_coverage() {
	local target_pid
	if [ ! -s "$PID_FILE" ]; then
		printf '%s\n' "pid tracker produced no tracked process ids" > "$OBSERVER_MANAGER_FAILURE_FILE"
		return 1
	fi
	while IFS= read -r target_pid; do
		[ -n "$target_pid" ] || continue
		if ! grep -E "^${target_pid} [0-9]+ [0-9]+ [0-9]+$" "$TARGET_OBSERVER_FILE" >/dev/null 2>&1; then
			if ! start_pid_observer "$target_pid"; then
				[ -s "$OBSERVER_MANAGER_FAILURE_FILE" ] || \
					printf 'PID-filtered lifecycle observer failed for tracked pid=%s\n' "$target_pid" > "$OBSERVER_MANAGER_FAILURE_FILE"
				return 1
			fi
		fi
	done < "$PID_FILE"
}

observe_tracked_pids() {
	local manager_failed=0
	while [ ! -e "$OBSERVER_STOP_FILE" ]; do
		if ! ensure_observer_coverage; then
			manager_failed=1
			[ -s "$OBSERVER_MANAGER_FAILURE_FILE" ] || \
				printf '%s\n' "observer manager could not establish complete tracked PID coverage" > "$OBSERVER_MANAGER_FAILURE_FILE"
			break
		fi
		sleep 0.2
	done
	if [ "$manager_failed" -eq 0 ] && ! ensure_observer_coverage; then
		manager_failed=1
		[ -s "$OBSERVER_MANAGER_FAILURE_FILE" ] || \
			printf '%s\n' "observer manager final coverage pass failed" > "$OBSERVER_MANAGER_FAILURE_FILE"
	fi
	if [ "$manager_failed" -eq 0 ] && ! check_observer_liveness; then
		manager_failed=1
		[ -s "$OBSERVER_MANAGER_FAILURE_FILE" ] || \
			printf '%s\n' "observer exited before intentional shutdown" > "$OBSERVER_MANAGER_FAILURE_FILE"
	fi
	if ! stop_pid_observers; then
		manager_failed=1
	fi
	if [ "$manager_failed" -eq 0 ]; then
		printf '%s\n' 'result=PASS' > "$OBSERVER_STOP_RESULT_FILE"
	else
		printf '%s\n' 'result=FAIL' > "$OBSERVER_STOP_RESULT_FILE"
	fi
	return "$manager_failed"
}

wait_for_observer() {
	local target_pid="$1"
	local seconds="$2"
	local i
	for i in $(seq 1 $((seconds * 10))); do
		if [ -s "$OBSERVER_MANAGER_FAILURE_FILE" ]; then
			return 1
		fi
		if grep -E "^${target_pid} [0-9]+ [0-9]+ [0-9]+$" "$TARGET_OBSERVER_FILE" >/dev/null 2>&1; then
			return 0
		fi
		if [ -n "$OBSERVER_MANAGER_PID" ] && ! process_alive "$OBSERVER_MANAGER_PID"; then
			return 1
		fi
		sleep 0.1
	done
	return 1
}

stop_pid_observers() {
	[ -n "$TARGET_OBSERVER_FILE" ] || return 0
	[ -f "$TARGET_OBSERVER_FILE" ] || return 0
	local target_pid
	local observer_pid
	local exec_observer_pid
	local fork_observer_pid
	local stop_failed=0
	while read -r target_pid observer_pid exec_observer_pid fork_observer_pid; do
		[ -n "$observer_pid" ] || continue
		stop_observer_process "filesystem-pid-$target_pid" "$observer_pid" "fs_usage" "$TARGET_TRACE_DIR/$target_pid.txt" || stop_failed=1
		stop_observer_process "exec-pid-$target_pid" "$exec_observer_pid" "fs_usage" "$TARGET_EXEC_DIR/$target_pid.txt" || stop_failed=1
		stop_observer_process "fork-pid-$target_pid" "$fork_observer_pid" "dtrace" "$TARGET_FORK_DIR/$target_pid.txt" || stop_failed=1
	done < "$TARGET_OBSERVER_FILE"
	if [ "$stop_failed" -ne 0 ]; then
		record "PID-filtered observers did not complete clean intentional shutdown"
		return 1
	fi
	TRACE_STOPPED=1
	record "PID-filtered fs_usage observers stopped and flushed"
}

assemble_pid_trace() {
	TRACE="$EVIDENCE_DIR/fs_usage.txt"
	: > "$TRACE"
	while read -r target_pid observer_pid exec_observer_pid fork_observer_pid; do
		[ -n "$target_pid" ] || continue
		printf '# observer-pid=%s\n' "$target_pid" >> "$TRACE"
		cat "$TARGET_TRACE_DIR/$target_pid.txt" >> "$TRACE" || fail "filesystem observer evidence" "could not read pid=$target_pid trace"
	done < "$TARGET_OBSERVER_FILE"
}

check_observer_liveness() {
	local target_pid
	local observer_pid
	local exec_observer_pid
	local fork_observer_pid
	local observer_failed=0
	while read -r target_pid observer_pid exec_observer_pid fork_observer_pid; do
		[ -n "$target_pid" ] || continue
		if ! process_alive "$observer_pid"; then
			printf 'target_pid=%s observer=filesystem observer_pid=%s state=exited\n' \
				"$target_pid" "$observer_pid" >> "$EVIDENCE_DIR/lifecycle-observer-status.txt"
			observer_failed=1
		else
			printf 'target_pid=%s observer=filesystem observer_pid=%s state=alive\n' \
				"$target_pid" "$observer_pid" >> "$EVIDENCE_DIR/lifecycle-observer-status.txt"
		fi
		if ! process_alive "$exec_observer_pid"; then
			printf 'target_pid=%s observer=exec observer_pid=%s state=exited\n' \
				"$target_pid" "$exec_observer_pid" >> "$EVIDENCE_DIR/lifecycle-observer-status.txt"
			observer_failed=1
		else
			printf 'target_pid=%s observer=exec observer_pid=%s state=alive\n' \
				"$target_pid" "$exec_observer_pid" >> "$EVIDENCE_DIR/lifecycle-observer-status.txt"
		fi
		if ! process_alive "$fork_observer_pid"; then
			printf 'target_pid=%s fork_observer_pid=%s state=exited\n' \
				"$target_pid" "$fork_observer_pid" >> "$EVIDENCE_DIR/lifecycle-observer-status.txt"
			observer_failed=1
		else
			printf 'target_pid=%s fork_observer_pid=%s state=alive\n' \
				"$target_pid" "$fork_observer_pid" >> "$EVIDENCE_DIR/lifecycle-observer-status.txt"
		fi
	done < "$TARGET_OBSERVER_FILE"
	return "$observer_failed"
}

check_process_observer_coverage() {
	local target_pid
	local tracked_pid
	local observer_pid
	local exec_observer_pid
	local fork_observer_pid
	local exec_trace
	local fork_trace
	local fork_events
	local event
	local child_pid
	: > "$EVIDENCE_DIR/descendant-fork-events.txt"
	: > "$EVIDENCE_DIR/descendant-spawn-events.txt"
	if [ -n "$OBSERVER_MANAGER_FAILURE_FILE" ] && [ -s "$OBSERVER_MANAGER_FAILURE_FILE" ]; then
		unavailable "observer manager could not establish complete tracked PID coverage"
	fi
	if [ ! -s "$PID_FILE" ]; then
		unavailable "pid tracker produced no tracked process ids"
	fi
	while IFS= read -r tracked_pid; do
		[ -n "$tracked_pid" ] || continue
		if ! [[ "$tracked_pid" =~ ^[0-9]+$ ]]; then
			unavailable "pid tracker recorded an invalid pid=$tracked_pid"
		fi
		if ! grep -E "^${tracked_pid} [0-9]+ [0-9]+ [0-9]+$" "$TARGET_OBSERVER_FILE" >/dev/null 2>&1; then
			unavailable "tracked pid has no independently attached observer pid=$tracked_pid"
		fi
	done < "$PID_FILE"
	while read -r target_pid observer_pid exec_observer_pid fork_observer_pid; do
		[ -n "$target_pid" ] || continue
		if ! grep -Fx "$target_pid" "$PID_FILE" >/dev/null 2>&1; then
			unavailable "observer row is not present in tracked PID history pid=$target_pid"
		fi
		exec_trace="$TARGET_EXEC_DIR/$target_pid.txt"
		fork_trace="$TARGET_FORK_DIR/$target_pid.txt"
		if [ ! -s "$TARGET_TRACE_DIR/$target_pid.txt" ]; then
			unavailable "PID-filtered fs_usage captured no filesystem events for pid=$target_pid"
		fi
		if [ ! -s "$exec_trace" ]; then
			unavailable "PID-filtered process observer captured no exec events for pid=$target_pid"
		fi
		if [ ! -e "$fork_trace" ]; then
			unavailable "fork observer evidence is missing for pid=$target_pid"
		fi
		if grep -Ei '^dtrace: (failed|error)' "$fork_trace" >/dev/null 2>&1; then
			unavailable "fork observer reported an error for pid=$target_pid"
		fi
		fork_events="$EVIDENCE_DIR/.fork-events-$target_pid"
		if grep -E '^fork parent=[0-9]+ child=[0-9]+$' "$fork_trace" > "$fork_events"; then
			cat "$fork_events" >> "$EVIDENCE_DIR/descendant-fork-events.txt"
			while IFS= read -r event; do
				if ! [[ "$event" =~ ^fork\ parent=([0-9]+)\ child=([0-9]+)$ ]]; then
					unavailable "fork observer emitted an invalid event for pid=$target_pid"
				fi
				if [ "${BASH_REMATCH[1]}" != "$target_pid" ]; then
					unavailable "fork observer attributed an event to the wrong parent pid=$target_pid"
				fi
				child_pid="${BASH_REMATCH[2]}"
				if ! grep -E "^${child_pid} [0-9]+ [0-9]+ [0-9]+$" "$TARGET_OBSERVER_FILE" >/dev/null 2>&1; then
					unavailable "forked descendant has no independently attached observer parent=$target_pid child=$child_pid"
				fi
			done < "$fork_events"
		fi
		rm -f "$fork_events"
		if grep -Ei '(^|[^[:alnum:]_])(spawn|posix_spawn)([^[:alnum:]_]|$)' "$exec_trace" >> "$EVIDENCE_DIR/descendant-spawn-events.txt"; then
			record "PID-filtered exec observer captured a spawn event for pid=$target_pid"
		fi
	done < "$TARGET_OBSERVER_FILE"
}

assert_alive() {
	local criterion="$1"
	local pid="$2"
	process_alive "$pid" || fail "$criterion" "pid=$pid is not alive"
}

assert_file() {
	local criterion="$1"
	local path="$2"
	[ -e "$path" ] || fail "$criterion" "missing path=$path"
}

assert_nonempty() {
	local criterion="$1"
	local path="$2"
	[ -s "$path" ] || fail "$criterion" "empty path=$path"
}

assert_equal() {
	local criterion="$1"
	local expected="$2"
	local actual="$3"
	[ "$actual" = "$expected" ] || fail "$criterion" "expected=$expected actual=$actual"
}

assert_not_equal() {
	local criterion="$1"
	local left="$2"
	local right="$3"
	[ "$left" != "$right" ] || fail "$criterion" "values=$left"
}

assert_grep() {
	local criterion="$1"
	local pattern="$2"
	local path="$3"
	grep -F "$pattern" "$path" >/dev/null 2>&1 || fail "$criterion" "pattern=$pattern path=$path"
}

require_tool() {
	local tool="$1"
	command -v "$tool" >/dev/null 2>&1 || unavailable "$tool is unavailable"
}

descendants() {
	local parent="$1"
	local child
	for child in $(pgrep -P "$parent" 2>/dev/null || true); do
		printf '%s\n' "$child"
		descendants "$child"
	done
}

refresh_pid_file() {
	local snapshot="${PID_FILE}.snapshot"
	local merged="${PID_FILE}.merged"
	local pid
	local i
	for i in $(seq 1 100); do
		if mkdir "$PID_LOCK_DIR" 2>/dev/null; then
			break
		fi
		if [ "$i" -eq 100 ]; then
			printf '%s\n' "pid tracker could not acquire its lock" > "$EVIDENCE_DIR/pid-tracking-failure.txt"
			return 1
		fi
		sleep 0.05
	done
	: > "$snapshot"
	while IFS= read -r pid; do
		[ -n "$pid" ] || continue
		printf '%s\n' "$pid" >> "$snapshot"
		descendants "$pid" >> "$snapshot"
	done < "$PID_ROOTS_FILE"
	if [ -s "$PID_FILE" ]; then
		cat "$PID_FILE" >> "$snapshot"
	fi
	if ! sort -nu "$snapshot" > "$merged"; then
		printf '%s\n' "pid tracker could not sort its snapshot" > "$EVIDENCE_DIR/pid-tracking-failure.txt"
		rm -f "$snapshot" "$merged"
		rmdir "$PID_LOCK_DIR" 2>/dev/null || true
		return 1
	fi
	if ! mv "$merged" "$PID_FILE"; then
		printf '%s\n' "pid tracker could not preserve its history" > "$EVIDENCE_DIR/pid-tracking-failure.txt"
		rm -f "$snapshot" "$merged"
		rmdir "$PID_LOCK_DIR" 2>/dev/null || true
		return 1
	fi
	rm -f "$snapshot"
	rmdir "$PID_LOCK_DIR" 2>/dev/null || true
}

track_pids() {
	while [ ! -e "$TRACK_STOP_FILE" ]; do
		if ! refresh_pid_file; then
			return 1
		fi
		sleep 0.2
	done
}

start_pid_tracking() {
	PID_ROOTS_FILE="$EVIDENCE_DIR/telegramd-root-pids.txt"
	PID_FILE="$EVIDENCE_DIR/telegramd-pids.txt"
	PID_LOCK_DIR="$EVIDENCE_DIR/.telegramd-pids.lock"
	TRACK_STOP_FILE="$EVIDENCE_DIR/.stop-pid-tracker"
	OBSERVER_STOP_FILE="$EVIDENCE_DIR/.stop-observer-manager"
	OBSERVER_MANAGER_FAILURE_FILE="$EVIDENCE_DIR/observer-manager-failure.txt"
	OBSERVER_STOP_RESULT_FILE="$EVIDENCE_DIR/observer-stop-result.txt"
	: > "$PID_ROOTS_FILE"
	: > "$PID_FILE"
	rm -f "$TRACK_STOP_FILE" "$OBSERVER_STOP_FILE" \
		"$EVIDENCE_DIR/pid-tracking-failure.txt" "$OBSERVER_MANAGER_FAILURE_FILE" \
		"$OBSERVER_STOP_RESULT_FILE"
	rmdir "$PID_LOCK_DIR" 2>/dev/null || true
	printf '%s\n' "$FORK_PID" >> "$PID_ROOTS_FILE"
	refresh_pid_file
	track_pids &
	TRACKER_PID=$!
	observe_tracked_pids &
	OBSERVER_MANAGER_PID=$!
}

add_pid_root() {
	printf '%s\n' "$1" >> "$PID_ROOTS_FILE"
	refresh_pid_file
}

stop_pid_tracking() {
	[ -n "$TRACKER_PID" ] || return 0
	local stop_failed=0
	local forced_kill=0
	local wait_status=0
	if ! touch "$TRACK_STOP_FILE"; then
		stop_failed=1
	fi
	if process_alive "$TRACKER_PID"; then
		if ! wait_for_exit "$TRACKER_PID" 5; then
			if ! kill -TERM "$TRACKER_PID" 2>/dev/null; then
				stop_failed=1
			fi
			if ! wait_for_exit "$TRACKER_PID" 5; then
				forced_kill=1
				stop_failed=1
				if ! kill -KILL "$TRACKER_PID" 2>/dev/null || ! wait_for_exit "$TRACKER_PID" 5; then
					stop_failed=1
				fi
			fi
		fi
	fi
	if process_alive "$TRACKER_PID"; then
		wait_status=still-alive
	else
		if wait "$TRACKER_PID" 2>/dev/null; then
			wait_status=0
		else
			wait_status=$?
		fi
	fi
	case "$wait_status" in
		0|143)
			;;
		*)
			stop_failed=1
			;;
	esac
	if ! refresh_pid_file; then
		stop_failed=1
	fi
	if [ "$forced_kill" -eq 1 ]; then
		record "pid tracker required forced kill"
	fi
	TRACKER_PID=""
	return "$stop_failed"
}

stop_observer_manager() {
	[ -n "$OBSERVER_MANAGER_PID" ] || return 0
	local stop_failed=0
	local forced_kill=0
	local wait_status=0
	if ! touch "$OBSERVER_STOP_FILE"; then
		stop_failed=1
	fi
	if process_alive "$OBSERVER_MANAGER_PID"; then
		if ! wait_for_exit "$OBSERVER_MANAGER_PID" 10; then
			if ! kill -TERM "$OBSERVER_MANAGER_PID" 2>/dev/null; then
				stop_failed=1
			fi
			if ! wait_for_exit "$OBSERVER_MANAGER_PID" 5; then
				forced_kill=1
				stop_failed=1
				if ! kill -KILL "$OBSERVER_MANAGER_PID" 2>/dev/null || ! wait_for_exit "$OBSERVER_MANAGER_PID" 5; then
					stop_failed=1
				fi
			fi
		fi
	fi
	if process_alive "$OBSERVER_MANAGER_PID"; then
		wait_status=still-alive
	else
		if wait "$OBSERVER_MANAGER_PID" 2>/dev/null; then
			wait_status=0
		else
			wait_status=$?
		fi
	fi
	if [ "$wait_status" != 0 ] || [ -s "$OBSERVER_MANAGER_FAILURE_FILE" ]; then
		stop_failed=1
	fi
	if [ ! -s "$OBSERVER_STOP_RESULT_FILE" ] || ! grep -Fx 'result=PASS' "$OBSERVER_STOP_RESULT_FILE" >/dev/null 2>&1; then
		stop_failed=1
	fi
	if [ "$forced_kill" -eq 1 ]; then
		record "observer manager required forced kill"
	fi
	printf 'observer_manager_pid=%s forced_kill=%s wait_status=%s result=%s\n' \
		"$OBSERVER_MANAGER_PID" "$forced_kill" "$wait_status" \
		"$([ "$stop_failed" -eq 0 ] && echo PASS || echo FAIL)" >> "$OBSERVER_SHUTDOWN_FILE"
	OBSERVER_MANAGER_PID=""
	return "$stop_failed"
}

capture_endpoints() {
	local hash="$1"
	local output="$2"
	local criterion="$3"
	if ! find "$SOCKET_ROOT" -type s -name "$hash-*" -print > "$output" 2> "$EVIDENCE_DIR/endpoint-search-errors.txt"; then
		fail "$criterion" "socket search failed"
	fi
}

wait_for_endpoint() {
	local hash="$1"
	local output="$2"
	local criterion="$3"
	local seconds="$4"
	local i
	for i in $(seq 1 "$seconds"); do
		capture_endpoints "$hash" "$output" "$criterion"
		if [ -s "$output" ]; then
			return 0
		fi
		sleep 1
	done
	fail "$criterion" "endpoint did not appear within ${seconds}s"
}

count_live_fork_processes() {
	local count=0
	local pid
	local command
	: > "$EVIDENCE_DIR/telegramd-live-pids.txt"
	while IFS= read -r pid; do
		[ -n "$pid" ] || continue
		if process_alive "$pid"; then
			command="$(process_command "$pid")"
			case "$command" in
				"$FORK_EXE"|"$FORK_EXE "*)
					printf '%s\n' "$pid" >> "$EVIDENCE_DIR/telegramd-live-pids.txt"
					count=$((count + 1))
					;;
			esac
		fi
	done < "$PID_FILE"
	printf '%s\n' "$count" > "$EVIDENCE_DIR/telegramd-process-count.txt"
	printf '%s\n' "$count"
}

assert_live_fork_process_count() {
	local criterion="$1"
	local expected="$2"
	local actual
	refresh_pid_file
	if [ -e "$EVIDENCE_DIR/pid-tracking-failure.txt" ]; then
		fail "$criterion" "pid tracker reported incomplete coverage"
	fi
	actual="$(count_live_fork_processes)"
	assert_equal "$criterion" "$expected" "$actual"
}

stop_trace() {
	if [ "$TRACE_STOPPED" -eq 1 ] || [ -z "$TARGET_OBSERVER_FILE" ]; then
		return 0
	fi
	local stop_failed=0
	local manager_started=0
	local manager_stop_ok=1
	if [ -n "$OBSERVER_MANAGER_PID" ]; then
		manager_started=1
		if ! stop_observer_manager; then
			stop_failed=1
			manager_stop_ok=0
		fi
	fi
	if [ "$manager_started" -eq 1 ]; then
		if [ "$manager_stop_ok" -eq 1 ] && grep -Fx 'result=PASS' "$OBSERVER_STOP_RESULT_FILE" >/dev/null 2>&1; then
			TRACE_STOPPED=1
		else
			stop_failed=1
			stop_pid_observers || true
		fi
	else
		if [ -n "$PID_FILE" ] && [ -f "$PID_FILE" ]; then
			if ! ensure_observer_coverage; then
				stop_failed=1
			fi
		fi
		stop_pid_observers || stop_failed=1
	fi
	return "$stop_failed"
}

terminate_recorded_process() {
	local pid="$1"
	local expected="$2"
	local command
	if ! process_alive "$pid"; then
		return 0
	fi
	command="$(process_command "$pid")"
	case "$command" in
		"$expected"*)
			if ! kill -TERM "$pid" 2>/dev/null && process_alive "$pid"; then
				record "cleanup failed to terminate pid=$pid command=$command"
				return 1
			fi
			;;
		*)
			record "cleanup refused pid=$pid command=$command expected=$expected"
			return 1
			;;
	esac
	local i
	for i in $(seq 1 10); do
		if ! process_alive "$pid"; then
			return 0
		fi
		sleep 1
	done
	command="$(process_command "$pid")"
	case "$command" in
		"$expected"*)
			if ! kill -KILL "$pid" 2>/dev/null && process_alive "$pid"; then
				record "cleanup failed to kill pid=$pid command=$command"
				return 1
			fi
			;;
		*)
			record "cleanup refused escalation pid=$pid command=$command expected=$expected"
			return 1
			;;
	esac
	if process_alive "$pid"; then
		record "cleanup process remained alive after escalation pid=$pid command=$command"
		return 1
	fi
	record "cleanup used forced kill pid=$pid command=$command"
	return 0
}

is_descendant_of() {
	local child="$1"
	local root="$2"
	local parent
	local i
	for i in $(seq 1 30); do
		parent="$(ps -p "$child" -o ppid= 2>/dev/null | tr -d '[:space:]')"
		[ -n "$parent" ] || return 1
		[ "$parent" = "$root" ] && return 0
		[ "$parent" = 1 ] && return 1
		child="$parent"
	done
	return 1
}

terminate_descendant_process() {
	local pid="$1"
	local root="$2"
	local command
	if ! process_alive "$pid"; then
		return 0
	fi
	if ! is_descendant_of "$pid" "$root"; then
		record "cleanup refused descendant pid=$pid root=$root"
		return 1
	fi
	command="$(process_command "$pid")"
	if ! kill -TERM "$pid" 2>/dev/null && process_alive "$pid"; then
		record "cleanup failed to terminate descendant pid=$pid command=$command root=$root"
		return 1
	fi
	local i
	for i in $(seq 1 10); do
		if ! process_alive "$pid"; then
			return 0
		fi
		sleep 1
	done
	if is_descendant_of "$pid" "$root"; then
		if ! kill -KILL "$pid" 2>/dev/null && process_alive "$pid"; then
			record "cleanup failed to kill descendant pid=$pid command=$command root=$root"
			return 1
		fi
		if process_alive "$pid"; then
			record "cleanup descendant remained alive after escalation pid=$pid command=$command root=$root"
			return 1
		fi
		record "cleanup used forced kill descendant pid=$pid command=$command root=$root"
		return 0
	fi
	record "cleanup refused descendant escalation pid=$pid command=$command root=$root"
	return 1
}

terminate_process_tree() {
	local root="$1"
	local expected="$2"
	local pid
	local pids
	local tree_failed=0
	if ! pids="$({ descendants "$root"; printf '%s\n' "$root"; } | sort -rn)"; then
		record "cleanup could not enumerate process tree root=$root"
		return 1
	fi
	for pid in $pids; do
		if [ "$pid" = "$root" ]; then
			terminate_recorded_process "$pid" "$expected" || tree_failed=1
		else
			terminate_descendant_process "$pid" "$root" || tree_failed=1
		fi
	done
	return "$tree_failed"
}

terminate_unclaimed_launcher() {
	local pid="$1"
	local command
	local i
	if ! process_alive "$pid"; then
		return 0
	fi
	command="$(process_command "$pid")"
	case "$command" in
		*'kill -STOP $$'*)
			kill -CONT "$pid" 2>/dev/null || true
			kill -TERM "$pid" 2>/dev/null || true
			;;
		*)
			record "cleanup refused unclaimed launcher pid=$pid command=$command"
			return 1
			;;
	esac
	for i in $(seq 1 10); do
		if ! process_alive "$pid"; then
			return 0
		fi
		sleep 1
	done
	command="$(process_command "$pid")"
	case "$command" in
		*'kill -STOP $$'*)
			kill -KILL "$pid" 2>/dev/null || true
			return 0
			;;
		*)
			record "cleanup refused unclaimed launcher escalation pid=$pid command=$command"
			return 1
			;;
	esac
}

cleanup() {
	local exit_code=$?
	local cleanup_failed=0
	set +e
	if [ -n "$CONTROL_RELEASE" ]; then
		touch "$CONTROL_RELEASE" 2>/dev/null || true
	fi
	if [ -n "$SPAWN_CONTROL_RELEASE" ]; then
		touch "$SPAWN_CONTROL_RELEASE" 2>/dev/null || true
	fi
	stop_lifecycle_observer_control || cleanup_failed=1
	stop_spawn_observer_control || cleanup_failed=1
	stop_pid_tracking || cleanup_failed=1
	stop_trace || cleanup_failed=1
	if [ -n "$SECOND_PID" ]; then
		terminate_recorded_process "$SECOND_PID" "$FORK_EXE" || cleanup_failed=1
		wait "$SECOND_PID" 2>/dev/null || true
	fi
	if [ -n "$QUIT_PID" ]; then
		terminate_recorded_process "$QUIT_PID" "$FORK_EXE" || cleanup_failed=1
		wait "$QUIT_PID" 2>/dev/null || true
	fi
	if [ -n "$RELAUNCH_PID" ]; then
		kill -CONT "$RELAUNCH_PID" 2>/dev/null || true
		terminate_process_tree "$RELAUNCH_PID" "$FORK_EXE" || cleanup_failed=1
	fi
	if [ -n "$FORK_PID" ]; then
		kill -CONT "$FORK_PID" 2>/dev/null || true
		terminate_process_tree "$FORK_PID" "$FORK_EXE" || cleanup_failed=1
	fi
	if [ -n "$LAUNCHED_PID" ]; then
		terminate_unclaimed_launcher "$LAUNCHED_PID" || cleanup_failed=1
	fi
	if [ -n "$OFFICIAL_PID" ]; then
		terminate_process_tree "$OFFICIAL_PID" "$OFFICIAL_APP" || cleanup_failed=1
	fi
	if [ "$MOUNTED" -eq 1 ]; then
		if ! hdiutil detach "$MOUNT_PATH" >> "$EVIDENCE_DIR/cleanup.txt" 2>&1; then
			cleanup_failed=1
		fi
		MOUNTED=0
	fi
	if [ -n "$RUN_ROOT" ]; then
		case "$RUN_ROOT" in
			/private/tmp/main701.*|/tmp/main701.*)
				if find "$RUN_ROOT" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
					rm -rf "$RUN_ROOT"
				else
					rmdir "$RUN_ROOT"
				fi
				;;
		*)
			record "cleanup refused unsafe root=$RUN_ROOT"
			cleanup_failed=1
			;;
		esac
	fi
	if [ "$cleanup_failed" -ne 0 ]; then
		record "cleanup failure detected"
		if [ "$exit_code" -eq 0 ]; then
			RESULT="FAIL"
			printf 'FAIL: cleanup did not complete safely\n' > "$EVIDENCE_DIR/status.txt"
			exit_code=1
		fi
	fi
	if [ "$exit_code" -ne 0 ]; then
		if [ ! -s "$EVIDENCE_DIR/status.txt" ]; then
			printf 'FAIL: unclassified command or assertion failure line=%s command=%s exit_code=%s\n' \
				"${LAST_ERROR_LINE:-unknown}" "${LAST_ERROR_COMMAND:-unknown}" "$exit_code" \
				> "$EVIDENCE_DIR/status.txt"
			record "failure unclassified line=${LAST_ERROR_LINE:-unknown} command=${LAST_ERROR_COMMAND:-unknown}"
		fi
		ps -axo pid=,ppid=,command= > "$EVIDENCE_DIR/failure-process-table.txt"
		{
			echo "official_pid=$OFFICIAL_PID"
			echo "official_command=$(if [ -n "$OFFICIAL_PID" ]; then process_command "$OFFICIAL_PID"; fi)"
			echo "telegramd_pid=$FORK_PID"
			echo "telegramd_command=$(if [ -n "$FORK_PID" ]; then process_command "$FORK_PID"; fi)"
		} > "$EVIDENCE_DIR/failure-snapshot.txt"
	fi
	{
		echo "result=$RESULT"
		echo "exit_code=$exit_code"
		echo "cleanup_failed=$cleanup_failed"
		echo "run_root_removed=$([ -n "$RUN_ROOT" ] && [ ! -e "$RUN_ROOT" ] && echo yes || echo no)"
	} >> "$EVIDENCE_DIR/cleanup.txt"
	exit "$exit_code"
}
capture_error() {
	LAST_ERROR_COMMAND="$BASH_COMMAND"
	LAST_ERROR_LINE="$LINENO"
}

trap capture_error ERR
trap cleanup EXIT

{
	echo "process_wait_seconds=30"
	echo "support_path_wait_seconds=60"
	echo "working_dir_log_wait_seconds=60"
	echo "second_launch_wait_seconds=5"
	echo "quit_wait_seconds=40"
	echo "relaunch_process_wait_seconds=30"
	echo "observer_lifetime=from-suspended-fork-launch-through-quit-relaunch"
	echo "observer_mode=kernel-filtered-fs_usage-exec-and-dtrace-fork-observer-per-tracked-pid"
	echo "descendant_policy=every-tracked-pid-must-have-independent-observer"
	echo "fork_observer=event-driven-dtrace-syscall-fork-return"
	echo "fork_observer_control=readiness-gated-dtrace-write-and-short-lived-fork-only-child"
	echo "spawn_observer_control=readiness-gated-dtrace-write-and-posix_spawn-parent-child-attribution"
	echo "pid_snapshot_interval_seconds=0.2"
} > "$EVIDENCE_DIR/timeouts.txt"

{
		echo "uname -m: $(uname -m)"
	sw_vers || true
	xcodebuild -version || true
	brew --version || true
	echo "runner_image: ${ImageOS:-unknown} ${ImageVersion:-unknown}"
} > "$EVIDENCE_DIR/preflight.txt" 2>&1

[ "$(uname -m)" = "arm64" ] || unavailable "runner is not arm64"
require_tool python3
PYTHON3="$(command -v python3)"
require_tool sw_vers
require_tool xcodebuild
require_tool brew
require_tool curl
require_tool hdiutil
require_tool ditto
require_tool plutil
require_tool osascript
[ -x /usr/bin/fs_usage ] || unavailable "/usr/bin/fs_usage is unavailable"
sudo -n true || unavailable "non-interactive sudo is unavailable"
pgrep -x WindowServer >/dev/null || unavailable "WindowServer is unavailable"
if ! launchctl print "gui/$(id -u)" > "$EVIDENCE_DIR/launchctl.txt" 2>&1; then
	unavailable "GUI launch context is unavailable"
fi
if ! python3 "$PARSER" --self-test > "$EVIDENCE_DIR/observer-sensitivity.txt"; then
	fail "observer sensitivity" "self-test failed"
fi

if ! APP_PATH="$(canonical_path "$APP_PATH")"; then
	fail "artifact canonical path" "could not canonicalize app path"
fi
PLIST="$APP_PATH/Contents/Info.plist"
FORK_EXE="$APP_PATH/Contents/MacOS/Telegramd"
[ -d "$APP_PATH" ] || fail "artifact app" "missing app=$APP_PATH"
[ -x "$FORK_EXE" ] || fail "artifact executable" "missing executable=$FORK_EXE"
if ! plutil -p "$PLIST" > "$EVIDENCE_DIR/plist.txt"; then
	fail "artifact plist" "could not read plist=$PLIST"
fi
if ! executable_name="$(plutil -extract CFBundleExecutable raw -o - "$PLIST")"; then
	fail "artifact executable metadata" "could not read CFBundleExecutable"
fi
if ! bundle_name="$(plutil -extract CFBundleName raw -o - "$PLIST")"; then
	fail "artifact bundle metadata" "could not read CFBundleName"
fi
if ! bundle_identifier="$(plutil -extract CFBundleIdentifier raw -o - "$PLIST")"; then
	fail "artifact identifier metadata" "could not read CFBundleIdentifier"
fi
assert_equal "artifact executable metadata" "Telegramd" "$executable_name"
assert_equal "artifact bundle metadata" "Telegramd" "$bundle_name"
assert_equal "artifact identifier metadata" "com.adambenhassen.telegramd" "$bundle_identifier"
if plutil -extract CFBundleURLTypes xml1 -o - "$PLIST" >/dev/null 2>&1; then
	fail "artifact URL schemes" "CFBundleURLTypes is present"
fi
for updater in \
	"$APP_PATH/Contents/Frameworks/Updater" \
	"$APP_PATH/Contents/Helpers/Updater"; do
	if [ -e "$updater" ]; then
		fail "artifact updater exclusion" "unexpected path=$updater"
	fi
done
if ! find "$APP_PATH" -type f -perm -111 -iname 'Updater' -print -quit > "$EVIDENCE_DIR/updater-search.txt" 2> "$EVIDENCE_DIR/updater-search-errors.txt"; then
	fail "artifact updater search" "recursive executable search failed"
fi
if [ -s "$EVIDENCE_DIR/updater-search.txt" ]; then
	fail "artifact updater exclusion" "recursive updater found"
fi
if ! {
	file "$FORK_EXE"
	lipo -archs "$FORK_EXE"
} > "$EVIDENCE_DIR/architecture.txt"; then
	fail "artifact architecture" "file or lipo failed"
fi
if ! archs="$(lipo -archs "$FORK_EXE")"; then
	fail "artifact architecture" "could not read architecture"
fi
assert_equal "artifact architecture" "arm64" "$archs"

SOURCE_PORTABLE_ROOT="$APP_PATH/Contents/MacOS/TelegramForcePortable"
if [ -e "$SOURCE_PORTABLE_ROOT" ]; then
	fail "artifact portable fixture isolation" "uploaded app already contains path=$SOURCE_PORTABLE_ROOT"
fi

RUN_ROOT="$(mktemp -d /tmp/main701.XXXXXX)"
RUN_ROOT="$(canonical_path "$RUN_ROOT")"
FORK_APP="$RUN_ROOT/Telegramd-test.app"
if ! ditto "$APP_PATH" "$FORK_APP"; then
	unavailable "could not create an isolated test copy of Telegramd.app"
fi
FORK_EXE="$FORK_APP/Contents/MacOS/Telegramd"
if ! shasum -a 256 "$APP_PATH/Contents/MacOS/Telegramd" "$FORK_EXE" > "$EVIDENCE_DIR/test-copy-hashes.txt"; then
	fail "test app copy" "could not hash artifact and isolated test copy"
fi
shasum -a 256 "$APP_PATH/Contents/MacOS/Telegramd" > "$EVIDENCE_DIR/artifact-source-hash-before.txt"
HOME_ROOT="$RUN_ROOT/home"
export HOME="$HOME_ROOT"
SUPPORT_ROOT="$HOME_ROOT/Library/Application Support"
OLD="$SUPPORT_ROOT/Telegram Desktop"
NEW="$SUPPORT_ROOT/Telegramd"
PORTABLE_ROOT="$FORK_APP/Contents/MacOS/TelegramForcePortable"
HOSTILE_WORKDIR="$PORTABLE_ROOT"
PORTABLE_CANARY="$PORTABLE_ROOT/tdata/alpha"
mkdir -p "$HOME_ROOT/Library/Application Support" \
	"$OLD/tdata" \
	"$OLD/tupdates/ready/Telegram.app/Contents/MacOS" \
	"$PORTABLE_ROOT/tdata"
printf 'MAIN701_OFFICIAL_CANARY\n' > "$OLD/tdata/official-canary"
printf 'MAIN701_RC1_CANARY\n' > "$OLD/tdata/rc1-canary"
printf 'MAIN701_READY_CANARY\n' > "$OLD/tupdates/ready/Telegram.app/Contents/MacOS/Telegram"
printf 'MAIN701_LOG_CANARY\n' > "$OLD/log-canary.txt"
printf 'MAIN701_PORTABLE_CANARY\n' > "$PORTABLE_CANARY"
printf '%s\n' "$HOSTILE_WORKDIR" > "$EVIDENCE_DIR/hostile-workdir.txt"
if [ -e "$NEW" ]; then
	fail "fresh Telegramd namespace" "pre-existing path=$NEW"
fi

CANARIES=(
	"$OLD/tdata/official-canary"
	"$OLD/tdata/rc1-canary"
	"$OLD/tupdates/ready/Telegram.app/Contents/MacOS/Telegram"
	"$OLD/log-canary.txt"
	"$PORTABLE_CANARY"
)
for canary in "${CANARIES[@]}"; do
	shasum -a 256 "$canary"
done > "$EVIDENCE_DIR/canaries-before.txt"
if ! find "$PORTABLE_ROOT" -print | LC_ALL=C sort > "$EVIDENCE_DIR/portable-tree-before.txt"; then
	fail "portable fixture availability" "could not snapshot executable-adjacent portable input"
fi
run_lifecycle_observer_control
run_spawn_observer_control

OFFICIAL_DMG="$RUN_ROOT/official.dmg"
if ! curl --fail --location --silent --show-error \
	--output "$OFFICIAL_DMG" "$OFFICIAL_DMG_URL"; then
	unavailable "official DMG download failed"
fi
if ! echo "$OFFICIAL_DMG_SHA256  $OFFICIAL_DMG" | shasum -a 256 -c - > "$EVIDENCE_DIR/official-dmg.txt"; then
	fail "official DMG integrity" "pinned SHA-256 mismatch"
fi
MOUNT_PATH="$RUN_ROOT/mount"
mkdir -p "$MOUNT_PATH"
if ! hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT_PATH" "$OFFICIAL_DMG" > "$EVIDENCE_DIR/mount.txt"; then
	unavailable "official DMG mount failed"
fi
MOUNTED=1
OFFICIAL_SOURCE="$(find "$MOUNT_PATH" -maxdepth 2 -type d -name '*.app' -print -quit 2>/dev/null || true)"
if [ -z "$OFFICIAL_SOURCE" ]; then
	fail "official app extraction" "no .app found in pinned DMG"
fi
OFFICIAL_APP="$RUN_ROOT/Official Telegram.app"
if ! ditto "$OFFICIAL_SOURCE" "$OFFICIAL_APP"; then
	fail "official app extraction" "ditto failed"
fi
if ! hdiutil detach "$MOUNT_PATH" >> "$EVIDENCE_DIR/mount.txt"; then
	unavailable "official DMG detach failed"
fi
MOUNTED=0
OFFICIAL_PLIST="$OFFICIAL_APP/Contents/Info.plist"
if ! OFFICIAL_EXE_NAME="$(plutil -extract CFBundleExecutable raw -o - "$OFFICIAL_PLIST")"; then
	fail "official identity" "could not read executable metadata"
fi
if ! OFFICIAL_BUNDLE_ID="$(plutil -extract CFBundleIdentifier raw -o - "$OFFICIAL_PLIST")"; then
	fail "official identity" "could not read bundle identifier"
fi
OFFICIAL_EXE="$OFFICIAL_APP/Contents/MacOS/$OFFICIAL_EXE_NAME"
if ! plutil -p "$OFFICIAL_PLIST" > "$EVIDENCE_DIR/official-identity.txt"; then
	fail "official identity" "could not dump plist"
fi
{
	echo "executable=$OFFICIAL_EXE"
	echo "bundle_identifier=$OFFICIAL_BUNDLE_ID"
} >> "$EVIDENCE_DIR/official-identity.txt"
assert_file "official executable" "$OFFICIAL_EXE"
[ -x "$OFFICIAL_EXE" ] || fail "official executable" "not executable=$OFFICIAL_EXE"

env HOME="$HOME_ROOT" "$OFFICIAL_EXE" -noupdate -debug -workdir "$OLD" > "$EVIDENCE_DIR/official.log" 2>&1 &
OFFICIAL_PID=$!
wait_for_process "$OFFICIAL_PID" 30 || fail "official process lifetime" "pid=$OFFICIAL_PID did not stay alive"
printf '%s\n' "$OFFICIAL_PID" > "$EVIDENCE_DIR/official-pid.txt"
if ! focus_application_process "$OFFICIAL_PID" "$EVIDENCE_DIR/official-activate.txt" 30; then
	unavailable "System Events could not focus the official process"
fi
if ! FRONTMOST_BEFORE="$(osascript -e 'tell application "System Events" to get bundle identifier of first application process whose frontmost is true')"; then
	unavailable "System Events cannot report the frontmost application"
fi
printf '%s\n' "$FRONTMOST_BEFORE" > "$EVIDENCE_DIR/frontmost-before.txt"
assert_equal "official frontmost identity" "$OFFICIAL_BUNDLE_ID" "$FRONTMOST_BEFORE"

OLD_HASH="$(printf '%s' "$OLD" | md5 -q)"
SOCKET_ROOT="$(canonical_path /tmp)"
wait_for_endpoint "$OLD_HASH" "$EVIDENCE_DIR/official-endpoints.txt" "official endpoint" 30

TARGET_TRACE_DIR="$EVIDENCE_DIR/fs_usage-pid"
TARGET_EXEC_DIR="$EVIDENCE_DIR/fs_usage-exec"
TARGET_FORK_DIR="$EVIDENCE_DIR/fs_usage-fork"
TARGET_OBSERVER_FILE="$EVIDENCE_DIR/telegramd-observers.txt"
mkdir -p "$TARGET_TRACE_DIR" "$TARGET_EXEC_DIR" "$TARGET_FORK_DIR"
: > "$TARGET_OBSERVER_FILE"
: > "$EVIDENCE_DIR/observer-commands.txt"
: > "$EVIDENCE_DIR/lifecycle-observer-status.txt"
launch_suspended "$EVIDENCE_DIR/telegramd.log" -noupdate -debug -workdir "$HOSTILE_WORKDIR"
FORK_PID="$LAUNCHED_PID"
LAUNCHED_PID=""
start_pid_tracking
if ! wait_for_observer "$FORK_PID" 10; then
	unavailable "PID-filtered lifecycle observer did not attach to primary pid=$FORK_PID"
fi
if ! kill -CONT "$FORK_PID"; then
	fail "Telegramd launch resume" "could not resume pid=$FORK_PID"
fi
wait_for_process "$FORK_PID" 30 || fail "Telegramd process lifetime" "pid=$FORK_PID did not stay alive"
printf '%s\n' "$FORK_PID" > "$EVIDENCE_DIR/telegramd-pid.txt"
if ! wait_for_file "$NEW/tdata" 60; then
	fail "Telegramd namespace creation" "missing path=$NEW/tdata"
fi
WORKING_LOG=""
for i in $(seq 1 60); do
	WORKING_LOG="$(find "$NEW" -maxdepth 1 -type f -name 'log*.txt' -print -quit 2>/dev/null || true)"
	if [ -n "$WORKING_LOG" ] && grep -F "Working dir: $NEW" "$WORKING_LOG" >/dev/null 2>&1; then
		break
	fi
	WORKING_LOG=""
	sleep 1
done
if [ -z "$WORKING_LOG" ]; then
	fail "Telegramd startup log" "working-directory record did not appear"
fi
cp "$WORKING_LOG" "$EVIDENCE_DIR/telegramd-working-dir.log"
assert_grep "Telegramd startup log" "Working dir: $NEW" "$WORKING_LOG"
process_command "$FORK_PID" > "$EVIDENCE_DIR/telegramd-command.txt"

NEW_HASH="$(printf '%s' "$NEW" | md5 -q)"
capture_endpoints "$OLD_HASH" "$EVIDENCE_DIR/official-endpoints.txt" "official endpoint"
wait_for_endpoint "$NEW_HASH" "$EVIDENCE_DIR/telegramd-endpoints.txt" "Telegramd endpoint" 30
assert_nonempty "official endpoint" "$EVIDENCE_DIR/official-endpoints.txt"
assert_nonempty "Telegramd endpoint" "$EVIDENCE_DIR/telegramd-endpoints.txt"
official_endpoint="$(head -n 1 "$EVIDENCE_DIR/official-endpoints.txt")"
telegramd_endpoint="$(head -n 1 "$EVIDENCE_DIR/telegramd-endpoints.txt")"
assert_not_equal "endpoint independence" "$official_endpoint" "$telegramd_endpoint"

if ! FRONTMOST_AFTER="$(osascript -e 'tell application "System Events" to get bundle identifier of first application process whose frontmost is true')"; then
	unavailable "System Events cannot report the post-launch frontmost application"
fi
printf '%s\n' "$FRONTMOST_AFTER" > "$EVIDENCE_DIR/frontmost-after.txt"
assert_not_equal "Telegramd launch focus" "$OFFICIAL_BUNDLE_ID" "$FRONTMOST_AFTER"
assert_alive "official coexistence" "$OFFICIAL_PID"
official_command="$(process_command "$OFFICIAL_PID")"
assert_equal "official command stability" "$OFFICIAL_EXE -noupdate -debug -workdir $OLD" "$official_command"

launch_suspended "$EVIDENCE_DIR/telegramd-second.log" -noupdate -debug -workdir "$HOSTILE_WORKDIR"
SECOND_PID="$LAUNCHED_PID"
LAUNCHED_PID=""
add_pid_root "$SECOND_PID"
if ! wait_for_observer "$SECOND_PID" 10; then
	unavailable "PID-filtered lifecycle observer did not attach to second-launch pid=$SECOND_PID"
fi
if ! kill -CONT "$SECOND_PID"; then
	fail "second launch resume" "could not resume pid=$SECOND_PID"
fi
if ! wait_for_exit "$SECOND_PID" 5; then
	fail "second launch bounded wait" "pid=$SECOND_PID did not exit within 5s"
fi
if ! wait "$SECOND_PID"; then
	fail "second launch result" "pid=$SECOND_PID returned failure"
fi
if ! ps -axo pid=,ppid=,command= > "$EVIDENCE_DIR/process-table-after-second.txt"; then
	fail "second launch process table" "ps failed"
fi
assert_alive "second launch official coexistence" "$OFFICIAL_PID"
assert_alive "second launch primary process" "$FORK_PID"
assert_live_fork_process_count "second launch process count" 1
cp "$EVIDENCE_DIR/telegramd-live-pids.txt" "$EVIDENCE_DIR/telegramd-live-pids-after-second.txt"
cp "$EVIDENCE_DIR/telegramd-process-count.txt" "$EVIDENCE_DIR/telegramd-process-count-after-second.txt"

launch_suspended "$EVIDENCE_DIR/telegramd-quit.log" -noupdate -debug -workdir "$HOSTILE_WORKDIR" -quit
QUIT_PID="$LAUNCHED_PID"
LAUNCHED_PID=""
add_pid_root "$QUIT_PID"
if ! wait_for_observer "$QUIT_PID" 10; then
	unavailable "PID-filtered lifecycle observer did not attach to quit pid=$QUIT_PID"
fi
if ! kill -CONT "$QUIT_PID"; then
	fail "quit launch resume" "could not resume pid=$QUIT_PID"
fi
if ! wait_for_exit "$QUIT_PID" 40; then
	fail "quit bounded wait" "pid=$QUIT_PID did not exit within 40s"
fi
if ! wait "$QUIT_PID"; then
	fail "quit result" "pid=$QUIT_PID returned failure"
fi
if ! wait_for_exit "$FORK_PID" 40; then
	fail "Telegramd quit lifecycle" "primary pid=$FORK_PID did not exit within 40s"
fi
assert_alive "official survives quit" "$OFFICIAL_PID"

launch_suspended "$EVIDENCE_DIR/telegramd-relaunch.log" -noupdate -debug -workdir "$HOSTILE_WORKDIR"
RELAUNCH_PID="$LAUNCHED_PID"
LAUNCHED_PID=""
add_pid_root "$RELAUNCH_PID"
if ! wait_for_observer "$RELAUNCH_PID" 10; then
	unavailable "PID-filtered lifecycle observer did not attach to relaunch pid=$RELAUNCH_PID"
fi
if ! kill -CONT "$RELAUNCH_PID"; then
	fail "Telegramd relaunch resume" "could not resume pid=$RELAUNCH_PID"
fi
wait_for_process "$RELAUNCH_PID" 30 || fail "Telegramd relaunch process lifetime" "pid=$RELAUNCH_PID did not stay alive"
if ! wait_for_file "$NEW/tdata" 60; then
	fail "Telegramd relaunch namespace" "missing path=$NEW/tdata"
fi
RELAUNCH_WORKING_LOG=""
for i in $(seq 1 60); do
	RELAUNCH_WORKING_LOG="$(find "$NEW" -maxdepth 1 -type f -name 'log*.txt' -print -quit 2>/dev/null || true)"
	if [ -n "$RELAUNCH_WORKING_LOG" ] && grep -F "Working dir: $NEW" "$RELAUNCH_WORKING_LOG" >/dev/null 2>&1; then
		break
	fi
	RELAUNCH_WORKING_LOG=""
	sleep 1
done
if [ -z "$RELAUNCH_WORKING_LOG" ]; then
	fail "Telegramd relaunch startup log" "working-directory record did not appear"
fi
cp "$RELAUNCH_WORKING_LOG" "$EVIDENCE_DIR/telegramd-relaunch-working-dir.log"
assert_grep "Telegramd relaunch startup log" "Working dir: $NEW" "$RELAUNCH_WORKING_LOG"
wait_for_endpoint "$OLD_HASH" "$EVIDENCE_DIR/official-endpoints-after-relaunch.txt" "official relaunch endpoint" 30
wait_for_endpoint "$NEW_HASH" "$EVIDENCE_DIR/telegramd-endpoints-after-relaunch.txt" "Telegramd relaunch endpoint" 30
assert_nonempty "official relaunch endpoint" "$EVIDENCE_DIR/official-endpoints-after-relaunch.txt"
assert_nonempty "Telegramd relaunch endpoint" "$EVIDENCE_DIR/telegramd-endpoints-after-relaunch.txt"
official_relaunch_endpoint="$(head -n 1 "$EVIDENCE_DIR/official-endpoints-after-relaunch.txt")"
telegramd_relaunch_endpoint="$(head -n 1 "$EVIDENCE_DIR/telegramd-endpoints-after-relaunch.txt")"
assert_not_equal "relaunch endpoint independence" "$official_relaunch_endpoint" "$telegramd_relaunch_endpoint"
if ! FRONTMOST_RELAUNCH="$(osascript -e 'tell application "System Events" to get bundle identifier of first application process whose frontmost is true')"; then
	unavailable "System Events cannot report the post-relaunch frontmost application"
fi
printf '%s\n' "$FRONTMOST_RELAUNCH" > "$EVIDENCE_DIR/frontmost-relaunch.txt"
assert_not_equal "Telegramd relaunch focus" "$OFFICIAL_BUNDLE_ID" "$FRONTMOST_RELAUNCH"
assert_alive "official survives relaunch" "$OFFICIAL_PID"
relaunch_official_command="$(process_command "$OFFICIAL_PID")"
assert_equal "official relaunch command stability" "$OFFICIAL_EXE -noupdate -debug -workdir $OLD" "$relaunch_official_command"
assert_alive "Telegramd relaunch process" "$RELAUNCH_PID"
assert_live_fork_process_count "relaunch process count" 1
cp "$EVIDENCE_DIR/telegramd-live-pids.txt" "$EVIDENCE_DIR/telegramd-live-pids-after-relaunch.txt"
cp "$EVIDENCE_DIR/telegramd-process-count.txt" "$EVIDENCE_DIR/telegramd-process-count-after-relaunch.txt"
if ! ps -axo pid=,ppid=,command= > "$EVIDENCE_DIR/process-table.txt"; then
	fail "relaunch process table" "ps failed"
fi

if ! stop_pid_tracking; then
	unavailable "pid tracker shutdown or final snapshot failed"
fi
if ! stop_trace; then
	unavailable "observer shutdown or flush failed"
fi
if [ -e "$EVIDENCE_DIR/pid-tracking-failure.txt" ]; then
	unavailable "pid tracker reported incomplete observer coverage"
fi
awk 'NR == FNR { roots[$1] = 1; next } !($1 in roots) { print }' \
	"$PID_ROOTS_FILE" "$PID_FILE" > "$EVIDENCE_DIR/telegramd-descendants.txt"
check_process_observer_coverage
assemble_pid_trace
parser_status=0
python3 "$PARSER" "$TRACE" "$OLD" "$EVIDENCE_DIR/telegramd-pids.txt" "$EVIDENCE_DIR/fs_usage-report.txt" || parser_status=$?
case "$parser_status" in
	0) ;;
	2) unavailable "filesystem observer PID attribution is incomplete; see fs_usage-report.txt" ;;
	*) fail "Telegramd official-namespace isolation" "filesystem observer reported a violation or ambiguous event" ;;
esac

if ! for canary in "${CANARIES[@]}"; do
	shasum -a 256 "$canary"
done > "$EVIDENCE_DIR/canaries-after.txt"; then
	fail "canary availability" "could not hash all canaries after lifecycle"
fi
if ! cmp "$EVIDENCE_DIR/canaries-before.txt" "$EVIDENCE_DIR/canaries-after.txt"; then
	fail "official canary integrity" "official or portable canary changed"
fi
if ! find "$PORTABLE_ROOT" -print | LC_ALL=C sort > "$EVIDENCE_DIR/portable-tree-after.txt"; then
	fail "portable fixture availability" "could not snapshot executable-adjacent portable input after lifecycle"
fi
if ! cmp "$EVIDENCE_DIR/portable-tree-before.txt" "$EVIDENCE_DIR/portable-tree-after.txt"; then
	fail "portable override isolation" "executable-adjacent portable input changed during lifecycle"
fi
if [ -e "$SOURCE_PORTABLE_ROOT" ]; then
	fail "artifact portable fixture isolation" "test fixture leaked into uploaded app path=$SOURCE_PORTABLE_ROOT"
fi
shasum -a 256 "$APP_PATH/Contents/MacOS/Telegramd" > "$EVIDENCE_DIR/artifact-source-hash-after.txt"
if ! cmp "$EVIDENCE_DIR/artifact-source-hash-before.txt" "$EVIDENCE_DIR/artifact-source-hash-after.txt"; then
	fail "artifact source integrity" "uploaded executable changed during isolation gate"
fi
RESULT="PASS"
printf 'PASS\n' > "$EVIDENCE_DIR/status.txt"
