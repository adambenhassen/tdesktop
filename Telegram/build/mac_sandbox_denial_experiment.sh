#!/usr/bin/env bash

set -Eeuo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: mac_sandbox_denial_experiment.sh TELEGRAMD_APP EVIDENCE_DIR" >&2
	exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_PATH=""
EVIDENCE_DIR="$2"
mkdir -p "$EVIDENCE_DIR"
EVIDENCE_DIR="$(cd "$EVIDENCE_DIR" && pwd)"
APP_EXE=""
STATUS_FILE="$EVIDENCE_DIR/status.txt"
RUN_ROOT=""
READ_CANARY=""
WRITE_CANARY=""
FIRST_PID=""
RELAUNCH_PID=""
LIFECYCLE_PIDS=(0)

capture_canaries_after() {
	if [ -z "$READ_CANARY" ] || [ -z "$WRITE_CANARY" ] \
		|| [ ! -f "$READ_CANARY" ] || [ ! -f "$WRITE_CANARY" ] \
		|| [ ! -f "$EVIDENCE_DIR/canaries-before.txt" ]; then
		printf 'unavailable'
		return 0
	fi
	if ! shasum -a 256 "$READ_CANARY" "$WRITE_CANARY" > "$EVIDENCE_DIR/canaries-after.txt"; then
		printf 'unavailable'
		return 0
	fi
	if cmp -s "$EVIDENCE_DIR/canaries-before.txt" "$EVIDENCE_DIR/canaries-after.txt"; then
		printf 'unchanged'
	else
		diff -u "$EVIDENCE_DIR/canaries-before.txt" "$EVIDENCE_DIR/canaries-after.txt" \
			> "$EVIDENCE_DIR/canaries-diff.txt" || true
		printf 'changed'
	fi
}

fail() {
	local detail="$*"
	local canaries
	canaries="$(capture_canaries_after)"
	printf 'FAIL: %s; official_root_canary_hashes=%s\n' "$detail" "$canaries" \
		| tee "$STATUS_FILE" >&2
	exit 1
}

unavailable() {
	local detail="$*"
	local canaries
	canaries="$(capture_canaries_after)"
	printf 'UNAVAILABLE: %s; official_root_canary_hashes=%s\n' "$detail" "$canaries" \
		| tee "$STATUS_FILE" >&2
	exit 2
}

process_alive() {
	local state
	[ -n "$1" ] && kill -0 "$1" 2>/dev/null || return 1
	state="$(ps -p "$1" -o state= 2>/dev/null | tr -d '[:space:]' || true)"
	case "$state" in
		""|Z*) return 1 ;;
	esac
	return 0
}

wait_for_process() {
	local pid="$1"
	local attempt
	for ((attempt = 0; attempt < 30; attempt++)); do
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
	local attempt
	for ((attempt = 0; attempt < seconds; attempt++)); do
		if ! process_alive "$pid"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

cleanup() {
	local status=$?
	trap - EXIT
	trap - ERR
	local pid
	for pid in "${LIFECYCLE_PIDS[@]}"; do
		if [ "$pid" -eq 0 ]; then
			continue
		fi
		if process_alive "$pid"; then
			kill -TERM "$pid" 2>/dev/null || true
		fi
		wait "$pid" 2>/dev/null || true
	done
	if [ -n "$RUN_ROOT" ] && [ -d "$RUN_ROOT" ]; then
		if ! rm -rf "$RUN_ROOT"; then
			printf 'FAIL: temporary experiment cleanup failed: %s\n' "$RUN_ROOT" | tee "$STATUS_FILE" >&2
			status=1
		fi
	fi
	exit "$status"
}

unexpected_error() {
	local status=$?
	trap - ERR
	printf 'FAIL: unexpected command failure status=%s line=%s command=%s\n' \
		"$status" "$LINENO" "${BASH_COMMAND:-unknown}" | tee "$STATUS_FILE" >&2
	exit "$status"
}

trap cleanup EXIT
trap unexpected_error ERR

mkdir -p "$EVIDENCE_DIR"
if [ ! -d "$1" ]; then
	fail "Telegramd app bundle is missing: $1"
fi
APP_PATH="$(cd "$1" && pwd)"
APP_EXE="$APP_PATH/Contents/MacOS/Telegramd"
if [ ! -x "$APP_EXE" ]; then
	fail "Telegramd executable is missing or not executable: $APP_EXE"
fi
if [ "$(uname -m)" != "arm64" ]; then
	unavailable "runner architecture is $(uname -m), expected arm64"
fi
if ! command -v sandbox-exec > "$EVIDENCE_DIR/sandbox-exec-command.txt" 2>&1; then
	unavailable "sandbox-exec is not available on this runner"
fi
if ! command -v clang > "$EVIDENCE_DIR/clang-command.txt" 2>&1; then
	unavailable "clang is not available on this runner"
fi
if ! command -v python3 > "$EVIDENCE_DIR/python-command.txt" 2>&1; then
	unavailable "python3 is not available on this runner"
fi

RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/main917-sandbox.XXXXXX")"
HOME_ROOT="$RUN_ROOT/home"
SUPPORT_ROOT="$HOME_ROOT/Library/Application Support"
OFFICIAL_ROOT="$SUPPORT_ROOT/Telegram Desktop"
TELEGRAMD_ROOT="$SUPPORT_ROOT/Telegramd"
PROFILE="$RUN_ROOT/deny-official-root.sb"
FIXTURE="$RUN_ROOT/sandbox-deny-fixture"
READ_CANARY="$OFFICIAL_ROOT/tdata/official-canary"
WRITE_CANARY="$OFFICIAL_ROOT/tdata/write-canary"
mkdir -p "$OFFICIAL_ROOT/tdata" "$TELEGRAMD_ROOT"
export HOME="$HOME_ROOT"
printf 'MAIN917_OFFICIAL_CANARY\n' > "$READ_CANARY"
printf 'MAIN917_WRITE_CANARY\n' > "$WRITE_CANARY"
shasum -a 256 "$READ_CANARY" "$WRITE_CANARY" > "$EVIDENCE_DIR/canaries-before.txt"
{
	printf 'head_sha=%s\n' "${GITHUB_SHA:-local}"
	printf 'runner_arch=%s\n' "$(uname -m)"
	sw_vers
	command -v sandbox-exec
} > "$EVIDENCE_DIR/environment.txt" 2>&1

python3 - "$PROFILE" "$OFFICIAL_ROOT" <<'PY'
import json
import sys

root = json.dumps(sys.argv[2])
with open(sys.argv[1], "w", encoding="utf-8") as profile:
    profile.write("(version 1)\n(allow default)\n")
    profile.write("(deny file-read* (subpath %s))\n" % root)
    profile.write("(deny file-write* (subpath %s))\n" % root)
PY
cp "$PROFILE" "$EVIDENCE_DIR/deny-official-root.sb"

if ! sandbox-exec -f "$PROFILE" /usr/bin/true > "$EVIDENCE_DIR/sandbox-probe.txt" 2>&1; then
	unavailable "sandbox-exec could not run an allow-default profile; see sandbox-probe.txt"
fi
printf 'probe=passed\n' >> "$EVIDENCE_DIR/sandbox-probe.txt"

if ! clang -std=c11 -Wall -Wextra -Werror \
	"$ROOT/Telegram/build/mac_sandbox_deny_fixture.c" \
	-o "$FIXTURE" > "$EVIDENCE_DIR/fixture-build.txt" 2>&1; then
	fail "could not compile the parent/child denial fixture; see fixture-build.txt"
fi

fixture_status=0
sandbox-exec -f "$PROFILE" "$FIXTURE" "$READ_CANARY" "$WRITE_CANARY" \
	> "$EVIDENCE_DIR/fixture.log" 2>&1 || fixture_status=$?
if [ "$fixture_status" -ne 0 ]; then
	fail "fixture did not observe EPERM for both processes; see fixture.log"
fi
if ! python3 - "$EVIDENCE_DIR/fixture.log" > "$EVIDENCE_DIR/fixture-pids.txt" \
	2> "$EVIDENCE_DIR/fixture-pid-validation.txt" <<'PY'
import sys

text = open(sys.argv[1], encoding="utf-8").read().splitlines()
processes = {}
spawned = None
accesses = []
for line in text:
    if line.startswith("process "):
        fields = dict(item.split("=", 1) for item in line.split()[1:])
        processes[fields["role"]] = (int(fields["pid"]), int(fields["ppid"]))
    elif line.startswith("spawn "):
        fields = dict(item.split("=", 1) for item in line.split()[1:])
        spawned = int(fields["child_pid"])
    elif line.startswith("access "):
        fields = dict(item.split("=", 1) for item in line.split()[1:])
        accesses.append(fields)

if set(processes) != {"parent", "child"}:
    raise SystemExit("fixture did not report exactly one parent and child PID")
if processes["parent"][0] == processes["child"][0] or spawned != processes["child"][0]:
    raise SystemExit("reported child PID does not match the PID returned by fork")
if processes["child"][1] != processes["parent"][0]:
    raise SystemExit("child PID is not parented by the reported fixture parent")
if len(accesses) != 4:
    raise SystemExit("fixture did not report four process-attributed accesses")
if {(access["role"], access["operation"]) for access in accesses} != {
    ("parent", "read"),
    ("parent", "write"),
    ("child", "read"),
    ("child", "write"),
}:
    raise SystemExit("fixture did not report parent and child read and write accesses")
for access in accesses:
    role = access["role"]
    if int(access["pid"]) != processes[role][0]:
        raise SystemExit("access PID does not match its actual fixture process")
    if access["result"] != "denied" or access["errno"] != "1" or access["name"] != "EPERM":
        raise SystemExit("fixture access was not denied with EPERM")
for role, pid in sorted(processes.items()):
    print("%s_pid=%d ppid=%d" % (role, pid[0], pid[1]))
PY
then
	fail "fixture PID or EPERM evidence was incomplete; see fixture-pid-validation.txt"
fi

launch_app() {
	local name="$1"
	local log="$EVIDENCE_DIR/telegramd-$name.log"
	HOME="$HOME_ROOT" sandbox-exec -f "$PROFILE" "$APP_EXE" \
		-noupdate -debug -workdir "$TELEGRAMD_ROOT" > "$log" 2>&1 &
	local pid=$!
	LIFECYCLE_PIDS+=("$pid")
	if ! wait_for_process "$pid"; then
		cat "$log" >&2
		fail "Telegramd $name did not stay alive; see telegramd-$name.log"
	fi
	ps -ww -p "$pid" -o pid=,ppid=,command= > "$EVIDENCE_DIR/telegramd-$name-process.txt"
	printf '%s\n' "$pid" > "$EVIDENCE_DIR/telegramd-$name-pid.txt"
	if [ "$name" = "first" ]; then
		FIRST_PID="$pid"
	else
		RELAUNCH_PID="$pid"
	fi
}

launch_second_instance() {
	local log="$EVIDENCE_DIR/telegramd-second-launch.log"
	HOME="$HOME_ROOT" sandbox-exec -f "$PROFILE" "$APP_EXE" \
		-noupdate -debug -workdir "$TELEGRAMD_ROOT" > "$log" 2>&1 &
	local pid=$!
	LIFECYCLE_PIDS+=("$pid")
	if ! wait_for_exit "$pid" 5; then
		cat "$log" >&2
		fail "Telegramd second launch did not exit within five seconds"
	fi
	if ! wait "$pid"; then
		cat "$log" >&2
		fail "Telegramd second launch returned a failure status"
	fi
	printf '%s\n' "$pid" > "$EVIDENCE_DIR/telegramd-second-launch-pid.txt"
	ps -ww -p "$FIRST_PID" -o pid=,ppid=,command= > "$EVIDENCE_DIR/telegramd-primary-after-second.txt"
	if ! process_alive "$FIRST_PID"; then
		fail "Telegramd primary process exited after the second launch"
	fi
}

quit_instance() {
	local name="$1"
	local pid="$2"
	local log="$EVIDENCE_DIR/telegramd-$name-quit.log"
	HOME="$HOME_ROOT" sandbox-exec -f "$PROFILE" "$APP_EXE" \
		-noupdate -debug -workdir "$TELEGRAMD_ROOT" -quit > "$log" 2>&1 &
	local quit_pid=$!
	LIFECYCLE_PIDS+=("$quit_pid")
	if ! wait_for_exit "$quit_pid" 40; then
		cat "$log" >&2
		fail "Telegramd $name quit request did not exit"
	fi
	if ! wait "$quit_pid"; then
		cat "$log" >&2
		fail "Telegramd $name quit request returned a failure status"
	fi
	if ! wait_for_exit "$pid" 40; then
		cat "$log" >&2
		fail "Telegramd $name process did not exit after quit"
	fi
	if ! wait "$pid"; then
		cat "$log" >&2
		fail "Telegramd $name process returned a failure status after quit"
	fi
}

launch_app first
launch_second_instance
quit_instance first "$FIRST_PID"
launch_app relaunch
if [ ! -d "$TELEGRAMD_ROOT" ]; then
	fail "Telegramd relaunch did not retain its working directory"
fi
if ! process_alive "$RELAUNCH_PID"; then
	fail "Telegramd relaunch process exited before the final canary check"
fi
quit_instance relaunch "$RELAUNCH_PID"
canary_result="$(capture_canaries_after)"
case "$canary_result" in
	unchanged) ;;
	changed) fail "official-root canary hashes changed during the fixture or Telegramd lifecycle" ;;
	*) fail "official-root canary hashes were unavailable after the fixture or Telegramd lifecycle" ;;
esac

printf 'PASS: sandbox-exec denied fixture parent and child filesystem accesses with EPERM; Telegramd second launch, quit, and relaunch succeeded; official-root canary hashes are unchanged.\n' | tee "$STATUS_FILE"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		echo '### MAIN-917 sandbox denial experiment'
		echo '- Allow-default sandbox profile executed successfully.'
		echo '- Fixture parent and short-lived child received EPERM for read and write access attempts; actual PIDs are in the evidence artifact.'
		echo '- Telegramd second launch, quit, and relaunch completed.'
		echo '- Official-root canary hashes were unchanged.'
	} >> "$GITHUB_STEP_SUMMARY"
fi
