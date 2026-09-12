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
FORK_EXE=""
OFFICIAL_PID=""
FORK_PID=""
SECOND_PID=""
QUIT_PID=""
RELAUNCH_PID=""
FS_PID=""
TRACKER_PID=""
PID_ROOTS_FILE=""
PID_FILE=""
TRACK_STOP_FILE=""
MOUNT_PATH=""
MOUNTED=0
TRACE_STOPPED=0
RESULT="FAIL"
LAST_ERROR_COMMAND=""
LAST_ERROR_LINE=""

mkdir -p "$EVIDENCE_DIR"

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
	local temporary="${PID_FILE}.tmp"
	: > "$temporary"
	while IFS= read -r pid; do
		[ -n "$pid" ] || continue
		printf '%s\n' "$pid" >> "$temporary"
		descendants "$pid" >> "$temporary"
	done < "$PID_ROOTS_FILE"
	if ! sort -nu "$temporary" > "$PID_FILE"; then
		printf '%s\n' "pid tracker could not sort its snapshot" > "$EVIDENCE_DIR/pid-tracking-failure.txt"
	fi
	rm -f "$temporary"
}

track_pids() {
	while [ ! -e "$TRACK_STOP_FILE" ]; do
		refresh_pid_file
		sleep 1
	done
}

start_pid_tracking() {
	PID_ROOTS_FILE="$EVIDENCE_DIR/telegramd-root-pids.txt"
	PID_FILE="$EVIDENCE_DIR/telegramd-pids.txt"
	TRACK_STOP_FILE="$EVIDENCE_DIR/.stop-pid-tracker"
	: > "$PID_ROOTS_FILE"
	: > "$PID_FILE"
	rm -f "$TRACK_STOP_FILE" "$EVIDENCE_DIR/pid-tracking-failure.txt"
	printf '%s\n' "$FORK_PID" >> "$PID_ROOTS_FILE"
	refresh_pid_file
	track_pids &
	TRACKER_PID=$!
}

add_pid_root() {
	printf '%s\n' "$1" >> "$PID_ROOTS_FILE"
	refresh_pid_file
}

stop_pid_tracking() {
	[ -n "$TRACKER_PID" ] || return 0
	touch "$TRACK_STOP_FILE"
	if ! wait_for_exit "$TRACKER_PID" 5; then
		kill -TERM "$TRACKER_PID" 2>/dev/null || true
		wait_for_exit "$TRACKER_PID" 5 || kill -KILL "$TRACKER_PID" 2>/dev/null || true
	fi
	wait "$TRACKER_PID" 2>/dev/null || true
	refresh_pid_file
	TRACKER_PID=""
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
	if [ "$TRACE_STOPPED" -eq 1 ] || [ -z "$FS_PID" ]; then
		return
	fi
	if process_alive "$FS_PID"; then
		sudo -n kill -INT "$FS_PID" 2>/dev/null || kill -INT "$FS_PID" 2>/dev/null || true
	fi
	if ! wait_for_exit "$FS_PID" 10; then
		record "fs_usage did not stop after SIGINT; escalating"
		kill -TERM "$FS_PID" 2>/dev/null || true
		if ! wait_for_exit "$FS_PID" 5; then
			kill -KILL "$FS_PID" 2>/dev/null || true
		fi
	fi
	wait "$FS_PID" 2>/dev/null || true
	TRACE_STOPPED=1
	record "fs_usage stopped pid=$FS_PID"
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
			kill -TERM "$pid" 2>/dev/null || true
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
			kill -KILL "$pid" 2>/dev/null || true
			;;
		*)
			record "cleanup refused escalation pid=$pid command=$command expected=$expected"
			return 1
			;;
	esac
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
	kill -TERM "$pid" 2>/dev/null || true
	local i
	for i in $(seq 1 10); do
		if ! process_alive "$pid"; then
			return 0
		fi
		sleep 1
	done
	if is_descendant_of "$pid" "$root"; then
		kill -KILL "$pid" 2>/dev/null || true
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
	pids="$({ descendants "$root"; printf '%s\n' "$root"; } | sort -rn)"
	for pid in $pids; do
		if [ "$pid" = "$root" ]; then
			terminate_recorded_process "$pid" "$expected"
		else
			terminate_descendant_process "$pid" "$root"
		fi
	done
}

cleanup() {
	local exit_code=$?
	local cleanup_failed=0
	set +e
	stop_trace
	stop_pid_tracking
	if [ -n "$SECOND_PID" ]; then
		terminate_recorded_process "$SECOND_PID" "$FORK_EXE" || cleanup_failed=1
		wait "$SECOND_PID" 2>/dev/null || true
	fi
	if [ -n "$QUIT_PID" ]; then
		terminate_recorded_process "$QUIT_PID" "$FORK_EXE" || cleanup_failed=1
		wait "$QUIT_PID" 2>/dev/null || true
	fi
	if [ -n "$RELAUNCH_PID" ]; then
		terminate_process_tree "$RELAUNCH_PID" "$APP_PATH" || cleanup_failed=1
	fi
	if [ -n "$FORK_PID" ]; then
		terminate_process_tree "$FORK_PID" "$APP_PATH" || cleanup_failed=1
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
	echo "second_launch_wait_seconds=30"
	echo "quit_wait_seconds=40"
	echo "relaunch_process_wait_seconds=30"
	echo "observer_lifetime=from-fork-launch-through-quit-relaunch"
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

RUN_ROOT="$(mktemp -d /tmp/main701.XXXXXX)"
RUN_ROOT="$(canonical_path "$RUN_ROOT")"
HOME_ROOT="$RUN_ROOT/home"
export HOME="$HOME_ROOT"
SUPPORT_ROOT="$HOME_ROOT/Library/Application Support"
OLD="$SUPPORT_ROOT/Telegram Desktop"
NEW="$SUPPORT_ROOT/Telegramd"
PORTABLE_ROOT="$APP_PATH/Contents/MacOS/TelegramForcePortable"
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
if ! osascript -e "tell application \"System Events\" to set frontmost of (first application process whose unix id is $OFFICIAL_PID) to true" > "$EVIDENCE_DIR/official-activate.txt" 2>&1; then
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

TRACE="$EVIDENCE_DIR/fs_usage.txt"
sudo -n /usr/bin/fs_usage -w -F -f filesys > "$TRACE" 2>&1 &
FS_PID=$!
sleep 1
assert_alive "filesystem observer startup" "$FS_PID"

env HOME="$HOME_ROOT" "$FORK_EXE" -noupdate -debug -workdir "$OLD" > "$EVIDENCE_DIR/telegramd.log" 2>&1 &
FORK_PID=$!
start_pid_tracking
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

env HOME="$HOME_ROOT" "$FORK_EXE" -noupdate -debug -workdir "$OLD" > "$EVIDENCE_DIR/telegramd-second.log" 2>&1 &
SECOND_PID=$!
add_pid_root "$SECOND_PID"
if ! wait_for_exit "$SECOND_PID" 30; then
	fail "second launch bounded wait" "pid=$SECOND_PID did not exit within 30s"
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

env HOME="$HOME_ROOT" "$FORK_EXE" -noupdate -debug -workdir "$OLD" -quit > "$EVIDENCE_DIR/telegramd-quit.log" 2>&1 &
QUIT_PID=$!
add_pid_root "$QUIT_PID"
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

env HOME="$HOME_ROOT" "$FORK_EXE" -noupdate -debug -workdir "$OLD" > "$EVIDENCE_DIR/telegramd-relaunch.log" 2>&1 &
RELAUNCH_PID=$!
add_pid_root "$RELAUNCH_PID"
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

while IFS= read -r root_pid; do
	[ -n "$root_pid" ] || continue
	descendants "$root_pid"
done < "$PID_ROOTS_FILE" | sort -nu > "$EVIDENCE_DIR/telegramd-descendants.txt"

stop_trace
stop_pid_tracking
if [ -e "$EVIDENCE_DIR/pid-tracking-failure.txt" ]; then
	fail "observer PID coverage" "pid tracker reported incomplete coverage"
fi
if ! python3 "$PARSER" "$TRACE" "$OLD" "$EVIDENCE_DIR/telegramd-pids.txt" "$EVIDENCE_DIR/fs_usage-report.txt"; then
	fail "Telegramd official-namespace isolation" "filesystem observer reported a violation or ambiguous event"
fi

if ! for canary in "${CANARIES[@]}"; do
	shasum -a 256 "$canary"
done > "$EVIDENCE_DIR/canaries-after.txt"; then
	fail "canary availability" "could not hash all canaries after lifecycle"
fi
if ! cmp "$EVIDENCE_DIR/canaries-before.txt" "$EVIDENCE_DIR/canaries-after.txt"; then
	fail "official canary integrity" "official or portable canary changed"
fi
RESULT="PASS"
printf 'PASS\n' > "$EVIDENCE_DIR/status.txt"
