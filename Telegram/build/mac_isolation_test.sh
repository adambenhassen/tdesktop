#!/usr/bin/env bash

set -euo pipefail

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
FS_PID=""
MOUNT_PATH=""
MOUNTED=0
TRACE_STOPPED=0
RESULT="FAIL"

mkdir -p "$EVIDENCE_DIR"

record() {
	printf '%s\n' "$*" >> "$EVIDENCE_DIR/events.txt"
}

canonical_path() {
	python3 - "$1" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
}

unavailable() {
	printf 'UNAVAILABLE: %s\n' "$*" | tee "$EVIDENCE_DIR/status.txt" >&2
	exit 2
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

descendants() {
	local parent="$1"
	local child
	for child in $(pgrep -P "$parent" 2>/dev/null || true); do
		printf '%s\n' "$child"
		descendants "$child"
	done
}

stop_trace() {
	if [ "$TRACE_STOPPED" -eq 1 ] || [ -z "$FS_PID" ]; then
		return
	fi
	if process_alive "$FS_PID"; then
		sudo -n kill -INT "$FS_PID" 2>/dev/null || kill -INT "$FS_PID" 2>/dev/null || true
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

terminate_process_tree() {
	local root="$1"
	local expected="$2"
	local pid
	local pids
	pids="$({ descendants "$root"; printf '%s\n' "$root"; } | sort -rn)"
	for pid in $pids; do
		terminate_recorded_process "$pid" "$expected"
	done
}

cleanup() {
	local exit_code=$?
	set +e
	stop_trace
	if [ -n "$SECOND_PID" ]; then
		terminate_recorded_process "$SECOND_PID" "$FORK_EXE"
		wait "$SECOND_PID" 2>/dev/null || true
	fi
	if [ -n "$FORK_PID" ]; then
		terminate_process_tree "$FORK_PID" "$APP_PATH"
	fi
	if [ -n "$OFFICIAL_PID" ]; then
		terminate_process_tree "$OFFICIAL_PID" "$OFFICIAL_APP"
	fi
	if [ "$MOUNTED" -eq 1 ]; then
		hdiutil detach "$MOUNT_PATH" >> "$EVIDENCE_DIR/cleanup.txt" 2>&1
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
				;;
		esac
	fi
	if [ "$exit_code" -ne 0 ]; then
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
		echo "run_root_removed=$([ -n "$RUN_ROOT" ] && [ ! -e "$RUN_ROOT" ] && echo yes || echo no)"
	} >> "$EVIDENCE_DIR/cleanup.txt"
	exit "$exit_code"
}

trap cleanup EXIT

{
	echo "process_wait_seconds=30"
	echo "support_path_wait_seconds=60"
	echo "working_dir_log_wait_seconds=60"
	echo "second_launch_wait_seconds=5"
	echo "fs_usage_seconds=45"
} > "$EVIDENCE_DIR/timeouts.txt"

	{
		echo "uname -m: $(uname -m)"
	sw_vers || true
	xcodebuild -version || true
	brew --version || true
	echo "runner_image: ${ImageOS:-unknown} ${ImageVersion:-unknown}"
} > "$EVIDENCE_DIR/preflight.txt" 2>&1

[ "$(uname -m)" = "arm64" ] || unavailable "runner is not arm64"
command -v python3 >/dev/null || unavailable "python3 is unavailable"
command -v sw_vers >/dev/null || unavailable "sw_vers is unavailable"
command -v xcodebuild >/dev/null || unavailable "xcodebuild is unavailable"
command -v brew >/dev/null || unavailable "brew is unavailable"
command -v curl >/dev/null || unavailable "curl is unavailable"
command -v hdiutil >/dev/null || unavailable "hdiutil is unavailable"
command -v ditto >/dev/null || unavailable "ditto is unavailable"
command -v plutil >/dev/null || unavailable "plutil is unavailable"
command -v osascript >/dev/null || unavailable "osascript is unavailable"
[ -x /usr/bin/fs_usage ] || unavailable "/usr/bin/fs_usage is unavailable"
sudo -n true || unavailable "non-interactive sudo is unavailable"
pgrep -x WindowServer >/dev/null || unavailable "WindowServer is unavailable"
launchctl print "gui/$(id -u)" > "$EVIDENCE_DIR/launchctl.txt" 2>&1 || unavailable "GUI launch context is unavailable"
python3 "$PARSER" --self-test > "$EVIDENCE_DIR/observer-sensitivity.txt"

APP_PATH="$(canonical_path "$APP_PATH")"
PLIST="$APP_PATH/Contents/Info.plist"
FORK_EXE="$APP_PATH/Contents/MacOS/Telegramd"
[ -d "$APP_PATH" ] || { echo "missing app: $APP_PATH" >&2; exit 1; }
[ -x "$FORK_EXE" ] || { echo "missing executable: $FORK_EXE" >&2; exit 1; }
plutil -p "$PLIST" > "$EVIDENCE_DIR/plist.txt"
test "$(plutil -extract CFBundleExecutable raw -o - "$PLIST")" = "Telegramd"
test "$(plutil -extract CFBundleName raw -o - "$PLIST")" = "Telegramd"
test "$(plutil -extract CFBundleIdentifier raw -o - "$PLIST")" = "com.adambenhassen.telegramd"
if plutil -extract CFBundleURLTypes xml1 -o - "$PLIST" >/dev/null 2>&1; then
	echo "CFBundleURLTypes must be absent from $PLIST" >&2
	exit 1
fi
test ! -e "$APP_PATH/Contents/Frameworks/Updater"
test ! -e "$APP_PATH/Contents/Helpers/Updater"
{
	file "$FORK_EXE"
	lipo -archs "$FORK_EXE"
} > "$EVIDENCE_DIR/architecture.txt"
test "$(lipo -archs "$FORK_EXE")" = "arm64"

RUN_ROOT="$(mktemp -d /tmp/main701.XXXXXX)"
RUN_ROOT="$(canonical_path "$RUN_ROOT")"
HOME_ROOT="$RUN_ROOT/home"
export HOME="$HOME_ROOT"
SUPPORT_ROOT="$HOME_ROOT/Library/Application Support"
OLD="$SUPPORT_ROOT/Telegram Desktop"
NEW="$SUPPORT_ROOT/Telegramd"
mkdir -p "$HOME_ROOT/Library/Application Support" \
	"$OLD/tdata" \
	"$OLD/tupdates/ready/Telegram.app/Contents/MacOS"
printf 'MAIN701_OFFICIAL_CANARY\n' > "$OLD/tdata/official-canary"
printf 'MAIN701_RC1_CANARY\n' > "$OLD/tdata/rc1-canary"
printf 'MAIN701_READY_CANARY\n' > "$OLD/tupdates/ready/Telegram.app/Contents/MacOS/Telegram"
printf 'MAIN701_LOG_CANARY\n' > "$OLD/log.txt"
test ! -e "$NEW"

CANARIES=(
	"$OLD/tdata/official-canary"
	"$OLD/tdata/rc1-canary"
	"$OLD/tupdates/ready/Telegram.app/Contents/MacOS/Telegram"
	"$OLD/log.txt"
)
for canary in "${CANARIES[@]}"; do
	shasum -a 256 "$canary"
done > "$EVIDENCE_DIR/canaries-before.txt"

OFFICIAL_DMG="$RUN_ROOT/official.dmg"
curl --fail --location --silent --show-error \
	--output "$OFFICIAL_DMG" "$OFFICIAL_DMG_URL"
echo "$OFFICIAL_DMG_SHA256  $OFFICIAL_DMG" | shasum -a 256 -c - > "$EVIDENCE_DIR/official-dmg.txt"
MOUNT_PATH="$RUN_ROOT/mount"
mkdir -p "$MOUNT_PATH"
hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT_PATH" "$OFFICIAL_DMG" > "$EVIDENCE_DIR/mount.txt"
MOUNTED=1
OFFICIAL_SOURCE="$(find "$MOUNT_PATH" -maxdepth 2 -type d -name '*.app' -print -quit 2>/dev/null || true)"
[ -n "$OFFICIAL_SOURCE" ] || { echo "official app missing from DMG" >&2; exit 1; }
OFFICIAL_APP="$RUN_ROOT/Official Telegram.app"
ditto "$OFFICIAL_SOURCE" "$OFFICIAL_APP"
hdiutil detach "$MOUNT_PATH" >> "$EVIDENCE_DIR/mount.txt"
MOUNTED=0
OFFICIAL_PLIST="$OFFICIAL_APP/Contents/Info.plist"
OFFICIAL_EXE_NAME="$(plutil -extract CFBundleExecutable raw -o - "$OFFICIAL_PLIST")"
OFFICIAL_BUNDLE_ID="$(plutil -extract CFBundleIdentifier raw -o - "$OFFICIAL_PLIST")"
OFFICIAL_EXE="$OFFICIAL_APP/Contents/MacOS/$OFFICIAL_EXE_NAME"
{
	plutil -p "$OFFICIAL_PLIST"
	echo "executable=$OFFICIAL_EXE"
	echo "bundle_identifier=$OFFICIAL_BUNDLE_ID"
} > "$EVIDENCE_DIR/official-identity.txt"
test -x "$OFFICIAL_EXE"

env HOME="$HOME_ROOT" "$OFFICIAL_EXE" -noupdate -debug -workdir "$OLD" > "$EVIDENCE_DIR/official.log" 2>&1 &
OFFICIAL_PID=$!
wait_for_process "$OFFICIAL_PID" 30 || { echo "official process did not stay alive" >&2; exit 1; }
printf '%s\n' "$OFFICIAL_PID" > "$EVIDENCE_DIR/official-pid.txt"
osascript -e "tell application \"System Events\" to set frontmost of (first application process whose unix id is $OFFICIAL_PID) to true" > "$EVIDENCE_DIR/official-activate.txt" 2>&1
FRONTMOST_BEFORE="$(osascript -e 'tell application "System Events" to get bundle identifier of first application process whose frontmost is true')" \
	|| unavailable "System Events cannot report the frontmost application"
printf '%s\n' "$FRONTMOST_BEFORE" > "$EVIDENCE_DIR/frontmost-before.txt"
test "$FRONTMOST_BEFORE" = "$OFFICIAL_BUNDLE_ID" || unavailable "official application could not become frontmost"

OLD_HASH="$(printf '%s' "$OLD" | md5 -q)"
SOCKET_ROOT="$(canonical_path /tmp)"
for i in $(seq 1 30); do
	find "$SOCKET_ROOT" -type s -name "$OLD_HASH-*" -print > "$EVIDENCE_DIR/official-endpoints.txt"
	if [ -s "$EVIDENCE_DIR/official-endpoints.txt" ]; then
		break
	fi
	sleep 1
done
test -s "$EVIDENCE_DIR/official-endpoints.txt" || unavailable "official endpoint did not appear"

TRACE="$EVIDENCE_DIR/fs_usage.txt"
sudo -n /usr/bin/fs_usage -w -F -f filesys -t 45 > "$TRACE" 2>&1 &
FS_PID=$!
sleep 1
process_alive "$FS_PID" || unavailable "fs_usage exited before launch"

env HOME="$HOME_ROOT" "$FORK_EXE" -noupdate -debug -workdir "$NEW" > "$EVIDENCE_DIR/telegramd.log" 2>&1 &
FORK_PID=$!
wait_for_process "$FORK_PID" 30 || { echo "Telegramd process did not stay alive" >&2; exit 1; }
printf '%s\n' "$FORK_PID" > "$EVIDENCE_DIR/telegramd-pid.txt"
wait_for_file "$NEW/tdata" 60 || { echo "Telegramd support directory did not appear" >&2; exit 1; }
WORKING_LOG=""
for i in $(seq 1 60); do
	WORKING_LOG="$(find "$NEW" -maxdepth 1 -type f -name 'log*.txt' -print -quit 2>/dev/null || true)"
	if [ -n "$WORKING_LOG" ] && grep -F "Working dir: $NEW" "$WORKING_LOG" >/dev/null 2>&1; then
		break
	fi
	WORKING_LOG=""
	sleep 1
done
[ -n "$WORKING_LOG" ]
cp "$WORKING_LOG" "$EVIDENCE_DIR/telegramd-working-dir.log"
grep -F "Working dir: $NEW" "$WORKING_LOG" >/dev/null

NEW_HASH="$(printf '%s' "$NEW" | md5 -q)"
find "$SOCKET_ROOT" -type s -name "$OLD_HASH-*" -print > "$EVIDENCE_DIR/official-endpoints.txt"
find "$SOCKET_ROOT" -type s -name "$NEW_HASH-*" -print > "$EVIDENCE_DIR/telegramd-endpoints.txt"
test -s "$EVIDENCE_DIR/official-endpoints.txt"
test -s "$EVIDENCE_DIR/telegramd-endpoints.txt"
test "$(head -n 1 "$EVIDENCE_DIR/official-endpoints.txt")" != "$(head -n 1 "$EVIDENCE_DIR/telegramd-endpoints.txt")"

FRONTMOST_AFTER="$(osascript -e 'tell application "System Events" to get bundle identifier of first application process whose frontmost is true')" \
	|| unavailable "System Events cannot report the post-launch frontmost application"
printf '%s\n' "$FRONTMOST_AFTER" > "$EVIDENCE_DIR/frontmost-after.txt"
test "$FRONTMOST_AFTER" != "$OFFICIAL_BUNDLE_ID"
process_alive "$OFFICIAL_PID" || { echo "official process exited after Telegramd launch" >&2; exit 1; }
test "$(process_command "$OFFICIAL_PID")" = "$OFFICIAL_EXE -noupdate -debug -workdir $OLD"

env HOME="$HOME_ROOT" "$FORK_EXE" -noupdate -debug -workdir "$NEW" > "$EVIDENCE_DIR/telegramd-second.log" 2>&1 &
SECOND_PID=$!
sleep 5
wait "$SECOND_PID" 2>/dev/null || true
descendants "$FORK_PID" | sort -nu > "$EVIDENCE_DIR/telegramd-descendants.txt"
cat "$EVIDENCE_DIR/telegramd-pid.txt" "$EVIDENCE_DIR/telegramd-descendants.txt" | sort -nu > "$EVIDENCE_DIR/telegramd-pids.txt"
ps -axo pid=,ppid=,command= > "$EVIDENCE_DIR/process-table.txt"
FORK_COUNT="$(awk -v exe="$FORK_EXE" '$3 == exe { count++ } END { print count + 0 }' "$EVIDENCE_DIR/process-table.txt")"
test "$FORK_COUNT" = 1
process_alive "$FORK_PID"
process_alive "$OFFICIAL_PID"

stop_trace
python3 "$PARSER" "$TRACE" "$OLD" "$EVIDENCE_DIR/telegramd-pids.txt" "$EVIDENCE_DIR/fs_usage-report.txt"

for canary in "${CANARIES[@]}"; do
	shasum -a 256 "$canary"
done > "$EVIDENCE_DIR/canaries-after.txt"
cmp "$EVIDENCE_DIR/canaries-before.txt" "$EVIDENCE_DIR/canaries-after.txt"
RESULT="PASS"
printf 'PASS\n' > "$EVIDENCE_DIR/status.txt"
