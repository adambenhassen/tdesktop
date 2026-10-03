#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <Teagram executable>" >&2
	exit 2
fi

if [[ "$(uname -s)" != Darwin ]]; then
	echo "macOS profile integration test requires Darwin." >&2
	exit 2
fi

APP="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
APP_BUNDLE="$(cd "$(dirname "$APP")/../.." && pwd -P)"
TEST_TMP_BASE="${TDESKTOP_MAC_PROFILE_TEST_TMP_BASE:-/tmp}"
if [[ ! -x "$APP" ]]; then
	echo "Teagram executable is not executable: $APP" >&2
	exit 2
fi
IPC_DIRECTORY="/tmp"
TEST_HOME="$(mktemp -d "$TEST_TMP_BASE/teagram-profile-test.XXXXXX")"
TEST_HOME="$(cd "$TEST_HOME" && pwd -P)"
IPC_SEARCH_DIRECTORY="$(cd "$IPC_DIRECTORY" 2>/dev/null && pwd -P || printf '%s' "$IPC_DIRECTORY")"

PROFILE="$TEST_HOME/Library/Application Support/Teagram"
HOSTILE_HOME="$TEST_HOME/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram"
REFUSAL_LOG="$TEST_HOME/refusal.log"
START_LOG="$TEST_HOME/start.log"
LOCK_SUFFIX="$(printf '%s' "$APP_BUNDLE" | md5 -q | cut -c1-16)"
SOCKET_SUFFIX="$(printf '%s' "$PROFILE" | md5 -q | cut -c1-16)"
LOCK_NAME="Teagram-lock-$LOCK_SUFFIX"
LOCK_PATH="$IPC_DIRECTORY/$LOCK_NAME"
SOCKET_PATH="$IPC_DIRECTORY/Teagram-$SOCKET_SUFFIX"
MAC_SOCKET_PATH_LIMIT=103
SOCKET_PATH_BYTES="$(LC_ALL=C printf '%s' "$SOCKET_PATH" | wc -c | tr -d '[:space:]')"
FIRST_PID=""

find_lock_path() {
	local candidate
	for candidate in "$IPC_SEARCH_DIRECTORY"/"$LOCK_NAME"*; do
		if [[ -e "$candidate" ]]; then
			printf '%s' "$candidate"
			return 0
		fi
	done
	return 0
}

has_start_record() {
	local record="$1"
	grep -F -q "$record" "$START_LOG" \
		|| grep -F -q "$record" "$PROFILE/log.txt" 2>/dev/null
}

report_result() {
	local name="$1"
	local passed="$2"
	local detail="$3"
	if [[ "$passed" == true ]]; then
		printf '%s=PASS %s\n' "$name" "$detail"
	else
		printf '%s=FAIL %s\n' "$name" "$detail" >&2
		return 1
	fi
}

fixture_unchanged() {
	local fixture="$1"
	local is_file="$2"
	local expected_contents="$3"
	if [[ "$is_file" == true ]]; then
		[[ -f "$fixture" ]] && [[ "$(cat "$fixture")" == "$expected_contents" ]]
	else
		[[ -d "$fixture" ]] \
			&& [[ -z "$(find "$fixture" -mindepth 1 -print -quit)" ]]
	fi
}

run_spoiler_cache_symlink_case() {
	local case_name="$1"
	local link_name="$2"
	local case_home="$TEST_HOME/$case_name"
	local PROFILE="$case_home/Library/Application Support/Teagram"
	local fixture="$case_home/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/SyntheticSpoilerCache"
	local fixture_is_file=false
	local fixture_contents='synthetic protected cache bytes'
	local START_LOG="$case_home/start.log"
	local quit_log="$case_home/quit.log"
	local LOCK_NAME="$LOCK_NAME"
	local IPC_SEARCH_DIRECTORY="$IPC_SEARCH_DIRECTORY"
	local SOCKET_PATH="/tmp/Teagram-$(printf '%s' "$PROFILE" | md5 -q | cut -c1-16)"
	local socket_bytes
	local PROFILE_READY=false
	local IPC_SELECTION_READY=false
	local LOCK_READY=false
	local SOCKET_PATH_READY=false
	local SOCKET_LISTENER_READY=false
	local SOCKET_FILE_READY=false
	local FIRST_PROCESS_ALIVE=false
	local FAILURES=0
	local quit_status
	local first_status
	local response
	local refusal

	case "$link_name" in
	emoji)
		mkdir -p "$PROFILE/tdata" "$fixture"
		ln -s "$fixture" "$PROFILE/tdata/emoji"
		;;
	spoiler)
		mkdir -p "$PROFILE/tdata/emoji" "$fixture"
		ln -s "$fixture" "$PROFILE/tdata/emoji/spoiler"
		;;
	text|image)
		mkdir -p "$PROFILE/tdata/emoji/spoiler" "$(dirname "$fixture")"
		printf '%s' "$fixture_contents" > "$fixture"
		ln -s "$fixture" "$PROFILE/tdata/emoji/spoiler/$link_name"
		fixture_is_file=true
		;;
	*)
		echo "unsupported spoiler cache symlink: $link_name" >&2
		return 2
		;;
	esac
	socket_bytes="$(LC_ALL=C printf '%s' "$SOCKET_PATH" | wc -c | tr -d '[:space:]')"
	if (( socket_bytes > MAC_SOCKET_PATH_LIMIT )); then
		echo "socket path is $socket_bytes bytes; macOS sun_path limit is $MAC_SOCKET_PATH_LIMIT: $SOCKET_PATH" >&2
		return 1
	fi

	env HOME="$case_home" TMPDIR="$TEST_TMP_BASE" \
		TDESKTOP_MAC_PROFILE_TEST_HOME="$case_home" \
		TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 \
		"$APP" >"$START_LOG" 2>&1 &
	FIRST_PID=$!
	for ((attempt = 0; attempt < 150; ++attempt)); do
		if grep -F -q "Working dir: $PROFILE/" "$PROFILE/log.txt" 2>/dev/null; then
			PROFILE_READY=true
		fi
		if has_start_record "Mac profile IPC selected: variant=non-store directory=$IPC_DIRECTORY"; then
			IPC_SELECTION_READY=true
		fi
		if grep -F -q "Connecting local socket to $SOCKET_PATH" "$PROFILE/log.txt" 2>/dev/null; then
			SOCKET_PATH_READY=true
		fi
		if [[ -n "$(find_lock_path)" ]]; then
			LOCK_READY=true
		fi
		if has_start_record "Mac profile IPC ready: listening=1 full_server_name=$SOCKET_PATH"; then
			SOCKET_LISTENER_READY=true
		fi
		if [[ -S "$SOCKET_PATH" ]]; then
			SOCKET_FILE_READY=true
		fi
		if kill -0 "$FIRST_PID" 2>/dev/null; then
			FIRST_PROCESS_ALIVE=true
		fi
		if [[ "$PROFILE_READY" == true \
			&& "$IPC_SELECTION_READY" == true \
			&& "$LOCK_READY" == true \
			&& "$SOCKET_PATH_READY" == true \
			&& "$SOCKET_LISTENER_READY" == true \
			&& "$SOCKET_FILE_READY" == true \
			&& "$FIRST_PROCESS_ALIVE" == true ]]; then
			break
		fi
		if ! kill -0 "$FIRST_PID" 2>/dev/null; then
			break
		fi
		sleep 0.2
	done

	report_result "${case_name}_profile" "$PROFILE_READY" "path=$PROFILE" || FAILURES=$((FAILURES + 1))
	report_result "${case_name}_ipc_directory" "$IPC_SELECTION_READY" \
		"variant=non-store directory=$IPC_DIRECTORY" || FAILURES=$((FAILURES + 1))
	report_result "${case_name}_lock" "$LOCK_READY" \
		"expected=$LOCK_PATH found=$(find_lock_path)" || FAILURES=$((FAILURES + 1))
	report_result "${case_name}_bound_socket" "$SOCKET_LISTENER_READY" \
		"path=$SOCKET_PATH filesystem_socket=$SOCKET_FILE_READY" || FAILURES=$((FAILURES + 1))
	if ! fixture_unchanged "$fixture" "$fixture_is_file" "$fixture_contents"; then
		report_result "${case_name}_fixture_untouched" false "fixture=$fixture" || FAILURES=$((FAILURES + 1))
	else
		report_result "${case_name}_fixture_untouched" true "fixture=$fixture"
	fi

	set +e
	env HOME="$case_home" TMPDIR="$TEST_TMP_BASE" \
		TDESKTOP_MAC_PROFILE_TEST_HOME="$case_home" \
		TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 \
		"$APP" -quit >"$quit_log" 2>&1
	quit_status=$?
	set -e
	report_result "${case_name}_second_instance_exit" "$([[ "$quit_status" -eq 0 ]] && printf true || printf false)" \
		"status=$quit_status" || FAILURES=$((FAILURES + 1))
	response="$(grep -hF "Show command response received, processId = $FIRST_PID, windowId = 0" "$PROFILE"/log*.txt || true)"
	report_result "${case_name}_first_pid_handshake" "$([[ -n "$response" ]] && printf true || printf false)" \
		"response=$response expected_pid=$FIRST_PID" || FAILURES=$((FAILURES + 1))
	for ((attempt = 0; attempt < 150; ++attempt)); do
		if ! kill -0 "$FIRST_PID" 2>/dev/null; then
			break
		fi
		sleep 0.2
	done
	if kill -0 "$FIRST_PID" 2>/dev/null; then
		report_result "${case_name}_first_instance_exit" false "pid=$FIRST_PID still_alive=1" || true
		return 1
	fi
	set +e
	wait "$FIRST_PID"
	first_status=$?
	set -e
	FIRST_PID=""
	report_result "${case_name}_first_instance_exit" "$([[ "$first_status" -eq 0 ]] && printf true || printf false)" \
		"status=$first_status" || FAILURES=$((FAILURES + 1))
	refusal="$(grep -F 'class=group-container callsite=emojiCacheFolder' \
		"$START_LOG" "$PROFILE/log.txt" 2>/dev/null || true)"
	if [[ -n "$refusal" ]]; then
		report_result "${case_name}_cache_refusal" true "$refusal"
	else
		report_result "${case_name}_cache_refusal" false "missing protected-path refusal from emojiCacheFolder" || FAILURES=$((FAILURES + 1))
	fi
	if ! fixture_unchanged "$fixture" "$fixture_is_file" "$fixture_contents"; then
		report_result "${case_name}_fixture_untouched_after_exit" false "fixture=$fixture" || FAILURES=$((FAILURES + 1))
	else
		report_result "${case_name}_fixture_untouched_after_exit" true "fixture=$fixture"
	fi
	if (( FAILURES > 0 )); then
		cat "$quit_log" "$START_LOG" >&2
		return 1
	fi
}

cleanup() {
	local status=$?
	if [[ -n "$FIRST_PID" ]] && kill -0 "$FIRST_PID" 2>/dev/null; then
		kill -TERM "$FIRST_PID" 2>/dev/null || true
		wait "$FIRST_PID" 2>/dev/null || true
	fi
	if [[ "$status" -eq 0 ]]; then
		rm -rf "$TEST_HOME"
	else
		case "$TEST_HOME/" in
		"$TEST_TMP_BASE/"*)
			;;
		*)
			mkdir -p "$TEST_TMP_BASE"
			cp -R "$TEST_HOME" "$TEST_TMP_BASE/teagram-profile-test-failure" \
				2>/dev/null || true
			;;
		esac
		printf 'Preserving failed synthetic profile state at %s\n' "$TEST_HOME" >&2
	fi
	return "$status"
}
trap cleanup EXIT

if (( SOCKET_PATH_BYTES > MAC_SOCKET_PATH_LIMIT )); then
	echo "socket path is $SOCKET_PATH_BYTES bytes; macOS sun_path limit is $MAC_SOCKET_PATH_LIMIT: $SOCKET_PATH" >&2
	exit 1
fi
printf 'socket_path_bytes=PASS %s/%s path=%s\n' \
	"$SOCKET_PATH_BYTES" "$MAC_SOCKET_PATH_LIMIT" "$SOCKET_PATH"

set +e
env HOME="$HOSTILE_HOME" TMPDIR="$HOSTILE_HOME" TDESKTOP_MAC_PROFILE_TEST_HOME="$TEST_HOME" TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 "$APP" -quit >"$REFUSAL_LOG" 2>&1
REFUSAL_STATUS=$?
set -e

if [[ "$REFUSAL_STATUS" -eq 0 ]]; then
	echo "hostile HOME unexpectedly started Teagram." >&2
	cat "$REFUSAL_LOG" >&2
	exit 1
fi
if ! grep -F -q "class=group-container callsite=profile.home" "$REFUSAL_LOG"; then
	echo "profile refusal did not identify the protected home source." >&2
	cat "$REFUSAL_LOG" >&2
	exit 1
fi
if grep -F -q "Working dir: $PROFILE/" "$REFUSAL_LOG" \
	|| grep -F -q "Mac profile IPC selected:" "$REFUSAL_LOG" \
	|| grep -F -q "Connecting local socket to $SOCKET_PATH" "$REFUSAL_LOG" \
	|| grep -F -q "Mac profile IPC ready:" "$REFUSAL_LOG"; then
	echo "profile refusal occurred after profile or socket startup began." >&2
	cat "$REFUSAL_LOG" >&2
	exit 1
fi
if [[ -n "$(find_lock_path)" ]]; then
	echo "profile refusal created or found an IPC lock." >&2
	exit 1
fi
if [[ -S "$SOCKET_PATH" ]]; then
	echo "profile refusal created an IPC socket." >&2
	exit 1
fi
if [[ -e "$PROFILE" || -e "$HOSTILE_HOME" ]]; then
	echo "hostile profile initialization created a profile or protected path." >&2
	exit 1
fi
printf 'protected_home_refusal=PASS status=%s class=group-container before_profile_and_ipc=1\n' "$REFUSAL_STATUS"

mkdir -p "$IPC_DIRECTORY"

env HOME="$TEST_HOME" TMPDIR="$TEST_TMP_BASE" TDESKTOP_MAC_PROFILE_TEST_HOME="$TEST_HOME" TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 "$APP" >"$START_LOG" 2>&1 &
FIRST_PID=$!

PROFILE_READY=false
IPC_SELECTION_READY=false
LOCK_READY=false
SOCKET_PATH_READY=false
SOCKET_LISTENER_READY=false
SOCKET_FILE_READY=false
FIRST_PROCESS_ALIVE=false
for ((attempt = 0; attempt < 150; ++attempt)); do
	if grep -F -q "Working dir: $PROFILE/" "$PROFILE/log.txt" 2>/dev/null; then
		PROFILE_READY=true
	fi
	if has_start_record "Mac profile IPC selected: variant=non-store directory=$IPC_DIRECTORY"; then
		IPC_SELECTION_READY=true
	fi
	if grep -F -q "Connecting local socket to $SOCKET_PATH" "$PROFILE/log.txt" 2>/dev/null; then
		SOCKET_PATH_READY=true
	fi
	if [[ -n "$(find_lock_path)" ]]; then
		LOCK_READY=true
	fi
	if has_start_record "Mac profile IPC ready: listening=1 full_server_name=$SOCKET_PATH"; then
		SOCKET_LISTENER_READY=true
	fi
	if [[ -S "$SOCKET_PATH" ]]; then
		SOCKET_FILE_READY=true
	fi
	if kill -0 "$FIRST_PID" 2>/dev/null; then
		FIRST_PROCESS_ALIVE=true
	fi
	if [[ "$PROFILE_READY" == true \
		&& "$IPC_SELECTION_READY" == true \
		&& "$LOCK_READY" == true \
		&& "$SOCKET_PATH_READY" == true \
		&& "$SOCKET_LISTENER_READY" == true \
		&& "$SOCKET_FILE_READY" == true \
		&& "$FIRST_PROCESS_ALIVE" == true ]]; then
		break
	fi
	if ! kill -0 "$FIRST_PID" 2>/dev/null; then
		break
	fi
	sleep 0.2
done

FAILURES=0
report_result profile "$PROFILE_READY" "path=$PROFILE" || FAILURES=$((FAILURES + 1))
report_result ipc_variant_and_directory "$IPC_SELECTION_READY" \
	"variant=non-store directory=$IPC_DIRECTORY" || FAILURES=$((FAILURES + 1))
report_result socket_path "$SOCKET_PATH_READY" \
	"path=$SOCKET_PATH bytes=$SOCKET_PATH_BYTES/$MAC_SOCKET_PATH_LIMIT" || FAILURES=$((FAILURES + 1))
LOCK_FOUND="$(find_lock_path)"
report_result lock "$LOCK_READY" \
	"expected=$LOCK_PATH found=${LOCK_FOUND:-missing}" || FAILURES=$((FAILURES + 1))
report_result bound_socket "$SOCKET_LISTENER_READY" \
	"listening=1 full_server_name=$SOCKET_PATH filesystem_socket=$SOCKET_FILE_READY" \
	|| FAILURES=$((FAILURES + 1))
report_result first_instance_pid "$FIRST_PROCESS_ALIVE" "pid=$FIRST_PID" \
	|| FAILURES=$((FAILURES + 1))
if (( FAILURES > 0 )); then
	cat "$START_LOG" >&2
	if [[ -f "$PROFILE/log.txt" ]]; then
		cat "$PROFILE/log.txt" >&2
	fi
	exit 1
fi

SOCKET_TARGET="$TEST_HOME/Library/Application Support/Telegram Desktop/tdata/socket-x"
mkdir -p "$(dirname "$SOCKET_TARGET")"

python3 - "$SOCKET_PATH" "$SOCKET_TARGET" <<'PY'
import pathlib
import socket
import sys
import time

socket_path, target = sys.argv[1:]


def request(command, deadline):
	remaining = deadline - time.monotonic()
	if remaining <= 0:
		raise TimeoutError("request deadline expired")
	with socket.socket(socket.AF_UNIX) as client:
		client.settimeout(remaining)
		client.connect(socket_path)
		client.sendall(command.encode())
		response = bytearray()
		while b";" not in response:
			chunk = client.recv(256)
			if not chunk:
				raise RuntimeError("socket closed before response")
			response.extend(chunk)
		if not response.startswith(b"RES:"):
			raise RuntimeError(f"unexpected socket response: {response!r}")
		return bytes(response)


deadline = time.monotonic() + 30
last_error = None
while time.monotonic() < deadline:
	try:
		request("CMD:show;", min(deadline, time.monotonic() + 2))
		break
	except (OSError, TimeoutError, RuntimeError) as error:
		last_error = error
		time.sleep(0.1)
else:
	raise RuntimeError(
		f"single-instance socket did not answer readiness probe: {last_error}")

request(
	"OPEN:" + pathlib.Path(target).as_uri() + ";",
	time.monotonic() + 10)
PY

for ((attempt = 0; attempt < 50; ++attempt)); do
	if has_start_record "class=application-support callsite=sandbox.open"; then
		break
	fi
	sleep 0.1
done
if ! has_start_record "class=application-support callsite=sandbox.open"; then
	echo "single-instance OPEN command was not refused before dispatch." >&2
	cat "$START_LOG" >&2
	if [[ -f "$PROFILE/log.txt" ]]; then
		cat "$PROFILE/log.txt" >&2
	fi
	exit 1
fi
if grep -F -q "$TEST_HOME/Library/Application Support/Telegram Desktop" "$START_LOG"; then
	echo "single-instance OPEN refusal disclosed the protected path." >&2
	cat "$START_LOG" >&2
	exit 1
fi
printf 'socket_open_protected_path_refusal=PASS class=application-support before-dispatch=1\n'

ARGV_HOME="$TEST_HOME/argv-home"
mkdir -p "$ARGV_HOME/uploads" \
	"$ARGV_HOME/Library/Application Support/Telegram Desktop/tdata"
ARGV_REFUSAL_LOG="$TEST_HOME/argv-refusal.log"
set +e
(cd "$ARGV_HOME" && env HOME="$ARGV_HOME" TMPDIR="$TEST_TMP_BASE" \
	TDESKTOP_MAC_PROFILE_TEST_HOME="$ARGV_HOME" \
	TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 \
	"$APP" -quit -- "./Library/Application Support/Telegram Desktop/tdata/x") >"$ARGV_REFUSAL_LOG" 2>&1
ARGV_REFUSAL_STATUS=$?
set -e
if [[ "$ARGV_REFUSAL_STATUS" -ne 0 ]] \
	|| ! grep -F -q "class=application-support callsite=launcher.argv" "$ARGV_REFUSAL_LOG"; then
	echo "protected command-line path was not refused before dispatch." >&2
	cat "$ARGV_REFUSAL_LOG" >&2
	exit 1
fi
if grep -F -q "$ARGV_HOME/Library/Application Support/Telegram Desktop" "$ARGV_REFUSAL_LOG"; then
	echo "command-line path refusal disclosed the protected path." >&2
	cat "$ARGV_REFUSAL_LOG" >&2
	exit 1
fi
printf 'argv_protected_path_refusal=PASS status=%s class=application-support before_dispatch=1\n' \
	"$ARGV_REFUSAL_STATUS"

ARGV_ALLOWED_LOG="$TEST_HOME/argv-allowed.log"
set +e
(cd "$ARGV_HOME" && env HOME="$ARGV_HOME" TMPDIR="$TEST_TMP_BASE" \
	TDESKTOP_MAC_PROFILE_TEST_HOME="$ARGV_HOME" \
	TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 \
	"$APP" -quit -- "./uploads/x") >"$ARGV_ALLOWED_LOG" 2>&1
ARGV_ALLOWED_STATUS=$?
set -e
if [[ "$ARGV_ALLOWED_STATUS" -ne 0 ]] \
	|| grep -F -q "callsite=launcher.argv" "$ARGV_ALLOWED_LOG"; then
	echo "safe command-line path was refused or failed to dispatch." >&2
	cat "$ARGV_ALLOWED_LOG" >&2
	exit 1
fi
printf 'argv_profile_relative_path_allowed=PASS status=%s\n' "$ARGV_ALLOWED_STATUS"

QUIT_LOG="$TEST_HOME/quit.log"
set +e
env HOME="$TEST_HOME" TMPDIR="$TEST_TMP_BASE" TDESKTOP_MAC_PROFILE_TEST_HOME="$TEST_HOME" TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 "$APP" -quit >"$QUIT_LOG" 2>&1
QUIT_STATUS=$?
set -e
report_result second_instance_exit "$([[ "$QUIT_STATUS" -eq 0 ]] && printf true || printf false)" \
	"status=$QUIT_STATUS" || FAILURES=$((FAILURES + 1))
QUIT_RESPONSE="$(grep -hF \
	"Show command response received, processId = $FIRST_PID, windowId = 0" \
	"$PROFILE"/log*.txt || true)"
if [[ -n "$QUIT_RESPONSE" ]]; then
	QUIT_HANDSHAKE_READY=true
else
	QUIT_HANDSHAKE_READY=false
fi
report_result second_instance_quit_handshake "$QUIT_HANDSHAKE_READY" \
	"response=$QUIT_RESPONSE expected_pid=$FIRST_PID" || FAILURES=$((FAILURES + 1))
if (( FAILURES > 0 )); then
	cat "$QUIT_LOG" >&2
	cat "$START_LOG" >&2
	exit 1
fi

for ((attempt = 0; attempt < 150; ++attempt)); do
	if ! kill -0 "$FIRST_PID" 2>/dev/null; then
		break
	fi
	sleep 0.2
done
if kill -0 "$FIRST_PID" 2>/dev/null; then
	report_result first_instance_exit false "pid=$FIRST_PID still_alive=1" || true
	echo "second-instance quit request did not stop the first instance." >&2
	exit 1
fi
FIRST_INSTANCE_PID="$FIRST_PID"
set +e
wait "$FIRST_PID"
FIRST_STATUS=$?
set -e
FIRST_PID=""
report_result first_instance_exit "$([[ "$FIRST_STATUS" -eq 0 ]] && printf true || printf false)" \
	"pid=$FIRST_INSTANCE_PID status=$FIRST_STATUS" || FAILURES=$((FAILURES + 1))
if (( FAILURES > 0 )); then
	cat "$START_LOG" >&2
	exit 1
fi

CACHE_TEXT="$PROFILE/tdata/emoji/spoiler/text"
CACHE_TEXT_FILES="$(find "$TEST_HOME" -type f -path '*/tdata/emoji/spoiler/text' -print)"
report_result spoiler_cache_location "$([[ -f "$CACHE_TEXT" && "$CACHE_TEXT_FILES" == "$CACHE_TEXT" ]] && printf true || printf false)" \
	"expected=$CACHE_TEXT found=${CACHE_TEXT_FILES:-missing}" || FAILURES=$((FAILURES + 1))
if (( FAILURES > 0 )); then
	exit 1
fi

run_spoiler_cache_symlink_case emoji-cache-symlink emoji
run_spoiler_cache_symlink_case spoiler-cache-symlink spoiler
run_spoiler_cache_symlink_case text-cache-leaf-symlink text
run_spoiler_cache_symlink_case image-cache-leaf-symlink image

AUTH_HOME="$TEST_HOME/authenticated-cache-regression"
AUTH_LOG="$TEST_HOME/authenticated-cache-regression.log"
mkdir -p "$AUTH_HOME"
if ! env HOME="$AUTH_HOME" TMPDIR="$TEST_TMP_BASE" \
	TDESKTOP_MAC_PROFILE_TEST_HOME="$AUTH_HOME" \
	TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 \
	TDESKTOP_AUTH_LIFECYCLE_REGRESSION=1 \
	"$APP" -noupdate -debug >"$AUTH_LOG" 2>&1; then
	cat "$AUTH_LOG" >&2
	echo "authenticated cache and cleanup regression failed." >&2
	exit 1
fi
if ! grep -F -q \
	"Authenticated cache regression passed: root, directory, and file symlinks refused for cache and media_cache." \
	"$AUTH_LOG"; then
	cat "$AUTH_LOG" >&2
	echo "authenticated cache regression did not report coverage." >&2
	exit 1
fi
if ! grep -F -q \
	"Authenticated cache post-open regression passed: get, put, and clear symlinks refused for cache and media_cache." \
	"$AUTH_LOG"; then
	cat "$AUTH_LOG" >&2
	echo "post-open authenticated cache regression did not report coverage." >&2
	exit 1
fi
if ! grep -F -q \
	"Authenticated refused download history regression passed: entry without a live message remained unpublished." \
	"$AUTH_LOG"; then
	cat "$AUTH_LOG" >&2
	echo "refused download-history regression did not report coverage." >&2
	exit 1
fi
if ! grep -F -q \
	"Mac protected path refusal: operation=read class=group-container callsite=download-history.resolve" \
	"$AUTH_LOG"; then
	cat "$AUTH_LOG" >&2
	echo "refused download-history fixture did not reach manager resolution." >&2
	exit 1
fi
printf 'authenticated_cache_regression=PASS roots=2 cache_directory_symlinks=2 cache_file_symlinks=2 cleanup_initial_symlink=1 cleanup_worker_symlink=1 download_history=PASS\n'

echo "profile, spoiler-cache, and non-store single-instance checks passed."
