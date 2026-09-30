#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
	echo "usage: $0 <Telegramd executable> [non-store|build_macstore]" >&2
	exit 2
fi

if [[ "$(uname -s)" != Darwin ]]; then
	echo "macOS profile integration test requires Darwin." >&2
	exit 2
fi

APP="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
MODE=non-store
TEST_TMP_BASE="${TDESKTOP_MAC_PROFILE_TEST_TMP_BASE:-/tmp}"
if [[ $# -eq 2 ]]; then
	MODE="$2"
fi
if [[ ! -x "$APP" ]]; then
	echo "Telegramd executable is not executable: $APP" >&2
	exit 2
fi
case "$MODE" in
non-store)
	IPC_DIRECTORY="/tmp"
	TEST_HOME="$(mktemp -d "$TEST_TMP_BASE/telegramd-profile-test.XXXXXX")"
	;;
build_macstore)
	TEST_HOME="$(mktemp -d "/tmp/telegramd-store-profile.XXXXXX")"
	TEST_HOME="$(cd "$TEST_HOME" && pwd -P)"
	IPC_DIRECTORY="$TEST_HOME/tmp"
	;;
*)
	echo "unsupported artifact variant: $MODE" >&2
	exit 2
	;;
esac
TEST_HOME="$(cd "$TEST_HOME" && pwd -P)"
IPC_SEARCH_DIRECTORY="$(cd "$IPC_DIRECTORY" 2>/dev/null && pwd -P || printf '%s' "$IPC_DIRECTORY")"

PROFILE="$TEST_HOME/Library/Application Support/Telegramd"
HOSTILE_HOME="$TEST_HOME/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram"
REFUSAL_LOG="$TEST_HOME/refusal.log"
START_LOG="$TEST_HOME/start.log"
LOCK_SUFFIX="$(printf '%s' "$APP" | md5 -q | cut -c1-16)"
SOCKET_SUFFIX="$(printf '%s' "$PROFILE" | md5 -q | cut -c1-16)"
EXPECTED_VARIANT=non-store
if [[ "$MODE" == build_macstore ]]; then
	EXPECTED_VARIANT=build_macstore
fi
LOCK_NAME="Telegramd-lock-$LOCK_SUFFIX"
LOCK_PATH="$IPC_DIRECTORY/$LOCK_NAME"
SOCKET_PATH="$IPC_DIRECTORY/Telegramd-$SOCKET_SUFFIX"
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
			cp -R "$TEST_HOME" "$TEST_TMP_BASE/telegramd-profile-test-failure" \
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
	echo "hostile HOME unexpectedly started Telegramd." >&2
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
if [[ "$MODE" == build_macstore && -e "$IPC_DIRECTORY" ]]; then
	echo "profile refusal created the store IPC directory before profile validation." >&2
	exit 1
fi
if [[ -e "$PROFILE" || -e "$HOSTILE_HOME" ]]; then
	echo "hostile profile initialization created a profile or protected path." >&2
	exit 1
fi
printf 'protected_home_refusal=PASS status=%s class=group-container before_profile_and_ipc=1\n' "$REFUSAL_STATUS"

if [[ "$MODE" == build_macstore ]]; then
	LONG_HOME_COMPONENT="$(printf '%110s' '' | tr ' ' x)"
	LONG_TEST_HOME="$TEST_HOME/$LONG_HOME_COMPONENT"
	mkdir -p "$LONG_TEST_HOME"
	LONG_PROFILE="$LONG_TEST_HOME/Library/Application Support/Telegramd"
	LONG_IPC_DIRECTORY="$LONG_TEST_HOME/tmp"
	LONG_SOCKET_SUFFIX="$(printf '%s' "$LONG_PROFILE" | md5 -q | cut -c1-16)"
	LONG_SOCKET_PATH="$LONG_IPC_DIRECTORY/Telegramd-$LONG_SOCKET_SUFFIX"
	LONG_SOCKET_PATH_BYTES="$(LC_ALL=C printf '%s' "$LONG_SOCKET_PATH" | wc -c | tr -d '[:space:]')"
	LONG_LOG="$LONG_TEST_HOME/socket-path-too-long.log"
	if (( LONG_SOCKET_PATH_BYTES <= MAC_SOCKET_PATH_LIMIT )); then
		echo "overlong store socket test path is only $LONG_SOCKET_PATH_BYTES bytes." >&2
		exit 1
	fi
	set +e
	env HOME="$LONG_TEST_HOME" TMPDIR="$TEST_TMP_BASE" TDESKTOP_MAC_PROFILE_TEST_HOME="$LONG_TEST_HOME" TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 "$APP" -quit >"$LONG_LOG" 2>&1
	LONG_STATUS=$?
	set -e
	if [[ "$LONG_STATUS" -eq 0 ]] \
		|| ! grep -F -q "Mac local socket path too long:" "$LONG_LOG" "$LONG_PROFILE/log.txt" 2>/dev/null \
		|| [[ -e "$LONG_IPC_DIRECTORY" || -S "$LONG_SOCKET_PATH" ]]; then
		echo "overlong store socket path was not refused before IPC access." >&2
		cat "$LONG_LOG" >&2
		if [[ -f "$LONG_PROFILE/log.txt" ]]; then
			cat "$LONG_PROFILE/log.txt" >&2
		fi
		exit 1
	fi
	printf 'socket_path_overflow=PASS status=%s bytes=%s limit=%s refused_before_ipc=1\n' \
		"$LONG_STATUS" "$LONG_SOCKET_PATH_BYTES" "$MAC_SOCKET_PATH_LIMIT"
else
	printf 'socket_path_overflow=N/A variant=%s path=%s bytes=%s limit=%s\n' \
		"$MODE" "$SOCKET_PATH" "$SOCKET_PATH_BYTES" "$MAC_SOCKET_PATH_LIMIT"
fi

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
	if has_start_record "Mac profile IPC selected: variant=$EXPECTED_VARIANT directory=$IPC_DIRECTORY"; then
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
	"variant=$EXPECTED_VARIANT directory=$IPC_DIRECTORY" || FAILURES=$((FAILURES + 1))
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

QUIT_LOG="$TEST_HOME/quit.log"
set +e
env HOME="$TEST_HOME" TMPDIR="$TEST_TMP_BASE" TDESKTOP_MAC_PROFILE_TEST_HOME="$TEST_HOME" TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 "$APP" -quit >"$QUIT_LOG" 2>&1
QUIT_STATUS=$?
set -e
report_result second_instance_exit "$([[ "$QUIT_STATUS" -eq 0 ]] && printf true || printf false)" \
	"status=$QUIT_STATUS" || FAILURES=$((FAILURES + 1))
if grep -E -q "Mac profile IPC cleanup response: RES:${FIRST_PID}_[0-9]+;" "$QUIT_LOG"; then
	QUIT_HANDSHAKE_READY=true
else
	QUIT_HANDSHAKE_READY=false
fi
QUIT_RESPONSE="$(sed -n 's/.*Mac profile IPC cleanup response: //p' "$QUIT_LOG" | head -n 1)"
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

echo "profile refusal and ordinary $MODE single-instance startup passed."
