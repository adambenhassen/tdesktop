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
APP_BUNDLE="$(cd "$(dirname "$APP")/../.." && pwd -P)"
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
	STORE_DATA="$HOME/Library/Containers/com.adambenhassen.telegramd/Data"
	mkdir -p "$STORE_DATA/tmp"
	TEST_HOME="$(mktemp -d "$STORE_DATA/tmp/telegramd-profile-test.XXXXXX")"
	IPC_DIRECTORY="$TEST_HOME/tmp"
	;;
*)
	echo "unsupported artifact variant: $MODE" >&2
	exit 2
	;;
esac
TEST_HOME="$(cd "$TEST_HOME" && pwd -P)"
mkdir -p "$IPC_DIRECTORY"

PROFILE="$TEST_HOME/Library/Application Support/Telegramd"
HOSTILE_HOME="$TEST_HOME/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram"
REFUSAL_LOG="$TEST_HOME/refusal.log"
START_LOG="$TEST_HOME/start.log"
LOCK_SUFFIX="$(printf '%s' "$APP_BUNDLE" | md5 -q | cut -c1-16)"
SOCKET_SUFFIX="$(printf '%s' "$PROFILE" | md5 -q | cut -c1-16)"
SOCKET_PATH="$IPC_DIRECTORY/Telegramd-$SOCKET_SUFFIX"
FIRST_PID=""

cleanup() {
	local status=$?
	if [[ -n "$FIRST_PID" ]] && kill -0 "$FIRST_PID" 2>/dev/null; then
		kill -TERM "$FIRST_PID" 2>/dev/null || true
		wait "$FIRST_PID" 2>/dev/null || true
	fi
	if [[ "$status" -eq 0 ]]; then
		rm -rf "$TEST_HOME"
	else
		printf 'Preserving failed synthetic profile state at %s\n' "$TEST_HOME" >&2
	fi
	return "$status"
}
trap cleanup EXIT

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
	|| grep -F -q "Connecting local socket to $SOCKET_PATH" "$REFUSAL_LOG"; then
	echo "profile refusal occurred after profile or socket startup began." >&2
	cat "$REFUSAL_LOG" >&2
	exit 1
fi
if find "$IPC_DIRECTORY" -maxdepth 1 -name "Telegramd-lock-$LOCK_SUFFIX*" -print -quit | grep -q .; then
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

env HOME="$TEST_HOME" TMPDIR="$TEST_TMP_BASE" TDESKTOP_MAC_PROFILE_TEST_HOME="$TEST_HOME" TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 "$APP" >"$START_LOG" 2>&1 &
FIRST_PID=$!

READY=false
for ((attempt = 0; attempt < 150; ++attempt)); do
	if grep -F -q "Working dir: $PROFILE/" "$PROFILE/log.txt" 2>/dev/null; then
		if grep -F -q "Connecting local socket to $SOCKET_PATH" "$PROFILE/log.txt" 2>/dev/null; then
			if find "$IPC_DIRECTORY" -maxdepth 1 -name "Telegramd-lock-$LOCK_SUFFIX*" -print -quit | grep -q .; then
				if [[ -S "$SOCKET_PATH" ]]; then
					READY=true
					break
				fi
			fi
		fi
	fi
	if ! kill -0 "$FIRST_PID" 2>/dev/null; then
		break
	fi
	sleep 0.2
done

if [[ "$READY" != true ]]; then
	echo "ordinary profile or IPC startup did not become ready." >&2
	cat "$START_LOG" >&2
	if [[ -f "$PROFILE/log.txt" ]]; then
		cat "$PROFILE/log.txt" >&2
	fi
	exit 1
fi

set +e
env HOME="$TEST_HOME" TMPDIR="$TEST_TMP_BASE" TDESKTOP_MAC_PROFILE_TEST_HOME="$TEST_HOME" TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST=1 "$APP" -quit >"$TEST_HOME/quit.log" 2>&1
QUIT_STATUS=$?
set -e
if [[ "$QUIT_STATUS" -ne 0 ]]; then
	echo "second-instance quit request failed with status $QUIT_STATUS." >&2
	cat "$TEST_HOME/quit.log" >&2
	exit 1
fi

for ((attempt = 0; attempt < 150; ++attempt)); do
	if ! kill -0 "$FIRST_PID" 2>/dev/null; then
		break
	fi
	sleep 0.2
done
if kill -0 "$FIRST_PID" 2>/dev/null; then
	echo "second-instance quit request did not stop the first instance." >&2
	exit 1
fi
set +e
wait "$FIRST_PID"
FIRST_STATUS=$?
set -e
FIRST_PID=""
if [[ "$FIRST_STATUS" -ne 0 ]]; then
	echo "first Telegramd instance exited with status $FIRST_STATUS." >&2
	cat "$START_LOG" >&2
	exit 1
fi

echo "profile refusal and ordinary $MODE single-instance startup passed."
