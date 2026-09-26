#!/usr/bin/env bash

set -u

if [ "$#" -ne 2 ]; then
	echo "usage: mac_launch_controls.sh TELEGRAMD_APP EVIDENCE_DIR" >&2
	exit 2
fi

APP_SOURCE="$1"
EVIDENCE_ROOT="$2"
RUNNER_HOME="${HOME:-}"
ACTIVE_ROOT=""
ACTIVE_PID=""

mkdir -p "$EVIDENCE_ROOT"
SUMMARY="$EVIDENCE_ROOT/summary.txt"
{
	echo "diagnostic_only=true"
	echo "artifact_ready=not_modified"
	echo "full_isolation_gate=still_required"
	echo "application_code_baseline=${DIAGNOSTIC_BUILD_BASELINE:-unknown}"
	echo "workflow_commit=${GITHUB_SHA:-unknown}"
	echo "runner_arch=$(uname -m)"
	echo "runner_os=$(sw_vers -productVersion 2>/dev/null || echo unavailable)"
} > "$SUMMARY"

process_state() {
	ps -p "$1" -o state= 2>/dev/null | tr -d '[:space:]' || true
}

process_present() {
	local state
	state="$(process_state "$1")"
	case "$state" in
		""|Z*) return 1 ;;
	esac
	return 0
}

cleanup_active() {
	local attempt
	if [ -n "$ACTIVE_PID" ] && process_present "$ACTIVE_PID"; then
		kill -CONT "$ACTIVE_PID" 2>/dev/null || true
		kill -TERM "$ACTIVE_PID" 2>/dev/null || true
		for (( attempt = 1; attempt <= 10; attempt++ )); do
			process_present "$ACTIVE_PID" || break
			sleep 1
		done
		if process_present "$ACTIVE_PID"; then
			kill -KILL "$ACTIVE_PID" 2>/dev/null || true
		fi
	fi
	if [ -n "$ACTIVE_PID" ]; then
		wait "$ACTIVE_PID" >/dev/null 2>&1 || true
		ACTIVE_PID=""
	fi
	case "$ACTIVE_ROOT" in
		/tmp/main858-launch-*|/private/tmp/main858-launch-*) rm -rf "$ACTIVE_ROOT" ;;
	esac
	ACTIVE_ROOT=""
}
trap cleanup_active EXIT

wait_for_natural_exit() {
	local pid="$1"
	local seconds="$2"
	local attempt
	for (( attempt = 1; attempt <= seconds; attempt++ )); do
		if ! process_present "$pid"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

capture_startup_logs() {
	local home="$1"
	local evidence="$2"
	local support="$home/Library/Application Support/Telegramd"
	local candidate
	local found=0
	local destination="$evidence/home-startup-logs"
	mkdir -p "$destination"
	: > "$evidence/home-startup-log-index.txt"
	for candidate in "$support/log.txt" "$support"/log_start*.txt; do
		if [ -f "$candidate" ]; then
			cp "$candidate" "$destination/$(basename "$candidate")"
			printf 'copied=%s\n' "$candidate" >> "$evidence/home-startup-log-index.txt"
			found=1
		fi
	done
	if [ "$found" -eq 0 ]; then
		echo "startup_logs=none" > "$evidence/home-startup-log-index.txt"
	fi
}

capture_crash_reports() {
	local home="$1"
	local evidence="$2"
	local marker="$3"
	local root
	local report
	local name
	local found=0
	local destination="$evidence/crash-reports"
	mkdir -p "$destination"
	: > "$evidence/crash-report-index.txt"
	: > "$evidence/crash-report-search-errors.txt"
	for root in \
		"$RUNNER_HOME/Library/Logs/DiagnosticReports" \
		"$home/Library/Logs/DiagnosticReports" \
		/Library/Logs/DiagnosticReports; do
		if [ -d "$root" ]; then
			while IFS= read -r report; do
				[ -f "$report" ] || continue
				name="$(basename "$report")"
				case "$name" in
					*Telegramd*|*telegramd*|*dyld*)
						cp "$report" "$destination/$name"
						printf 'copied=%s\n' "$report" >> "$evidence/crash-report-index.txt"
						found=1
						;;
				esac
			done < <(find "$root" -maxdepth 1 -type f -newer "$marker" -print 2>> "$evidence/crash-report-search-errors.txt")
		fi
	done
	if [ "$found" -eq 0 ]; then
		echo "process_crash_reports=none" > "$evidence/crash-report-index.txt"
	fi
}

capture_system_log() {
	local evidence="$1"
	local start_time="$2"
	local status
	if /usr/bin/log show --style compact --start "$start_time" \
		--predicate 'process == "Telegramd" OR process == "dyld" OR process == "amfid" OR process == "taskgated" OR process == "ReportCrash" OR process == "syspolicyd"' \
		> "$evidence/macos-launch-log.txt" 2>&1; then
		status=0
	else
		status=$?
	fi
	printf 'unified_log_status=%s\n' "$status" >> "$evidence/summary.txt"
}

record_code_signing() {
	local app="$1"
	local evidence="$2"
	local status
	: > "$evidence/code-signing.txt"
	if codesign -dv --verbose=4 "$app" >> "$evidence/code-signing.txt" 2>&1; then
		status=0
	else
		status=$?
	fi
	printf 'codesign_display_status=%s\n' "$status" >> "$evidence/code-signing.txt"
	if codesign --verify --deep --strict --verbose=2 "$app" >> "$evidence/code-signing.txt" 2>&1; then
		status=0
	else
		status=$?
	fi
	printf 'codesign_verify_status=%s\n' "$status" >> "$evidence/code-signing.txt"
	{
		file "$app/Contents/MacOS/Telegramd"
		otool -L "$app/Contents/MacOS/Telegramd"
	} > "$evidence/binary-linkage.txt" 2>&1
}

run_control() {
	local mode="$1"
	local evidence="$EVIDENCE_ROOT/$mode"
	local root
	local app
	local home
	local hostile
	local executable
	local pid
	local state
	local attempt
	local exit_status
	local cleanup_status
	local natural_exit=0
	local start_time
	local marker
	local source_hash
	local copy_hash
	local wait_seconds=60
	mkdir -p "$evidence"
	root="$(mktemp -d "/tmp/main858-launch-$mode.XXXXXX" 2> "$evidence/setup-errors.txt")"
	if [ -z "$root" ]; then
		echo "fixture_setup=failed" > "$evidence/summary.txt"
		return 0
	fi
	ACTIVE_ROOT="$root"
	app="$root/Telegramd-test.app"
	home="$root/home"
	hostile="$app/Contents/MacOS/TelegramForcePortable"
	executable="$app/Contents/MacOS/Telegramd"
	if ! ditto "$APP_SOURCE" "$app" > "$evidence/app-copy.txt" 2>&1; then
		echo "fixture_setup=app-copy-failed" > "$evidence/summary.txt"
		cleanup_active
		return 0
	fi
	record_code_signing "$app" "$evidence"
	if ! mkdir -p "$home/Library/Application Support/Telegram Desktop/tdata" "$hostile/tdata"; then
		echo "fixture_setup=directory-creation-failed" > "$evidence/summary.txt"
		cleanup_active
		return 0
	fi
	printf 'CONTROL_%s_HOME_CANARY\n' "$mode" > "$home/Library/Application Support/Telegram Desktop/tdata/official-canary"
	printf 'CONTROL_%s_HOSTILE_CANARY\n' "$mode" > "$hostile/tdata/alpha"
	source_hash="$(shasum -a 256 "$APP_SOURCE/Contents/MacOS/Telegramd" | awk '{print $1}')"
	copy_hash="$(shasum -a 256 "$executable" | awk '{print $1}')"
	{
		echo "fixture_setup=pass"
		echo "control=$mode"
		echo "observer_processes=none"
		echo "app_copy=$app"
		echo "app_source_sha256=$source_hash"
		echo "app_copy_sha256=$copy_hash"
		echo "app_copy_matches_source=$([ "$source_hash" = "$copy_hash" ] && echo yes || echo no)"
		echo "home=$home"
		echo "hostile_fixture=$hostile"
		echo "workdir_argument=$hostile"
		echo "wait_seconds=$wait_seconds"
	} > "$evidence/summary.txt"
	marker="$evidence/crash-report-marker"
	touch "$marker"
	start_time="$(date '+%Y-%m-%d %H:%M:%S')"
	if [ "$mode" = direct ]; then
		env HOME="$home" "$executable" -noupdate -debug -workdir "$hostile" \
			> "$evidence/process-output.txt" 2>&1 &
		ACTIVE_PID=$!
		printf 'launch_method=direct\npid=%s\nstop_signal=not-used\ncontinue_signal=not-used\n' \
			"$ACTIVE_PID" >> "$evidence/summary.txt"
	else
		env HOME="$home" /bin/sh -c 'kill -STOP $$; exec "$@"' \
			telegramd-launcher "$executable" -noupdate -debug -workdir "$hostile" \
			> "$evidence/process-output.txt" 2>&1 &
		ACTIVE_PID=$!
		for (( attempt = 1; attempt <= 10; attempt++ )); do
			state="$(process_state "$ACTIVE_PID")"
			case "$state" in
				T*) break ;;
			esac
			process_present "$ACTIVE_PID" || break
			sleep 1
		done
		state="$(process_state "$ACTIVE_PID")"
		case "$state" in
			T*) echo "stop_observed=yes" ;;
			*) echo "stop_observed=no" ;;
		esac >> "$evidence/summary.txt"
		printf 'launch_method=stop-then-continue\npid=%s\nstate_before_continue=%s\n' \
			"$ACTIVE_PID" "${state:-missing}" >> "$evidence/summary.txt"
		if kill -CONT "$ACTIVE_PID" 2>/dev/null; then
			echo "continue_signal=sent" >> "$evidence/summary.txt"
		else
			echo "continue_signal=failed" >> "$evidence/summary.txt"
		fi
		for (( attempt = 1; attempt <= 10; attempt++ )); do
			state="$(process_state "$ACTIVE_PID")"
			case "$state" in
				""|Z*) break ;;
				T*) sleep 1 ;;
				*) break ;;
			esac
		done
		printf 'state_after_continue=%s\n' "${state:-missing}" >> "$evidence/summary.txt"
	fi
	if wait_for_natural_exit "$ACTIVE_PID" "$wait_seconds"; then
		if wait "$ACTIVE_PID"; then
			exit_status=0
		else
			exit_status=$?
		fi
		natural_exit=1
		ACTIVE_PID=""
		echo "process_exit=natural" >> "$evidence/summary.txt"
		echo "process_exit_status=$exit_status" >> "$evidence/summary.txt"
	else
		echo "process_exit=not-observed-within-${wait_seconds}s" >> "$evidence/summary.txt"
		echo "process_exit_status=unknown-before-cleanup" >> "$evidence/summary.txt"
		kill -CONT "$ACTIVE_PID" 2>/dev/null || true
		kill -TERM "$ACTIVE_PID" 2>/dev/null || true
		for (( attempt = 1; attempt <= 10; attempt++ )); do
			process_present "$ACTIVE_PID" || break
			sleep 1
		done
		if process_present "$ACTIVE_PID"; then
			kill -KILL "$ACTIVE_PID" 2>/dev/null || true
		fi
		if wait "$ACTIVE_PID"; then
			cleanup_status=0
		else
			cleanup_status=$?
		fi
		ACTIVE_PID=""
		echo "cleanup_wait_status=$cleanup_status" >> "$evidence/summary.txt"
	fi
	echo "natural_exit_observed=$natural_exit" >> "$evidence/summary.txt"
	sleep 5
	capture_startup_logs "$home" "$evidence"
	capture_crash_reports "$home" "$evidence" "$marker"
	capture_system_log "$evidence" "$start_time"
	cleanup_active
}

if [ ! -d "$APP_SOURCE" ] || [ ! -x "$APP_SOURCE/Contents/MacOS/Telegramd" ]; then
	echo "app_source=missing" >> "$SUMMARY"
	exit 0
fi

run_control direct
run_control stop-cont
echo "controls_collected=true" >> "$SUMMARY"
exit 0
