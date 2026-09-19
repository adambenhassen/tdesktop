#!/usr/bin/env bash

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER="$ROOT/network_trace.py"
UNIT_TEST="$ROOT/network_trace_test.py"
CASE_MANIFEST="$ROOT/network_trace_cases.json"
EVIDENCE_DIR=""
CASE_NAME=""
PHASE=""
TIMEOUT_SECONDS=20
ORIGINS=()
ALLOW_DESTINATIONS=()
ALLOW_DNS=()
ALLOW_PROXIES=()
COMMAND=()
RUN_ROOT=""
RUNNER_PID=""

usage() {
	cat >&2 <<'EOF'
usage:
  network_isolation_test.sh --self-test
  network_isolation_test.sh --list-cases
  network_isolation_test.sh --case CASE --phase PHASE --evidence-dir DIR \
    [--origin URL] [--allow-destination HOST:PORT] [--allow-dns HOST:53] \
    [--allow-proxy HOST:PORT] \
    [--timeout SECONDS] -- TELEGRAMD [ARGS...]

PHASE is one of preselection, public-discovery, local-direct, or pinned-endpoint.
The command is started with an empty HOME and work directory. Its network syscalls
are captured with strace and checked fail-closed against the supplied destination set.
EOF
}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

cleanup() {
	local status=$?
	set +e
	if [ -n "$RUNNER_PID" ] && kill -0 "$RUNNER_PID" 2>/dev/null; then
		kill -TERM "$RUNNER_PID" 2>/dev/null || true
		wait "$RUNNER_PID" 2>/dev/null || true
	fi
	return "$status"
}

run_expected_failure() {
	local label="$1"
	shift
	if "$@" >/dev/null 2>&1; then
		echo "FAIL: self-test expected $label to fail" >&2
		return 1
	fi
	echo "PASS: $label fails closed"
}

run_expected_success() {
	local label="$1"
	shift
	if ! "$@" >/dev/null 2>&1; then
		echo "FAIL: self-test expected $label to pass" >&2
		return 1
	fi
	echo "PASS: $label passes"
}

run_self_test() {
	require_command python3
	local test_root
	test_root="$(mktemp -d "${TMPDIR:-/tmp}/main839-network-trace.XXXXXX")"
	trap 'rm -rf -- "$test_root"' RETURN
	PYTHONPATH="$ROOT" python3 -m unittest "$UNIT_TEST"

	cat > "$test_root/vulnerable.trace" <<'EOF'
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("149.154.167.50")}, 16) = -1 EINPROGRESS
EOF
	cat > "$test_root/fixed.trace" <<'EOF'
socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3
connect(3, {sa_family=AF_UNIX, sun_path="/tmp/display"}, 19) = 0
EOF
	cat > "$test_root/public.trace" <<'EOF'
socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
sendto(3, "dns", 3, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 3
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4
connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = 0
EOF
	cat > "$test_root/public-fallback.trace" <<'EOF'
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED
EOF
	cat > "$test_root/proxy.trace" <<'EOF'
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(1080), sin_addr=inet_addr("198.51.100.9")}, 16) = 0
EOF

	local parser=(python3 "$PARSER")
	run_expected_failure vulnerable-preselection "${parser[@]}" \
		--trace "$test_root/vulnerable.trace" \
		--case fresh-empty --phase preselection
	run_expected_success fixed-preselection "${parser[@]}" \
		--trace "$test_root/fixed.trace" \
		--case fresh-empty --phase preselection
	run_expected_success public-discovery "${parser[@]}" \
		--trace "$test_root/public.trace" \
		--case public-selection --phase public-discovery \
		--origin https://public.example/.well-known/telegramd/client \
		--allow-destination 203.0.113.10:443 \
		--allow-dns 127.0.0.53:53
	run_expected_failure public-direct-fallback "${parser[@]}" \
		--trace "$test_root/public-fallback.trace" \
		--case public-failure --phase public-discovery \
		--origin https://public.example/.well-known/telegramd/client \
		--allow-destination 203.0.113.10:443 \
		--allow-dns 127.0.0.53:53
	run_expected_success proxy-intermediary "${parser[@]}" \
		--trace "$test_root/proxy.trace" \
		--case proxy-intermediary --phase pinned-endpoint \
		--allow-destination 192.0.2.10:443 \
		--allow-proxy 198.51.100.9:1080
	trap - RETURN
	rm -rf -- "$test_root"
	echo "network-isolation-self-test=PASS"
}

list_cases() {
	require_command python3
	python3 - "$CASE_MANIFEST" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as manifest:
    for case in json.load(manifest)["cases"]:
        print(f'{case["name"]}\t{case["phase"]}\t{case["description"]}')
PY
}

validate_case() {
	python3 - "$CASE_MANIFEST" "$CASE_NAME" "$PHASE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as manifest:
    cases = json.load(manifest)["cases"]
for case in cases:
    if case["name"] == sys.argv[2]:
        if case["phase"] != sys.argv[3]:
            print(
                f'case {sys.argv[2]} requires phase {case["phase"]}',
                file=sys.stderr,
            )
            raise SystemExit(1)
        raise SystemExit(0)
print(f'unknown trace case: {sys.argv[2]}', file=sys.stderr)
raise SystemExit(1)
PY
}

parse_arguments() {
	if [ "$#" -eq 1 ] && [ "$1" = "--self-test" ]; then
		run_self_test
		exit 0
	fi
	if [ "$#" -eq 1 ] && [ "$1" = "--list-cases" ]; then
		list_cases
		exit 0
	fi
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--case)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			CASE_NAME="$2"
			shift 2
			;;
		--phase)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			PHASE="$2"
			shift 2
			;;
		--evidence-dir)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			EVIDENCE_DIR="$2"
			shift 2
			;;
		--origin)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			ORIGINS+=("$2")
			shift 2
			;;
		--allow-destination)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			ALLOW_DESTINATIONS+=("$2")
			shift 2
			;;
		--allow-dns)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			ALLOW_DNS+=("$2")
			shift 2
			;;
		--allow-proxy)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			ALLOW_PROXIES+=("$2")
			shift 2
			;;
		--timeout)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			TIMEOUT_SECONDS="$2"
			shift 2
			;;
		--)
			shift
			COMMAND=("$@")
			break
			;;
		*)
			usage
			exit 2
			;;
		esac
	done
}

parse_arguments "$@"
[ -n "$CASE_NAME" ] || { usage; exit 2; }
[ -n "$PHASE" ] || { usage; exit 2; }
[ -n "$EVIDENCE_DIR" ] || { usage; exit 2; }
[ "${#COMMAND[@]}" -gt 0 ] || { usage; exit 2; }
case "$PHASE" in
preselection|public-discovery|local-direct|pinned-endpoint)
	;;
*)
	usage
	exit 2
	;;
esac
[[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] || fail "timeout must be a positive integer"

require_command python3
require_command strace
require_command timeout
[ -f "$CASE_MANIFEST" ] || fail "trace case manifest is missing: $CASE_MANIFEST"
[ -x "$PARSER" ] || fail "trace parser is missing or not executable: $PARSER"
[ -x "${COMMAND[0]}" ] || fail "target executable is missing or not executable: ${COMMAND[0]}"
validate_case || fail "trace case validation failed"

mkdir -p "$EVIDENCE_DIR"
RUN_ROOT="$(mktemp -d "$EVIDENCE_DIR/run.XXXXXX")"
mkdir -p "$RUN_ROOT/home" "$RUN_ROOT/workdir"
TRACE_PREFIX="$RUN_ROOT/strace"
REPORT="$EVIDENCE_DIR/network-report.json"
COMMAND_FILE="$EVIDENCE_DIR/command.txt"
STATUS_FILE="$EVIDENCE_DIR/status.txt"

{
	echo "case=$CASE_NAME"
	echo "phase=$PHASE"
	echo "timeout_seconds=$TIMEOUT_SECONDS"
	echo "home=$RUN_ROOT/home"
	echo "workdir=$RUN_ROOT/workdir"
	strace -V
} > "$EVIDENCE_DIR/observer.txt" 2>&1
printf '%s\n' "${ORIGINS[@]}" > "$EVIDENCE_DIR/allowed-origins.txt"
printf '%s\n' "${ALLOW_DESTINATIONS[@]}" > "$EVIDENCE_DIR/allowed-destinations.txt"
printf '%s\n' "${ALLOW_DNS[@]}" > "$EVIDENCE_DIR/allowed-dns.txt"
printf '%s\n' "${ALLOW_PROXIES[@]}" > "$EVIDENCE_DIR/allowed-proxies.txt"

has_argument() {
	local value="$1"
	shift
	local candidate
	for candidate in "$@"; do
		[ "$candidate" = "$value" ] && return 0
	done
	return 1
}

if ! has_argument -noupdate "${COMMAND[@]}"; then
	COMMAND+=( -noupdate )
fi
if ! has_argument -debug "${COMMAND[@]}"; then
	COMMAND+=( -debug )
fi
if ! has_argument -workdir "${COMMAND[@]}"; then
	COMMAND+=( -workdir "$RUN_ROOT/workdir" )
fi
printf '%q ' "${COMMAND[@]}" > "$COMMAND_FILE"
printf '\n' >> "$COMMAND_FILE"

trap cleanup EXIT
set +e
env \
	HOME="$RUN_ROOT/home" \
	XDG_CONFIG_HOME="$RUN_ROOT/home/.config" \
	XDG_DATA_HOME="$RUN_ROOT/home/.local/share" \
	RES_OPTIONS="attempts:1 timeout:1" \
	timeout --signal=TERM --kill-after=5s "$TIMEOUT_SECONDS" \
	strace -ff -ttt -yy -s 4096 -e trace=%network -o "$TRACE_PREFIX" \
	"${COMMAND[@]}" \
	> "$EVIDENCE_DIR/stdout.log" \
	2> "$EVIDENCE_DIR/stderr.log" &
RUNNER_PID=$!
wait "$RUNNER_PID"
PROCESS_STATUS=$?
RUNNER_PID=""
set -e
printf 'process_status=%s\n' "$PROCESS_STATUS" > "$EVIDENCE_DIR/process-status.txt"
if [ "$PROCESS_STATUS" -ne 0 ] && [ "$PROCESS_STATUS" -ne 124 ] \
	&& [ "$PROCESS_STATUS" -ne 137 ] && [ "$PROCESS_STATUS" -ne 143 ]; then
	printf 'FAIL: target process exited with status %s\n' "$PROCESS_STATUS" \
		> "$STATUS_FILE"
	exit 1
fi

PARSER_COMMAND=(python3 "$PARSER" --trace "$TRACE_PREFIX.*"
	--case "$CASE_NAME" --phase "$PHASE" --report "$REPORT")
for origin in "${ORIGINS[@]}"; do
	PARSER_COMMAND+=(--origin "$origin")
done
for destination in "${ALLOW_DESTINATIONS[@]}"; do
	PARSER_COMMAND+=(--allow-destination "$destination")
done
for dns in "${ALLOW_DNS[@]}"; do
	PARSER_COMMAND+=(--allow-dns "$dns")
done
for proxy in "${ALLOW_PROXIES[@]}"; do
	PARSER_COMMAND+=(--allow-proxy "$proxy")
done

set +e
"${PARSER_COMMAND[@]}" > "$EVIDENCE_DIR/network-report.stdout.json"
CHECK_STATUS=$?
set -e
if [ "$CHECK_STATUS" -eq 0 ]; then
	printf 'PASS: case=%s phase=%s process_status=%s\n' \
		"$CASE_NAME" "$PHASE" "$PROCESS_STATUS" | tee "$STATUS_FILE"
	exit 0
fi
printf 'FAIL: case=%s phase=%s process_status=%s report=%s\n' \
	"$CASE_NAME" "$PHASE" "$PROCESS_STATUS" "$REPORT" | tee "$STATUS_FILE" >&2
exit 1
