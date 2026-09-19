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
TIMEOUT_SET=0
MANIFEST_MODE=0
CASE_CONTRACT=""
REPORT_NAME="network-report.json"
INVOCATION_ARGS=()
INVOCATION_ENV=()
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
  network_isolation_test.sh --manifest MANIFEST --case CASE \
    --evidence-dir DIR -- TELEGRAMD [ARGS...]
  network_isolation_test.sh --case CASE --phase PHASE --evidence-dir DIR \
    [--origin URL] [--allow-destination HOST:PORT] [--allow-dns HOST:53] \
    [--allow-proxy HOST:PORT] \
    [--timeout SECONDS] -- TELEGRAMD [ARGS...]

With --manifest, the case supplies the phase, bounded invocation, destination
allowlist, and report name. Without it, PHASE and the allowlist flags are
required explicitly. PHASE is one of preselection, public-discovery,
local-direct, or pinned-endpoint.
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
	validate_manifest
	python3 - "$CASE_MANIFEST" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as manifest:
    for case in json.load(manifest)["cases"]:
        invocation = case["invocation"]
        allowlist = case["allowlist"]
        print("\t".join((
            case["name"],
            case["phase"],
            str(invocation["timeout_seconds"]),
            case["report"],
            json.dumps(invocation, sort_keys=True),
            json.dumps(allowlist, sort_keys=True),
            case["description"],
        )))
PY
}

validate_manifest() {
	python3 - "$CASE_MANIFEST" <<'PY'
import json
import re
import sys
from pathlib import PurePath

phases = {"preselection", "public-discovery", "local-direct", "pinned-endpoint"}
environment_key = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
allowlist_fields = ("origins", "destinations", "dns", "proxies")

def fail(message):
    print(f"invalid network trace manifest: {message}", file=sys.stderr)
    raise SystemExit(1)

try:
    with open(sys.argv[1], encoding="utf-8") as manifest:
        document = json.load(manifest)
except (OSError, json.JSONDecodeError) as error:
    fail(str(error))

if document.get("version") != 2:
    fail("version must be 2")
cases = document.get("cases")
if not isinstance(cases, list) or not cases:
    fail("cases must be a non-empty list")

names = set()
for index, case in enumerate(cases):
    prefix = f"case {index}"
    if not isinstance(case, dict):
        fail(f"{prefix} must be an object")
    name = case.get("name")
    phase = case.get("phase")
    if not isinstance(name, str) or not name or name in names:
        fail(f"{prefix} has a duplicate or invalid name")
    names.add(name)
    if phase not in phases:
        fail(f"{name} has an invalid phase")
    if not isinstance(case.get("description"), str) or not case["description"]:
        fail(f"{name} needs a description")

    invocation = case.get("invocation")
    if not isinstance(invocation, dict):
        fail(f"{name} needs an invocation contract")
    timeout = invocation.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300:
        fail(f"{name} needs a timeout from 1 through 300 seconds")
    arguments = invocation.get("arguments")
    if not isinstance(arguments, list) or not arguments or any(
        not isinstance(argument, str) or not argument for argument in arguments
    ):
        fail(f"{name} needs non-empty invocation arguments")
    environment = invocation.get("environment")
    if not isinstance(environment, dict):
        fail(f"{name} needs an invocation environment")
    if environment.get("TDESKTOP_NETWORK_TRACE_CASE") != name:
        fail(f"{name} must bind TDESKTOP_NETWORK_TRACE_CASE")
    for key, value in environment.items():
        if not isinstance(key, str) or not environment_key.fullmatch(key):
            fail(f"{name} has an invalid environment key")
        if not isinstance(value, str) or "\n" in value or "\t" in value:
            fail(f"{name} has an invalid environment value")

    allowlist = case.get("allowlist")
    if not isinstance(allowlist, dict):
        fail(f"{name} needs an explicit destination allowlist")
    if set(allowlist) != set(allowlist_fields):
        fail(f"{name} must specify origins, destinations, dns, and proxies")
    for field in allowlist_fields:
        values = allowlist[field]
        if not isinstance(values, list) or any(
            not isinstance(value, str) or not value for value in values
        ):
            fail(f"{name} has an invalid {field} allowlist")
    if phase == "public-discovery" and len(allowlist["origins"]) != 1:
        fail(f"{name} needs exactly one public discovery origin")
    if phase != "public-discovery" and allowlist["origins"]:
        fail(f"{name} cannot allow a public discovery origin")

    report = case.get("report")
    if (
        not isinstance(report, str)
        or not report
        or PurePath(report).name != report
        or report in {".", ".."}
    ):
        fail(f"{name} needs a relative report filename")
PY
}

load_case_contract() {
	CASE_CONTRACT="$(python3 - "$CASE_MANIFEST" "$CASE_NAME" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as manifest:
    cases = json.load(manifest)["cases"]
for case in cases:
    if case["name"] == sys.argv[2]:
        print(json.dumps(case, separators=(",", ":")))
        raise SystemExit(0)
print(f"unknown trace case: {sys.argv[2]}", file=sys.stderr)
raise SystemExit(1)
PY
	)" || fail "trace case loading failed"
}

case_contract_values() {
	python3 - "$CASE_CONTRACT" "$1" <<'PY'
import json
import sys

case = json.loads(sys.argv[1])
field = sys.argv[2]
if field == "phase":
    print(case["phase"])
elif field == "timeout_seconds":
    print(case["invocation"]["timeout_seconds"])
elif field == "report":
    print(case["report"])
elif field == "arguments":
    print("\n".join(case["invocation"]["arguments"]))
elif field == "environment":
    for key, value in case["invocation"]["environment"].items():
        print(f"{key}\t{value}")
elif field in {"origins", "destinations", "dns", "proxies"}:
    print("\n".join(case["allowlist"][field]))
else:
    raise SystemExit(f"unknown contract field: {field}")
PY
}

validate_case() {
	load_case_contract
	local manifest_phase
	manifest_phase="$(case_contract_values phase)"
	if [ "$manifest_phase" != "$PHASE" ]; then
		printf 'case %s requires phase %s\n' "$CASE_NAME" "$manifest_phase" >&2
		return 1
	fi
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
		--manifest)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			CASE_MANIFEST="$2"
			MANIFEST_MODE=1
			shift 2
			;;
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
			TIMEOUT_SET=1
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
[ -n "$EVIDENCE_DIR" ] || { usage; exit 2; }
[ "${#COMMAND[@]}" -gt 0 ] || { usage; exit 2; }
require_command python3

if [ "$MANIFEST_MODE" -eq 1 ]; then
	[ -f "$CASE_MANIFEST" ] || fail "trace case manifest is missing: $CASE_MANIFEST"
	[ -z "$PHASE" ] || fail "--manifest supplies the phase; omit --phase"
	[ "$TIMEOUT_SET" -eq 0 ] || fail "--manifest supplies the timeout; omit --timeout"
	[ "${#ORIGINS[@]}" -eq 0 ] || fail "--manifest supplies origins"
	[ "${#ALLOW_DESTINATIONS[@]}" -eq 0 ] || fail "--manifest supplies destinations"
	[ "${#ALLOW_DNS[@]}" -eq 0 ] || fail "--manifest supplies DNS"
	[ "${#ALLOW_PROXIES[@]}" -eq 0 ] || fail "--manifest supplies proxies"
	validate_manifest || fail "trace case manifest validation failed"
	load_case_contract
	PHASE="$(case_contract_values phase)"
	TIMEOUT_SECONDS="$(case_contract_values timeout_seconds)"
	REPORT_NAME="$(case_contract_values report)"
	while IFS= read -r argument; do
		[ -n "$argument" ] && INVOCATION_ARGS+=("$argument")
	done < <(case_contract_values arguments)
	while IFS=$'\t' read -r key value; do
		[ -n "$key" ] && INVOCATION_ENV+=("$key=$value")
	done < <(case_contract_values environment)
	while IFS= read -r origin; do
		[ -n "$origin" ] && ORIGINS+=("$origin")
	done < <(case_contract_values origins)
	while IFS= read -r destination; do
		[ -n "$destination" ] && ALLOW_DESTINATIONS+=("$destination")
	done < <(case_contract_values destinations)
	while IFS= read -r dns; do
		[ -n "$dns" ] && ALLOW_DNS+=("$dns")
	done < <(case_contract_values dns)
	while IFS= read -r proxy; do
		[ -n "$proxy" ] && ALLOW_PROXIES+=("$proxy")
	done < <(case_contract_values proxies)
else
	[ -n "$PHASE" ] || { usage; exit 2; }
fi
case "$PHASE" in
preselection|public-discovery|local-direct|pinned-endpoint)
	;;
*)
	usage
	exit 2
	;;
esac
[[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] || fail "timeout must be a positive integer"

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
REPORT="$EVIDENCE_DIR/$REPORT_NAME"
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

if [ "$MANIFEST_MODE" -eq 1 ]; then
	COMMAND+=("${INVOCATION_ARGS[@]}")
fi

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
	"${INVOCATION_ENV[@]}" \
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

PARSER_COMMAND=(python3 "$PARSER" --trace "$TRACE_PREFIX.*"
	--case "$CASE_NAME" --phase "$PHASE"
	--target-status "$PROCESS_STATUS" --report "$REPORT")
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
