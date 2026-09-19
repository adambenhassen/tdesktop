#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER="$ROOT/network_trace.py"
UNIT_TEST="$ROOT/network_trace_test.py"
CASE_MANIFEST="$ROOT/network_trace_cases.json"
EVIDENCE_DIR=""
CASE_NAME=""
PHASE=""
TIMEOUT_SECONDS=20
CASE_CONTRACT=""
REPORT_NAME="network-report.json"
UPDATE_MODE="disabled"
COMPLETION_LOG_NAME="test_log.txt"
COMPLETION_MARKER="TEST_COMPLETE"
COMPLETION_RESULT="SCENARIO_RESULT: PASS"
RESOLUTION_FILE=""
FAILURE_EVIDENCE_FILE=""
FAILURE_EVIDENCE_ENDPOINT=""
TEST_EVIDENCE_DIR=""
PROXY_ASSERTION_FILE=""
PROXY_TARGET=""
PUBLIC_FIXTURE_FILE=""
PUBLIC_FIXTURE_ADDRESS=""
PUBLIC_FIXTURE_PROXY=""
INVOCATION_ARGS=()
INVOCATION_ENV=()
ORIGINS=()
ALLOW_DESTINATIONS=()
ALLOW_DNS=()
ALLOW_PROXIES=()
REQUIRED_DESTINATIONS=()
REQUIRED_DNS=()
REQUIRED_PROXIES=()
COMMAND=()
RUN_ROOT=""
RUNNER_PID=""
PUBLIC_FIXTURE_PID=""

usage() {
	cat >&2 <<'EOF'
usage:
  network_isolation_test.sh --self-test
  network_isolation_test.sh --list-cases
  network_isolation_test.sh --case CASE --evidence-dir DIR \
    -- TELEGRAMD [ARGS...]

The trusted manifest supplies the phase, bounded invocation, destination
allowlist, and report name. Caller-supplied policy flags are not accepted.
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
	if [ -n "$PUBLIC_FIXTURE_PID" ] && kill -0 "$PUBLIC_FIXTURE_PID" 2>/dev/null; then
		kill -TERM "$PUBLIC_FIXTURE_PID" 2>/dev/null || true
		wait "$PUBLIC_FIXTURE_PID" 2>/dev/null || true
	fi
	if [ -n "$RUNNER_PID" ] && kill -0 "$RUNNER_PID" 2>/dev/null; then
		kill -TERM "$RUNNER_PID" 2>/dev/null || true
		wait "$RUNNER_PID" 2>/dev/null || true
	fi
	if [ -n "$RUN_ROOT" ] && [ -d "$RUN_ROOT" ]; then
		rm -rf -- "$RUN_ROOT"
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
	cat > "$test_root/public-failure.trace" <<'EOF'
socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
sendto(3, "dns", 3, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 3
EOF
	cat > "$test_root/public-resolution.json" <<'EOF'
{"origin":"https://public.example/.well-known/telegramd/client","host":"public.example","error":"NoError","addresses":["203.0.113.10"],"destinations":["203.0.113.10:443"]}
EOF
	cat > "$test_root/public-failure-resolution.json" <<'EOF'
{"origin":"https://public-failure.invalid/.well-known/telegramd/client","host":"public-failure.invalid","error":"HostNotFound","addresses":[],"destinations":[]}
EOF
	cat > "$test_root/proxy.trace" <<'EOF'
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(19080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
EOF
	printf '%s\n' '{"protocol":"SOCKS5","version":5,"command":"CONNECT","target":"192.0.2.10:443","observed":true}' > "$test_root/proxy-target.txt"

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
		--allow-dns 127.0.0.53:53 \
		--require-destination 203.0.113.10:443 \
		--require-dns 127.0.0.53:53 \
		--resolution-evidence "$test_root/public-resolution.json"
	run_expected_failure public-direct-fallback "${parser[@]}" \
		--trace "$test_root/public-fallback.trace" \
		--case public-failure --phase public-discovery \
		--origin https://public-failure.invalid/.well-known/telegramd/client \
		--allow-dns 127.0.0.53:53 \
		--resolution-evidence "$test_root/public-failure-resolution.json"
	run_expected_success public-failure-without-fallback "${parser[@]}" \
		--trace "$test_root/public-failure.trace" \
		--case public-failure --phase public-discovery \
		--origin https://public-failure.invalid/.well-known/telegramd/client \
		--allow-dns 127.0.0.53:53 \
		--require-dns 127.0.0.53:53 \
		--resolution-evidence "$test_root/public-failure-resolution.json"
	run_expected_success proxy-intermediary "${parser[@]}" \
		--trace "$test_root/proxy.trace" \
		--case proxy-intermediary --phase pinned-endpoint \
		--allow-destination 192.0.2.10:443 \
		--allow-proxy 127.0.0.1:19080 \
		--require-destination 192.0.2.10:443 \
		--require-proxy 127.0.0.1:19080 \
		--proxy-target 192.0.2.10:443 \
		--proxy-target-proof "$test_root/proxy-target.txt"
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
            json.dumps(case["required"], sort_keys=True),
            json.dumps(case.get("resolution"), sort_keys=True),
            json.dumps(case.get("failure_evidence"), sort_keys=True),
            json.dumps(case["completion"], sort_keys=True),
            case["description"],
        )))
PY
}

validate_manifest() {
	python3 - "$CASE_MANIFEST" <<'PY'
import json
import ipaddress
import re
import sys
import urllib.parse
from pathlib import PurePath

phases = {"preselection", "public-discovery", "local-direct", "pinned-endpoint"}
environment_key = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
allowlist_fields = ("origins", "destinations", "dns", "proxies")

def fail(message):
    print(f"invalid network trace manifest: {message}", file=sys.stderr)
    raise SystemExit(1)

def split_endpoint(value):
    if value.startswith("["):
        separator = value.find("]:")
        if separator < 0:
            return None
        return value[1:separator], value[separator + 2:]
    host, separator, port = value.rpartition(":")
    if not separator:
        return None
    return host, port

def valid_ip_endpoint(value):
    parsed = split_endpoint(value)
    if parsed is None:
        return False
    host, port = parsed
    try:
        port_number = int(port)
        ipaddress.ip_network(host, strict=False)
    except (ValueError, TypeError):
        return False
    return 0 <= port_number <= 65535

def valid_dns_endpoint(value):
    if value.startswith("unix:"):
        path = value[len("unix:"):]
        return path.startswith("/") and "\n" not in path and "\r" not in path
    return valid_ip_endpoint(value)

def valid_public_origin(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
    except ValueError:
        return False
    return (
        bool(hostname)
        and hostname.isascii()
        and hostname == hostname.lower()
        and not hostname.endswith(".")
        and value == f"https://{hostname}/.well-known/telegramd/client"
    )

try:
    with open(sys.argv[1], encoding="utf-8") as manifest:
        document = json.load(manifest)
except (OSError, json.JSONDecodeError) as error:
    fail(str(error))

if document.get("version") != 5:
    fail("version must be 5")
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
    if invocation.get("update_mode") not in {"enabled", "disabled"}:
        fail(f"{name} needs an explicit update mode")
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
        if field != "origins":
            validator = valid_dns_endpoint if field == "dns" else valid_ip_endpoint
            if any(not validator(value) for value in values):
                fail(f"{name} has a non-IP {field} allowlist entry")
    if phase == "public-discovery" and len(allowlist["origins"]) != 1:
        fail(f"{name} needs exactly one public discovery origin")
    if phase == "public-discovery" and not valid_public_origin(allowlist["origins"][0]):
        fail(f"{name} has an invalid public discovery origin")
    if phase != "public-discovery" and allowlist["origins"]:
        fail(f"{name} cannot allow a public discovery origin")
    if phase == "preselection" and any(
        allowlist[field] for field in ("destinations", "dns", "proxies")
    ):
        fail(f"{name} must keep preselection network-free")

    required = case.get("required")
    if not isinstance(required, dict) or set(required) != {
        "destinations", "dns", "proxies", "proxy_target"
    }:
        fail(f"{name} needs explicit required evidence")
    for field in ("destinations", "dns", "proxies"):
        values = required[field]
        if not isinstance(values, list) or any(
            not isinstance(value, str) or not value for value in values
        ):
            fail(f"{name} has invalid required {field} evidence")
        if any(value not in allowlist[field] for value in values):
            fail(f"{name} requires a value outside its {field} allowlist")
    if phase == "preselection" and any(
        required[field] for field in ("destinations", "dns", "proxies")
    ):
        fail(f"{name} must not require preselection network evidence")
    proxy_target = required["proxy_target"]
    if proxy_target is not None and (
        not isinstance(proxy_target, str)
        or not valid_ip_endpoint(proxy_target)
        or proxy_target not in required["destinations"]
    ):
        fail(f"{name} has an invalid proxy target assertion")
    if phase == "public-discovery" and (
        (
            not required["dns"]
            and not (required["proxies"] and proxy_target is not None)
        )
        or (
            name != "public-failure"
            and (
                not required["destinations"]
                or set(required["destinations"]) != set(allowlist["destinations"])
            )
        )
    ):
        fail(f"{name} must bind its origin to every resolved destination")
    if phase == "public-discovery" and invocation["environment"].get(
        "TDESKTOP_NETWORK_TRACE_PUBLIC_FIXTURE"
    ) != "public-discovery.json":
        fail(f"{name} must use the controlled public fixture")
    if phase == "public-discovery" and (
        invocation["environment"].get("TDESKTOP_NETWORK_TRACE_PUBLIC_ADDRESS")
        != "203.0.113.10"
        or invocation["environment"].get("TDESKTOP_NETWORK_TRACE_PUBLIC_PROXY")
        != "127.0.0.1:19444"
    ):
        fail(f"{name} must bind the controlled public fixture endpoints")
    if phase in {"local-direct", "pinned-endpoint"} and not required["destinations"]:
        fail(f"{name} needs required endpoint evidence")
    if name == "proxy-intermediary" and (
        not required["proxies"] or proxy_target is None
    ):
        fail(f"{name} needs proxy transport and target evidence")

    failure_evidence = case.get("failure_evidence")
    if name == "selected-endpoint-failure":
        if failure_evidence != {
            "file": "network-selected-failure.json",
            "endpoint": "127.0.0.1:19083",
            "attempted": True,
            "failed": True,
            "fallback_suppressed": True,
        }:
            fail(f"{name} needs post-commit failure evidence")
    elif failure_evidence is not None:
        fail(f"{name} cannot declare failure evidence")

    resolution = case.get("resolution")
    if phase == "public-discovery":
        if not isinstance(resolution, dict) or set(resolution) != {
            "file", "origin", "host", "destinations"
        }:
            fail(f"{name} needs observed resolution evidence contract")
        resolution_file = resolution["file"]
        if (
            not isinstance(resolution_file, str)
            or not resolution_file
            or PurePath(resolution_file).name != resolution_file
            or resolution_file in {".", ".."}
            or "\n" in resolution_file
            or "\r" in resolution_file
        ):
            fail(f"{name} needs a relative resolution evidence file")
        if (
            not isinstance(resolution["origin"], str)
            or not valid_public_origin(resolution["origin"])
            or resolution["origin"] != allowlist["origins"][0]
        ):
            fail(f"{name} resolution origin must match its allowlist")
        if (
            not isinstance(resolution["host"], str)
            or resolution["host"]
            != urllib.parse.urlsplit(resolution["origin"]).hostname
        ):
            fail(f"{name} resolution host must match its origin")
        if (
            not isinstance(resolution["destinations"], list)
            or any(
                not isinstance(value, str)
                or not valid_ip_endpoint(value)
                for value in resolution["destinations"]
            )
            or resolution["destinations"] != required["destinations"]
        ):
            fail(f"{name} resolution destinations must match required evidence")
    elif resolution is not None:
        fail(f"{name} cannot declare resolution evidence outside public discovery")

    completion = case.get("completion")
    if not isinstance(completion, dict) or set(completion) != {
        "log", "marker", "result"
    }:
        fail(f"{name} needs a completion contract")
    log_name = completion["log"]
    if (
        not isinstance(log_name, str)
        or not log_name
        or PurePath(log_name).name != log_name
    ):
        fail(f"{name} needs a relative completion log")
    for field in ("marker", "result"):
        if (
            not isinstance(completion[field], str)
            or not completion[field]
            or "\n" in completion[field]
        ):
            fail(f"{name} needs a single-line completion {field}")

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
elif field == "update_mode":
    print(case["invocation"]["update_mode"])
elif field == "report":
    print(case["report"])
elif field == "completion_log":
    print(case["completion"]["log"])
elif field == "completion_marker":
    print(case["completion"]["marker"])
elif field == "completion_result":
    print(case["completion"]["result"])
elif field == "resolution_file":
    if case.get("resolution") is not None:
        print(case["resolution"]["file"])
elif field == "failure_evidence_file":
    if case.get("failure_evidence") is not None:
        print(case["failure_evidence"]["file"])
elif field == "failure_evidence_endpoint":
    if case.get("failure_evidence") is not None:
        print(case["failure_evidence"]["endpoint"])
elif field == "public_fixture_file":
    print(case["invocation"]["environment"].get(
        "TDESKTOP_NETWORK_TRACE_PUBLIC_FIXTURE", ""
    ))
elif field == "public_fixture_address":
    print(case["invocation"]["environment"].get(
        "TDESKTOP_NETWORK_TRACE_PUBLIC_ADDRESS", ""
    ))
elif field == "public_fixture_proxy":
    print(case["invocation"]["environment"].get(
        "TDESKTOP_NETWORK_TRACE_PUBLIC_PROXY", ""
    ))
elif field == "arguments":
    print("\n".join(case["invocation"]["arguments"]))
elif field == "environment":
    for key, value in case["invocation"]["environment"].items():
        print(f"{key}\t{value}")
elif field in {"origins", "destinations", "dns", "proxies"}:
    print("\n".join(case["allowlist"][field]))
elif field in {"required_destinations", "required_dns", "required_proxies"}:
    required_field = field[len("required_"):]
    print("\n".join(case["required"][required_field]))
elif field == "proxy_target":
    if case["required"]["proxy_target"] is not None:
        print(case["required"]["proxy_target"])
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
		--case)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			CASE_NAME="$2"
			shift 2
			;;
		--evidence-dir)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			EVIDENCE_DIR="$2"
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
[ -f "$CASE_MANIFEST" ] || fail "trace case manifest is missing: $CASE_MANIFEST"
validate_manifest || fail "trace case manifest validation failed"
load_case_contract
PHASE="$(case_contract_values phase)"
TIMEOUT_SECONDS="$(case_contract_values timeout_seconds)"
REPORT_NAME="$(case_contract_values report)"
UPDATE_MODE="$(case_contract_values update_mode)"
COMPLETION_LOG_NAME="$(case_contract_values completion_log)"
COMPLETION_MARKER="$(case_contract_values completion_marker)"
COMPLETION_RESULT="$(case_contract_values completion_result)"
RESOLUTION_FILE="$(case_contract_values resolution_file)"
FAILURE_EVIDENCE_FILE="$(case_contract_values failure_evidence_file)"
FAILURE_EVIDENCE_ENDPOINT="$(case_contract_values failure_evidence_endpoint)"
PUBLIC_FIXTURE_FILE="$(case_contract_values public_fixture_file)"
PUBLIC_FIXTURE_ADDRESS="$(case_contract_values public_fixture_address)"
PUBLIC_FIXTURE_PROXY="$(case_contract_values public_fixture_proxy)"
PROXY_TARGET="$(case_contract_values proxy_target)"
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
while IFS= read -r destination; do
	[ -n "$destination" ] && REQUIRED_DESTINATIONS+=("$destination")
done < <(case_contract_values required_destinations)
while IFS= read -r dns; do
	[ -n "$dns" ] && REQUIRED_DNS+=("$dns")
done < <(case_contract_values required_dns)
while IFS= read -r proxy; do
	[ -n "$proxy" ] && REQUIRED_PROXIES+=("$proxy")
done < <(case_contract_values required_proxies)
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
touch "$RUN_ROOT/workdir/testing"
TEST_EVIDENCE_DIR="$EVIDENCE_DIR/test-evidence"
PROXY_ASSERTION_FILE="$TEST_EVIDENCE_DIR/proxy-target.txt"
mkdir -p "$TEST_EVIDENCE_DIR"
rm -f -- "$TEST_EVIDENCE_DIR/$COMPLETION_LOG_NAME" "$PROXY_ASSERTION_FILE"
if [ -n "$RESOLUTION_FILE" ]; then
	rm -f -- "$TEST_EVIDENCE_DIR/$RESOLUTION_FILE"
fi
if [ -n "$FAILURE_EVIDENCE_FILE" ]; then
	rm -f -- "$TEST_EVIDENCE_DIR/$FAILURE_EVIDENCE_FILE"
fi
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

COMMAND+=("${INVOCATION_ARGS[@]}")

has_argument() {
	local value="$1"
	shift
	local candidate
	for candidate in "$@"; do
		[ "$candidate" = "$value" ] && return 0
	done
	return 1
}

if [ "$UPDATE_MODE" = "disabled" ]; then
	if ! has_argument -noupdate "${COMMAND[@]}"; then
		COMMAND+=( -noupdate )
	fi
elif has_argument -noupdate "${COMMAND[@]}"; then
	fail "case $CASE_NAME requires update mode"
fi
if ! has_argument -debug "${COMMAND[@]}"; then
	COMMAND+=( -debug )
fi
if ! has_argument -workdir "${COMMAND[@]}"; then
	COMMAND+=( -workdir "$RUN_ROOT/workdir" )
fi
printf '%q ' "${COMMAND[@]}" > "$COMMAND_FILE"
printf '\n' >> "$COMMAND_FILE"

start_public_fixture() {
	if [ "$PHASE" != "public-discovery" ]; then
		return
	fi
	require_command openssl
	[ "$PUBLIC_FIXTURE_FILE" = "public-discovery.json" ] || \
		fail "public fixture file is not trusted"
	[ "$PUBLIC_FIXTURE_ADDRESS" = "203.0.113.10" ] || \
		fail "public fixture address is not trusted"
	[ "$PUBLIC_FIXTURE_PROXY" = "127.0.0.1:19444" ] || \
		fail "public fixture proxy is not trusted"
	local certificate="$RUN_ROOT/public-fixture-cert.pem"
	local key="$RUN_ROOT/public-fixture-key.pem"
	local ready="$RUN_ROOT/public-fixture.ready"
	openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
		-subj /CN=public.example \
		-addext subjectAltName=DNS:public.example \
		-keyout "$key" -out "$certificate" >/dev/null 2>&1 \
		|| fail "public fixture certificate generation failed"
	python3 "$ROOT/network_public_fixture.py" \
		--certificate "$certificate" \
		--key "$key" \
		--response "$ROOT/network_trace_fixtures/$PUBLIC_FIXTURE_FILE" \
		--proof "$PROXY_ASSERTION_FILE" \
		--ready "$ready" \
		--proxy-port "${PUBLIC_FIXTURE_PROXY##*:}" \
		--https-port 19443 &
	PUBLIC_FIXTURE_PID=$!
	for _ in $(seq 1 100); do
		if [ -f "$ready" ]; then
			return
		fi
		if ! kill -0 "$PUBLIC_FIXTURE_PID" 2>/dev/null; then
			wait "$PUBLIC_FIXTURE_PID" 2>/dev/null || true
			fail "public fixture exited before becoming ready"
		fi
		sleep 0.05
	done
	fail "public fixture did not become ready"
}

trap cleanup EXIT
start_public_fixture

set +e
env \
	HOME="$RUN_ROOT/home" \
	XDG_CONFIG_HOME="$RUN_ROOT/home/.config" \
	XDG_DATA_HOME="$RUN_ROOT/home/.local/share" \
	RES_OPTIONS="attempts:1 timeout:1" \
	TDESKTOP_TEST_EVIDENCE_DIR="$TEST_EVIDENCE_DIR" \
	TDESKTOP_PROXY_ASSERTION_FILE="$PROXY_ASSERTION_FILE" \
	"${INVOCATION_ENV[@]}" \
	timeout --signal=TERM --kill-after=5s "$TIMEOUT_SECONDS" \
	strace -ff -ttt -yy -s 0 -e trace=%network -o "$TRACE_PREFIX" \
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
	--target-status "$PROCESS_STATUS" --report "$REPORT"
	--proxy-target "$PROXY_TARGET")
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
for destination in "${REQUIRED_DESTINATIONS[@]}"; do
	PARSER_COMMAND+=(--require-destination "$destination")
done
for dns in "${REQUIRED_DNS[@]}"; do
	PARSER_COMMAND+=(--require-dns "$dns")
done
for proxy in "${REQUIRED_PROXIES[@]}"; do
	PARSER_COMMAND+=(--require-proxy "$proxy")
done
if [ -n "$PROXY_TARGET" ]; then
	PARSER_COMMAND+=(--proxy-target-proof "$PROXY_ASSERTION_FILE")
fi
if [ -n "$RESOLUTION_FILE" ]; then
	PARSER_COMMAND+=(--resolution-evidence "$TEST_EVIDENCE_DIR/$RESOLUTION_FILE")
fi
if [ -n "$FAILURE_EVIDENCE_FILE" ]; then
	PARSER_COMMAND+=(
		--failure-evidence "$TEST_EVIDENCE_DIR/$FAILURE_EVIDENCE_FILE"
		--failure-endpoint "$FAILURE_EVIDENCE_ENDPOINT"
	)
fi

set +e
"${PARSER_COMMAND[@]}" > "$EVIDENCE_DIR/network-report.stdout.json"
CHECK_STATUS=$?
set -e
for trace_file in "$TRACE_PREFIX".*; do
	if [ -f "$trace_file" ]; then
		rm -f -- "$trace_file"
	fi
done
if [ "$CHECK_STATUS" -ne 0 ]; then
	printf 'FAIL: case=%s phase=%s process_status=%s report=%s\n' \
		"$CASE_NAME" "$PHASE" "$PROCESS_STATUS" "$REPORT" | tee "$STATUS_FILE" >&2
	exit 1
fi

case "$PROCESS_STATUS" in
124|137|143)
	printf 'FAIL: case=%s timed out or was terminated process_status=%s\n' \
		"$CASE_NAME" "$PROCESS_STATUS" | tee "$STATUS_FILE" >&2
	exit 1
;;
esac

COMPLETION_LOG="$TEST_EVIDENCE_DIR/$COMPLETION_LOG_NAME"
if ! grep -Fqx "$COMPLETION_MARKER" "$COMPLETION_LOG" 2>/dev/null; then
	printf 'FAIL: case=%s missing completion marker=%s\n' \
		"$CASE_NAME" "$COMPLETION_MARKER" | tee "$STATUS_FILE" >&2
	exit 1
fi
if ! grep -Fqx "$COMPLETION_RESULT" "$COMPLETION_LOG" 2>/dev/null; then
	printf 'FAIL: case=%s missing completion result=%s\n' \
		"$CASE_NAME" "$COMPLETION_RESULT" | tee "$STATUS_FILE" >&2
	exit 1
fi

if [ -n "$FAILURE_EVIDENCE_FILE" ]; then
	python3 - "$TEST_EVIDENCE_DIR/$FAILURE_EVIDENCE_FILE" "$FAILURE_EVIDENCE_ENDPOINT" <<'PY'
import json
import sys

path, endpoint = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as evidence:
        observed = json.load(evidence)
except (OSError, json.JSONDecodeError) as error:
    print(f"FAIL: selected endpoint failure evidence is invalid: {error}", file=sys.stderr)
    raise SystemExit(1)
expected = {
    "endpoint": endpoint,
    "attempted": True,
    "failed": True,
    "fallback_suppressed": True,
}
if observed != expected:
    print(
        f"FAIL: selected endpoint failure evidence mismatch: {observed!r}",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
fi

printf 'PASS: case=%s phase=%s process_status=%s\n' \
	"$CASE_NAME" "$PHASE" "$PROCESS_STATUS" | tee "$STATUS_FILE"
exit 0
