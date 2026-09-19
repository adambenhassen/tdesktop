#!/usr/bin/env bash

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$ROOT/network_isolation_test.sh"

if [ ! -x "$SCRIPT" ]; then
	echo "FAIL: network isolation runner is missing or not executable" >&2
	exit 1
fi

"$SCRIPT" --self-test

python3 - "$ROOT/network_trace_cases.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as manifest:
    cases = {case["name"]: case for case in json.load(manifest)["cases"]}

for name in (
    "canceled-selection",
    "failed-selection",
    "partial-selection",
    "timed-out-selection",
    "late-callback",
):
    case = cases[name]
    for field in ("destinations", "dns", "proxies"):
        if case["allowlist"][field] or case["required"][field]:
            raise SystemExit(
                f"FAIL: {name} must remain network-free before selection"
            )

for name in ("public-selection", "public-failure"):
    fixture = cases[name]["invocation"]["environment"].get(
        "TDESKTOP_NETWORK_TRACE_PUBLIC_FIXTURE"
    )
    if fixture != "public-discovery.json":
        raise SystemExit(f"FAIL: {name} lacks the controlled public fixture")

failure = cases["selected-endpoint-failure"].get("failure_evidence")
if failure != {
    "file": "network-selected-failure.json",
    "endpoint": "127.0.0.1:19083",
    "attempted": True,
    "failed": True,
    "fallback_suppressed": True,
}:
    raise SystemExit(
        "FAIL: selected-endpoint-failure lacks post-commit failure evidence"
    )
PY

if ! python3 "$ROOT/network_public_fixture.py" --help >/dev/null; then
	echo "FAIL: controlled public fixture is unavailable" >&2
	exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/main839-network-runner.XXXXXX")"
trap 'rm -rf -- "$TEST_ROOT"' EXIT
FAKE_BIN="$TEST_ROOT/bin"
EVIDENCE_DIR="$TEST_ROOT/evidence"
TARGET="$TEST_ROOT/target"
mkdir -p "$FAKE_BIN"

cat > "$TARGET" <<'EOF'
#!/usr/bin/env bash
printf 'trace-case=%s args=%s\n' "${TDESKTOP_NETWORK_TRACE_CASE:-unset}" "$*"
if [ "${TDESKTOP_NETWORK_TRACE_CASE:-}" = proxy-intermediary ] \
	&& [ "${TDESKTOP_SKIP_PROXY_ASSERTION:-0}" != 1 ]; then
printf '%s\n' '{"protocol":"SOCKS5","version":5,"command":"CONNECT","target":"127.0.0.1:19082","observed":true}' > "$TDESKTOP_PROXY_ASSERTION_FILE"
fi
if { [ "${TDESKTOP_NETWORK_TRACE_CASE:-}" = public-selection ] \
	|| [ "${TDESKTOP_NETWORK_TRACE_CASE:-}" = public-failure ]; } \
	&& [ "${TDESKTOP_SKIP_PROXY_ASSERTION:-0}" != 1 ]; then
	printf '%s\n' '{"protocol":"SOCKS5","version":5,"command":"CONNECT","target":"203.0.113.10:443","observed":true}' > "$TDESKTOP_PROXY_ASSERTION_FILE"
fi
if [ "${TDESKTOP_NETWORK_TRACE_CASE:-}" = public-selection ]; then
	printf '%s\n' '{"origin":"https://public.example/.well-known/telegramd/client","host":"public.example","error":"NoError","addresses":["203.0.113.10"],"destinations":["203.0.113.10:443"]}' \
		> "$TDESKTOP_TEST_EVIDENCE_DIR/network-resolution.json"
elif [ "${TDESKTOP_NETWORK_TRACE_CASE:-}" = public-failure ]; then
	printf '%s\n' '{"origin":"https://public-failure.invalid/.well-known/telegramd/client","host":"public-failure.invalid","error":"NoError","addresses":["203.0.113.10"],"destinations":["203.0.113.10:443"]}' \
		> "$TDESKTOP_TEST_EVIDENCE_DIR/network-resolution.json"
elif [ "${TDESKTOP_NETWORK_TRACE_CASE:-}" = selected-endpoint-failure ]; then
	printf '%s\n' '{"endpoint":"127.0.0.1:19083","attempted":true,"failed":true,"fallback_suppressed":true}' \
		> "$TDESKTOP_TEST_EVIDENCE_DIR/network-selected-failure.json"
fi
if [ "${TDESKTOP_SKIP_COMPLETION:-0}" != 1 ]; then
	mkdir -p "$TDESKTOP_TEST_EVIDENCE_DIR"
	printf '%s\n' 'SCENARIO_RESULT: PASS' 'TEST_COMPLETE' \
		> "$TDESKTOP_TEST_EVIDENCE_DIR/test_log.txt"
fi
exit 7
EOF
chmod +x "$TARGET"

cat > "$FAKE_BIN/strace" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [ "${1:-}" = "-V" ]; then
	echo "strace -- fake observer"
	exit 0
fi

TRACE_PREFIX=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	-o)
		TRACE_PREFIX="$2"
		shift 2
		;;
	-s|-e)
		shift 2
		;;
	-*)
		shift
		;;
	*)
		break
		;;
	esac
done

case "${TDESKTOP_NETWORK_TRACE_CASE:-}" in
public-selection|public-failure)
	cat > "${TRACE_PREFIX}.$$" <<'TRACE'
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(19444), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
TRACE
	;;
background-refresh)
	cat > "${TRACE_PREFIX}.$$" <<'TRACE'
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(19082), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
TRACE
	;;
proxy-intermediary)
	cat > "${TRACE_PREFIX}.$$" <<'TRACE'
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(19080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
TRACE
	;;
failed-selection|canceled-selection|partial-selection|timed-out-selection|late-callback)
	cat > "${TRACE_PREFIX}.$$" <<'TRACE'
socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3
connect(3, {sa_family=AF_UNIX, sun_path="/tmp/display"}, 19) = 0
TRACE
	;;
local-preflight)
	cat > "${TRACE_PREFIX}.$$" <<'TRACE'
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(19081), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
TRACE
	;;
pinned-endpoint|restart-pinned|multiple-account-isolation)
	cat > "${TRACE_PREFIX}.$$" <<'TRACE'
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(19082), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
TRACE
	;;
selected-endpoint-failure)
	cat > "${TRACE_PREFIX}.$$" <<'TRACE'
socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(19083), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED
TRACE
	;;
*)
	cat > "${TRACE_PREFIX}.$$" <<'TRACE'
socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3
connect(3, {sa_family=AF_UNIX, sun_path="/tmp/display"}, 19) = 0
TRACE
	;;
esac
"$@"
EOF
chmod +x "$FAKE_BIN/strace"

if ! PATH="$FAKE_BIN:$PATH" "$SCRIPT" \
	--case fresh-empty \
	--evidence-dir "$EVIDENCE_DIR" \
	-- "$TARGET"; then
	echo "FAIL: clean trace should be enforced despite target status 7" >&2
	exit 1
fi

if ! grep -Fxq 'process_status=7' "$EVIDENCE_DIR/process-status.txt"; then
	echo "FAIL: target status was not preserved as metadata" >&2
	exit 1
fi

CONTRACT_EVIDENCE="$TEST_ROOT/contract-evidence"
if ! PATH="$FAKE_BIN:$PATH" "$SCRIPT" \
	--case fresh-empty \
	--evidence-dir "$CONTRACT_EVIDENCE" \
	-- "$TARGET"; then
	echo "FAIL: manifest case contract should execute" >&2
	exit 1
fi

if ! grep -Fq 'trace-case=fresh-empty' "$CONTRACT_EVIDENCE/stdout.log"; then
	echo "FAIL: manifest invocation environment was not applied" >&2
	exit 1
fi

if ! grep -Fq '"target_status": 7' "$CONTRACT_EVIDENCE/network-report.json"; then
	echo "FAIL: target status was not included in the trace report" >&2
	exit 1
fi

if grep -Fq '"line"' "$CONTRACT_EVIDENCE/network-report.json"; then
	echo "FAIL: raw observer lines were retained in the report" >&2
	exit 1
fi

if [ -n "$(find "$CONTRACT_EVIDENCE" -name 'strace*' -print -quit)" ]; then
	echo "FAIL: raw observer files were retained in the evidence" >&2
	exit 1
fi

if PATH="$FAKE_BIN:$PATH" TDESKTOP_SKIP_COMPLETION=1 "$SCRIPT" \
	--case fresh-empty \
	--evidence-dir "$TEST_ROOT/incomplete-evidence" \
	-- "$TARGET"; then
	echo "FAIL: incomplete scenario should fail" >&2
	exit 1
fi

BACKGROUND_EVIDENCE="$TEST_ROOT/background-evidence"
if ! PATH="$FAKE_BIN:$PATH" "$SCRIPT" \
	--case background-refresh \
	--evidence-dir "$BACKGROUND_EVIDENCE" \
	-- "$TARGET"; then
	echo "FAIL: background-refresh contract should execute" >&2
	exit 1
fi

if grep -Fq -- '-noupdate' "$BACKGROUND_EVIDENCE/stdout.log"; then
	echo "FAIL: background-refresh must exercise update mode" >&2
	exit 1
fi

PROXY_EVIDENCE="$TEST_ROOT/proxy-evidence"
if ! PATH="$FAKE_BIN:$PATH" "$SCRIPT" \
	--case proxy-intermediary \
	--evidence-dir "$PROXY_EVIDENCE" \
	-- "$TARGET"; then
	echo "FAIL: proxy target assertion should satisfy the pinned-target contract" >&2
	exit 1
fi

if PATH="$FAKE_BIN:$PATH" TDESKTOP_SKIP_PROXY_ASSERTION=1 "$SCRIPT" \
	--case proxy-intermediary \
	--evidence-dir "$TEST_ROOT/unproven-proxy-evidence" \
	-- "$TARGET"; then
	echo "FAIL: missing proxy target assertion should fail" >&2
	exit 1
fi

SELECTED_FAILURE_EVIDENCE="$TEST_ROOT/selected-failure-evidence"
if ! PATH="$FAKE_BIN:$PATH" "$SCRIPT" \
	--case selected-endpoint-failure \
	--evidence-dir "$SELECTED_FAILURE_EVIDENCE" \
	-- "$TARGET"; then
	echo "FAIL: selected endpoint failure contract should execute" >&2
	exit 1
fi
if ! grep -Fq '"failure_evidence"' \
	"$SELECTED_FAILURE_EVIDENCE/network-report.json"; then
	echo "FAIL: selected endpoint failure was not recorded in the report" >&2
	exit 1
fi

for case_name in \
	fresh-empty malformed-selection canceled-selection failed-selection \
	partial-selection timed-out-selection public-selection public-failure \
	local-preflight pinned-endpoint restart-pinned multiple-account-isolation \
	proxy-intermediary background-refresh selected-endpoint-failure late-callback; do
	if ! PATH="$FAKE_BIN:$PATH" "$SCRIPT" \
		--case "$case_name" \
		--evidence-dir "$TEST_ROOT/all-cases/$case_name" \
		-- "$TARGET" >/dev/null; then
		echo "FAIL: manifest case did not execute: $case_name" >&2
		exit 1
	fi
done

echo "network-isolation-runner-status=PASS"
