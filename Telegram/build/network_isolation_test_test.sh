#!/usr/bin/env bash

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$ROOT/network_isolation_test.sh"

if [ ! -x "$SCRIPT" ]; then
	echo "FAIL: network isolation runner is missing or not executable" >&2
	exit 1
fi

"$SCRIPT" --self-test

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/main839-network-runner.XXXXXX")"
trap 'rm -rf -- "$TEST_ROOT"' EXIT
FAKE_BIN="$TEST_ROOT/bin"
EVIDENCE_DIR="$TEST_ROOT/evidence"
TARGET="$TEST_ROOT/target"
mkdir -p "$FAKE_BIN"

cat > "$TARGET" <<'EOF'
#!/usr/bin/env bash
printf 'trace-case=%s args=%s\n' "${TDESKTOP_NETWORK_TRACE_CASE:-unset}" "$*"
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

cat > "${TRACE_PREFIX}.$$" <<'TRACE'
socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3
connect(3, {sa_family=AF_UNIX, sun_path="/tmp/display"}, 19) = 0
TRACE
"$@"
EOF
chmod +x "$FAKE_BIN/strace"

if ! PATH="$FAKE_BIN:$PATH" "$SCRIPT" \
	--case fresh-empty \
	--phase preselection \
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
	--manifest "$ROOT/network_trace_cases.json" \
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

echo "network-isolation-runner-status=PASS"
