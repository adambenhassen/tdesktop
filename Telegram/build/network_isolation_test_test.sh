#!/usr/bin/env bash

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$ROOT/network_isolation_test.sh"

if [ ! -x "$SCRIPT" ]; then
	echo "FAIL: network isolation runner is missing or not executable" >&2
	exit 1
fi

"$SCRIPT" --self-test
