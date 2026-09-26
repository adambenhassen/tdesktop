#!/usr/bin/env bash

set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
PLIST_FILE="$ROOT/Telegram/Telegram.plist"
ISOLATION_FILE="$ROOT/Telegram/build/mac_isolation_test.sh"
PARSER_FILE="$ROOT/Telegram/build/check_mac_fs_usage.py"

test -f "$PLIST_FILE"
test -x "$ISOLATION_FILE"
test -x "$PARSER_FILE"

bash -n "$ISOLATION_FILE"
"$ISOLATION_FILE" --self-test-cleanup
"$ISOLATION_FILE" --self-test-observer-coverage
python3 - "$PLIST_FILE" <<'PY'
import sys
import xml.etree.ElementTree as ElementTree

root = ElementTree.parse(sys.argv[1]).getroot()
keys = {
    element.text
    for element in root.iter('key')
    if element.text
}
assert 'CFBundleURLTypes' not in keys
assert 'Telegramd messaging app' in {
    element.text
    for element in root.iter('string')
    if element.text
}
assert all(
    value not in {
        'tg',
        'tonsite',
    }
    for element in root.iter('string')
    for value in [element.text]
)
PY

python3 - "$PARSER_FILE" <<'PY'
import pathlib
import sys

compile(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'), sys.argv[1], 'exec')
PY
python3 "$PARSER_FILE" --self-test >/dev/null
