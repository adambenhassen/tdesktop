#!/usr/bin/env bash

set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
MODE="${2:-all}"
PLIST_FILE="$ROOT/Telegram/Telegram.plist"
CMAKE_FILE="$ROOT/Telegram/CMakeLists.txt"
VERSION_FILE="$ROOT/Telegram/SourceFiles/core/version.h"
PROFILE_POLICY_FILE="$ROOT/Telegram/SourceFiles/core/mac_protected_path_policy.cpp"
SANDBOX_FILE="$ROOT/Telegram/SourceFiles/core/sandbox.cpp"
SOCKET_FILE="$ROOT/Telegram/SourceFiles/platform/mac/specific_mac.mm"
PROFILE_TEST_FILE="$ROOT/Telegram/build/test_mac_profile_guard.sh"
GLOBAL_MENU_FILE="$ROOT/Telegram/SourceFiles/platform/mac/global_menu_mac.mm"
WINDOW_TITLE_FILE="$ROOT/Telegram/SourceFiles/window/main_window.cpp"
INTRO_FILE="$ROOT/Telegram/SourceFiles/intro/intro_start.cpp"
LANG_FILE="$ROOT/Telegram/Resources/langs/lang.strings"
MAC_WORKFLOW_FILE="$ROOT/.github/workflows/mac.yml"
PACKAGED_WORKFLOW_FILE="$ROOT/.github/workflows/mac_packaged.yml"
ISOLATION_FILE="$ROOT/Telegram/build/mac_isolation_test.sh"
PARSER_FILE="$ROOT/Telegram/build/check_mac_fs_usage.py"

case "$MODE" in
all|identity|observer)
	;;
*)
	echo "usage: $0 [repo-root] [all|identity|observer]" >&2
	exit 2
	;;
esac

if [ "$MODE" != observer ]; then
	test -f "$PLIST_FILE"
	test -f "$CMAKE_FILE"
	test -f "$VERSION_FILE"
	test -f "$PROFILE_POLICY_FILE"
	test -f "$SANDBOX_FILE"
	test -f "$SOCKET_FILE"
	test -f "$PROFILE_TEST_FILE"
	test -f "$GLOBAL_MENU_FILE"
	test -f "$WINDOW_TITLE_FILE"
	test -f "$INTRO_FILE"
	test -f "$LANG_FILE"
	test -f "$MAC_WORKFLOW_FILE"
	test -f "$PACKAGED_WORKFLOW_FILE"
	python3 - \
		"$PLIST_FILE" \
		"$CMAKE_FILE" \
		"$VERSION_FILE" \
		"$PROFILE_POLICY_FILE" \
		"$SANDBOX_FILE" \
		"$SOCKET_FILE" \
		"$PROFILE_TEST_FILE" \
		"$GLOBAL_MENU_FILE" \
		"$WINDOW_TITLE_FILE" \
		"$INTRO_FILE" \
		"$LANG_FILE" \
		"$MAC_WORKFLOW_FILE" \
		"$PACKAGED_WORKFLOW_FILE" <<'PY'
import pathlib
import sys
import xml.etree.ElementTree as ElementTree

root = ElementTree.parse(sys.argv[1]).getroot()
keys = {
    element.text
    for element in root.iter('key')
    if element.text
}
assert 'CFBundleURLTypes' not in keys
assert 'Teagram messaging app' in {
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
cmake = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
assert cmake.count('set(bundle_identifier "io.teagram.desktop")') == 2
assert cmake.count('set(output_name "Teagram")') == 2
assert 'TDESKTOP_TEAGRAM' in cmake
version = pathlib.Path(sys.argv[3]).read_text(encoding='utf-8')
assert 'constexpr auto AppName = "Teagram"_cs;' in version
assert 'constexpr auto AppFile = "Teagram"_cs;' in version
assert 'constexpr auto MacSupportDirectoryName = "Teagram"_cs;' in version
profile_policy = pathlib.Path(sys.argv[4]).read_text(encoding='utf-8')
sandbox = pathlib.Path(sys.argv[5]).read_text(encoding='utf-8')
socket = pathlib.Path(sys.argv[6]).read_text(encoding='utf-8')
profile_test = pathlib.Path(sys.argv[7]).read_text(encoding='utf-8')
global_menu = pathlib.Path(sys.argv[8]).read_text(encoding='utf-8')
window_title = pathlib.Path(sys.argv[9]).read_text(encoding='utf-8')
intro = pathlib.Path(sys.argv[10]).read_text(encoding='utf-8')
languages = pathlib.Path(sys.argv[11]).read_text(encoding='utf-8')
assert 'Library/Application Support/Teagram' in profile_policy
assert 'Teagram-lock-' in sandbox
assert '/Teagram-' in socket
assert 'Library/Application Support/Teagram' in profile_test
assert 'Teagram-lock-' in profile_test
assert 'Teagram-' in profile_test
assert 'Show Teagram' in global_menu
assert 'u"Teagram"_q' in window_title
assert 'u"Teagram"_q' in intro
assert 'lng_intro_teagram_about' in intro
assert '"lng_intro_teagram_about" = "Welcome to Teagram.' in languages
assert '"lng_mac_menu_show" = "Show Teagram";' in languages
mac_workflow = pathlib.Path(sys.argv[12]).read_text(encoding='utf-8')
packaged_workflow = pathlib.Path(sys.argv[13]).read_text(encoding='utf-8')
for identity in (
    'Teagram.app',
    'Contents/MacOS/Teagram',
    'io.teagram.desktop',
    'Teagram-macOS-arm64',
    'Teagram-macOS-arm64-evidence',
):
    assert identity in mac_workflow
for identity in (
    'Teagram.app',
    'Contents/MacOS/Teagram',
    'io.teagram.desktop',
    'Teagram-macOS-arm64-QA',
):
    assert identity in packaged_workflow
PY
fi

if [ "$MODE" != observer ]; then
	python3 - "$ROOT" <<'PY'
import math
import pathlib
import struct
import sys
import zlib

root = pathlib.Path(sys.argv[1])


def paeth(left, above, upper_left):
	guess = left + above - upper_left
	left_distance = abs(guess - left)
	above_distance = abs(guess - above)
	upper_left_distance = abs(guess - upper_left)
	if left_distance <= above_distance and left_distance <= upper_left_distance:
		return left
	if above_distance <= upper_left_distance:
		return above
	return upper_left


def alpha_bounds(path):
	data = path.read_bytes()
	assert data[:8] == b'\x89PNG\r\n\x1a\n', f'{path}: not a PNG'
	position = 8
	width = height = None
	compressed = []
	while position < len(data):
		length = struct.unpack_from('>I', data, position)[0]
		kind = data[position + 4:position + 8]
		chunk = data[position + 8:position + 8 + length]
		position += length + 12
		if kind == b'IHDR':
			(
				width,
				height,
				bit_depth,
				color_type,
				compression,
				filter_method,
				interlace,
			) = struct.unpack('>IIBBBBB', chunk)
			assert (
				bit_depth,
				color_type,
				compression,
				filter_method,
				interlace,
			) == (8, 6, 0, 0, 0), f'{path}: expected 8-bit RGBA PNG'
		elif kind == b'IDAT':
			compressed.append(chunk)
		elif kind == b'IEND':
			break
	assert width and height, f'{path}: missing PNG dimensions'
	stride = width * 4
	raw = zlib.decompress(b''.join(compressed))
	assert len(raw) == height * (stride + 1), f'{path}: invalid PNG data length'
	previous = bytearray(width)
	minimum_x = width
	minimum_y = height
	maximum_x = maximum_y = -1
	for y in range(height):
		start = y * (stride + 1)
		filter_type = raw[start]
		encoded = raw[start + 1:start + 1 + stride]
		row = bytearray(width)
		for x in range(width):
			value = encoded[x * 4 + 3]
			left = row[x - 1] if x else 0
			above = previous[x]
			upper_left = previous[x - 1] if x else 0
			if filter_type == 0:
				predictor = 0
			elif filter_type == 1:
				predictor = left
			elif filter_type == 2:
				predictor = above
			elif filter_type == 3:
				predictor = (left + above) // 2
			elif filter_type == 4:
				predictor = paeth(left, above, upper_left)
			else:
				raise AssertionError(f'{path}: unknown PNG filter {filter_type}')
			row[x] = (value + predictor) & 255
			if row[x]:
				minimum_x = min(minimum_x, x)
				minimum_y = min(minimum_y, y)
				maximum_x = max(maximum_x, x)
				maximum_y = max(maximum_y, y)
		previous = row
	assert maximum_x >= 0, f'{path}: image is fully transparent'
	return width, height, (minimum_x, minimum_y, maximum_x + 1, maximum_y + 1)


sizes = (16, 32, 64, 128, 256, 512, 1024)
catalogs = (
	root / 'Telegram/Telegram/Images.xcassets/Icon.iconset',
	root / 'Telegram/Telegram/Images.xcassets/Icon.appiconset',
)
paths = []
for catalog in catalogs:
	images = sorted(catalog.glob('*.png'))
	assert len(images) == 10, f'{catalog}: expected 10 icon slots, got {len(images)}'
	paths.extend(images)
paths.extend(
	root / f'Telegram/Resources/art/teagram-icon-{size}.png'
	for size in sizes
)
paths.append(root / 'Telegram/Resources/art/teagram-app-icon-t.png')
paths.append(root / 'Telegram/Resources/art/icon_round512@2x.png')

for path in paths:
	assert path.is_file(), f'missing macOS icon asset: {path}'
	width, height, bounds = alpha_bounds(path)
	assert width == height and width in sizes, f'{path}: unexpected dimensions {width}x{height}'
	expected = (
		math.floor(100 * width / 1024),
		math.floor(100 * height / 1024),
		math.ceil(924 * width / 1024),
		math.ceil(924 * height / 1024),
	)
	tolerance = 0 if width == 1024 else 1
	assert all(abs(actual - target) <= tolerance for actual, target in zip(bounds, expected)), (
		f'{path}: alpha bounds {bounds}, expected {expected} '
		f'(tolerance {tolerance}px)'
	)
PY
fi

if [ "$MODE" != identity ]; then
	test -x "$ISOLATION_FILE"
	test -x "$PARSER_FILE"
	bash -n "$ISOLATION_FILE"
	"$ISOLATION_FILE" --self-test-cleanup
	"$ISOLATION_FILE" --self-test-observer-coverage
	python3 - "$PARSER_FILE" <<'PY'
import pathlib
import sys

compile(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'), sys.argv[1], 'exec')
PY
	python3 "$PARSER_FILE" --self-test >/dev/null
fi
