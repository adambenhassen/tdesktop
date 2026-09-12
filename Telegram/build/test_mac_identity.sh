#!/usr/bin/env bash

set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
CMAKE_FILE="$ROOT/Telegram/CMakeLists.txt"
PLIST_FILE="$ROOT/Telegram/Telegram.plist"
OPTIONS_FILE="$ROOT/Telegram/cmake/telegram_options.cmake"
VERSION_FILE="$ROOT/Telegram/SourceFiles/core/version.h"
LAUNCHER_FILE="$ROOT/Telegram/SourceFiles/core/launcher.cpp"
APPLICATION_FILE="$ROOT/Telegram/SourceFiles/core/application.cpp"
UPDATE_CHECKER_FILE="$ROOT/Telegram/SourceFiles/core/update_checker.cpp"
MAC_PATH_FILE="$ROOT/Telegram/SourceFiles/platform/mac/specific_mac_p.mm"
WORKFLOW_FILE="$ROOT/.github/workflows/mac.yml"
PACKAGED_WORKFLOW_FILE="$ROOT/.github/workflows/mac_packaged.yml"
ISOLATION_FILE="$ROOT/Telegram/build/mac_isolation_test.sh"
PARSER_FILE="$ROOT/Telegram/build/check_mac_fs_usage.py"

grep -F 'set(bundle_identifier "com.adambenhassen.telegramd")' "$CMAKE_FILE" >/dev/null
grep -F 'set(output_name "Telegramd")' "$CMAKE_FILE" >/dev/null
grep -F 'TDESKTOP_TELEGRAMD' "$CMAKE_FILE" >/dev/null
grep -F 'TDESKTOP_TELEGRAMD' "$VERSION_FILE" >/dev/null
grep -F 'setApplicationName(u"Telegramd"_q)' "$LAUNCHER_FILE" >/dev/null
grep -F '#ifdef TDESKTOP_TELEGRAMD' "$APPLICATION_FILE" >/dev/null
grep -F 'tupdates/temp/Telegramd.app/Contents/Frameworks/Updater' "$UPDATE_CHECKER_FILE" >/dev/null
grep -F 'AppName.utf16()' "$MAC_PATH_FILE" >/dev/null
grep -F 'Telegramd messaging app' "$PLIST_FILE" >/dev/null
test "$(rg -c '<key>CFBundleURLTypes</key>' "$PLIST_FILE" || echo 0)" = 0
test "$(rg -c '<string>(tg|tonsite)</string>' "$PLIST_FILE" || echo 0)" = 0
grep -F 'if (NOT DESKTOP_APP_DISABLE_AUTOUPDATE AND NOT APPLE' "$CMAKE_FILE" >/dev/null
grep -F 'target_compile_definitions(Telegram PRIVATE TDESKTOP_DISABLE_AUTOUPDATE)' "$OPTIONS_FILE" >/dev/null
grep -F -- '-D DESKTOP_APP_DISABLE_AUTOUPDATE=ON' "$WORKFLOW_FILE" >/dev/null
grep -F 'ARTIFACT_NAME=Telegramd-macOS-arm64' "$WORKFLOW_FILE" >/dev/null
grep -F 'Telegramd.app' "$PACKAGED_WORKFLOW_FILE" >/dev/null
grep -F -- '-DDESKTOP_APP_DISABLE_AUTOUPDATE=ON' "$PACKAGED_WORKFLOW_FILE" >/dev/null
test -x "$ISOLATION_FILE" || test -f "$ISOLATION_FILE"
test -f "$PARSER_FILE"
grep -F 'fs_usage' "$ISOLATION_FILE" >/dev/null
grep -F -- '--self-test' "$ISOLATION_FILE" >/dev/null
grep -F "OFFICIAL_SOURCE=\"\$(find \"\$MOUNT_PATH\" -maxdepth 2 -type d -name '*.app' -print -quit 2>/dev/null || true)\"" "$ISOLATION_FILE" >/dev/null
grep -F 'set frontmost of (first application process whose unix id is $OFFICIAL_PID) to true' "$ISOLATION_FILE" >/dev/null
grep -F 'env HOME="$HOME_ROOT" "$OFFICIAL_EXE" -noupdate -debug -workdir "$OLD"' "$ISOLATION_FILE" >/dev/null
grep -F 'env HOME="$HOME_ROOT" "$FORK_EXE" -noupdate -debug -workdir "$NEW"' "$ISOLATION_FILE" >/dev/null
