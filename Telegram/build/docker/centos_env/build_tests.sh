#!/bin/bash
set -e

# Runs inside the tdesktop:centos_env image, alongside build.sh. Configures
# the tree the same way, builds only the console test binary, and runs it.
# The exit code is the test result.

CONFIG="${CONFIG:-Debug}"

cd Telegram
./configure.sh "$@"
cmake --build ../out --config "$CONFIG" --target test_unit
"../out/$CONFIG/test_unit"
