#!/usr/bin/env bash
set -euo pipefail

misses="${1:-}"
case "${misses}" in
  ''|*[!0-9]*)
    printf 'ccache miss count must be a non-negative integer.\n' >&2
    exit 2
    ;;
esac

if (( 10#${misses} > 0 )); then
  printf 'save=true\n'
else
  printf 'save=false\n'
fi
