#!/usr/bin/env bash
set -euo pipefail

stats="$(cat)"
misses="$(printf '%s\n' "${stats}" | sed -n 's/^cache_miss\t//p')"
if [[ ! "${misses}" =~ ^[0-9]+$ ]]; then
  printf 'ccache statistics must contain exactly one non-negative cache_miss count.\n' >&2
  exit 2
fi

printf '%s\n' "${misses}"
