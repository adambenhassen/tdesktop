#!/usr/bin/env bash
set -euo pipefail

if ! misses="$(awk -F '\t' '
  $1 == "cache_miss" || $0 ~ /^cache_miss[[:space:]]/ {
    count++
    if ($1 != "cache_miss" || NF != 2 || $2 !~ /^[0-9]+$/) {
      invalid = 1
    } else {
      value = $2
    }
  }
  END {
    if (count != 1 || invalid) {
      exit 2
    }
    print value
  }
')"; then
  printf 'ccache statistics must contain exactly one non-negative cache_miss count.\n' >&2
  exit 2
fi

printf '%s\n' "${misses}"
