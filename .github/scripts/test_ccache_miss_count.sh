#!/usr/bin/env bash
set -euo pipefail

scripts_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
parser_script="${scripts_dir}/ccache_miss_count.sh"

assert_count() {
  local stats="$1"
  local expected="$2"
  local actual
  actual="$(printf '%s' "${stats}" | bash "${parser_script}")"
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'Expected %s misses, got %s.\n' "${expected}" "${actual}" >&2
    exit 1
  fi
}

assert_rejected() {
  local stats="$1"
  if printf '%s' "${stats}" | bash "${parser_script}" >/dev/null 2>&1; then
    printf 'Invalid ccache statistics should fail.\n' >&2
    exit 1
  fi
}

assert_count $'cache_hit\t5\ncache_miss\t17\n' 17
assert_count $'cache_miss\t0\n' 0
assert_rejected $'cache_hit\t5\n'
assert_rejected $'cache_miss\tbad\n'
assert_rejected $'cache_miss\t1\ncache_miss\t2\n'

printf 'ccache miss count tests passed.\n'
