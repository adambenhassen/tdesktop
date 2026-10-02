#!/usr/bin/env bash
set -euo pipefail

scripts_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
decision_script="${scripts_dir}/ccache_save_decision.sh"

assert_decision() {
  local misses="$1"
  local expected="save=$2"
  local actual
  actual="$(bash "${decision_script}" "${misses}")"
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'Expected %s misses to produce %s, got %s.\n' "${misses}" "${expected}" "${actual}" >&2
    exit 1
  fi
}

assert_decision 0 false
assert_decision 1 true
assert_decision 300 true
assert_decision 301 true

if bash "${decision_script}" invalid >/dev/null 2>&1; then
  printf 'A non-integer miss count should fail.\n' >&2
  exit 1
fi

printf 'ccache save decision tests passed.\n'
