#!/usr/bin/env bash
set -euo pipefail

scripts_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
detector="${scripts_dir}/detect_linux_changes.sh"
temp_dir="$(mktemp -d)"
trap 'rm -rf "${temp_dir}"' EXIT

mkdir -p "${temp_dir}/bin"
cat > "${temp_dir}/bin/git" <<'MOCK_GIT'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  rev-parse)
    if [[ "${2:-}" == "--verify" ]]; then
      revision="${3:-}"
    else
      revision="${2:-}"
    fi

    case "${revision}" in
      HEAD^1)
        printf '%s\n' "${MOCK_MERGE_BASE_SHA}"
        ;;
      HEAD^2)
        if [[ "${MOCK_HAS_SECOND_PARENT}" != "true" ]]; then
          exit 1
        fi
        printf '%s\n' "${MOCK_MERGE_HEAD_SHA}"
        ;;
      *)
        printf 'unexpected git rev-parse target: %s\n' "${revision}" >&2
        exit 1
        ;;
    esac
    ;;
  diff)
    if [[ "${2:-}" != "--name-only" || "${3:-}" != "--no-renames" ]]; then
      printf 'git diff must disable rename detection: %s\n' "$*" >&2
      exit 1
    fi
    if [[ "${4:-}" != "${MOCK_MERGE_BASE_SHA}" || "${5:-}" != "HEAD" ]]; then
      printf 'git diff must compare the merge parent to HEAD: %s\n' "$*" >&2
      exit 1
    fi
    if [[ "${MOCK_DIFF_STATUS}" != "0" ]]; then
      printf 'simulated git diff failure\n' >&2
      exit "${MOCK_DIFF_STATUS}"
    fi
    printf '%s' "${MOCK_CHANGED_PATHS}"
    ;;
  *)
    printf 'unexpected git command: %s\n' "$*" >&2
    exit 1
    ;;
esac
MOCK_GIT
chmod +x "${temp_dir}/bin/git"

base_sha=0123456789abcdef0123456789abcdef01234567
merge_base_sha=fedcba9876543210fedcba9876543210fedcba98
head_sha=89abcdef0123456789abcdef0123456789abcdef
output="${temp_dir}/output"

run_detector() {
  local event_name="$1"
  local diff_status="$2"
  local changed_paths="$3"
  local checked_out_base_sha="${4:-${base_sha}}"
  local has_second_parent="${5:-true}"

  export MOCK_MERGE_BASE_SHA="${checked_out_base_sha}"
  export MOCK_HAS_SECOND_PARENT="${has_second_parent}"
  export MOCK_MERGE_HEAD_SHA="${head_sha}"
  : > "${output}"
  env \
    PATH="${temp_dir}/bin:${PATH}" \
    EVENT_NAME="${event_name}" \
    BASE_SHA="${base_sha}" \
    GITHUB_SHA="${head_sha}" \
    GITHUB_OUTPUT="${output}" \
    MOCK_DIFF_STATUS="${diff_status}" \
    MOCK_CHANGED_PATHS="${changed_paths}" \
    bash "${detector}"
}

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

if run_detector pull_request 2 ''; then
  fail 'A failed git diff must fail change detection.'
fi
if [[ -s "${output}" ]]; then
  fail 'A failed git diff must not write a successful output.'
fi

run_detector pull_request 0 ''
if [[ "$(<"${output}")" != 'required=false' ]]; then
  fail 'An empty diff should skip the Linux build.'
fi

run_detector pull_request 0 'docs/readme.md'
if [[ "$(<"${output}")" != 'required=false' ]]; then
  fail 'Documentation-only changes should skip the Linux build.'
fi

run_detector pull_request 0 'docs/readme.md' "${merge_base_sha}"
if [[ "$(<"${output}")" != 'required=false' ]]; then
  fail 'A moved event base should use the checked-out merge commit parent.'
fi

if run_detector pull_request 0 '' "${merge_base_sha}" false; then
  fail 'A pull request ref without a second merge parent must fail detection.'
fi
if [[ -s "${output}" ]]; then
  fail 'A non-merge pull request ref must not write a successful output.'
fi

run_detector pull_request 0 $'Telegram/SourceFiles/core.cpp\nTelegram/SourceFiles/platform/mac/core.cpp'
if [[ "$(<"${output}")" != 'required=true' ]]; then
  fail 'Renaming a Linux-relevant file into an ignored path should require the Linux build.'
fi

run_detector pull_request 0 'Telegram/build/docker/centos_env/build.sh'
if [[ "$(<"${output}")" != 'required=true' ]]; then
  fail 'Changes to the Linux build environment should require the Linux build.'
fi

run_detector pull_request 0 '.github/workflows/linux.yml'
if [[ "$(<"${output}")" != 'required=true' ]]; then
  fail 'Changes to the Linux workflow should require the Linux build.'
fi

run_detector pull_request 0 $'Telegram/SourceFiles/platform/mac/main.mm\nTelegram/SourceFiles/platform/win/main.cpp'
if [[ "$(<"${output}")" != 'required=false' ]]; then
  fail 'macOS- and Windows-only changes should skip the Linux build.'
fi

run_detector pull_request 0 'Telegram/SourceFiles/main.cpp'
if [[ "$(<"${output}")" != 'required=true' ]]; then
  fail 'Linux-relevant changes should require the Linux build.'
fi

run_detector push 2 ''
if [[ "$(<"${output}")" != 'required=true' ]]; then
  fail 'Non-PR events should keep the Linux build enabled.'
fi

printf 'Linux change detection tests passed.\n'
