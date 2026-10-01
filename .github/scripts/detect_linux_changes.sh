#!/usr/bin/env bash
set -euo pipefail

if [[ "${EVENT_NAME}" != "pull_request" ]]; then
  echo "required=true" >> "${GITHUB_OUTPUT}"
  exit 0
fi

if ! merge_base_sha="$(git rev-parse --verify HEAD^1 2>/dev/null)" ||
  ! git rev-parse --verify HEAD^2 >/dev/null 2>&1; then
  echo "::error::The checked-out pull request ref is not a merge commit with two parents."
  exit 1
fi

required=false
echo "::notice::Diffing changed paths from ${merge_base_sha} to HEAD."
if ! changed_paths="$(git diff --name-only --no-renames "${merge_base_sha}" HEAD)"; then
  echo "::error::Unable to determine changed files for the pull request."
  exit 1
fi

while IFS= read -r path; do
  [[ -n "${path}" ]] || continue

  case "${path}" in
    .github/workflows/linux.yml|.github/scripts/detect_linux_changes.sh|.github/scripts/test_detect_linux_changes.sh|Telegram/build/docker/centos_env/*)
      required=true
      break
      ;;
    docs/*|*.md|changelog.txt|LEGAL|LICENSE|.github/*|snap/*|Telegram/build/*|Telegram/Resources/uwp/*|Telegram/Resources/winrc/*|Telegram/SourceFiles/platform/win/*|Telegram/SourceFiles/platform/mac/*|Telegram/Telegram/*|Telegram/configure.bat|Telegram/Telegram.plist)
      ;;
    *)
      required=true
      break
      ;;
  esac
done <<< "${changed_paths}"

echo "required=${required}" >> "${GITHUB_OUTPUT}"
if [[ "${required}" == "false" ]]; then
  echo "No Linux-relevant files changed; the Rocky Linux 8 build will be skipped."
fi
