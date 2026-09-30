#!/usr/bin/env bash
set -euo pipefail

if [[ "${EVENT_NAME}" != "pull_request" ]]; then
  echo "required=true" >> "${GITHUB_OUTPUT}"
  exit 0
fi

if [[ "$(git rev-parse HEAD^1)" != "${BASE_SHA}" ]]; then
  echo "::error::The checked-out pull request merge commit does not have the expected base as its first parent."
  exit 1
fi

required=false
if ! changed_paths="$(git diff --name-only "${BASE_SHA}" "${GITHUB_SHA}")"; then
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
