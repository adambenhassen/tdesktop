# Persisted account startup regression

This app-only regression prepares a synthetic profile, exits, then reloads it through normal application startup. It covers damaged pin state and replay of each durable Forget boundary. It is compiled into the Debug app when `TDESKTOP_LIFECYCLE_REGRESSION` is enabled.

The fixture root is a fresh directory under the system temporary directory. Each profile lives at `<root>/cases/<case>/work/tdata/`; `HOME` must be `<root>/home`. The app refuses to start the regression unless the caller supplies an explicit `-workdir`, the root marker, and paths that resolve inside that root.

```bash
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/tdesktop-auth-startup.XXXXXX")"
app="/path/to/Telegramd.app/Contents/MacOS/Telegramd"
mkdir -p "$fixture_root/home"
printf '%s' 'tdesktop-auth-startup-regression-v1' \
  > "$fixture_root/.tdesktop-auth-startup-regression"

run_case() {
  local phase="$1"
  local name="$2"
  local work="$fixture_root/cases/$name/work"
  mkdir -p "$work"
  env \
    HOME="$fixture_root/home" \
    TDESKTOP_AUTH_STARTUP_REGRESSION_ROOT="$fixture_root" \
    TDESKTOP_AUTH_STARTUP_REGRESSION="$phase:$name" \
    "$app" -noupdate -debug -workdir "$work"
}

for case_name in \
  missing-pin \
  incomplete-pin \
  unreadable-config \
  unreadable-pin \
  forget-1 forget-2 forget-3 forget-4 forget-5 forget-6; do
  run_case prepare "$case_name"
  run_case verify "$case_name"
done
```

Each invocation exits after its phase. A 30-second app watchdog exits with status 124 if startup or the regression does not finish. The prepare phase stores synthetic user `4242` and an old authorization key; pin-damage cases then leave the marker/config combination named by the case. Forget cases use a loopback endpoint and the test RSA key, then interrupt after the tombstone write or before one of the next five durable cleanup steps.

The verify phase reports the case and fails unless normal startup leaves it blocked or paused, denies account networking, clears the restored identity and authorization keys, and prevents a newly selected identity from inheriting keys. Forget replay cases also require the prior fingerprint/user cache binding to match. `unreadable-config` removes the persisted config variants; `unreadable-pin` removes the prefs file referenced by the account map so the normal startup reader observes an unreadable pin marker. Run the verify command under MAIN-1066's socket observer; it can observe the whole launch before the app exits, with the fixture files under the workdir shown above.
