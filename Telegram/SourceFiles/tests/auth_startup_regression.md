# Persisted account startup regression

The app-only regression prepares ten synthetic profiles, reloads each through
normal startup, and checks damaged pin state plus every durable Forget
boundary. It is compiled into the Debug app when
`TDESKTOP_LIFECYCLE_REGRESSION` is enabled. Run it only from an isolated
macOS app artifact and record the exact source revision used to build that
artifact.

Each prepare phase synchronously flushes prefs and the per-account map, then
reads both back from disk. It confirms the map points to the expected prefs
file and that the file contains the expected pin marker before removing config
or prefs, beginning an interrupted Forget, or exiting. The `incomplete-pin`,
`unreadable-config`, and `unreadable-pin` verification cases assert separate
reloaded states: a readable marker with a readable unpinned config, a readable
marker with an unreadable config, and unreadable prefs beside a readable
config. None can pass as `missing-pin`.

Verification keeps the app event loop alive for 1.5 seconds after startup,
then rechecks authorization, enrollment networking, and the cache binding. The
optional sensitivity pass schedules a loopback TCP connect after 250 ms; the
verification must observe and fail on that delayed synthetic forbidden
outbound attempt. The separate Python runner applies a 60-second process
deadline from app launch through storage work and teardown. On timeout it
sends SIGTERM to the isolated process group, waits at most the cleanup grace,
then sends SIGKILL and waits at most one more grace period. Timeout status is
124. The in-app timer is only an event-loop watchdog; it cannot replace this
process deadline. Prepare exits immediately after its synchronous disk
readback and fixture mutation so shutdown cannot rewrite a deliberately
damaged profile; verification exits through normal app teardown.

```bash
tested_sha="$(git rev-parse HEAD)"
python3 Telegram/SourceFiles/tests/auth_startup_regression.py \
  --app "/path/to/Telegramd.app/Contents/MacOS/Telegramd" \
  --tested-sha "$tested_sha" \
  --self-test
```

The runner creates a fresh temporary root with isolated `HOME` and one
workdir per case. It retains a log for each invocation under that root and
prints the revision, exact app command, status, elapsed time, timeout cleanup,
and app output. Preserve the `FIXTURE_ROOT` and `LOG_PATH` output with the
hosted run record. Do not reuse a root.

`--self-test` first injects a reported failure in the first prepare while
allowing `forget-6` verification to pass, and requires the ten-case invocation
to remain nonzero. It then checks delayed outbound detection and injected
startup, synchronous storage, and teardown hangs against the external
deadline. The final ten-case matrix runs without injections and must pass.
Every prepare and verify status contributes to the matrix result; a later
passing case cannot erase an earlier failure.

Run the normal matrix without sensitivity probes when only the restored cases
are needed:

```bash
python3 Telegram/SourceFiles/tests/auth_startup_regression.py \
  --app "/path/to/Telegramd.app/Contents/MacOS/Telegramd" \
  --tested-sha "$tested_sha"
```

Run the verify command under MAIN-1066's socket observer. Its observer must
include the complete 1.5-second interval and report any socket attempt,
including the sensitivity probe's `127.0.0.1:9` connect. MAIN-1066 owns the
workflow and actual lifecycle/startup/socket integration; this runner supplies
the app invocation contract and does not modify that workflow.
