## Running the tests

`test_unit` is a console binary covering the parts of the client that can be
checked without a display or a server. It links the same `td_mtproto` objects
the application does, so what it exercises is the shipped code.

It is built by the ordinary build — no option to turn on — and it runs in the
`Linux.` GitHub Actions workflow between the build check and the artifact
upload, so a failing test stops the upload.

### One command

From the repository root, with the `tdesktop:centos_env` image present and
the submodules checked out (`git submodule update --init --recursive --depth 1
-j 4`, about 90 seconds; without them the configure step dies on
`ModuleNotFoundError: No module named 'run_cmake'`):

```bash
docker run --rm -u $(id -u) -v $PWD:/usr/src/tdesktop -e CONFIG=Debug \
	tdesktop:centos_env \
	/usr/src/tdesktop/Telegram/build/docker/centos_env/build_tests.sh \
	-D CMAKE_CONFIGURATION_TYPES=Debug \
	-D TDESKTOP_API_TEST=ON
```

`build_tests.sh` configures the tree, builds `--target test_unit` only, and
runs it. Building just that target skips the application's own translation
units, which is most of the build: 171 compile steps against 2217 for the
client. On four arm64 cores that is about 13 minutes from cold and under a
minute for a rebuild after touching one file — a loop you can actually use,
which a full client build is not.

The exit code is the result: `0` all cases passed, `1` at least one failed —
or no case ran at all, which is treated as a failure rather than a pass, since
a binary that covers nothing would otherwise report success.

Output goes to stderr: a `run` line before each case and a `ok` or `FAIL` line
after it, so a case that aborts the process still names itself, plus a
`file:line` and both sides of the comparison for every failed check.

If the tree is already configured, the build and run alone are:

```bash
docker run --rm -u $(id -u) -v $PWD:/usr/src/tdesktop tdesktop:centos_env \
	bash -lc "cd /usr/src/tdesktop && cmake --build out --config Debug --target test_unit && out/Debug/test_unit"
```

### Adding a case

Write a `TEST_CASE` in a file under `Telegram/SourceFiles/tests/unit/` and add
that file to `Telegram/cmake/tests_unit.cmake`. Registration happens at static
initialisation, so there is no central list of cases to keep in sync.

```cpp
TEST_CASE(SomethingHolds) {
	CHECK(condition);
	CHECK_EQ(actual, expected);
}
```

A case that cannot fail is not evidence of anything. When adding one, break
the code it covers on purpose, confirm the case goes red, and restore it.

## Clean-process network trace

`Telegram/build/network_isolation_test.sh` is the process-level destination
gate for the account network boundary. It starts the supplied Debug executable
with an empty `HOME` and work directory, captures the target process and its
children with `strace`, and fails closed when a network socket has no allowed
DNS or destination event. AF_UNIX display and desktop-integration sockets are
not remote network activity.

The case manifest is the required scenario inventory and execution contract:

```bash
Telegram/build/network_isolation_test.sh --list-cases
```

Every case in the version-5 manifest declares its phase, bounded timeout, `-testagent` arguments, the
`TDESKTOP_NETWORK_TRACE_CASE` environment binding, all four destination
allowlists, required evidence, completion marker, update mode, and report
filename. Public cases also declare the resolution-evidence filename, origin,
and destination sequence that the client must produce. The runner reads this
checked-in manifest directly. It does not accept a caller-supplied manifest,
phase, origin, destination, DNS, proxy, or timeout policy.

Run a fixed-head case from that contract:

An empty-storage check records no DNS, socket, or connect activity:

```bash
Telegram/build/network_isolation_test.sh \
  --case fresh-empty \
  --evidence-dir "$PWD/network-evidence/fresh-empty" \
  -- "$PWD/out/Debug/Telegram"
```

The workflow can invoke each manifest entry the same way. Discovery and
pinned-endpoint cases carry their resolved destination sets explicitly. A public
origin is bound to that resolved set, while the IP:port values are the only
remote destinations accepted by the trace checker:

```bash
Telegram/build/network_isolation_test.sh \
  --case public-selection \
  --evidence-dir "$PWD/network-evidence/public-selection" \
  -- "$PWD/out/Debug/Telegram"
```

For a configured proxy, the manifest lists its transport address separately
from the pinned endpoint. The checked-in driver runs a bounded SOCKS5
CONNECT exchange against its local observer, which writes a JSON proof only
after parsing the target request. An unrelated destination, protocol, or
missing proof fails. A public scenario writes `network-resolution.json` under
`$TDESKTOP_TEST_EVIDENCE_DIR` only from the `QHostInfo` completion callback;
the file contains the selected host, callback error, every returned address,
and derived `host:port` destinations. The parser requires that callback result
to match the normalized origin and observed connect activity. Each report
preserves the case, observed socket metadata, target exit status, origin,
resolution, destination, DNS, proxy, and required evidence contract. Raw
`strace` files are not retained.

The checked-in Debug driver in `Telegram/SourceFiles/test/test_scenario.cpp`
consumes `TDESKTOP_NETWORK_TRACE_CASE` and registers every manifest case with
the test runner. Preselection cases exercise distinct validation, cancellation,
timeout, parser, and generation-cancellation paths against bounded live local
discovery sockets. Local preflight exercises the framed discovery request; pin,
restart, account-isolation, selected-failure, and refresh cases use the actual
account enrollment, persistence, activation, fallback-suppression, app-config,
and update-check paths. Public cases issue the HTTPS discovery request and record
the `QHostInfo` callback, and the proxy case performs a SOCKS5 target exchange.
The selected scenario must write the manifest's completion log under
`$TDESKTOP_TEST_EVIDENCE_DIR`, including both
`TEST_COMPLETE` and `SCENARIO_RESULT: PASS`. A missing marker, failed result, or
bounded timeout fails the case even when the trace has no forbidden contact.
`background-refresh` is the one case whose contract leaves update mode enabled;
the runner only adds `-noupdate` for cases that explicitly disable updates.

The target exit status is metadata, not a destination verdict. A target may
finish with an ordinary nonzero status after producing a valid trace; the
runner still parses and enforces that trace. Missing or invalid observer
output remains a hard failure.

The observer and parser have a deterministic self-test. It includes the
reported official-DC connect as a vulnerable fixture, verifies that it fails,
and verifies that the fixed empty-process and public-origin fixtures pass:

```bash
Telegram/build/network_isolation_test.sh --self-test
```

The process trace is intentionally separate from the unit binary. Unit tests
prove framing, canonicalization, persistence, gate ordering, and cancellation;
this runner proves what the operating system observed for DNS, sockets, and
connect destinations. The runner uses `strace -yy` so socket identity remains
stable across worker trace files; if the parser is used without `-yy`, its
fallback identity is scoped to process ID plus file descriptor. A missing
`strace`, target executable, trace file, or case manifest is an error, never an
advisory pass.

### The build image

The workflow builds `tdesktop:centos_env` from
`Telegram/build/docker/centos_env/`. That directory's `Dockerfile` is a Jinja
template, not a Dockerfile: `docker build` on it as committed fails part way
through with `gcc: error: unrecognized debug output level 'z{%'`, because
`CFLAGS` still holds the unrendered `{% if DEBUG %}` markers. Render it first,
the way the workflow does:

```bash
cd Telegram/build/docker/centos_env
poetry install
DEBUG= LTO= poetry run gen_dockerfile > Dockerfile.rendered
docker build -f Dockerfile.rendered -t tdesktop:centos_env .
```

The image builds every dependency, Qt included, from source. On four arm64
cores it took about two and a quarter hours and came out at roughly 4.2 GB;
budget well more than that in free disk for the intermediate layers. It builds
natively on aarch64 — no emulation, no cross-compilation — and it is a
one-time cost, after which the loop above reuses it.

### test_text

`Telegram/SourceFiles/tests/test_text.cpp` is a separate, older thing: a
windowed application a human looks at, wired up by
`Telegram/cmake/tests.cmake` behind `DESKTOP_APP_TEST_APPS`, off by default. It
needs a display and does not report a pass or fail exit code, so it is not part
of CI.
