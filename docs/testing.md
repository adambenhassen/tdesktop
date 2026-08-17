## Running the tests

`test_unit` is a console binary covering the parts of the client that can be
checked without a display or a server. It links the same `td_mtproto` objects
the application does, so what it exercises is the shipped code.

It is built by the ordinary build — no option to turn on — and it runs in the
`Linux.` GitHub Actions workflow between the build check and the artifact
upload, so a failing test stops the upload.

### One command

From the repository root, with the `tdesktop:centos_env` image present:

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

The exit code is the result: `0` all cases passed, `1` at least one failed.
Output is one line per case on stderr, plus a `file:line` and both sides of
the comparison for every failed check.

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
