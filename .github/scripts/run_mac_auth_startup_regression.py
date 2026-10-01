#!/usr/bin/env python3

import getpass
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


CASES = (
    "missing-pin",
    "incomplete-pin",
    "unreadable-config",
    "unreadable-pin",
    "forget-1",
    "forget-2",
    "forget-3",
    "forget-4",
    "forget-5",
    "forget-6",
)
APP_WATCHDOG_SECONDS = 30
EXTERNAL_WATCHDOG_SECONDS = 45
ATTEMPT_MARKER = "OUTBOUND_SOCKET_ATTEMPT"


class VerificationFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise VerificationFailure(message)


def observed_program(execname):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+", execname) is not None,
            "unsafe DTrace executable name")
    return """
syscall::connect:entry
/execname == "%s" && arg1 != 0/
{
  this->family = *(uint8_t *)copyin((uintptr_t)arg1 + 1, 1);
  if ((this->family == 2) || (this->family == 30)) {
    printf("%s pid=%%d syscall=%%s family=%%d\\n", pid, probefunc, this->family);
  }
}
syscall::connect_nocancel:entry
/execname == "%s" && arg1 != 0/
{
  this->family = *(uint8_t *)copyin((uintptr_t)arg1 + 1, 1);
  if ((this->family == 2) || (this->family == 30)) {
    printf("%s pid=%%d syscall=%%s family=%%d\\n", pid, probefunc, this->family);
  }
}
syscall::connectx*:entry
/execname == "%s"/
{
  printf("%s pid=%%d syscall=%%s\\n", pid, probefunc);
}
syscall::sendto*:entry
/execname == "%s" && arg4 != 0 && arg5 >= 2/
{
  this->family = *(uint8_t *)copyin((uintptr_t)arg4 + 1, 1);
  if ((this->family == 2) || (this->family == 30)) {
    printf("%s pid=%%d syscall=%%s family=%%d\\n", pid, probefunc, this->family);
  }
}
syscall::sendmsg*:entry
/execname == "%s" && arg1 != 0/
{
  this->name = *(uintptr_t *)copyin((uintptr_t)arg1, sizeof(uintptr_t));
  if (this->name != 0) {
    this->family = *(uint8_t *)copyin(this->name + 1, 1);
    if ((this->family == 2) || (this->family == 30)) {
      printf("%s pid=%%d syscall=%%s family=%%d\\n", pid, probefunc, this->family);
    }
  }
}
""" % (
        execname, ATTEMPT_MARKER,
        execname, ATTEMPT_MARKER,
        execname, ATTEMPT_MARKER,
        execname, ATTEMPT_MARKER,
        execname, ATTEMPT_MARKER,
    )


def kill_process_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def run_observed(label, command, execname, evidence_dir, log, *, sandboxed=False):
    trace_path = evidence_dir / (label + ".dtrace.log")
    stdout_path = evidence_dir / (label + ".stdout.log")
    stderr_path = evidence_dir / (label + ".stderr.log")
    started = time.monotonic()
    dtrace = shutil.which("dtrace")
    require(dtrace is not None, "dtrace is unavailable on this macOS runner")
    sudo = shutil.which("sudo")
    require(sudo is not None, "sudo is unavailable on this macOS runner")
    runner_command = shlex.join(
        [sudo, "-n", "-u", getpass.getuser()] + command
    )

    invocation = [
        "sudo",
        "-n",
        dtrace,
        "-q",
        "-Z",
        "-o",
        str(trace_path),
        "-n",
        observed_program(execname),
        "-c",
        runner_command,
    ]
    timed_out = False
    with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
        process = subprocess.Popen(
            invocation,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
        )
        try:
            return_code = process.wait(timeout=EXTERNAL_WATCHDOG_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_process_group(process)
            return_code = process.returncode

    elapsed = time.monotonic() - started
    trace = trace_path.read_text(encoding="utf-8", errors="replace") \
        if trace_path.exists() else ""
    stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
    stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
    attempts = [
        line for line in trace.splitlines()
        if line.startswith(ATTEMPT_MARKER + " ")
    ]
    record = {
        "return_code": return_code,
        "timed_out": timed_out,
        "elapsed": elapsed,
        "attempts": attempts,
        "stdout": stdout,
        "stderr": stderr,
    }
    boundary = "sandbox=deny-network-outbound" if sandboxed else "sandbox=none"
    log(
        "%s dtrace_return=%s watchdog=%ss elapsed=%.2fs %s outbound_socket_count=%d"
        % (
            label,
            "timeout" if timed_out else return_code,
            EXTERNAL_WATCHDOG_SECONDS,
            elapsed,
            boundary,
            len(attempts),
        )
    )
    for line in attempts:
        log("%s %s" % (label, line))
    for source, content in (("stdout", stdout), ("stderr", stderr)):
        if content:
            log("%s %s_begin" % (label, source))
            log(content.rstrip())
            log("%s %s_end" % (label, source))
    return record


def write_socket_probe_source(path):
    path.write_text(
        """#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
\tconst int fd = socket(AF_INET, SOCK_STREAM, 0);
\tif (fd < 0) {
\t\tperror("socket");
\t\treturn 2;
\t}
\tstruct sockaddr_in target;
\tmemset(&target, 0, sizeof(target));
\ttarget.sin_family = AF_INET;
\ttarget.sin_port = htons(9);
\tif (inet_pton(AF_INET, "127.0.0.1", &target.sin_addr) != 1) {
\t\tclose(fd);
\t\treturn 3;
\t}
\tconst int result = connect(fd, (struct sockaddr *)&target, sizeof(target));
\tconst int error = errno;
\tclose(fd);
\tif ((result < 0) && ((error == EPERM) || (error == EACCES))) {
\t\tprintf("SOCKET_PROBE_CONNECT=blocked errno=%d\\n", error);
\t} else {
\t\tprintf("SOCKET_PROBE_CONNECT=enabled errno=%d\\n", result < 0 ? error : 0);
\t}
\treturn 0;
}
""",
        encoding="utf-8",
    )


def valid_observer_result(result, expected_marker):
    require(not result["timed_out"],
            "observer self-test exceeded its external watchdog")
    require(result["return_code"] == 0,
            "observer self-test command failed with status %s"
            % result["return_code"])
    require(len(result["attempts"]) == 1,
            "observer self-test expected one connect attempt, observed %d"
            % len(result["attempts"]))
    require(expected_marker in result["stdout"],
            "observer self-test did not report %s" % expected_marker)


def assert_no_outbound_socket_attempts(result):
    require(not result["attempts"],
            "observed %d outbound socket attempt(s)"
            % len(result["attempts"]))


def run_test(label, command, execname, evidence_dir, log, expected_marker=None):
    result = run_observed(
        label,
        command,
        execname,
        evidence_dir,
        log,
        sandboxed=True,
    )
    output = result["stdout"] + result["stderr"]
    passed = not result["timed_out"] and result["return_code"] == 0
    if expected_marker is not None:
        passed = passed and expected_marker in output
    try:
        assert_no_outbound_socket_attempts(result)
    except VerificationFailure:
        passed = False
    log(
        "%s outcome=%s exit=%s bounded_termination=%s app_watchdog=%ss "
        "external_watchdog=%ss pre_enrollment_outbound_socket_count=%d"
        % (
            label,
            "PASS" if passed else "FAIL",
            "timeout" if result["timed_out"] else result["return_code"],
            "outer-watchdog" if result["timed_out"] else "process-exit",
            APP_WATCHDOG_SECONDS,
            EXTERNAL_WATCHDOG_SECONDS,
            len(result["attempts"]),
        )
    )
    return passed


def main():
    if len(sys.argv) != 4:
        print(
            "usage: run_mac_auth_startup_regression.py APP_PATH TESTED_SHA EVIDENCE_DIR",
            file=sys.stderr,
        )
        return 2

    app_path = Path(sys.argv[1]).resolve()
    tested_sha = sys.argv[2]
    evidence_dir = Path(sys.argv[3]).resolve()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    summary_path = evidence_dir / "runtime-results.txt"

    def log(message):
        print(message, flush=True)
        with summary_path.open("a", encoding="utf-8") as summary:
            summary.write(message + "\n")

    try:
        require(re.fullmatch(r"[0-9a-f]{40}", tested_sha) is not None,
                "tested SHA must be a full 40-character commit")
        require(app_path.is_file() and os.access(app_path, os.X_OK),
                "candidate app executable is missing or not executable")
        require(os.uname().machine == "arm64",
                "runtime checks require the Apple Silicon runner")
        sandbox_exec = shutil.which("sandbox-exec")
        require(sandbox_exec is not None,
                "sandbox-exec is unavailable; refusing to launch the candidate without the egress boundary")
        require(shutil.which("clang") is not None,
                "clang is unavailable for the socket observer negative control")

        log("tested_sha=%s" % tested_sha)
        log("app_path=%s" % app_path)
        log("runtime_arch=%s" % os.uname().machine)
        log("socket_observer=dtrace syscall entry probes for IPv4/IPv6 connect/connectx/sendto/sendmsg")
        log("network_boundary=sandbox-exec denies network-outbound for every candidate launch")
        log("app_watchdog_seconds=%d external_watchdog_seconds=%d"
            % (APP_WATCHDOG_SECONDS, EXTERNAL_WATCHDOG_SECONDS))

        profile = evidence_dir / "deny-network-outbound.sb"
        profile.write_text(
            "(version 1)\n"
            "(deny network-outbound)\n"
            "(allow default)\n",
            encoding="utf-8",
        )
        log("network_profile=%s" % profile.name)

        probe_source = evidence_dir / "auth_socket_probe.c"
        probe_path = evidence_dir / "sockprobe"
        write_socket_probe_source(probe_source)
        compile_result = subprocess.run(
            ["clang", str(probe_source), "-o", str(probe_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        (evidence_dir / "socket-probe-build.stdout.log").write_text(
            compile_result.stdout, encoding="utf-8"
        )
        (evidence_dir / "socket-probe-build.stderr.log").write_text(
            compile_result.stderr, encoding="utf-8"
        )
        require(compile_result.returncode == 0,
                "could not compile the loopback socket observer negative control")

        enabled = run_observed(
            "observer-enabled-loopback-self-test",
            [str(probe_path)],
            "sockprobe",
            evidence_dir,
            log,
        )
        valid_observer_result(enabled, "SOCKET_PROBE_CONNECT=enabled")
        try:
            assert_no_outbound_socket_attempts(enabled)
        except VerificationFailure:
            log("observer_negative_control_assertion=FAIL_AS_EXPECTED")
        else:
            raise VerificationFailure(
                "observer's zero-socket assertion accepted an enabled connect"
            )
        log("observer_enabled_socket_negative_control=PASS; "
            "one loopback connect was observed and rejected by the zero-socket assertion")

        blocked = run_observed(
            "egress-boundary-loopback-self-test",
            [sandbox_exec, "-f", str(profile), str(probe_path)],
            "sockprobe",
            evidence_dir,
            log,
            sandboxed=True,
        )
        valid_observer_result(blocked, "SOCKET_PROBE_CONNECT=blocked")
        log("egress_boundary_self_test=PASS; "
            "loopback connect was denied by the sandbox before any candidate launch")

        fixture_root = Path(tempfile.mkdtemp(
            prefix="tdesktop-auth-startup.",
            dir=tempfile.gettempdir(),
        )).resolve(strict=True)
        temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
        require(fixture_root != temp_root and temp_root in fixture_root.parents,
                "synthetic fixture root escaped the system temporary directory")
        (fixture_root / "home").mkdir()
        (fixture_root / ".tdesktop-auth-startup-regression").write_text(
            "tdesktop-auth-startup-regression-v1",
            encoding="ascii",
        )
        log("synthetic_fixture_root=%s" % fixture_root)
        log("synthetic_fixture_root_disposable=true")

        all_passed = True
        startup_cases_passed = True
        lifecycle_work = fixture_root / "lifecycle" / "work"
        lifecycle_home = fixture_root / "home" / "lifecycle"
        lifecycle_work.mkdir(parents=True)
        lifecycle_home.mkdir(parents=True)
        lifecycle_command = [
            sandbox_exec,
            "-f",
            str(profile),
            "/usr/bin/env",
            "HOME=%s" % lifecycle_home,
            "TDESKTOP_AUTH_LIFECYCLE_REGRESSION=1",
            "/usr/bin/arch",
            "-arm64",
            str(app_path),
            "-noupdate",
            "-debug",
            "-workdir",
            str(lifecycle_work),
        ]
        lifecycle = run_observed(
            "auth-lifecycle-regression",
            lifecycle_command,
            "Telegramd",
            evidence_dir,
            log,
            sandboxed=True,
        )
        lifecycle_output = lifecycle["stdout"] + lifecycle["stderr"]
        lifecycle_passed = (
            not lifecycle["timed_out"]
            and lifecycle["return_code"] == 0
            and "Chat participants regression passed." in lifecycle_output
            and not lifecycle["attempts"]
        )
        log(
            "case=auth-lifecycle-regression outcome=%s exit=%s bounded_termination=%s "
            "pre_enrollment_outbound_socket_count=%d"
            % (
                "PASS" if lifecycle_passed else "FAIL",
                "timeout" if lifecycle["timed_out"] else lifecycle["return_code"],
                "outer-watchdog" if lifecycle["timed_out"] else "process-exit",
                len(lifecycle["attempts"]),
            )
        )
        all_passed = all_passed and lifecycle_passed

        for case in CASES:
            work = fixture_root / "cases" / case / "work"
            work.mkdir(parents=True)
            for phase in ("prepare", "verify"):
                command = [
                    sandbox_exec,
                    "-f",
                    str(profile),
                    "/usr/bin/env",
                    "HOME=%s" % (fixture_root / "home"),
                    "TDESKTOP_AUTH_STARTUP_REGRESSION_ROOT=%s" % fixture_root,
                    "TDESKTOP_AUTH_STARTUP_REGRESSION=%s:%s" % (phase, case),
                    "/usr/bin/arch",
                    "-arm64",
                    str(app_path),
                    "-noupdate",
                    "-debug",
                    "-workdir",
                    str(work),
                ]
                marker = "Auth startup regression %s: case=%s" % (
                    "prepared" if phase == "prepare" else "passed",
                    case,
                )
                label = "case-%s-%s" % (case, phase)
                result_passed = run_test(
                    label,
                    command,
                    "Telegramd",
                    evidence_dir,
                    log,
                    expected_marker=marker,
                )
                all_passed = all_passed and result_passed
                startup_cases_passed = startup_cases_passed and result_passed
                log(
                    "case=%s phase=%s outcome=%s"
                    % (case, phase, "PASS" if result_passed else "FAIL")
                )
                if (phase == "prepare") and not result_passed:
                    log("case=%s phase=verify outcome=SKIPPED reason=prepare-failed" % case)
                    break

        log("runtime_result=%s" % ("PASS" if all_passed else "FAIL"))
        step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if step_summary:
            with open(step_summary, "a", encoding="utf-8") as summary:
                summary.write(
                    "\n### macOS auth lifecycle and persisted-startup verification\n\n"
                    "- Tested SHA: %s\n"
                    "- Lifecycle regression: %s\n"
                    "- Persisted startup and Forget cases: %s\n"
                    "- Socket observer negative control: passed\n"
                    "- Egress boundary loopback check: passed\n"
                    "- Runtime evidence artifact: macOS-auth-startup-socket-evidence\n"
                    % (
                        tested_sha,
                        "passed" if lifecycle_passed else "failed",
                        "passed" if startup_cases_passed else "one or more failed",
                    )
                )
        return 0 if all_passed else 1
    except (OSError, subprocess.SubprocessError, VerificationFailure) as error:
        log("runtime_result=UNAVAILABLE_OR_FAILED reason=%s" % error)
        return 1


if __name__ == "__main__":
    sys.exit(main())
