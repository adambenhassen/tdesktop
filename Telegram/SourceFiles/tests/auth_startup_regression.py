#!/usr/bin/env python3
"""Run the disposable-profile auth startup regression with process deadlines."""

import argparse
import datetime
import os
import pathlib
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time


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
ROOT_MARKER = ".tdesktop-auth-startup-regression"
MARKER_CONTENT = "tdesktop-auth-startup-regression-v1"
REGRESSION_ENV = (
    "TDESKTOP_AUTH_STARTUP_REGRESSION",
    "TDESKTOP_AUTH_STARTUP_REGRESSION_ROOT",
    "TDESKTOP_AUTH_STARTUP_REGRESSION_FAIL_PREPARE",
    "TDESKTOP_AUTH_STARTUP_REGRESSION_FORBIDDEN_OUTBOUND",
    "TDESKTOP_AUTH_STARTUP_REGRESSION_HANG",
)


class Result:
    def __init__(self, status, timed_out, log, log_path):
        self.status = status
        self.timed_out = timed_out
        self.log = log
        self.log_path = log_path


def create_fixture_root():
    root = pathlib.Path(tempfile.mkdtemp(prefix="tdesktop-auth-startup."))
    (root / "home").mkdir()
    (root / ROOT_MARKER).write_text(MARKER_CONTENT, encoding="utf-8")
    return root.resolve()


def terminate_process_group(process, grace_seconds):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        output, _ = process.communicate(timeout=grace_seconds)
        return "SIGTERM", output
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            output, _ = process.communicate(timeout=grace_seconds)
        except subprocess.TimeoutExpired as error:
            process.stdout.close()
            raise RuntimeError("process group did not stop after SIGKILL") from error
        return "SIGTERM+SIGKILL", output


def run_phase(
    app,
    tested_sha,
    root,
    case_name,
    phase,
    timeout_seconds,
    cleanup_seconds,
    log_tag,
    fail_prepare=False,
    forbidden_outbound=False,
    hang=None,
    work_override=None,
    regression_request=None,
    require_workdir_selection=True,
):
    work = pathlib.Path(work_override) if work_override else (
        root / "cases" / case_name / "work"
    )
    work.mkdir(parents=True, exist_ok=True)
    log_dir = root / "logs"
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / (log_tag + "-" + phase + "-" + case_name + ".log")
    command = [str(app), "-noupdate", "-debug", "-workdir", str(work)]
    environment = os.environ.copy()
    for name in REGRESSION_ENV:
        environment.pop(name, None)
    environment["HOME"] = str(root / "home")
    environment["TDESKTOP_AUTH_STARTUP_REGRESSION_ROOT"] = str(root)
    environment["TDESKTOP_AUTH_STARTUP_REGRESSION"] = (
        regression_request or (phase + ":" + case_name)
    )
    if fail_prepare:
        environment["TDESKTOP_AUTH_STARTUP_REGRESSION_FAIL_PREPARE"] = case_name
    if forbidden_outbound:
        environment["TDESKTOP_AUTH_STARTUP_REGRESSION_FORBIDDEN_OUTBOUND"] = "1"
    if hang:
        environment["TDESKTOP_AUTH_STARTUP_REGRESSION_HANG"] = hang

    started = time.monotonic()
    launch_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    process = None
    output = ""
    timed_out = False
    cleanup = "not-needed"
    try:
        process = subprocess.Popen(
            command,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        remaining = max(0.0, timeout_seconds - (time.monotonic() - started))
        raw_output, _ = process.communicate(timeout=remaining)
        output = raw_output.decode("utf-8", errors="replace")
        status = process.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        cleanup, raw_output = terminate_process_group(
            process,
            cleanup_seconds,
        )
        status = 124
        output = raw_output.decode("utf-8", errors="replace")
    except OSError as error:
        status = 127
        output = "could not launch app: " + str(error) + "\n"

    elapsed = time.monotonic() - started
    expected_workdir = str(work.resolve())
    selected_workdir = (
        "Auth startup regression selected workdir: " + expected_workdir
    ) in output
    if require_workdir_selection and not selected_workdir:
        status = 125
        output += (
            "Auth startup regression did not select the explicit workdir: "
            + expected_workdir
            + "\n"
        )
    record = (
        "TESTED_SHA=" + tested_sha + "\n"
        + "STARTED_UTC=" + launch_time + "\n"
        + "PHASE=" + phase + " CASE=" + case_name + "\n"
        + "COMMAND=" + shlex.join(command) + "\n"
        + "EXPECTED_WORKDIR=" + expected_workdir + "\n"
        + "WORKDIR_SELECTED=" + str(selected_workdir).lower() + "\n"
        + "STATUS=" + str(status) + " TIMED_OUT=" + str(timed_out).lower()
        + " ELAPSED_SECONDS=" + format(elapsed, ".3f")
        + " CLEANUP=" + cleanup + "\n"
        + "--- app output ---\n"
        + output
    )
    log_path.write_text(record, encoding="utf-8")
    print(record, end="" if record.endswith("\n") else "\n", flush=True)
    print("LOG_PATH=" + str(log_path), flush=True)
    return Result(status, timed_out, record, log_path)


def assert_rejected_invocation(
    args,
    log_tag,
    root,
    case_name,
    phase,
    regression_request,
    work_override=None,
    marker_content=MARKER_CONTENT,
):
    (root / ROOT_MARKER).write_text(marker_content, encoding="utf-8")
    work = pathlib.Path(work_override) if work_override else (
        root / "cases" / case_name / "work"
    )
    work.mkdir(parents=True, exist_ok=True)
    home = root / "home"
    result = run_phase(
        args.app,
        args.tested_sha,
        root,
        case_name,
        phase,
        args.timeout_seconds,
        args.cleanup_seconds,
        log_tag,
        work_override=work,
        regression_request=regression_request,
        require_workdir_selection=False,
    )
    if (
        result.status == 0
        or "Auth startup regression refused:" not in result.log
        or any(home.iterdir())
        or any(work.iterdir())
    ):
        raise RuntimeError(
            log_tag + " did not refuse safely before profile mutation"
        )
    print(
        "INPUT_REJECTION_OK=" + log_tag
        + " STATUS=" + str(result.status)
        + " PROFILE_MUTATION=false",
        flush=True,
    )


def run_input_validation_sensitivities(args):
    root = create_fixture_root()
    assert_rejected_invocation(
        args,
        "invalid-marker-root",
        root,
        CASES[0],
        "prepare",
        "prepare:missing-pin",
        marker_content="invalid-marker",
    )

    root = create_fixture_root()
    outside_work = root.parent / (root.name + "-outside-work")
    assert_rejected_invocation(
        args,
        "outside-workdir",
        root,
        CASES[0],
        "prepare",
        "prepare:missing-pin",
        work_override=outside_work,
    )

    for name, phase, request in (
        ("invalid-phase", "prepare", "invalid:missing-pin"),
        ("invalid-case", "prepare", "prepare:unknown-case"),
    ):
        root = create_fixture_root()
        assert_rejected_invocation(
            args,
            name,
            root,
            CASES[0],
            phase,
            request,
        )


def run_matrix(args, log_tag, inject_first_prepare_failure=False):
    root = create_fixture_root()
    print("FIXTURE_ROOT=" + str(root), flush=True)
    results = {}
    failed = False
    for case_name in CASES:
        prepare = run_phase(
            args.app,
            args.tested_sha,
            root,
            case_name,
            "prepare",
            args.timeout_seconds,
            args.cleanup_seconds,
            log_tag,
            fail_prepare=inject_first_prepare_failure
            and (case_name == CASES[0]),
        )
        verify = run_phase(
            args.app,
            args.tested_sha,
            root,
            case_name,
            "verify",
            args.timeout_seconds,
            args.cleanup_seconds,
            log_tag,
        )
        results[case_name] = (prepare, verify)
        case_failed = (prepare.status != 0) or (verify.status != 0)
        failed = failed or case_failed
        print(
            "CASE_RESULT=" + case_name
            + " PREPARE_STATUS=" + str(prepare.status)
            + " VERIFY_STATUS=" + str(verify.status)
            + " FAILED=" + str(case_failed).lower(),
            flush=True,
        )
    final_verify = results[CASES[-1]][1]
    status = 1 if failed else 0
    print(
        "MATRIX_RESULT=" + log_tag
        + " FINAL_CASE=" + CASES[-1]
        + " FINAL_VERIFY_STATUS=" + str(final_verify.status)
        + " OVERALL_STATUS=" + str(status),
        flush=True,
    )
    return root, results, status


def run_sensitivities(args):
    run_input_validation_sensitivities(args)

    _, failure_results, failure_status = run_matrix(
        args,
        "sensitivity-prepare-failure",
        inject_first_prepare_failure=True,
    )
    first_prepare = failure_results[CASES[0]][0]
    final_verify = failure_results[CASES[-1]][1]
    failed_phases = sum(
        result.status != 0
        for phases in failure_results.values()
        for result in phases
    )
    if not (
        failure_status != 0
        and first_prepare.status != 0
        and final_verify.status == 0
        and failed_phases == 1
    ):
        raise RuntimeError(
            "prepare failure sensitivity did not fail overall after the final case passed"
        )
    print(
        "SENSITIVITY_OK=first_prepare_failure"
        " FIRST_PREPARE_STATUS=" + str(first_prepare.status)
        + " FINAL_VERIFY_STATUS=" + str(final_verify.status)
        + " FAILED_PHASES=" + str(failed_phases)
        + " OVERALL_STATUS=" + str(failure_status),
        flush=True,
    )

    root = create_fixture_root()
    prepare = run_phase(
        args.app,
        args.tested_sha,
        root,
        CASES[0],
        "prepare",
        args.timeout_seconds,
        args.cleanup_seconds,
        "sensitivity-forbidden-outbound",
    )
    verify = run_phase(
        args.app,
        args.tested_sha,
        root,
        CASES[0],
        "verify",
        args.timeout_seconds,
        args.cleanup_seconds,
        "sensitivity-forbidden-outbound",
        forbidden_outbound=True,
    )
    if (
        prepare.status != 0
        or verify.status == 0
        or "synthetic forbidden outbound attempt" not in verify.log
        or "deferred synthetic forbidden outbound attempt was observed"
        not in verify.log
    ):
        raise RuntimeError("deferred forbidden outbound sensitivity was not detected")
    print(
        "SENSITIVITY_OK=deferred_forbidden_outbound"
        " PREPARE_STATUS=" + str(prepare.status)
        + " VERIFY_STATUS=" + str(verify.status),
        flush=True,
    )

    for hang in ("startup", "storage", "teardown"):
        root = create_fixture_root()
        expected_marker = {
            "startup": "startup hang",
            "storage": "synchronous storage hang",
            "teardown": "teardown hang",
        }[hang]
        if hang == "teardown":
            prepare = run_phase(
                args.app,
                args.tested_sha,
                root,
                CASES[0],
                "prepare",
                args.timeout_seconds,
                args.cleanup_seconds,
                "sensitivity-" + hang + "-hang",
            )
            if prepare.status != 0:
                raise RuntimeError("teardown sensitivity fixture did not prepare")
            phase = "verify"
        else:
            phase = "prepare"
        result = run_phase(
            args.app,
            args.tested_sha,
            root,
            CASES[0],
            phase,
            15.0,
            min(args.cleanup_seconds, 0.5),
            "sensitivity-" + hang + "-hang",
            hang=hang,
        )
        if (
            not result.timed_out
            or result.status == 0
            or expected_marker not in result.log
            or (
                hang == "teardown"
                and "passed after 1500ms observation: case=missing-pin"
                not in result.log
            )
        ):
            raise RuntimeError(hang + " hang did not hit the external deadline")
        print(
            "SENSITIVITY_OK=" + hang + "_hang"
            + " STATUS=" + str(result.status)
            + " CLEANUP_BOUNDED=true",
            flush=True,
        )


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, type=pathlib.Path)
    parser.add_argument("--tested-sha", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--cleanup-seconds", type=float, default=2.0)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run failure, delayed-activity, and deadline sensitivity probes before the passing matrix",
    )
    args = parser.parse_args()
    args.app = args.app.resolve()
    if not args.app.is_file():
        parser.error("--app must name an existing application executable")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", args.tested_sha):
        parser.error("--tested-sha must be the exact 40-character tested revision")
    if args.timeout_seconds <= 0 or args.cleanup_seconds <= 0:
        parser.error("timeouts must be positive")
    return args


def main():
    args = parse_args()
    print("TESTED_SHA=" + args.tested_sha, flush=True)
    if args.self_test:
        run_sensitivities(args)
    _, _, status = run_matrix(args, "restored-passing-matrix")
    return status


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print("AUTH_STARTUP_REGRESSION_ERROR=" + str(error), file=sys.stderr)
        raise SystemExit(1)
