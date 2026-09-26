#!/usr/bin/env python3

import argparse
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path


EVENTS = (
    "access",
    "close",
    "create",
    "dup",
    "exec",
    "exit",
    "fcntl",
    "fork",
    "lookup",
    "open",
    "rename",
    "write",
)
REQUIRED_EVENTS = {"exec", "exit", "fork", "open"}
FIXTURE = r'''
import json
import os
import sys
import time

parent_path, child_path, result_path = sys.argv[1:]
ready_read, ready_write = os.pipe()
child_pid = os.fork()
if child_pid == 0:
    os.close(ready_write)
    os.read(ready_read, 1)
    os.close(ready_read)
    try:
        descriptor = os.open(child_path, os.O_RDONLY)
        os.close(descriptor)
        time.sleep(0.15)
        os._exit(0)
    except OSError:
        os._exit(2)

os.close(ready_read)
with open(result_path, "w", encoding="utf-8") as output:
    json.dump({"parent_pid": os.getpid(), "child_pid": child_pid}, output)

def access_parent():
    descriptor = os.open(parent_path, os.O_RDONLY)
    os.close(descriptor)

access_parent()
os.write(ready_write, b"1")
os.close(ready_write)
access_count = 1
until = time.monotonic() + 0.3
while time.monotonic() < until:
    access_parent()
    access_count += 1
    time.sleep(0.005)

_, child_status = os.waitpid(child_pid, 0)
with open(result_path, "w", encoding="utf-8") as output:
    json.dump({
        "parent_pid": os.getpid(),
        "child_pid": child_pid,
        "parent_access_count": access_count,
        "child_exit_status": os.waitstatus_to_exitcode(child_status),
    }, output)
'''


def event_kind(record):
    event = record.get("event")
    if isinstance(event, dict):
        for name, details in event.items():
            if details is not None:
                return name, details
    return str(record.get("event_type", "unknown")).lower(), {}


def process_identity(record):
    process = record.get("process")
    if not isinstance(process, dict):
        return None, None
    token = process.get("audit_token")
    token = token if isinstance(token, dict) else {}
    pid = token.get("pid", process.get("pid"))
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        pid = None
    return pid, process.get("start_time")


def nested_path(value):
    if isinstance(value, dict):
        path = value.get("path")
        if isinstance(path, str):
            return path
    return None


def event_file_path(details):
    if not isinstance(details, dict):
        return None
    for key in ("file", "target", "source"):
        path = nested_path(details.get(key))
        if path:
            return path
    return None


def read_records(path):
    records = []
    malformed = []
    for number, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(),
        1,
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            malformed.append(number)
            continue
        if isinstance(value, list):
            records.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            records.append(value)
        else:
            malformed.append(number)
    return records, malformed


def canonical(path):
    return os.path.normcase(os.path.realpath(path))


def stop_process_group(process):
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def write_summary(path, summary):
    path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("telemetry_probe_result=" + summary["result"])
    print("telemetry_probe_summary=" + str(path))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()

    evidence = Path(args.evidence_dir)
    evidence.mkdir(parents=True, exist_ok=True)
    summary_path = evidence / "summary.json"
    events_path = evidence / "eslogger.jsonl"
    stderr_path = evidence / "eslogger.stderr"
    sentinel = evidence / "observer-ready"
    fixture_result = evidence / "fixture.json"
    summary = {
        "runner_architecture": platform.machine(),
        "runner_platform": platform.platform(),
        "result": "UNAVAILABLE",
        "limitations": [
            "One low-volume fixture does not establish whole-tree coverage under production load.",
            "eslogger output is not a stable API; a shipping gate needs a supported native client or another stable interface.",
        ],
    }
    if platform.system() != "Darwin":
        summary["reason"] = "probe must run on macOS"
        write_summary(summary_path, summary)
        return 0

    eslogger = Path("/usr/bin/eslogger")
    summary["eslogger_path"] = str(eslogger)
    if not eslogger.is_file():
        summary["reason"] = "Apple eslogger is absent from this runner"
        write_summary(summary_path, summary)
        return 0

    signature = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(eslogger)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    summary["eslogger_signature"] = signature.stdout.strip()
    summary["eslogger_has_endpoint_security_entitlement"] = (
        "com.apple.developer.endpoint-security.client" in signature.stdout
    )

    listed = subprocess.run(
        [str(eslogger), "--list-events"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    summary["event_list_exit_code"] = listed.returncode
    summary["event_list"] = listed.stdout.strip()
    available = set()
    for line in listed.stdout.splitlines():
        tokens = line.strip().split()
        if tokens and re.fullmatch(r"[a-z0-9_]+", tokens[0]):
            available.add(tokens[0])
    selected = [event for event in EVENTS if event in available]
    summary["events_requested"] = selected
    if listed.returncode != 0 or not REQUIRED_EVENTS.issubset(available):
        summary["reason"] = "required Endpoint Security notify events are unavailable"
        write_summary(summary_path, summary)
        return 0

    home = Path.home()
    old_root = home / "Library" / "Application Support" / "Telegram Desktop"
    created_directories = []
    probe_root = old_root / (".main-909-" + uuid.uuid4().hex)
    parent_file = probe_root / "parent-access"
    child_file = probe_root / "child-access"
    logger = None
    logger_stdout = None
    logger_stderr = None
    fixture_process = None
    cleanup_errors = []
    try:
        for directory in (
            home / "Library",
            home / "Library" / "Application Support",
            old_root,
        ):
            if not directory.exists():
                directory.mkdir()
                created_directories.append(directory)
            if not directory.is_dir():
                raise OSError("old-root component is not a directory: " + str(directory))
        probe_root.mkdir()
        parent_file.write_bytes(b"parent")
        child_file.write_bytes(b"child")
        sentinel.touch()

        logger_stdout = events_path.open("w", encoding="utf-8")
        logger_stderr = stderr_path.open("w", encoding="utf-8")
        command = ["/usr/bin/sudo", "-n", str(eslogger), *selected]
        summary["command"] = command
        try:
            logger = subprocess.Popen(
                command,
                stdout=logger_stdout,
                stderr=logger_stderr,
                start_new_session=True,
            )
        except OSError as error:
            summary["reason"] = "could not start eslogger: " + str(error)
            summary["event_count"] = 0
            write_summary(summary_path, summary)
            return 0

        ready = False
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and logger.poll() is None:
            descriptor = os.open(sentinel, os.O_WRONLY | os.O_TRUNC)
            os.close(descriptor)
            time.sleep(0.05)
            records, _ = read_records(events_path)
            for record in records:
                kind, details = event_kind(record)
                path = event_file_path(details)
                if kind == "open" and path and canonical(path) == canonical(sentinel):
                    ready = True
                    break
            if ready:
                break
        summary["sentinel_event_observed_before_fixture"] = ready
        if logger.poll() is not None:
            summary["logger_exit_before_fixture"] = logger.returncode

        fixture_process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                FIXTURE,
                str(parent_file),
                str(child_file),
                str(fixture_result),
            ],
            start_new_session=True,
        )
        try:
            fixture_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            stop_process_group(fixture_process)
            summary["fixture_timeout"] = True
        summary["fixture_exit_code"] = fixture_process.returncode
        if fixture_result.is_file():
            summary["fixture"] = json.loads(fixture_result.read_text(encoding="utf-8"))
        time.sleep(0.2)
    except Exception as error:
        summary["reason"] = type(error).__name__ + ": " + str(error)
    finally:
        stop_process_group(logger)
        stop_process_group(fixture_process)
        if logger_stdout:
            logger_stdout.close()
        if logger_stderr:
            logger_stderr.close()
        if probe_root.exists():
            try:
                shutil.rmtree(probe_root)
            except OSError as error:
                cleanup_errors.append(str(error))
        for directory in reversed(created_directories):
            try:
                directory.rmdir()
            except FileNotFoundError:
                continue
            except OSError as error:
                cleanup_errors.append(str(error))

    records, malformed = read_records(events_path) if events_path.exists() else ([], [])
    summary["event_count"] = len(records)
    summary["malformed_json_lines"] = malformed
    summary["logger_stderr_text"] = (
        stderr_path.read_text(encoding="utf-8", errors="replace")
        if stderr_path.exists()
        else ""
    )
    summary["cleanup_errors"] = cleanup_errors
    sequence_gaps = []
    last_sequence = {}
    sequence_records = 0
    missing_sequence = 0
    unresolved_open = []
    unresolved_identity = []
    observed = {}
    identities = {}
    fork_child_observed = False
    child_exit_observed = False
    fixture = summary.get("fixture", {})
    expected = {
        int(fixture[key]): name
        for key, name in (("parent_pid", "parent"), ("child_pid", "child"))
        if fixture.get(key) is not None
    }
    old_root_path = canonical(old_root)
    for record in records:
        kind, details = event_kind(record)
        seq = record.get("seq_num")
        if seq is not None:
            sequence_records += 1
            try:
                seq = int(seq)
                previous = last_sequence.get(kind)
                if previous is not None and seq != previous + 1:
                    sequence_gaps.append(
                        {"event": kind, "previous": previous, "current": seq}
                    )
                last_sequence[kind] = seq
            except (TypeError, ValueError):
                sequence_gaps.append({"event": kind, "reason": "invalid seq_num"})
        else:
            missing_sequence += 1

        pid, start_time = process_identity(record)
        if pid in expected and start_time is not None:
            key = str(pid)
            identities.setdefault(key, set()).add(json.dumps(start_time, sort_keys=True))
        if kind == "fork" and pid == fixture.get("parent_pid"):
            child = details.get("child") if isinstance(details, dict) else None
            child_token = child.get("audit_token") if isinstance(child, dict) else None
            child_token = child_token if isinstance(child_token, dict) else {}
            child_pid = child_token.get(
                "pid",
                child.get("pid") if isinstance(child, dict) else None,
            )
            try:
                fork_child_observed = int(child_pid) == fixture.get("child_pid")
            except (TypeError, ValueError):
                pass
        if kind == "exit" and pid == fixture.get("child_pid"):
            child_exit_observed = True
        if kind == "open":
            path = event_file_path(details)
            if pid in expected and not path:
                unresolved_open.append(pid)
            elif pid in expected and path and canonical(path).startswith(old_root_path + os.sep):
                if start_time is None:
                    unresolved_identity.append(pid)
                else:
                    observed.setdefault(expected[pid], []).append(
                        {"pid": pid, "path": path, "start_time": start_time}
                    )

    summary["sequence_records"] = sequence_records
    summary["missing_sequence_records"] = missing_sequence
    summary["sequence_gaps"] = sequence_gaps
    summary["unresolved_open_paths"] = unresolved_open
    summary["unresolved_process_identity"] = unresolved_identity
    summary["observed_forbidden_accesses"] = observed
    summary["fork_event_identified_child"] = fork_child_observed
    summary["exit_event_identified_child"] = child_exit_observed
    summary["process_start_identity_consistent"] = {
        pid: len(values) == 1 for pid, values in identities.items()
    }
    expected_names = {"parent", "child"}
    identity_complete = (
        set(identities) == {str(pid) for pid in expected}
        and all(len(values) == 1 for values in identities.values())
        and len(expected) == 2
    )
    attribution_complete = all(observed.get(name) for name in expected_names)
    loss_detection_available = sequence_records > 0 and missing_sequence == 0
    fixture_ok = (
        summary.get("sentinel_event_observed_before_fixture") is True
        and summary.get("fixture_exit_code") == 0
        and fixture.get("child_exit_status") == 0
        and fixture.get("parent_access_count", 0) > 1
        and attribution_complete
        and identity_complete
        and fork_child_observed
        and child_exit_observed
        and loss_detection_available
        and not sequence_gaps
        and not unresolved_open
        and not unresolved_identity
        and not malformed
    )
    summary["fixture_attribution_pass"] = attribution_complete
    summary["process_start_identity_pass"] = identity_complete
    summary["sequence_gap_detection_available"] = loss_detection_available
    summary["fixture_result"] = "PASS" if fixture_ok else "UNAVAILABLE"
    summary["result"] = summary["fixture_result"]
    if not fixture_ok and "reason" not in summary:
        summary["reason"] = (
            "one or more attribution, readiness, path, or loss-detection checks were incomplete"
        )
    write_summary(summary_path, summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
