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
import tempfile
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
SUMMARY_FIELDS = {
    "runner_architecture",
    "runner_platform",
    "result",
    "reason",
    "eslogger_present",
    "eslogger_has_endpoint_security_entitlement",
    "events_requested",
    "sentinel_event_observed_before_fixture",
    "fixture_exit_code",
    "logger_started",
    "logger_alive_at_parent_exit",
    "logger_exit_code",
    "logger_group_exited",
    "no_eslogger_process_remains",
    "private_data_removed",
    "fixture_files_removed",
    "event_count",
    "malformed_record_count",
    "outside_tree_event_counts",
    "tracked_process_events",
    "global_sequence",
    "parent_exec_observed",
    "parent_exit_observed",
    "child_exit_observed",
    "fork_event_identified_child",
    "fixture_attribution_pass",
    "process_identity_pass",
    "logger_shutdown_pass",
    "sequence_gap_detection_available",
    "fixture_result",
    "limitations",
}
EVENT_FIELDS = {
    "event",
    "global_seq_num",
    "seq_num",
    "pid",
    "pidversion",
    "start_time",
    "ppid",
    "target_path",
    "file_path",
}
FIXTURE_FIELDS = {
    "parent_pid",
    "child_pid",
    "parent_access_count",
    "child_exit_status",
}
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
                return (name if name in EVENTS else "unknown"), details
    name = str(record.get("event_type", "unknown")).lower()
    return (name if name in EVENTS else "unknown"), {}


def process_identity(record):
    process = record.get("process")
    if not isinstance(process, dict):
        return None, None, None, None
    token = process.get("audit_token")
    token = token if isinstance(token, dict) else {}
    pid = token.get("pid", process.get("pid"))
    pidversion = token.get("pidversion", process.get("pidversion"))
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        pid = None
    try:
        pidversion = int(pidversion) if pidversion is not None else None
    except (TypeError, ValueError):
        pidversion = None
    start_time = process.get("start_time")
    if not isinstance(start_time, (str, int, float)) or isinstance(start_time, bool):
        start_time = None
    ppid = process.get("ppid")
    try:
        ppid = int(ppid) if ppid is not None else None
    except (TypeError, ValueError):
        ppid = None
    return pid, pidversion, start_time, ppid


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


def event_exec_target_path(details):
    if not isinstance(details, dict):
        return None
    for key in ("target", "executable"):
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
            if any(not isinstance(item, dict) for item in value):
                malformed.append(number)
        elif isinstance(value, dict):
            records.append(value)
        else:
            malformed.append(number)
    return records, malformed


def canonical(path):
    return os.path.normcase(os.path.realpath(path))


def stop_process_group(process):
    if process is None:
        return
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    if process_group_exists(process):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.wait(timeout=5)
    deadline = time.monotonic() + 1
    while process_group_exists(process) and time.monotonic() < deadline:
        time.sleep(0.05)


def process_group_exists(process):
    if process is None:
        return False
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def no_eslogger_process_remains():
    result = subprocess.run(
        ["/usr/bin/pgrep", "-x", "eslogger"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 1


def eslogger_process_running():
    result = subprocess.run(
        ["/usr/bin/pgrep", "-x", "eslogger"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def wait_for_parent_exit(logger, events_path, parent_pid):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if logger.poll() is not None:
            return False
        records, _ = read_records(events_path)
        if any(
            event_kind(record)[0] == "exit"
            and process_identity(record)[0] == parent_pid
            for record in records
        ):
            return logger.poll() is None and eslogger_process_running()
        time.sleep(0.05)
    return False


def write_summary(path, summary):
    summary = {
        key: value
        for key, value in summary.items()
        if key in SUMMARY_FIELDS
    }
    path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("telemetry_probe_result=" + summary["result"])


def public_fixture(fixture):
    if not isinstance(fixture, dict):
        return {}
    return {
        key: fixture[key]
        for key in FIXTURE_FIELDS
        if key in fixture and isinstance(fixture[key], int)
        and not isinstance(fixture[key], bool)
    }


def sequence_report(records):
    previous = None
    observed = 0
    missing = 0
    invalid = 0
    gaps = 0
    for record in records:
        value = record.get("global_seq_num")
        if value is None:
            missing += 1
            continue
        if isinstance(value, int) and not isinstance(value, bool):
            current = value
        elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
            current = int(value)
        else:
            invalid += 1
            continue
        observed += 1
        if previous is not None and current != previous + 1:
            gaps += 1
        previous = current
    return {
        "records": len(records),
        "observed": observed,
        "missing": missing,
        "invalid": invalid,
        "gaps": gaps,
        "contiguous": bool(records) and missing == 0 and invalid == 0 and gaps == 0,
    }


def sanitized_event(record, kind, details, old_root_path, expected):
    pid, pidversion, start_time, ppid = process_identity(record)
    if pid not in expected:
        return None
    item = {"event": kind, "pid": pid}
    for key in ("global_seq_num", "seq_num"):
        value = record.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            item[key] = value
        elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
            item[key] = int(value)
        else:
            item.pop(key, None)
    if pidversion is not None:
        item["pidversion"] = pidversion
    if start_time is not None:
        item["start_time"] = start_time
    if ppid is not None:
        item["ppid"] = ppid
    if kind == "exec":
        target_path = event_exec_target_path(details)
        if target_path:
            item["target_path"] = target_path
    path = event_file_path(details)
    if path and canonical(path).startswith(old_root_path + os.sep):
        item["file_path"] = path
    return {key: value for key, value in item.items() if key in EVENT_FIELDS}


def analyze_records(records, malformed, fixture, old_root, checks):
    fixture = public_fixture(fixture)
    expected = {}
    for key, role in (("parent_pid", "parent"), ("child_pid", "child")):
        try:
            expected[int(fixture[key])] = role
        except (KeyError, TypeError, ValueError):
            pass

    old_root_path = canonical(old_root)
    sequence = sequence_report(records)
    outside_counts = {}
    tracked_events = []
    identities = {}
    accesses = set()
    parent_exec = False
    parent_exit = False
    child_exit = False
    fork_child = False
    unresolved_identity = False

    for record in records:
        kind, details = event_kind(record)
        pid, pidversion, start_time, _ = process_identity(record)
        if pid not in expected:
            outside_counts[kind] = outside_counts.get(kind, 0) + 1
            continue

        safe_event = sanitized_event(record, kind, details, old_root_path, expected)
        if safe_event:
            tracked_events.append(safe_event)
        identity = pidversion if pidversion is not None else start_time
        if identity is not None:
            identities.setdefault(pid, set()).add(json.dumps(identity, sort_keys=True))
        else:
            unresolved_identity = True

        if kind == "exec" and expected[pid] == "parent":
            parent_exec = True
        if kind == "exit" and expected[pid] == "parent":
            parent_exit = True
        if kind == "exit" and expected[pid] == "child":
            child_exit = True
        if kind == "fork" and expected[pid] == "parent":
            child = details.get("child") if isinstance(details, dict) else None
            child_token = child.get("audit_token") if isinstance(child, dict) else None
            child_token = child_token if isinstance(child_token, dict) else {}
            child_pid = child_token.get(
                "pid",
                child.get("pid") if isinstance(child, dict) else None,
            )
            try:
                fork_child = int(child_pid) == fixture.get("child_pid")
            except (TypeError, ValueError):
                pass
        if kind == "open" and expected[pid] in ("parent", "child"):
            path = event_file_path(details)
            if path and canonical(path).startswith(old_root_path + os.sep):
                accesses.add(expected[pid])

    identity_complete = (
        set(identities) == set(expected)
        and len(expected) == 2
        and all(len(values) == 1 for values in identities.values())
        and not unresolved_identity
    )
    attribution_complete = accesses == {"parent", "child"}
    sequence_complete = (
        sequence["observed"] > 0
        and sequence["missing"] == 0
        and sequence["invalid"] == 0
    )
    logger_shutdown = (
        checks.get("logger_exit_code") is not None
        and checks.get("logger_group_exited") is True
        and checks.get("no_eslogger_process_remains") is True
    )
    fixture_ok = (
        checks.get("sentinel_event_observed_before_fixture") is True
        and checks.get("fixture_exit_code") == 0
        and fixture.get("child_exit_status") == 0
        and fixture.get("parent_access_count", 0) > 1
        and attribution_complete
        and identity_complete
        and fork_child
        and parent_exec
        and parent_exit
        and child_exit
        and checks.get("logger_alive_at_parent_exit") is True
        and logger_shutdown
        and checks.get("private_data_removed") is True
        and checks.get("fixture_files_removed") is True
        and sequence_complete
        and sequence["contiguous"]
        and not malformed
    )
    summary = {
        **checks,
        "event_count": len(records),
        "malformed_record_count": len(malformed),
        "outside_tree_event_counts": outside_counts,
        "tracked_process_events": tracked_events,
        "global_sequence": sequence,
        "parent_exec_observed": parent_exec,
        "parent_exit_observed": parent_exit,
        "child_exit_observed": child_exit,
        "fork_event_identified_child": fork_child,
        "fixture_attribution_pass": attribution_complete,
        "process_identity_pass": identity_complete,
        "logger_shutdown_pass": logger_shutdown,
        "sequence_gap_detection_available": sequence_complete,
        "fixture_result": "PASS" if fixture_ok else "UNAVAILABLE",
        "result": "PASS" if fixture_ok else "UNAVAILABLE",
    }
    if not fixture_ok and "reason" not in summary:
        summary["reason"] = "required fixture, sequence, lifecycle, or logger checks were incomplete"
    return summary


def probe_step_failed(summary):
    return summary.get("logger_started") is True and (
        summary.get("logger_shutdown_pass") is not True
        or summary.get("private_data_removed") is not True
    )


def run_macos_probe(eslogger, selected):
    home = Path.home()
    old_root = home / "Library" / "Application Support" / "Telegram Desktop"
    probe_root = old_root / (".main-909-" + uuid.uuid4().hex)
    parent_file = probe_root / "parent-access"
    child_file = probe_root / "child-access"
    created_directories = []
    private_root = None
    logger = None
    logger_stdout = None
    logger_stderr = None
    fixture_process = None
    fixture = {}
    records = []
    malformed = []
    reason = None
    checks = {
        "sentinel_event_observed_before_fixture": False,
        "fixture_exit_code": None,
        "logger_started": False,
        "logger_alive_at_parent_exit": False,
        "logger_exit_code": None,
        "logger_group_exited": False,
        "no_eslogger_process_remains": False,
        "private_data_removed": False,
        "fixture_files_removed": False,
    }

    try:
        runner_temp = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
        runner_temp.mkdir(parents=True, exist_ok=True)
        private_root = Path(
            tempfile.mkdtemp(prefix="mac-eslogger-probe-", dir=runner_temp)
        )
        events_path = private_root / "eslogger.jsonl"
        stderr_path = private_root / "eslogger.stderr"
        sentinel = private_root / "observer-ready"
        fixture_result = private_root / "fixture.json"

        for directory in (
            home / "Library",
            home / "Library" / "Application Support",
            old_root,
        ):
            if not directory.exists():
                directory.mkdir()
                created_directories.append(directory)
            if not directory.is_dir():
                raise OSError

        probe_root.mkdir()
        parent_file.write_bytes(b"parent")
        child_file.write_bytes(b"child")
        sentinel.touch()
        logger_stdout = events_path.open("w", encoding="utf-8")
        logger_stderr = stderr_path.open("w", encoding="utf-8")
        try:
            logger = subprocess.Popen(
                ["/usr/bin/sudo", "-n", str(eslogger), *selected],
                stdout=logger_stdout,
                stderr=logger_stderr,
                start_new_session=True,
            )
        except OSError:
            reason = "could not start eslogger"

        if logger is not None:
            ready = False
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and logger.poll() is None:
                descriptor = os.open(sentinel, os.O_WRONLY | os.O_TRUNC)
                os.close(descriptor)
                time.sleep(0.05)
                current, _ = read_records(events_path)
                for record in current:
                    kind, details = event_kind(record)
                    observed_path = event_file_path(details)
                    if (
                        kind == "open"
                        and observed_path
                        and canonical(observed_path) == canonical(sentinel)
                    ):
                        ready = True
                        break
                if ready:
                    break
            checks["sentinel_event_observed_before_fixture"] = ready

            if ready and logger.poll() is None:
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
                checks["fixture_exit_code"] = fixture_process.returncode
                if fixture_result.is_file():
                    fixture = public_fixture(
                        json.loads(fixture_result.read_text(encoding="utf-8"))
                    )
                if (
                    checks["fixture_exit_code"] == 0
                    and fixture.get("parent_pid") is not None
                ):
                    checks["logger_alive_at_parent_exit"] = wait_for_parent_exit(
                        logger,
                        events_path,
                        fixture["parent_pid"],
                    )
            elif reason is None:
                reason = "Endpoint Security observer did not become ready"
    except Exception:
        reason = reason or "probe execution or cleanup failed"
    finally:
        try:
            stop_process_group(fixture_process)
        except Exception:
            reason = reason or "fixture process did not stop cleanly"
        try:
            stop_process_group(logger)
        except Exception:
            reason = reason or "eslogger process did not stop cleanly"
        checks["logger_exit_code"] = (
            logger.returncode if logger is not None else None
        )
        checks["logger_started"] = logger is not None
        checks["logger_group_exited"] = (
            logger is not None and not process_group_exists(logger)
        )
        try:
            checks["no_eslogger_process_remains"] = no_eslogger_process_remains()
        except OSError:
            checks["no_eslogger_process_remains"] = False
        for stream in (logger_stdout, logger_stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    reason = reason or "eslogger output could not be closed"

        if private_root is not None:
            events_path = private_root / "eslogger.jsonl"
            try:
                records, malformed = (
                    read_records(events_path) if events_path.is_file() else ([], [])
                )
            except OSError:
                malformed = [1]

        try:
            if probe_root.exists():
                shutil.rmtree(probe_root)
            for directory in reversed(created_directories):
                try:
                    directory.rmdir()
                except FileNotFoundError:
                    pass
            checks["fixture_files_removed"] = (
                not probe_root.exists()
                and all(not directory.exists() for directory in created_directories)
            )
        except OSError:
            checks["fixture_files_removed"] = False

        if private_root is not None:
            try:
                shutil.rmtree(private_root)
            except OSError:
                try:
                    shutil.rmtree(private_root, ignore_errors=True)
                except OSError:
                    pass
            checks["private_data_removed"] = not private_root.exists()

    if reason:
        checks["reason"] = reason
    return records, malformed, fixture, checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()

    evidence = Path(args.evidence_dir)
    evidence.mkdir(parents=True, exist_ok=True)
    summary_path = evidence / "summary.json"
    fixture_path = evidence / "fixture.json"
    fixture_path.write_text("{}\n", encoding="utf-8")
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
    summary["eslogger_present"] = eslogger.is_file()
    if not summary["eslogger_present"]:
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

    records, malformed, fixture, checks = run_macos_probe(
        eslogger,
        selected,
    )
    summary = summary | analyze_records(
        records,
        malformed,
        fixture,
        Path.home() / "Library" / "Application Support" / "Telegram Desktop",
        checks,
    )
    fixture_path.write_text(
        json.dumps(public_fixture(fixture), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_summary(summary_path, summary)
    if probe_step_failed(summary):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
