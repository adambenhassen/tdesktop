#!/usr/bin/env python3

import os
import re
import sys
import tempfile


PATH_OPERATIONS = {
    "access",
    "copyfile",
    "clonefile",
    "delete",
    "fstat",
    "getattrlist",
    "getdirentries",
    "lstat",
    "link",
    "mkdir",
    "open",
    "page-in",
    "page-out",
    "fcntl",
    "flock",
    "pread",
    "pwrite",
    "read",
    "readv",
    "rddata",
    "rdmeta",
    "rename",
    "rmdir",
    "stat",
    "stat64",
    "statfs",
    "symlink",
    "truncate",
    "unlink",
    "write",
    "writev",
    "wrdata",
    "wrmeta",
}


def canonical(path):
    return os.path.realpath(path)


def inside(path, root):
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def path_candidates(body):
    return [
        match.group(0)
        for match in re.finditer(r"(?<!\S)/(?:\\\s|[^\s])+", body)
    ]


def contains_path_under_root(body, root):
    normalized = body.replace("\\\\ ", " ")
    for match in re.finditer(re.escape(root), normalized):
        before = normalized[match.start() - 1] if match.start() else " "
        after = normalized[match.end()] if match.end() < len(normalized) else " "
        if (before.isspace() or before in "([") and (after.isspace() or after == "/"):
            return True
    return False


def scan(lines, old_root, pids, empty_pids=()):
    # fs_usage labels events with a process name and thread id. The numeric
    # suffix is not the OS pid collected by the lifecycle observer, so each
    # section must carry the OS pid used for its kernel-side filter.
    old_root = canonical(old_root)
    tracked_pids = set(pids)
    empty_pids = set(empty_pids)
    process_pattern = re.compile(r"(?P<name>[^\s]+)\.(?P<thread>[0-9]+)\s*$")
    observer_pattern = re.compile(r"^# observer-pid=(?P<pid>[0-9]+)\s*$")
    timestamp_pattern = re.compile(r"^[0-9]{2}:[0-9]{2}:[0-9]{2}\.")
    violations = []
    ambiguous = []
    coverage = []
    observed_pids = set()
    parseable_pids = set()
    detected = set()
    target_events = 0
    observer_pid = None

    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip("\n")
        observer_match = observer_pattern.match(line)
        if observer_match:
            observer_pid = int(observer_match.group("pid"))
            observed_pids.add(observer_pid)
            if observer_pid not in tracked_pids:
                coverage.append((line_number, "untracked observer pid", line))
            continue
        if not line or line.startswith("#") or not timestamp_pattern.match(line):
            continue
        match = process_pattern.search(line)
        if not match:
            if observer_pid is None:
                coverage.append((line_number, "missing observer pid", line))
            elif observer_pid in tracked_pids:
                ambiguous.append((line_number, "missing process thread", line))
            continue
        if observer_pid is None:
            coverage.append((line_number, "missing observer pid", line))
            continue
        if observer_pid not in tracked_pids:
            coverage.append((line_number, "event from untracked observer pid", line))
            continue
        target_events += 1

        body = line[:match.start()].rstrip()
        duration = re.search(r"\s+[0-9]+\.[0-9]+(?:\s+W)?\s*$", body)
        if duration:
            body = body[:duration.start()].rstrip()
        fields = body.split()
        operation = fields[1].lower().replace("_", "-") if len(fields) > 1 else ""
        operation = re.sub(r"\[.*\]$", "", operation)
        normalized = body.replace("\\ ", " ")
        if contains_path_under_root(normalized, old_root):
            violations.append((line_number, operation or "unknown", "direct path", line))

        candidates = path_candidates(body)
        known_operation = operation in PATH_OPERATIONS
        if not known_operation:
            ambiguous.append((line_number, operation or "unknown", line))
        else:
            detected.add(operation)
        if not candidates or "..." in body:
            if known_operation:
                ambiguous.append((line_number, operation, line))
            # An unknown operation is already ambiguous; there is no
            # parseable event to record for this PID.
            continue

        event_ambiguous = not known_operation
        for candidate in candidates:
            if "..." in candidate:
                ambiguous.append((line_number, operation or "unknown", line))
                event_ambiguous = True
                continue
            path = candidate.replace("\\ ", " ")
            if not path.startswith("/"):
                ambiguous.append((line_number, operation or "unknown", line))
                event_ambiguous = True
                continue
            if inside(canonical(path), old_root):
                violations.append((line_number, operation or "unknown", "canonical path", line))
        if not event_ambiguous:
            parseable_pids.add(observer_pid)

    missing_pids = sorted(tracked_pids - observed_pids)
    for pid in missing_pids:
        coverage.append((0, "missing observer section pid=%d" % pid, ""))
    missing_event_pids = sorted(tracked_pids - parseable_pids - empty_pids)
    for pid in missing_event_pids:
        coverage.append((0, "missing parseable filesystem event pid=%d" % pid, ""))
    return (
        violations,
        ambiguous,
        coverage,
        detected,
        target_events,
        observed_pids,
        parseable_pids,
    )


def format_report(
    violations,
    ambiguous,
    coverage,
    detected,
    target_events,
    tracked_pids,
    observed_pids,
    parseable_pids,
):
    lines = ["detected=" + ",".join(sorted(detected))]
    lines.append("target_events=" + str(target_events))
    lines.append("tracked_os_pids=" + ",".join(str(pid) for pid in sorted(tracked_pids)))
    lines.append("observed_os_pids=" + ",".join(str(pid) for pid in sorted(observed_pids)))
    lines.append("parseable_os_pids=" + ",".join(str(pid) for pid in sorted(parseable_pids)))
    lines.append("violations=" + str(len(violations)))
    lines.append("ambiguous=" + str(len(ambiguous)))
    lines.append("coverage_gaps=" + str(len(coverage)))
    for line_number, operation, reason, line in violations:
        lines.append("violation line=%d operation=%s reason=%s %s" % (
            line_number,
            operation,
            reason,
            line,
        ))
    for line_number, operation, line in ambiguous:
        lines.append("ambiguous line=%d operation=%s %s" % (
            line_number,
            operation,
            line,
        ))
    for line_number, reason, line in coverage:
        lines.append("coverage line=%d reason=%s %s" % (
            line_number,
            reason,
            line,
        ))
    return "\n".join(lines) + "\n"


def self_test():
    with tempfile.TemporaryDirectory(prefix="mac-fs-usage-") as root:
        old = os.path.join(root, "Library", "Application Support", "Telegram Desktop")
        allowed = os.path.join(root, "Library", "Application Support", "Telegramd")
        os.makedirs(os.path.join(old, "tdata"))
        os.makedirs(allowed)
        alias = os.path.join(root, "old-alias")
        os.symlink(old, alias)
        old_alias = canonical(alias)
        target_pid = 50178
        thread_suffix = 708206
        forbidden = [
            "open",
            "read",
            "write",
            "stat",
            "getattrlist",
            "rename",
            "copyfile",
            "delete",
            "unlink",
            "pwrite",
            "fcntl",
            "flock",
        ]
        trace = ["# observer-pid=%d" % target_pid]
        for index, operation in enumerate(forbidden, 1):
            path = os.path.join(alias, "tdata", "entry-%d" % index)
            trace.append("12:00:%02d.000 %s %s 0.001 Telegramd.%d" % (
                index,
                operation,
                path,
                thread_suffix,
            ))
        trace.append("12:00:20.000 open %s/tdata/allowed 0.001 TelegramdHelper.%d" % (
            allowed,
            thread_suffix + 1,
        ))
        (
            violations,
            ambiguous,
            coverage,
            detected,
            target_events,
            observed_pids,
            parseable_pids,
        ) = scan(
            trace,
            old_alias,
            (target_pid,),
        )
        expected = set(forbidden)
        if (
            ambiguous
            or coverage
            or target_events != len(trace) - 1
            or observed_pids != {target_pid}
            or parseable_pids != {target_pid}
            or not expected.issubset(detected)
        ):
            raise AssertionError("observer did not detect all operation classes")
        if len(violations) < len(forbidden):
            raise AssertionError("observer did not canonicalize the forbidden alias")

        clean_trace = [
            "# observer-pid=%d" % target_pid,
            "12:00:30.000 open %s/tdata/allowed 0.001 Telegramd.%d" % (
                allowed,
                thread_suffix,
            ),
            "12:00:31.000 open %s-backup/tdata/allowed 0.001 Telegramd.%d" % (
                old,
                thread_suffix + 1,
            ),
        ]
        (
            clean_violations,
            clean_ambiguous,
            clean_coverage,
            _,
            clean_target_events,
            _,
            clean_parseable_pids,
        ) = scan(
            clean_trace,
            old_alias,
            (target_pid,),
        )
        if (
            clean_violations
            or clean_ambiguous
            or clean_coverage
            or clean_target_events != len(clean_trace) - 1
            or clean_parseable_pids != {target_pid}
        ):
            raise AssertionError("observer rejected an allowed canonical root")
        truncated_trace = ["# observer-pid=%d" % target_pid] + [
            "12:00:%02d.000 %s ... Telegramd.%d" % (40 + index, operation, thread_suffix)
            for index, operation in enumerate(forbidden)
        ]
        _, truncated_ambiguous, _, _, _, _, truncated_parseable_pids = scan(
            truncated_trace,
            old_alias,
            (target_pid,),
        )
        if (
            len(truncated_ambiguous) != len(truncated_trace) - 1
            or truncated_parseable_pids
        ):
            raise AssertionError("observer accepted an ambiguous target event")
        (
            _,
            thread_ambiguous,
            thread_coverage,
            _,
            thread_target_events,
            _,
            thread_parseable_pids,
        ) = scan(
            [
                "# observer-pid=%d" % target_pid,
                "12:00:55.000 open %s/tdata/entry 0.001 Telegramd.708875" % allowed,
            ],
            old_alias,
            (target_pid,),
        )
        if (
            thread_ambiguous
            or thread_coverage
            or thread_target_events != 1
            or thread_parseable_pids != {target_pid}
        ):
            raise AssertionError("observer treated a thread suffix as an OS pid")
        missing_suffix_trace = [
            "# observer-pid=%d" % target_pid,
            "12:00:56.000 open %s/tdata/entry 0.001 Telegramd" % allowed,
        ]
        _, missing_suffix_ambiguous, _, _, _, _, missing_suffix_parseable_pids = scan(
            missing_suffix_trace,
            old_alias,
            (target_pid,),
        )
        if missing_suffix_parseable_pids or not missing_suffix_ambiguous:
            raise AssertionError("observer accepted a target event without a thread suffix")
        _, _, untracked_coverage, _, _, _, _ = scan(
            [
                "# observer-pid=99999",
                "12:00:57.000 open %s/tdata/entry 0.001 Telegramd.9999" % allowed,
            ],
            old_alias,
            (target_pid,),
        )
        if not untracked_coverage:
            raise AssertionError("observer accepted an untracked OS pid section")
        _, _, missing_section_coverage, _, _, _, _ = scan(
            [
                "# observer-pid=%d" % target_pid,
                "12:00:58.000 open %s/tdata/entry 0.001 Telegramd.%d" % (
                    allowed,
                    thread_suffix,
                ),
            ],
            old_alias,
            (target_pid, target_pid + 1),
        )
        if not any(
            "missing observer section" in reason
            for _, reason, _ in missing_section_coverage
        ):
            raise AssertionError("observer accepted a missing tracked PID section")
        (
            missing_event_violations,
            missing_event_ambiguous,
            missing_event_coverage,
            _,
            missing_event_target_events,
            missing_event_observed_pids,
            missing_event_parseable_pids,
        ) = scan(
            [
                "# observer-pid=%d" % target_pid,
                "12:00:59.000 open %s/tdata/entry 0.001 Telegramd.%d" % (
                    allowed,
                    thread_suffix,
                ),
                "# observer-pid=%d" % (target_pid + 1),
            ],
            old_alias,
            (target_pid, target_pid + 1),
        )
        if (
            missing_event_violations
            or missing_event_ambiguous
            or missing_event_target_events != 1
            or missing_event_observed_pids != {target_pid, target_pid + 1}
            or missing_event_parseable_pids != {target_pid}
            or not any(
                "missing parseable filesystem event pid=%d" % (target_pid + 1)
                in reason
                for _, reason, _ in missing_event_coverage
            )
        ):
            raise AssertionError("observer accepted a header-only tracked PID section")
        (
            empty_event_violations,
            empty_event_ambiguous,
            empty_event_coverage,
            _,
            empty_event_target_events,
            empty_event_observed_pids,
            empty_event_parseable_pids,
        ) = scan(
            ["# observer-pid=%d" % target_pid],
            old_alias,
            (target_pid,),
            (target_pid,),
        )
        if (
            empty_event_violations
            or empty_event_ambiguous
            or empty_event_coverage
            or empty_event_target_events
            or empty_event_observed_pids != {target_pid}
            or empty_event_parseable_pids
        ):
            raise AssertionError("observer rejected a pre-execution empty child section")
        (
            unknown_violations,
            unknown_ambiguous,
            unknown_coverage,
            _,
            unknown_target_events,
            _,
            unknown_parseable_pids,
        ) = scan(
            [
                "# observer-pid=%d" % target_pid,
                "12:01:00.000 open %s/tdata/entry 0.001 Telegramd.%d" % (
                    allowed,
                    thread_suffix,
                ),
                "12:01:01.000 setattrlist %s/tdata/forbidden 0.001 Telegramd.%d" % (
                    alias,
                    thread_suffix,
                ),
            ],
            old_alias,
            (target_pid,),
        )
        if (
            not unknown_violations
            or len(unknown_ambiguous) != 1
            or unknown_coverage
            or unknown_target_events != 2
            or unknown_parseable_pids != {target_pid}
        ):
            raise AssertionError("observer accepted an unknown filesystem operation")
        return "canonical-alias=PASS\ndetected=" + ",".join(sorted(expected)) + "\n"


def main(argv):
    if argv == ["--self-test"]:
        sys.stdout.write(self_test())
        return 0
    if len(argv) not in (4, 5):
        print("usage: check_mac_fs_usage.py TRACE OLD_ROOT PID_FILE REPORT [EMPTY_PID_FILE]", file=sys.stderr)
        return 2

    trace_path, old_root, pid_path, report_path = argv[:4]
    with open(pid_path, encoding="utf-8") as pid_file:
        pids = [int(line.strip()) for line in pid_file if line.strip()]
    empty_pids = []
    if len(argv) == 5:
        with open(argv[4], encoding="utf-8") as empty_pid_file:
            for line in empty_pid_file:
                value = line.strip()
                if not value:
                    continue
                if not value.isdigit():
                    print("invalid pre-execution empty PID: %s" % value, file=sys.stderr)
                    return 2
                empty_pids.append(int(value))
    if not set(empty_pids).issubset(set(pids)):
        print("pre-execution empty PID is not tracked", file=sys.stderr)
        return 2
    with open(trace_path, encoding="utf-8", errors="replace") as trace_file:
        lines = trace_file.readlines()
    (
        violations,
        ambiguous,
        coverage,
        detected,
        target_events,
        observed_pids,
        parseable_pids,
    ) = scan(
        lines,
        old_root,
        pids,
        empty_pids,
    )
    report = format_report(
        violations,
        ambiguous,
        coverage,
        detected,
        target_events,
        set(pids),
        observed_pids,
        parseable_pids,
    )
    report += "pre_execution_empty_os_pids=%s\n" % ",".join(
        str(pid) for pid in sorted(empty_pids)
    )
    with open(report_path, "w", encoding="utf-8") as output:
        output.write(report)
    sys.stdout.write(report)
    if coverage:
        return 2
    return 1 if violations or ambiguous or not pids or not target_events or not detected else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
