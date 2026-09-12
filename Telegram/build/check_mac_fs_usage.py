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


def scan(lines, old_root, pids, process_names=("Telegramd",)):
    old_root = canonical(old_root)
    pid_strings = {str(pid) for pid in pids}
    process_pattern = re.compile(r"(?P<name>[^\s]+)\.(?P<pid>[0-9]+)\s*$")
    target_pattern = re.compile(
        r"(?:^|\s)(?:" + "|".join(re.escape(name) for name in process_names) + r")(?:\.|\s|$)"
    )
    violations = []
    ambiguous = []
    detected = set()
    target_events = 0

    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip("\n")
        match = process_pattern.search(line)
        if not match:
            if target_pattern.search(line):
                ambiguous.append((line_number, "missing process pid", line))
            continue
        process_name = match.group("name")
        if process_name in process_names and match.group("pid") not in pid_strings:
            ambiguous.append((line_number, "untracked process pid", line))
            continue
        if match.group("pid") not in pid_strings:
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
        if operation in PATH_OPERATIONS:
            detected.add(operation)
            if not candidates or "..." in body:
                ambiguous.append((line_number, operation, line))
                continue

        for candidate in candidates:
            if "..." in candidate:
                ambiguous.append((line_number, operation or "unknown", line))
                continue
            path = candidate.replace("\\ ", " ")
            if not path.startswith("/"):
                ambiguous.append((line_number, operation or "unknown", line))
                continue
            if inside(canonical(path), old_root):
                violations.append((line_number, operation or "unknown", "canonical path", line))

    return violations, ambiguous, detected, target_events


def format_report(violations, ambiguous, detected, target_events):
    lines = ["detected=" + ",".join(sorted(detected))]
    lines.append("target_events=" + str(target_events))
    lines.append("violations=" + str(len(violations)))
    lines.append("ambiguous=" + str(len(ambiguous)))
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
        target_pid = 4242
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
        trace = []
        for index, operation in enumerate(forbidden, 1):
            path = os.path.join(alias, "tdata", "entry-%d" % index)
            trace.append("12:00:%02d.000 %s %s 0.001 Telegramd.%d" % (
                index,
                operation,
                path,
                target_pid,
            ))
        trace.append("12:00:20.000 open %s/tdata/allowed 0.001 Telegramd.%d" % (
            allowed,
            target_pid,
        ))
        violations, ambiguous, detected, target_events = scan(
            trace,
            old_alias,
            (target_pid,),
        )
        expected = set(forbidden)
        if ambiguous or target_events != len(trace) or not expected.issubset(detected):
            raise AssertionError("observer did not detect all operation classes")
        if len(violations) < len(forbidden):
            raise AssertionError("observer did not canonicalize the forbidden alias")

        clean_trace = [
            "12:00:30.000 open %s/tdata/allowed 0.001 Telegramd.%d" % (
                allowed,
                target_pid,
            ),
            "12:00:31.000 open %s-backup/tdata/allowed 0.001 Telegramd.%d" % (
                old,
                target_pid,
            ),
        ]
        clean_violations, clean_ambiguous, _, clean_target_events = scan(
            clean_trace,
            old_alias,
            (target_pid,),
        )
        if clean_violations or clean_ambiguous or clean_target_events != len(clean_trace):
            raise AssertionError("observer rejected an allowed canonical root")
        truncated_trace = [
            "12:00:%02d.000 %s ... Telegramd.%d" % (40 + index, operation, target_pid)
            for index, operation in enumerate(forbidden)
        ]
        _, truncated_ambiguous, _, _ = scan(
            truncated_trace,
            old_alias,
            (target_pid,),
        )
        if len(truncated_ambiguous) != len(truncated_trace):
            raise AssertionError("observer accepted an ambiguous target event")
        _, untracked_ambiguous, _, _ = scan(
            ["12:00:55.000 open %s/tdata/entry 0.001 Telegramd.9999" % old],
            old_alias,
            (target_pid,),
        )
        if not untracked_ambiguous:
            raise AssertionError("observer accepted an untracked target process")
        return "canonical-alias=PASS\ndetected=" + ",".join(sorted(expected)) + "\n"


def main(argv):
    if argv == ["--self-test"]:
        sys.stdout.write(self_test())
        return 0
    if len(argv) != 4:
        print("usage: check_mac_fs_usage.py TRACE OLD_ROOT PID_FILE REPORT", file=sys.stderr)
        return 2

    trace_path, old_root, pid_path, report_path = argv
    with open(pid_path, encoding="utf-8") as pid_file:
        pids = [int(line.strip()) for line in pid_file if line.strip()]
    with open(trace_path, encoding="utf-8", errors="replace") as trace_file:
        lines = trace_file.readlines()
    violations, ambiguous, detected, target_events = scan(lines, old_root, pids)
    report = format_report(violations, ambiguous, detected, target_events)
    with open(report_path, "w", encoding="utf-8") as output:
        output.write(report)
    sys.stdout.write(report)
    return 1 if violations or ambiguous or not pids or not target_events or not detected else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
