#!/usr/bin/env python3

from __future__ import annotations

import argparse
import glob
import ipaddress
import json
import re
import sys
import urllib.parse

from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Iterable, Sequence


_SYSCALL = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<args>.*)\)\s+=\s+(?P<result>.*)$"
)
_PREFIX = re.compile(
    r"^(?:\[pid\s+(?P<bracket_pid>\d+)\]\s+|"
    r"(?P<pid>\d+)\s+)?"
    r"(?:(?:\d{2}:\d{2}:\d{2}\.\d+|\d+\.\d+)\s+)?"
    r"(?P<body>.*)$"
)
_FD = re.compile(r"^\s*(-?\d+)(?:<([^>]+)>)?")
_PORT = re.compile(r"(?:sin6?_)?port=htons\((\d+)\)")
_IPV4 = re.compile(
    r"(?:inet_addr|inet_aton)\(\"([^\"]+)\"\)"
    r"|inet_pton\(AF_INET,\s*\"([^\"]+)\"\)"
)
_IPV6 = re.compile(r"inet_pton\(AF_INET6,\s*\"([^\"]+)\"\)")
_FAMILY = re.compile(r"sa_family=(AF_[A-Z0-9_]+)")


@dataclass(frozen=True)
class NetworkEvent:
    kind: str
    syscall: str
    fd: int | None
    socket_id: str | None
    destination: str | None
    family: str | None
    line: str
    pid: int | None


def _fd_info(text: str) -> tuple[int | None, str | None]:
    match = _FD.match(text)
    return (
        (int(match.group(1)), match.group(2))
        if match
        else (None, None)
    )


def _pid_and_body(line: str) -> tuple[int | None, str]:
    match = _PREFIX.match(line.rstrip("\n"))
    if not match:
        return None, line.rstrip("\n")
    pid = match.group("bracket_pid") or match.group("pid")
    return (int(pid) if pid else None), match.group("body")


def _destination(text: str) -> tuple[str | None, str | None]:
    family_match = _FAMILY.search(text)
    family = family_match.group(1) if family_match else None
    port_match = _PORT.search(text)
    if not port_match:
        return family, None
    port = int(port_match.group(1))
    if family == "AF_INET6" or _IPV6.search(text):
        ipv6_match = _IPV6.search(text)
        if not ipv6_match:
            return family, None
        return family, f"[{ipv6_match.group(1)}]:{port}"
    ipv4_match = _IPV4.search(text)
    if not ipv4_match:
        return family, None
    address = ipv4_match.group(1) or ipv4_match.group(2)
    return family, f"{address}:{port}"


def _is_network_family(family: str | None) -> bool:
    return family in {"AF_INET", "AF_INET6"}


def parse_trace_lines(lines: Iterable[str]) -> list[NetworkEvent]:
    result = []
    for raw_line in lines:
        line = raw_line.rstrip("\n")
        pid, body = _pid_and_body(line)
        match = _SYSCALL.match(body)
        if not match:
            continue
        syscall = match.group("name")
        args = match.group("args")
        if syscall == "socket":
            family = args.split(",", 1)[0].strip()
            if not _is_network_family(family):
                continue
            fd, socket_id = _fd_info(match.group("result"))
            result.append(NetworkEvent(
                kind="socket",
                syscall=syscall,
                fd=fd,
                socket_id=socket_id,
                destination=None,
                family=family,
                line=line,
                pid=pid,
            ))
            continue
        if syscall not in {"connect", "sendto", "sendmsg", "sendmmsg"}:
            continue
        family, destination = _destination(args)
        if family is not None and not _is_network_family(family):
            continue
        fd, socket_id = _fd_info(args)
        if syscall == "connect":
            kind = "dns" if destination and destination.endswith(":53") else "connect"
        elif destination and destination.endswith(":53"):
            kind = "dns"
        else:
            kind = "send"
        result.append(NetworkEvent(
            kind=kind,
            syscall=syscall,
            fd=fd,
            socket_id=socket_id,
            destination=destination,
            family=family,
            line=line,
            pid=pid,
        ))
    return result


def _split_destination(destination: str) -> tuple[str, int] | None:
    if destination.startswith("["):
        separator = destination.find("]:")
        if separator < 0:
            return None
        host = destination[1:separator]
        port_text = destination[separator + 2:]
    else:
        host, separator, port_text = destination.rpartition(":")
        if not separator:
            return None
    try:
        return host, int(port_text)
    except ValueError:
        return None


def _destination_allowed(
        destination: str | None,
        allowed: Sequence[str]) -> bool:
    if destination is None:
        return False
    if destination in allowed:
        return True
    actual = _split_destination(destination)
    if actual is None:
        return False
    host, port = actual
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    for candidate in allowed:
        parsed = _split_destination(candidate)
        if parsed is None or parsed[1] != port:
            continue
        try:
            network = ipaddress.ip_network(parsed[0], strict=False)
        except ValueError:
            continue
        if address in network:
            return True
    return False


def _valid_public_origin(origin: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(origin)
        hostname = parsed.hostname
    except ValueError:
        return False
    return (
        bool(hostname)
        and hostname.isascii()
        and hostname == hostname.lower()
        and not hostname.endswith(".")
        and origin == (
            f"https://{hostname}/.well-known/telegramd/client"
        )
    )


def _fd_key(event: NetworkEvent) -> tuple:
    if event.socket_id:
        return ("socket", event.socket_id)
    return ("process", event.pid, event.fd)


def check_trace(
        events: Sequence[NetworkEvent],
        *,
        case: str,
        phase: str,
        allowed_destinations: Sequence[str],
        allowed_dns: Sequence[str],
        allowed_origins: Sequence[str] = (),
        allowed_proxies: Sequence[str] = ()) -> dict:
    destinations = list(allowed_destinations)
    dns = list(allowed_dns)
    proxies = list(allowed_proxies)
    if phase == "preselection":
        destinations = []
        dns = []
        proxies = []
    elif phase == "public-discovery":
        proxies = []
    elif phase == "local-direct":
        proxies = []
    violations = []
    if phase == "public-discovery":
        if len(allowed_origins) != 1:
            violations.append("public discovery requires one origin")
        elif not _valid_public_origin(allowed_origins[0]):
            violations.append(
                f"invalid public discovery origin {allowed_origins[0]}"
            )
    allowed_fds = set()
    socket_events = []
    for event in events:
        if event.kind == "socket":
            socket_events.append(event)
            continue
        if event.kind == "dns":
            if _destination_allowed(event.destination, dns):
                if event.fd is not None and event.fd >= 0:
                    allowed_fds.add(_fd_key(event))
            else:
                violations.append(
                    f"unallowed DNS destination {event.destination or '<unknown>'}"
                )
            continue
        if event.kind in {"connect", "send"}:
            if _destination_allowed(event.destination, destinations) \
                    or _destination_allowed(event.destination, proxies):
                if event.fd is not None and event.fd >= 0:
                    allowed_fds.add(_fd_key(event))
            else:
                violations.append(
                    f"unallowed {event.kind} destination "
                    f"{event.destination or '<unknown>'}"
                )
    for event in socket_events:
        if _fd_key(event) not in allowed_fds:
            violations.append(
                f"network socket has no allowed destination fd={event.fd}"
            )
    return {
        "case": case,
        "phase": phase,
        "passed": not violations,
        "events": [asdict(event) for event in events],
        "violations": violations,
        "allowlist": {
            "origins": list(allowed_origins),
            "destinations": destinations,
            "dns": dns,
            "proxies": proxies,
        },
    }


def _trace_paths(patterns: Sequence[str]) -> list[Path]:
    paths = []
    for pattern in patterns:
        matches = sorted(Path(path) for path in glob.glob(pattern))
        if not matches and Path(pattern).is_file():
            matches = [Path(pattern)]
        paths.extend(matches)
    return list(dict.fromkeys(paths))


def _read_trace(paths: Sequence[Path]) -> list[NetworkEvent]:
    events = []
    for path in paths:
        source_pid = None
        pid_match = re.search(r"\.(\d+)$", path.name)
        if pid_match:
            source_pid = int(pid_match.group(1))
        with path.open(encoding="utf-8", errors="replace") as trace:
            for event in parse_trace_lines(trace):
                events.append(
                    replace(event, pid=source_pid)
                    if event.pid is None and source_pid is not None
                    else event
                )
    return events


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse and enforce a destination allowlist for strace network events."
    )
    parser.add_argument(
        "--trace",
        action="append",
        required=True,
        help="strace file or glob; repeat for multiple trace files",
    )
    parser.add_argument("--case", required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--origin", action="append", default=[])
    parser.add_argument("--allow-destination", action="append", default=[])
    parser.add_argument("--allow-dns", action="append", default=[])
    parser.add_argument("--allow-proxy", action="append", default=[])
    parser.add_argument("--report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    paths = _trace_paths(args.trace)
    if not paths:
        print("no trace files matched", file=sys.stderr)
        return 2
    events = _read_trace(paths)
    report = check_trace(
        events,
        case=args.case,
        phase=args.phase,
        allowed_destinations=args.allow_destination,
        allowed_dns=args.allow_dns,
        allowed_origins=args.origin,
        allowed_proxies=args.allow_proxy,
    )
    report["trace_files"] = [str(path) for path in paths]
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        Path(args.report).write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
