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
_UNIX_PATH = re.compile(r"sun_path=\"([^\"]*)\"")


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


def _split_call_args(text: str) -> list[str]:
    result = []
    start = 0
    depth = 0
    quote = False
    escaped = False
    for index, character in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quote = False
            continue
        if character == '"':
            quote = True
        elif character in "{[(":
            depth += 1
        elif character in "}])":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            result.append(text[start:index].strip())
            start = index + 1
    result.append(text[start:].strip())
    return result


def _named_values(text: str, name: str) -> list[str]:
    text = text.strip()
    if len(text) < 2 or text[0] not in "{[" or text[-1] not in "}]":
        return []
    result = []
    for field in _split_call_args(text[1:-1]):
        field = field.strip()
        if not field:
            continue
        if field[0] in "{[":
            result.extend(_named_values(field, name))
            continue
        key, separator, value = field.partition("=")
        if not separator:
            continue
        if key.strip() == name:
            result.append(value.strip())
        if value.strip().startswith(("{", "[")):
            result.extend(_named_values(value.strip(), name))
    return result


def _sockaddr_texts(syscall: str, args: str) -> list[str]:
    parts = _split_call_args(args)
    if syscall == "connect":
        return [parts[1]] if len(parts) > 1 else [""]
    if syscall == "sendto":
        return [parts[4]] if len(parts) > 4 else [""]
    if syscall in {"sendmsg", "sendmmsg"}:
        values = _named_values(parts[1], "msg_name") if len(parts) > 1 else []
        return values or [""]
    return [""]


def _unix_path(text: str) -> str | None:
    match = _UNIX_PATH.search(text)
    return match.group(1) if match else None


def _is_local_unix_path(path: str | None) -> bool:
    return bool(path) and (
        path == "/tmp/display"
        or path.startswith("/tmp/.X11-unix/")
        or path == "/run/dbus/system_bus_socket"
        or (path.startswith("/run/user/") and path.endswith("/bus"))
    )


def _is_resolver_unix_path(path: str | None) -> bool:
    return bool(path) and path.startswith("/run/systemd/resolve/")


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
            if family == "AF_UNIX":
                continue
            fd, socket_id = _fd_info(match.group("result"))
            result.append(NetworkEvent(
                kind="socket" if _is_network_family(family) else "unknown",
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
        fd, socket_id = _fd_info(args)
        for sockaddr in _sockaddr_texts(syscall, args):
            family, destination = _destination(sockaddr)
            if family == "AF_UNIX":
                path = _unix_path(sockaddr)
                destination = f"unix:{path}" if path else None
                kind = (
                    "local" if _is_local_unix_path(path)
                    else "dns" if _is_resolver_unix_path(path)
                    else "unknown"
                )
            elif not _is_network_family(family):
                kind = "unknown"
            elif syscall == "connect":
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
    if not isinstance(destination, str):
        return None
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


def _valid_unix_destination(destination: str) -> bool:
    return (
        isinstance(destination, str)
        and destination.startswith("unix:/")
        and "\n" not in destination
        and "\r" not in destination
    )


def _valid_ip_destination(destination: str) -> bool:
    if not isinstance(destination, str):
        return False
    parsed = _split_destination(destination)
    if parsed is None:
        return False
    host, port = parsed
    if not 0 <= port <= 65535:
        return False
    try:
        ipaddress.ip_network(host, strict=False)
    except ValueError:
        return False
    return True


def _valid_allowlist_destination(
        destination: str,
        *,
        allow_unix: bool) -> bool:
    return (
        _valid_unix_destination(destination)
        if allow_unix and destination.startswith("unix:")
        else _valid_ip_destination(destination)
    )


def _destination_allowed(
        destination: str | None,
        allowed: Sequence[str]) -> bool:
    if not isinstance(destination, str):
        return False
    if destination.startswith("unix:"):
        return any(
            _valid_unix_destination(candidate) and candidate == destination
            for candidate in allowed
        )
    actual = _split_destination(destination)
    if actual is None:
        return False
    host, port = actual
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    addresses = [address]
    if address.version == 6 and address.ipv4_mapped:
        addresses.append(address.ipv4_mapped)
    for candidate in allowed:
        if not _valid_ip_destination(candidate):
            continue
        parsed = _split_destination(candidate)
        if parsed is None or parsed[1] != port:
            continue
        try:
            network = ipaddress.ip_network(parsed[0], strict=False)
        except ValueError:
            continue
        if any(candidate_address in network for candidate_address in addresses):
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
        allowed_proxies: Sequence[str] = (),
        required_destinations: Sequence[str] = (),
        required_dns: Sequence[str] = (),
        required_proxies: Sequence[str] = (),
        proxy_target: str | None = None,
        proxy_target_proven: bool = False) -> dict:
    configured_destinations = list(allowed_destinations)
    configured_dns = list(allowed_dns)
    configured_proxies = list(allowed_proxies)
    destinations = list(configured_destinations)
    dns = list(configured_dns)
    proxies = list(configured_proxies)
    if phase == "preselection":
        destinations = []
        dns = []
        proxies = []
    elif phase == "public-discovery":
        proxies = []
    elif phase == "local-direct":
        proxies = []
    violations = []
    for label, values, allow_unix in (
        ("destination", configured_destinations, False),
        ("DNS", configured_dns, True),
        ("proxy", configured_proxies, False),
    ):
        for value in values:
            if not _valid_allowlist_destination(value, allow_unix=allow_unix):
                violations.append(f"invalid {label} allowlist destination {value}")
    for label, values, allow_unix in (
        ("required destination", required_destinations, False),
        ("required DNS", required_dns, True),
        ("required proxy", required_proxies, False),
    ):
        for value in values:
            if not _valid_allowlist_destination(value, allow_unix=allow_unix):
                violations.append(f"invalid {label} {value}")
    if any(value not in configured_destinations for value in required_destinations):
        violations.append("required destination is outside the destination allowlist")
    if any(value not in configured_dns for value in required_dns):
        violations.append("required DNS destination is outside the DNS allowlist")
    if any(value not in configured_proxies for value in required_proxies):
        violations.append("required proxy is outside the proxy allowlist")
    if proxy_target:
        if not _valid_ip_destination(proxy_target):
            violations.append(f"invalid proxy target {proxy_target}")
        elif proxy_target not in configured_destinations:
            violations.append("proxy target is outside the destination allowlist")
        elif proxy_target not in required_destinations:
            violations.append("proxy target is not part of required evidence")
        elif not proxy_target_proven:
            violations.append("proxy target assertion was not proven")
    if phase == "public-discovery" and (
        not required_destinations or not required_dns
    ):
        violations.append("public discovery requires destination and DNS evidence")
    if phase in {"local-direct", "pinned-endpoint"} and not required_destinations:
        if not (proxy_target and proxy_target_proven):
            violations.append("endpoint phase requires destination evidence")
    if phase == "public-discovery":
        if set(required_destinations) != set(configured_destinations):
            violations.append(
                "public discovery origin is not bound to its destination allowlist"
            )
        if len(allowed_origins) != 1:
            violations.append("public discovery requires one origin")
        elif not _valid_public_origin(allowed_origins[0]):
            violations.append(
                f"invalid public discovery origin {allowed_origins[0]}"
            )
    elif allowed_origins:
        violations.append("non-public phases cannot allow a discovery origin")
    allowed_fds = set()
    socket_events = []
    for event in events:
        if event.kind == "socket":
            socket_events.append(event)
            continue
        if event.kind == "local":
            continue
        if event.kind == "unknown":
            violations.append(
                f"unknown network family {event.family or '<unknown>'}"
            )
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
    for required in required_destinations:
        if proxy_target_proven and required == proxy_target:
            continue
        if not any(
                event.kind in {"connect", "send"}
                and _destination_allowed(event.destination, [required])
                for event in events):
            violations.append(f"required destination not observed {required}")
    if required_dns and not any(
            event.kind == "dns"
            and any(
                _destination_allowed(event.destination, [required])
                for required in required_dns
            )
            for event in events):
        violations.append(
            "required DNS destination not observed "
            + ", ".join(required_dns)
        )
    for required in required_proxies:
        if not any(
                event.kind in {"connect", "send"}
                and _destination_allowed(event.destination, [required])
                for event in events):
            violations.append(f"required proxy not observed {required}")

    def event_report(event: NetworkEvent) -> dict:
        report = asdict(event)
        del report["line"]
        return report

    return {
        "case": case,
        "phase": phase,
        "passed": not violations,
        "events": [event_report(event) for event in events],
        "violations": violations,
        "allowlist": {
            "origins": list(allowed_origins),
            "destinations": destinations,
            "dns": dns,
            "proxies": proxies,
            "required_destinations": list(required_destinations),
            "required_dns": list(required_dns),
            "required_proxies": list(required_proxies),
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


def _proxy_target_proven(path: str | None, expected: str | None) -> bool:
    if not path or not expected:
        return False
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return False
    return lines == [expected]


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
    parser.add_argument("--require-destination", action="append", default=[])
    parser.add_argument("--require-dns", action="append", default=[])
    parser.add_argument("--require-proxy", action="append", default=[])
    parser.add_argument("--proxy-target")
    parser.add_argument("--proxy-target-proof")
    parser.add_argument("--target-status", type=int)
    parser.add_argument("--report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    paths = _trace_paths(args.trace)
    if not paths:
        print("no trace files matched", file=sys.stderr)
        return 2
    events = _read_trace(paths)
    proxy_target_proven = _proxy_target_proven(
        args.proxy_target_proof,
        args.proxy_target,
    )
    report = check_trace(
        events,
        case=args.case,
        phase=args.phase,
        allowed_destinations=args.allow_destination,
        allowed_dns=args.allow_dns,
        allowed_origins=args.origin,
        allowed_proxies=args.allow_proxy,
        required_destinations=args.require_destination,
        required_dns=args.require_dns,
        required_proxies=args.require_proxy,
        proxy_target=args.proxy_target,
        proxy_target_proven=proxy_target_proven,
    )
    report["trace_count"] = len(paths)
    if args.target_status is not None:
        report["target_status"] = args.target_status
    if args.proxy_target:
        report["proxy_target"] = args.proxy_target
        report["proxy_target_proven"] = proxy_target_proven
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        Path(args.report).write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
