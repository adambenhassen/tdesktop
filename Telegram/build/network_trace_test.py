#!/usr/bin/env python3

import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from network_trace import (
    _proxy_target_proven,
    _read_trace,
    check_trace,
    parse_trace_lines,
)
from network_public_fixture import PublicFixture
from network_socks_fixture import SocksFixture


def public_fixture_evidence(origin, host):
    return {
        "origin": origin,
        "host": host,
        "error": "NoError",
        "addresses": ["203.0.113.10"],
        "destinations": ["203.0.113.10:443"],
        "request_path": "/.well-known/telegramd/client",
        "proxy_target": "203.0.113.10:443",
        "observed": True,
        "source": "network_public_fixture",
    }


class NetworkTraceTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            parse_trace_lines,
            "network_trace.py must provide the process trace parser",
        )
        self.assertIsNotNone(
            check_trace,
            "network_trace.py must provide the destination allowlist check",
        )

    def test_unix_sockets_are_not_network_activity(self):
        events = parse_trace_lines([
            'socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3',
            'connect(3, {sa_family=AF_UNIX, sun_path="/tmp/display"}, 19) = 0',
        ])

        result = check_trace(
            events,
            case="fresh-empty",
            phase="preselection",
            allowed_destinations=[],
            allowed_dns=[],
        )

        self.assertTrue(result["passed"], result)
        self.assertEqual(result["events"][0]["kind"], "local")

    def test_allowlisted_listener_bind_keeps_observer_socket_bounded(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'bind(3, {sa_family=AF_INET, sin_port=htons(19081), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
            'connect(3, {sa_family=AF_INET, sin_port=htons(19081), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="local-preflight",
            phase="local-direct",
            allowed_destinations=["127.0.0.1:19081"],
            allowed_dns=[],
            required_destinations=["127.0.0.1:19081"],
        )

        self.assertTrue(result["passed"], result)

        rejected = check_trace(
            events,
            case="local-preflight",
            phase="local-direct",
            allowed_destinations=["127.0.0.1:19082"],
            allowed_dns=[],
            required_destinations=["127.0.0.1:19082"],
        )
        self.assertFalse(rejected["passed"], rejected)

    def test_preselection_rejects_official_connect(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("149.154.167.50")}, 16) = -1 EINPROGRESS',
        ])

        result = check_trace(
            events,
            case="fresh-empty",
            phase="preselection",
            allowed_destinations=[],
            allowed_dns=[],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("149.154.167.50:443", result["violations"][0])

    def test_unfinished_network_syscall_is_reported_as_unknown(self):
        events = parse_trace_lines([
            'connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("192.0.2.10")}, 16 <unfinished ...>',
        ])

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "unknown")
        result = check_trace(
            events,
            case="pinned-endpoint",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            required_destinations=["192.0.2.10:443"],
        )
        self.assertFalse(result["passed"], result)
        self.assertIn("unknown network syscall connect", result["violations"])

    def test_unmatched_network_syscall_record_is_reported_as_unknown(self):
        events = parse_trace_lines([
            '<... connect resumed> = -1 ECONNREFUSED (Connection refused)',
        ])

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "unknown")
        result = check_trace(
            events,
            case="pinned-endpoint",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            required_destinations=["192.0.2.10:443"],
        )
        self.assertFalse(result["passed"], result)
        self.assertIn("unknown network syscall connect", result["violations"])

    def test_preselection_rejects_proxy_activity_too(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(1080), '
            'sin_addr=inet_addr("198.51.100.9")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="fresh-empty",
            phase="preselection",
            allowed_destinations=[],
            allowed_dns=[],
            allowed_proxies=["198.51.100.9:1080"],
        )

        self.assertFalse(result["passed"], result)

    def test_preselection_rejects_case_destination_allowlist(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(19081), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="canceled-selection",
            phase="preselection",
            allowed_destinations=["127.0.0.1:19081"],
            allowed_dns=[],
            required_destinations=["127.0.0.1:19081"],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn(
            "preselection cannot allow network destinations",
            " ".join(result["violations"]),
        )

    def test_public_discovery_allows_only_resolver_and_origin(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3',
            'sendto(3, "dns", 3, MSG_NOSIGNAL, {sa_family=AF_INET, '
            'sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, '
            '16) = 3',
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("203.0.113.10")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="public-selection",
            phase="public-discovery",
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=["127.0.0.53:53"],
            allowed_origins=[
                "https://public.example/.well-known/telegramd/client",
            ],
            required_destinations=["203.0.113.10:443"],
            required_dns=["127.0.0.53:53"],
            resolution_evidence=public_fixture_evidence(
                "https://public.example/.well-known/telegramd/client",
                "public.example",
            ),
        )

        self.assertTrue(result["passed"], result)

    def test_public_fixture_binds_proxy_target_to_resolution(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(19444), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="public-selection",
            phase="public-discovery",
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=[],
            allowed_origins=[
                "https://public.example/.well-known/telegramd/client",
            ],
            allowed_proxies=["127.0.0.1:19444"],
            required_destinations=["203.0.113.10:443"],
            required_proxies=["127.0.0.1:19444"],
            proxy_target="203.0.113.10:443",
            proxy_target_proven=True,
            resolution_evidence=public_fixture_evidence(
                "https://public.example/.well-known/telegramd/client",
                "public.example",
            ),
        )

        self.assertTrue(result["passed"], result)

    def test_public_discovery_requires_observed_resolution_evidence(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3',
            'sendto(3, "dns", 3, MSG_NOSIGNAL, {sa_family=AF_INET, '
            'sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, '
            '16) = 3',
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("203.0.113.10")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="public-selection",
            phase="public-discovery",
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=["127.0.0.53:53"],
            allowed_origins=[
                "https://public.example/.well-known/telegramd/client",
            ],
            required_destinations=["203.0.113.10:443"],
            required_dns=["127.0.0.53:53"],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn(
            "resolution evidence",
            " ".join(result["violations"]),
        )

    def test_public_resolution_evidence_requires_callback_result(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3',
            'sendto(3, "dns", 3, MSG_NOSIGNAL, {sa_family=AF_INET, '
            'sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, '
            '16) = 3',
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("203.0.113.10")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="public-selection",
            phase="public-discovery",
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=["127.0.0.53:53"],
            allowed_origins=[
                "https://public.example/.well-known/telegramd/client",
            ],
            required_destinations=["203.0.113.10:443"],
            required_dns=["127.0.0.53:53"],
            resolution_evidence={
                "origin": "https://public.example/.well-known/telegramd/client",
                "destinations": ["203.0.113.10:443"],
            },
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("fixture", " ".join(result["violations"]))

    def test_proxy_proof_requires_observed_socks_exchange(self):
        with tempfile.TemporaryDirectory() as directory:
            proof = Path(directory) / "proxy-proof.json"
            proof.write_text(
                '{"protocol":"SOCKS5","version":5,"command":"CONNECT",'
                '"target":"192.0.2.10:443","observed":true}\n',
                encoding="utf-8",
            )
            self.assertTrue(
                _proxy_target_proven(str(proof), "192.0.2.10:443"),
            )

            proof.write_text(
                "192.0.2.10:443\n",
                encoding="utf-8",
            )
            self.assertFalse(
                _proxy_target_proven(str(proof), "192.0.2.10:443"),
            )

    def test_selected_failure_requires_two_traced_attempts(self):
        parser = Path(__file__).resolve().parent / "network_trace.py"
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace"
            trace.write_text(
                'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3\n'
                'connect(3, {sa_family=AF_INET, sin_port=htons(19083), '
                'sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED\n',
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(parser),
                    "--trace",
                    str(trace),
                    "--case",
                    "selected-endpoint-failure",
                    "--phase",
                    "pinned-endpoint",
                    "--allow-destination",
                    "127.0.0.1:19083",
                    "--require-destination",
                    "127.0.0.1:19083",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("post-commit", result.stderr + result.stdout)

    def test_selected_endpoint_failure_is_correlated_to_trace(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(19083), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET, sin_port=htons(19083), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS',
            'getsockopt(4, SOL_SOCKET, SO_ERROR, [ECONNREFUSED], [4]) = 0',
        ])

        result = check_trace(
            events,
            case="selected-endpoint-failure",
            phase="pinned-endpoint",
            allowed_destinations=["127.0.0.1:19083"],
            allowed_dns=[],
            required_destinations=["127.0.0.1:19083"],
        )

        self.assertTrue(result["passed"], result)
        self.assertTrue(result["selected_endpoint_failure"]["observed"])
        self.assertEqual(
            result["selected_endpoint_failure"]["post_commit_result"],
            "ECONNREFUSED",
        )

        only_preflight = check_trace(
            events[:2],
            case="selected-endpoint-failure",
            phase="pinned-endpoint",
            allowed_destinations=["127.0.0.1:19083"],
            allowed_dns=[],
            required_destinations=["127.0.0.1:19083"],
        )
        self.assertFalse(only_preflight["passed"], only_preflight)
        self.assertIn(
            "post-commit selected endpoint failure not observed in trace",
            only_preflight["violations"],
        )

    def test_pinned_lifecycle_cases_require_post_commit_contact(self):
        one_attempt = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(19082), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
        ])
        two_attempts = one_attempt + parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET, sin_port=htons(19082), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
        ])

        for case in (
            "pinned-endpoint",
            "restart-pinned",
            "multiple-account-isolation",
            "background-refresh",
        ):
            with self.subTest(case=case):
                rejected = check_trace(
                    one_attempt,
                    case=case,
                    phase="pinned-endpoint",
                    allowed_destinations=["127.0.0.1:19082"],
                    allowed_dns=[],
                    required_destinations=["127.0.0.1:19082"],
                )
                self.assertFalse(rejected["passed"], rejected)
                self.assertIn(
                    "post-commit selected endpoint contact not observed in trace",
                    rejected["violations"],
                )
                accepted = check_trace(
                    two_attempts,
                    case=case,
                    phase="pinned-endpoint",
                    allowed_destinations=["127.0.0.1:19082"],
                    allowed_dns=[],
                    required_destinations=["127.0.0.1:19082"],
                )
                self.assertTrue(accepted["passed"], accepted)

    def test_public_failure_rejects_direct_fallback(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED',
        ])

        result = check_trace(
            events,
            case="public-failure",
            phase="public-discovery",
            allowed_destinations=[],
            allowed_dns=["127.0.0.53:53"],
            allowed_origins=[
                "https://public-failure.invalid/.well-known/telegramd/client",
            ],
            resolution_evidence=public_fixture_evidence(
                "https://public-failure.invalid/.well-known/telegramd/client",
                "public-failure.invalid",
            ),
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("127.0.0.1:443", " ".join(result["violations"]))

    def test_public_failure_without_fallback_passes(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(19444), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="public-failure",
            phase="public-discovery",
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=[],
            allowed_origins=[
                "https://public-failure.invalid/.well-known/telegramd/client",
            ],
            allowed_proxies=["127.0.0.1:19444"],
            required_destinations=["203.0.113.10:443"],
            required_proxies=["127.0.0.1:19444"],
            proxy_target="203.0.113.10:443",
            proxy_target_proven=True,
            resolution_evidence=public_fixture_evidence(
                "https://public-failure.invalid/.well-known/telegramd/client",
                "public-failure.invalid",
            ),
        )

        self.assertTrue(result["passed"], result)

    def test_public_discovery_requires_observed_origin_contact(self):
        result = check_trace(
            [],
            case="public-selection",
            phase="public-discovery",
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=["127.0.0.53:53"],
            allowed_origins=[
                "https://public.example/.well-known/telegramd/client",
            ],
            required_destinations=["203.0.113.10:443"],
            required_dns=["127.0.0.53:53"],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("required destination", " ".join(result["violations"]))

    def test_public_discovery_does_not_use_configured_proxy(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(1080), '
            'sin_addr=inet_addr("198.51.100.9")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="public-selection",
            phase="public-discovery",
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=[],
            allowed_origins=[
                "https://public.example/.well-known/telegramd/client",
            ],
            allowed_proxies=["198.51.100.9:1080"],
        )

        self.assertFalse(result["passed"], result)

    def test_local_preflight_and_pinned_endpoint_are_explicit(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("192.0.2.10")}, 16) = 0',
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("192.0.2.10")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="local-preflight",
            phase="local-direct",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            required_destinations=["192.0.2.10:443"],
        )

        self.assertTrue(result["passed"], result)

    def test_local_preflight_does_not_use_configured_proxy(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(1080), '
            'sin_addr=inet_addr("198.51.100.9")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="local-preflight",
            phase="local-direct",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            allowed_proxies=["198.51.100.9:1080"],
        )

        self.assertFalse(result["passed"], result)

    def test_unknown_network_destination_fails_closed(self):
        events = parse_trace_lines([
            'socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET6, sin6_port=htons(443), '
            'sin6_addr=inet_pton(AF_INET6, "2001:db8::10")}, 28) = 0',
        ])

        result = check_trace(
            events,
            case="pinned-endpoint",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            required_destinations=["192.0.2.10:443"],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("[2001:db8::10]:443", " ".join(result["violations"]))

    def test_ipv4_mapped_ipv6_matches_ipv4_allowlist(self):
        events = parse_trace_lines([
            'socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET6, sin6_port=htons(443), '
            'sin6_addr=inet_pton(AF_INET6, "::ffff:192.0.2.10")}, 28) = 0',
            'socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET6, sin6_port=htons(443), '
            'sin6_addr=inet_pton(AF_INET6, "::ffff:192.0.2.10")}, 28) = 0',
        ])

        result = check_trace(
            events,
            case="pinned-endpoint",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            required_destinations=["192.0.2.10:443"],
        )

        self.assertTrue(result["passed"], result)

    def test_unknown_network_family_fails_closed(self):
        events = parse_trace_lines([
            'socket(AF_PACKET, SOCK_RAW|SOCK_CLOEXEC, htons(0x0800)) = 3',
        ])

        result = check_trace(
            events,
            case="fresh-empty",
            phase="preselection",
            allowed_destinations=[],
            allowed_dns=[],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("unknown network family", " ".join(result["violations"]))

    def test_resolver_unix_socket_is_not_ignored(self):
        events = parse_trace_lines([
            'socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3',
            'connect(3, {sa_family=AF_UNIX, '
            'sun_path="/run/systemd/resolve/io.systemd.Resolve"}, 52) = 0',
        ])

        result = check_trace(
            events,
            case="fresh-empty",
            phase="preselection",
            allowed_destinations=[],
            allowed_dns=[],
        )

        self.assertFalse(result["passed"], result)

    def test_resolver_unix_socket_can_be_explicit_dns_evidence(self):
        events = parse_trace_lines([
            'socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3',
            'connect(3, {sa_family=AF_UNIX, '
            'sun_path="/run/systemd/resolve/io.systemd.Resolve"}, 52) = 0',
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("203.0.113.10")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="public-selection",
            phase="public-discovery",
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=["unix:/run/systemd/resolve/io.systemd.Resolve"],
            allowed_origins=[
                "https://public.example/.well-known/telegramd/client",
            ],
            required_destinations=["203.0.113.10:443"],
            required_dns=["unix:/run/systemd/resolve/io.systemd.Resolve"],
            resolution_evidence=public_fixture_evidence(
                "https://public.example/.well-known/telegramd/client",
                "public.example",
            ),
        )

        self.assertTrue(result["passed"], result)

    def test_socket_without_destination_fails_closed(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
        ])

        result = check_trace(
            events,
            case="pinned-endpoint",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            required_destinations=["192.0.2.10:443"],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("fd=3", " ".join(result["violations"]))

    def test_proxy_is_only_an_explicit_transport_intermediary(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("192.0.2.10")}, 16) = 0',
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET, sin_port=htons(1080), '
            'sin_addr=inet_addr("198.51.100.9")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="proxy-intermediary",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            allowed_proxies=["198.51.100.9:1080"],
            required_destinations=["192.0.2.10:443"],
            required_proxies=["198.51.100.9:1080"],
            proxy_target="192.0.2.10:443",
            proxy_target_proven=True,
        )

        self.assertTrue(result["passed"], result)
        self.assertEqual(
            result["allowlist"]["proxies"],
            ["198.51.100.9:1080"],
        )

        unlisted = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("203.0.113.99")}, 16) = 0',
        ])
        rejected = check_trace(
            unlisted,
            case="proxy-intermediary",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            allowed_proxies=["198.51.100.9:1080"],
        )

        self.assertFalse(rejected["passed"], rejected)

    def test_payload_text_cannot_supply_the_destination(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP) = 3',
            'sendto(3, "inet_addr(\\"203.0.113.10\\")", 30, 0, '
            '{sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("198.51.100.10")}, 16) = 30',
        ])

        result = check_trace(
            events,
            case="pinned-endpoint",
            phase="pinned-endpoint",
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=[],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("198.51.100.10:443", " ".join(result["violations"]))
        self.assertNotIn("line", result["events"][0])

    def test_sendmsg_payload_cannot_supply_msg_name(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP) = 3',
            'sendmsg(3, {msg_name={sa_family=AF_INET, '
            'sin_port=htons(443), sin_addr=inet_addr("198.51.100.10")}, '
            'msg_namelen=16, msg_iov=[{iov_base="msg_name={sa_family=AF_INET, '
            'sin_port=htons(443), sin_addr=inet_addr(203.0.113.10)}", '
            'iov_len=30}]}, 0) = 30',
        ])

        result = check_trace(
            events,
            case="pinned-endpoint",
            phase="pinned-endpoint",
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=[],
            required_destinations=["203.0.113.10:443"],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("198.51.100.10:443", " ".join(result["violations"]))

    def test_empty_endpoint_trace_fails_closed(self):
        result = check_trace(
            [],
            case="pinned-endpoint",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            required_destinations=["192.0.2.10:443"],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("required destination", " ".join(result["violations"]))

    def test_hostname_allowlist_is_rejected(self):
        result = check_trace(
            [],
            case="fresh-empty",
            phase="preselection",
            allowed_destinations=["telegram.example:443"],
            allowed_dns=[],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("invalid destination allowlist", " ".join(result["violations"]))

    def test_proxy_target_proof_replaces_process_target_connect(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("192.0.2.10")}, 16) = 0',
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET, sin_port=htons(1080), '
            'sin_addr=inet_addr("198.51.100.9")}, 16) = 0',
        ])

        result = check_trace(
            events,
            case="proxy-intermediary",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            allowed_proxies=["198.51.100.9:1080"],
            required_destinations=["192.0.2.10:443"],
            required_proxies=["198.51.100.9:1080"],
            proxy_target="192.0.2.10:443",
            proxy_target_proven=True,
        )

        self.assertTrue(result["passed"], result)

        unproven = check_trace(
            events,
            case="proxy-intermediary",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            allowed_proxies=["198.51.100.9:1080"],
            required_destinations=["192.0.2.10:443"],
            required_proxies=["198.51.100.9:1080"],
            proxy_target="192.0.2.10:443",
        )

        self.assertFalse(unproven["passed"], unproven)

    def test_proxy_route_requires_preflight_before_account_proxy(self):
        def report(lines):
            return check_trace(
                parse_trace_lines(lines),
                case="proxy-intermediary",
                phase="pinned-endpoint",
                allowed_destinations=["192.0.2.10:443"],
                allowed_dns=[],
                allowed_proxies=["198.51.100.9:1080"],
                required_destinations=["192.0.2.10:443"],
                required_proxies=["198.51.100.9:1080"],
                proxy_target="192.0.2.10:443",
                proxy_target_proven=True,
            )

        missing_preflight = report([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4',
            'connect(4, {sa_family=AF_INET, sin_port=htons(1080), '
            'sin_addr=inet_addr("198.51.100.9")}, 16) = 0',
        ])
        self.assertFalse(missing_preflight["passed"], missing_preflight)
        self.assertFalse(
            missing_preflight["proxy_route"]["observed"],
            missing_preflight,
        )

        missing_account_proxy = report([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
            'connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("192.0.2.10")}, 16) = 0',
        ])
        self.assertFalse(missing_account_proxy["passed"], missing_account_proxy)
        self.assertFalse(
            missing_account_proxy["proxy_route"]["observed"],
            missing_account_proxy,
        )

    def test_public_origin_must_be_normalized_https_discovery_url(self):
        result = check_trace(
            [],
            case="public-selection",
            phase="public-discovery",
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=["127.0.0.53:53"],
            allowed_origins=["http://public.example/"],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("origin", " ".join(result["violations"]))

    def test_file_descriptor_allowlist_is_scoped_to_process(self):
        events = parse_trace_lines([
            '101 1.000 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3',
            '101 1.001 connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("192.0.2.10")}, 16) = 0',
            '202 1.002 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3',
        ])

        result = check_trace(
            events,
            case="multiple-account-isolation",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("fd=3", " ".join(result["violations"]))

    def test_socket_identity_can_cross_worker_thread_trace_files(self):
        events = parse_trace_lines([
            '101 1.000 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = '
            '3<TCP:[12345]>',
            '202 1.001 connect(3<TCP:[12345]>, {sa_family=AF_INET, '
            'sin_port=htons(443), sin_addr=inet_addr("192.0.2.10")}, '
            '16) = 0',
            '101 1.002 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = '
            '4<TCP:[23456]>',
            '202 1.003 connect(4<TCP:[23456]>, {sa_family=AF_INET, '
            'sin_port=htons(443), sin_addr=inet_addr("192.0.2.10")}, '
            '16) = 0',
        ])

        result = check_trace(
            events,
            case="pinned-endpoint",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
            required_destinations=["192.0.2.10:443"],
        )

        self.assertTrue(result["passed"], result)

    def test_trace_files_are_merged_by_observer_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            later = Path(directory) / "trace.1"
            earlier = Path(directory) / "trace.2"
            later.write_text(
                '100.200 connect(3, {sa_family=AF_INET, '
                'sin_port=htons(19083), sin_addr=inet_addr("127.0.0.1")}, '
                '16) = 0\n',
                encoding="utf-8",
            )
            earlier.write_text(
                '100.100 connect(4, {sa_family=AF_INET, '
                'sin_port=htons(19082), sin_addr=inet_addr("127.0.0.1")}, '
                '16) = 0\n',
                encoding="utf-8",
            )

            events = _read_trace([later, earlier])

        self.assertEqual(
            [event.destination for event in events],
            ["127.0.0.1:19082", "127.0.0.1:19083"],
        )

    def test_debug_driver_uses_production_lifecycle_paths(self):
        source_path = (
            Path(__file__).resolve().parents[1]
            / "SourceFiles"
            / "test"
            / "test_scenario.cpp"
        )
        source = source_path.read_text(encoding="utf-8")
        for required in (
            '"core/application.h"',
            '"core/update_checker.h"',
            '"intro/intro_server_discovery.h"',
            '"main/main_account.h"',
            '"main/main_domain.h"',
            '"main/main_app_config.h"',
            '"lang/lang_cloud_manager.h"',
            '"mtproto/mtproto_server_enrollment.h"',
            "Core::App().domain()",
            "ServerWidgetDiscovery",
            "QNetworkAccessManager",
            "CommitServerEnrollment",
            "appConfig().refresh",
            "langCloudManager",
            "requestLangPackDifference",
            "requestCDNConfig",
            "requestConfigIfOld",
            "UpdateChecker",
            "domainPtr = &domain",
            "_localServer->close()",
        ):
            self.assertIn(required, source)
        self.assertNotIn("WriteBinding", source)
        self.assertNotIn("ReadBinding", source)
        self.assertNotIn("WriteResolutionEvidence", source)
        self.assertNotIn("WriteSelectedFailureEvidence", source)

    def test_runner_fixture_records_observed_https_and_socks_evidence(self):
        fixture_root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certificate = root / "certificate.pem"
            key = root / "key.pem"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-nodes", "-days", "1", "-subj", "/CN=public.example",
                    "-addext",
                    "subjectAltName=DNS:public.example,DNS:public-failure.invalid",
                    "-keyout", str(key), "-out", str(certificate),
                ],
                check=True,
                capture_output=True,
            )
            proxy_port = self._free_port()
            https_port = self._free_port()
            proof = root / "proxy-proof.json"
            resolution = root / "resolution-proof.json"
            ready = root / "ready"
            fixture = PublicFixture(
                certificate=certificate,
                key=key,
                response=(
                    fixture_root / "network_trace_fixtures"
                    / "public-discovery.json"
                ).read_bytes(),
                proof=proof,
                resolution_proof=resolution,
                proxy_port=proxy_port,
                https_port=https_port,
                ready=ready,
            )
            server = threading.Thread(target=fixture.run, daemon=True)
            server.start()
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "fixture did not start")
                for host, expected_status in (
                    ("public.example", b"200 OK"),
                    ("public-failure.invalid", b"503 Service Unavailable"),
                ):
                    response = self._https_through_fixture(host, proxy_port)
                    self.assertIn(expected_status, response.split(b"\r\n", 1)[0])
                    observed = json.loads(resolution.read_text(encoding="utf-8"))
                    self.assertEqual(observed["host"], host)
                    self.assertEqual(
                        observed["origin"],
                        f"https://{host}/.well-known/telegramd/client",
                    )
                    self.assertEqual(
                        observed["request_path"],
                        "/.well-known/telegramd/client",
                    )
                    self.assertEqual(
                        observed["proxy_target"], "203.0.113.10:443"
                    )
                    self.assertTrue(observed["observed"])
                    self.assertEqual(
                        json.loads(proof.read_text(encoding="utf-8")),
                        {
                            "protocol": "SOCKS5",
                            "version": 5,
                            "command": "CONNECT",
                            "target": "203.0.113.10:443",
                            "observed": True,
                        },
                    )
            finally:
                fixture.stop()
                server.join(timeout=2)
                self.assertFalse(server.is_alive(), "fixture did not stop")

    def test_runner_socks_fixture_proves_and_relays_account_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            target.bind(("127.0.0.1", 0))
            target.listen(1)
            target.settimeout(5)
            target_port = target.getsockname()[1]
            expected_target = f"127.0.0.1:{target_port}"

            def echo_target():
                peer, _ = target.accept()
                with peer:
                    peer.sendall(peer.recv(4)[::-1])

            echo = threading.Thread(target=echo_target, daemon=True)
            echo.start()
            proof = root / "proxy-proof.json"
            ready = root / "ready"
            proxy_port = self._free_port()
            fixture = SocksFixture(
                proof=proof,
                expected_target=expected_target,
                port=proxy_port,
                ready=ready,
            )
            server = threading.Thread(target=fixture.run, daemon=True)
            server.start()
            client = None
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "SOCKS fixture did not start")
                client = socket.create_connection(("127.0.0.1", proxy_port), 5)
                client.settimeout(5)
                client.sendall(b"\x05\x01\x00")
                self.assertEqual(client.recv(2), b"\x05\x00")
                client.sendall(
                    b"\x05\x01\x00\x01"
                    + socket.inet_aton("127.0.0.1")
                    + target_port.to_bytes(2, "big")
                )
                self.assertEqual(self._receive_exact(client, 10)[:2], b"\x05\x00")
                client.sendall(b"ping")
                self.assertEqual(self._receive_exact(client, 4), b"gnip")
                self.assertEqual(
                    json.loads(proof.read_text(encoding="utf-8")),
                    {
                        "protocol": "SOCKS5",
                        "version": 5,
                        "command": "CONNECT",
                        "target": expected_target,
                        "observed": True,
                    },
                )
            finally:
                if client:
                    client.close()
                fixture.stop()
                server.join(timeout=2)
                target.close()
                echo.join(timeout=2)
                self.assertFalse(server.is_alive(), "SOCKS fixture did not stop")

    @staticmethod
    def _free_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return listener.getsockname()[1]

    @staticmethod
    def _receive_exact(peer, size):
        result = bytearray()
        while len(result) < size:
            chunk = peer.recv(size - len(result))
            if not chunk:
                raise AssertionError("fixture peer closed early")
            result.extend(chunk)
        return bytes(result)

    @staticmethod
    def _https_through_fixture(host, proxy_port):
        proxy = socket.create_connection(("127.0.0.1", proxy_port), 5)
        proxy.settimeout(5)
        proxy.sendall(b"\x05\x01\x00")
        if proxy.recv(2) != b"\x05\x00":
            raise AssertionError("SOCKS5 greeting was rejected")
        encoded_host = host.encode("ascii")
        proxy.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(encoded_host)])
            + encoded_host
            + b"\x01\xbb"
        )
        reply = bytearray()
        while len(reply) < 10:
            chunk = proxy.recv(10 - len(reply))
            if not chunk:
                raise AssertionError("SOCKS5 CONNECT was not accepted")
            reply.extend(chunk)
        if reply[:2] != b"\x05\x00":
            raise AssertionError("SOCKS5 CONNECT was rejected")
        context = ssl._create_unverified_context()
        with context.wrap_socket(proxy, server_hostname=host) as secure:
            secure.sendall(
                b"GET /.well-known/telegramd/client HTTP/1.1\r\n"
                + b"Host: " + host.encode("ascii") + b"\r\n"
                + b"Connection: close\r\n\r\n"
            )
            response = bytearray()
            while True:
                chunk = secure.recv(4096)
                if not chunk:
                    return bytes(response)
                response.extend(chunk)


if __name__ == "__main__":
    unittest.main()
