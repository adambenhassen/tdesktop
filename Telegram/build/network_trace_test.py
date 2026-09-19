#!/usr/bin/env python3

import unittest
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from network_trace import (
    _proxy_target_proven,
    check_trace,
    parse_trace_lines,
)


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

    def test_preselection_can_bind_a_live_case_destination(self):
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

        self.assertTrue(result["passed"], result)

        rejected = check_trace(
            parse_trace_lines([
                'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, '
                'IPPROTO_TCP) = 4',
                'connect(4, {sa_family=AF_INET, sin_port=htons(19082), '
                'sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
            ]),
            case="canceled-selection",
            phase="preselection",
            allowed_destinations=["127.0.0.1:19081"],
            allowed_dns=[],
            required_destinations=["127.0.0.1:19081"],
        )
        self.assertFalse(rejected["passed"], rejected)

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
            resolution_evidence={
                "origin": "https://public.example/.well-known/telegramd/client",
                "host": "public.example",
                "error": "NoError",
                "addresses": ["203.0.113.10"],
                "destinations": ["203.0.113.10:443"],
            },
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
        self.assertIn("callback", " ".join(result["violations"]))

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
            resolution_evidence={
                "origin": "https://public-failure.invalid/.well-known/telegramd/client",
                "host": "public-failure.invalid",
                "error": "HostNotFound",
                "addresses": [],
                "destinations": [],
            },
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("127.0.0.1:443", " ".join(result["violations"]))

    def test_public_failure_without_fallback_passes(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3',
            'sendto(3, "dns", 3, MSG_NOSIGNAL, {sa_family=AF_INET, '
            'sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, '
            '16) = 3',
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
            required_dns=["127.0.0.53:53"],
            resolution_evidence={
                "origin": "https://public-failure.invalid/.well-known/telegramd/client",
                "host": "public-failure.invalid",
                "error": "HostNotFound",
                "addresses": [],
                "destinations": [],
            },
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
            resolution_evidence={
                "origin": "https://public.example/.well-known/telegramd/client",
                "host": "public.example",
                "error": "NoError",
                "addresses": ["203.0.113.10"],
                "destinations": ["203.0.113.10:443"],
            },
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
            'connect(3, {sa_family=AF_INET, sin_port=htons(1080), '
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
            'connect(3, {sa_family=AF_INET, sin_port=htons(1080), '
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
            '"mtproto/mtproto_server_enrollment.h"',
            "Core::App().domain()",
            "ServerWidgetDiscovery",
            "QNetworkAccessManager",
            "CommitServerEnrollment",
            "appConfig().refresh",
            "UpdateChecker",
        ):
            self.assertIn(required, source)
        self.assertNotIn("WriteBinding", source)
        self.assertNotIn("ReadBinding", source)


if __name__ == "__main__":
    unittest.main()
