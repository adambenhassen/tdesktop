#!/usr/bin/env python3

import unittest

try:
    from network_trace import check_trace, parse_trace_lines
except ImportError:
    check_trace = None
    parse_trace_lines = None


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
        self.assertEqual(result["events"], [])

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
        )

        self.assertTrue(result["passed"], result)

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
            allowed_destinations=["203.0.113.10:443"],
            allowed_dns=["127.0.0.53:53"],
            allowed_origins=[
                "https://public.example/.well-known/telegramd/client",
            ],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("127.0.0.1:443", " ".join(result["violations"]))

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
            case="local-preflight-and-bind",
            phase="local-direct",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
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
            case="bound-endpoint",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
        )

        self.assertFalse(result["passed"], result)
        self.assertIn("[2001:db8::10]:443", " ".join(result["violations"]))

    def test_socket_without_destination_fails_closed(self):
        events = parse_trace_lines([
            'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3',
        ])

        result = check_trace(
            events,
            case="late-callback",
            phase="pinned-endpoint",
            allowed_destinations=["192.0.2.10:443"],
            allowed_dns=[],
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
        )

        self.assertTrue(result["passed"], result)


if __name__ == "__main__":
    unittest.main()
