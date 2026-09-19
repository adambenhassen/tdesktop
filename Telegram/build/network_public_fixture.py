#!/usr/bin/env python3

"""Serve the deterministic HTTPS public-discovery fixture.

The target connects to the SOCKS5 listener, which proves the CONNECT target is
the fixed public address while this process forwards the TLS exchange to the
repository-controlled HTTPS listener. This process is started outside strace.
"""

from __future__ import annotations

import argparse
import json
import select
import signal
import socket
import ssl
import threading
from pathlib import Path


EXPECTED_TARGET = "203.0.113.10:443"


def _receive(socket_: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = socket_.recv(size - len(result))
        if not chunk:
            raise ConnectionError("fixture peer closed the connection")
        result += chunk
    return bytes(result)


def _relay(left: socket.socket, right: socket.socket) -> None:
    peers = [left, right]
    while True:
        readable, _, _ = select.select(peers, [], [], 1.0)
        if not readable:
            continue
        for source in readable:
            data = source.recv(65536)
            if not data:
                return
            target = right if source is left else left
            target.sendall(data)


class PublicFixture:
    def __init__(
        self,
        *,
        certificate: Path,
        key: Path,
        response: bytes,
        proof: Path,
        proxy_port: int,
        https_port: int,
        ready: Path,
    ) -> None:
        self._certificate = certificate
        self._key = key
        self._response = response
        self._proof = proof
        self._proxy_port = proxy_port
        self._https_port = https_port
        self._ready = ready
        self._stop = threading.Event()
        self._listeners: list[socket.socket] = []

    def run(self) -> None:
        proxy = self._listen(self._proxy_port)
        https = self._listen(self._https_port)
        self._listeners.extend((proxy, https))
        self._ready.touch()
        threads = [
            threading.Thread(
                target=self._accept_proxy,
                args=(proxy,),
                daemon=True,
            ),
            threading.Thread(
                target=self._accept_https,
                args=(https,),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        self._stop.wait()
        for listener in self._listeners:
            listener.close()

    def stop(self) -> None:
        self._stop.set()
        for listener in self._listeners:
            listener.close()

    @staticmethod
    def _listen(port: int) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(8)
        listener.settimeout(0.5)
        return listener

    def _accept_proxy(self, listener: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                client, _ = listener.accept()
            except (OSError, TimeoutError):
                continue
            threading.Thread(
                target=self._handle_proxy,
                args=(client,),
                daemon=True,
            ).start()

    def _accept_https(self, listener: socket.socket) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self._certificate, self._key)
        while not self._stop.is_set():
            try:
                client, _ = listener.accept()
            except (OSError, TimeoutError):
                continue
            threading.Thread(
                target=self._handle_https,
                args=(context, client),
                daemon=True,
            ).start()

    def _handle_proxy(self, client: socket.socket) -> None:
        try:
            client.settimeout(5)
            version, method_count = _receive(client, 2)
            if version != 5:
                return
            methods = _receive(client, method_count)
            if 0 not in methods:
                return
            client.sendall(b"\x05\x00")
            header = _receive(client, 4)
            version, command, reserved, address_type = header
            if (version, command, reserved) != (5, 1, 0):
                return
            if address_type == 1:
                address = socket.inet_ntoa(_receive(client, 4))
            elif address_type == 3:
                length = _receive(client, 1)[0]
                address = _receive(client, length).decode("ascii")
            else:
                return
            port = int.from_bytes(_receive(client, 2), "big")
            if port != 443 or address not in {
                "public.example",
                "public-failure.invalid",
                "203.0.113.10",
            }:
                return
            target = EXPECTED_TARGET
            self._proof.write_text(
                json.dumps(
                    {
                        "protocol": "SOCKS5",
                        "version": 5,
                        "command": "CONNECT",
                        "target": target,
                        "observed": True,
                    },
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            upstream = socket.create_connection(("127.0.0.1", self._https_port), 5)
            with upstream:
                client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01")
                client.sendall(self._https_port.to_bytes(2, "big"))
                _relay(client, upstream)
        except (ConnectionError, OSError, TimeoutError):
            return
        finally:
            client.close()

    def _handle_https(
        self,
        context: ssl.SSLContext,
        client: socket.socket,
    ) -> None:
        try:
            with context.wrap_socket(client, server_side=True) as secure:
                secure.settimeout(5)
                request = bytearray()
                while b"\r\n\r\n" not in request and len(request) < 16384:
                    chunk = secure.recv(4096)
                    if not chunk:
                        return
                    request += chunk
                status = b"503 Service Unavailable" \
                    if b"public-failure.invalid" in request \
                    else b"200 OK"
                body = self._response
                response = (
                    b"HTTP/1.1 " + status + b"\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                secure.sendall(response)
        except (ConnectionError, OSError, ssl.SSLError, TimeoutError):
            return
        finally:
            client.close()


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--proxy-port", type=int, default=19444)
    parser.add_argument("--https-port", type=int, default=19443)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    fixture = PublicFixture(
        certificate=args.certificate,
        key=args.key,
        response=args.response.read_bytes(),
        proof=args.proof,
        proxy_port=args.proxy_port,
        https_port=args.https_port,
        ready=args.ready,
    )
    signal.signal(signal.SIGTERM, lambda *_: fixture.stop())
    signal.signal(signal.SIGINT, lambda *_: fixture.stop())
    fixture.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
