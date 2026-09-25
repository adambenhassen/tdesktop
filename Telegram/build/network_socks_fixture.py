#!/usr/bin/env python3

"""Run a bounded SOCKS5 relay outside the traced Telegram process."""

from __future__ import annotations

import argparse
import ipaddress
import json
import select
import signal
import socket
import threading
from pathlib import Path


def _receive(peer: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = peer.recv(size - len(result))
        if not chunk:
            raise ConnectionError("SOCKS5 peer closed before the request completed")
        result.extend(chunk)
    return bytes(result)


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    host, separator, port = endpoint.rpartition(":")
    if not separator:
        raise ValueError("expected an IPv4 target and port")
    address = ipaddress.ip_address(host)
    if address.version != 4 or not 0 < int(port) <= 65535:
        raise ValueError("expected a bounded IPv4 target and port")
    return str(address), int(port)


class SocksFixture:
    def __init__(self, *, proof: Path, expected_target: str, port: int, ready: Path):
        self._proof = proof
        self._target = _split_endpoint(expected_target)
        self._target_text = f"{self._target[0]}:{self._target[1]}"
        self._port = port
        self._ready = ready
        self._stopping = threading.Event()
        self._listener: socket.socket | None = None

    def run(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self._port))
        listener.listen(8)
        listener.settimeout(0.5)
        self._listener = listener
        self._ready.touch()
        while not self._stopping.is_set():
            try:
                client, _ = listener.accept()
            except (OSError, TimeoutError):
                continue
            threading.Thread(
                target=self._handle,
                args=(client,),
                daemon=True,
            ).start()
        listener.close()

    def stop(self) -> None:
        self._stopping.set()
        if self._listener:
            self._listener.close()

    def _handle(self, client: socket.socket) -> None:
        try:
            client.settimeout(5)
            version, count = _receive(client, 2)
            methods = _receive(client, count)
            if version != 5 or 0 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x00")
            version, command, reserved, kind = _receive(client, 4)
            if kind == 1:
                address = socket.inet_ntoa(_receive(client, 4))
            elif kind == 3:
                length = _receive(client, 1)[0]
                address = _receive(client, length).decode("ascii")
            elif kind == 4:
                address = socket.inet_ntop(socket.AF_INET6, _receive(client, 16))
            else:
                return
            port = int.from_bytes(_receive(client, 2), "big")
            if (
                (version, command, reserved) != (5, 1, 0)
                or (address, port) != self._target
            ):
                client.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            upstream = socket.create_connection(self._target, timeout=5)
            with upstream:
                bound = upstream.getsockname()
                client.sendall(
                    b"\x05\x00\x00\x01"
                    + socket.inet_aton(bound[0])
                    + int(bound[1]).to_bytes(2, "big")
                )
                self._proof.write_text(
                    json.dumps(
                        {
                            "protocol": "SOCKS5",
                            "version": 5,
                            "command": "CONNECT",
                            "target": self._target_text,
                            "observed": True,
                        },
                        separators=(",", ":"),
                    ) + "\n",
                    encoding="utf-8",
                )
                self._relay(client, upstream)
        except (ConnectionError, OSError, TimeoutError, UnicodeError):
            return
        finally:
            client.close()

    @staticmethod
    def _relay(left: socket.socket, right: socket.socket) -> None:
        left.settimeout(None)
        right.settimeout(None)
        while True:
            readable, _, exceptional = select.select(
                [left, right], [], [left, right], 1.0
            )
            if exceptional:
                return
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                (right if source is left else left).sendall(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    args = parser.parse_args()
    fixture = SocksFixture(
        proof=args.proof,
        expected_target=args.expected_target,
        port=args.port,
        ready=args.ready,
    )
    signal.signal(signal.SIGTERM, lambda *_: fixture.stop())
    signal.signal(signal.SIGINT, lambda *_: fixture.stop())
    fixture.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
