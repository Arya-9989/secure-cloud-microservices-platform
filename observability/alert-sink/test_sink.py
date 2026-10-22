"""Unit tests for the local alert sink, against a real server on an ephemeral port."""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from typing import Any

import httpx
import pytest
import sink

CRLF = "\r\n"


@pytest.fixture
def server() -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), sink.make_handler(sink.Store(limit=3)))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def webhook(alertname: str, status: str = "firing") -> dict[str, Any]:
    return {
        "version": "4",
        "status": status,
        "receiver": "pager",
        "alerts": [{"status": status, "labels": {"alertname": alertname}}],
    }


def test_records_notifications_per_receiver(server: str) -> None:
    assert httpx.post(f"{server}/pager", json=webhook("TargetDown")).status_code == 200
    assert httpx.post(f"{server}/security", json=webhook("RefreshTokenReuse")).status_code == 200

    everything = httpx.get(f"{server}/notifications").json()
    pager = httpx.get(f"{server}/notifications", params={"receiver": "pager"}).json()

    assert [n["receiver"] for n in everything] == ["pager", "security"]
    assert [n["payload"]["alerts"][0]["labels"]["alertname"] for n in pager] == ["TargetDown"]
    assert pager[0]["received_at"]


def test_keeps_only_the_newest_notifications(server: str) -> None:
    for name in ("a", "b", "c", "d"):
        httpx.post(f"{server}/platform", json=webhook(name))

    kept = httpx.get(f"{server}/notifications").json()

    assert [n["payload"]["alerts"][0]["labels"]["alertname"] for n in kept] == ["b", "c", "d"]


@pytest.mark.parametrize(
    ("path", "body", "status"),
    [
        ("/pager", b"not json", 400),
        ("/pager", json.dumps({"alerts": "nope"}).encode(), 400),
        ("/pager", json.dumps([1, 2]).encode(), 400),
        ("/pager", b"", 400),
        ("/../etc/passwd", json.dumps(webhook("x")).encode(), 404),
        ("/Pager", json.dumps(webhook("x")).encode(), 404),
    ],
)
def test_rejects_malformed_requests(server: str, path: str, body: bytes, status: int) -> None:
    response = httpx.post(
        f"{server}{path}", content=body, headers={"Content-Type": "application/json"}
    )

    assert response.status_code == status
    assert httpx.get(f"{server}/notifications").json() == []


def test_rejects_oversized_bodies_without_reading_them(server: str) -> None:
    host, port = server.removeprefix("http://").split(":")
    request = CRLF.join(
        [
            "POST /pager HTTP/1.1",
            f"Host: {host}",
            "Content-Type: application/json",
            f"Content-Length: {sink.MAX_BODY_BYTES + 1}",
            "",
            "{}",
        ]
    )
    with socket.create_connection((host, int(port)), timeout=5) as conn:
        conn.sendall(request.encode())
        status_line = conn.recv(1024).split(CRLF.encode(), 1)[0]

    assert status_line == b"HTTP/1.0 413 Request Entity Too Large"
    assert httpx.get(f"{server}/notifications").json() == []


def test_health(server: str) -> None:
    assert httpx.get(f"{server}/healthz").json() == {"status": "UP"}
