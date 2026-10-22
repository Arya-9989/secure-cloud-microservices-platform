#!/usr/bin/env python3
"""Local stand-in for PagerDuty / Slack: records what Alertmanager delivers.

    POST /<receiver>          Alertmanager webhook payload (JSON, at most 1 MiB)
    GET  /notifications       everything received, newest last (?receiver=pager filters)
    GET  /healthz

Notifications are kept in memory, bounded (oldest dropped first), and each one is
logged as a JSON line. Standard library only; it runs in the stock Python image.
Local and CI use only: it has no authentication and is bound to localhost.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from collections import deque
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

MAX_BODY_BYTES = 1024 * 1024
MAX_NOTIFICATIONS = int(os.environ.get("ALERT_SINK_MAX_NOTIFICATIONS", "500"))
RECEIVER = re.compile(r"^/([a-z][a-z0-9-]{0,62})$")

log = logging.getLogger("alert-sink")


class Store:
    def __init__(self, limit: int) -> None:
        self._items: deque[dict[str, Any]] = deque(maxlen=limit)
        self._lock = threading.Lock()

    def add(self, receiver: str, payload: dict[str, Any]) -> dict[str, Any]:
        item = {
            "receiver": receiver,
            "received_at": datetime.now(UTC).isoformat(),
            "payload": payload,
        }
        with self._lock:
            self._items.append(item)
        return item

    def list(self, receiver: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            return [i for i in self._items if receiver is None or i["receiver"] == receiver]


def parse_webhook(body: bytes) -> dict[str, Any]:
    """Validate the shape Alertmanager sends (version 4); raise ValueError otherwise."""
    payload = json.loads(body)
    if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
        raise ValueError("expected an Alertmanager webhook payload with an `alerts` list")
    return payload


def make_handler(store: Store) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "alert-sink"
        sys_version = ""
        timeout = 10  # seconds per socket operation: a stalled client cannot pin a thread

        def do_GET(self) -> None:  # http.server API
            url = urlsplit(self.path)
            if url.path == "/healthz":
                self._send(HTTPStatus.OK, {"status": "UP"})
            elif url.path == "/notifications":
                receiver = parse_qs(url.query).get("receiver", [None])[0]
                self._send(HTTPStatus.OK, store.list(receiver))
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:  # http.server API
            match = RECEIVER.match(urlsplit(self.path).path)
            if match is None:
                self._send(HTTPStatus.NOT_FOUND, {"error": "unknown receiver path"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length required"})
                return
            if length <= 0:
                self._send(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return
            if length > MAX_BODY_BYTES:
                self.close_connection = True  # the unread body must not be parsed as a request
                self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
                return
            try:
                payload = parse_webhook(self.rfile.read(length))
            except ValueError as exc:  # includes json.JSONDecodeError
                self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            store.add(match.group(1), payload)
            log.info(
                json.dumps(
                    {
                        "message": "notification received",
                        "receiver": match.group(1),
                        "status": payload.get("status"),
                        "alerts": [a.get("labels", {}).get("alertname") for a in payload["alerts"]],
                    }
                )
            )
            self._send(HTTPStatus.OK, {"status": "recorded"})

        def log_message(self, format: str, *args: Any) -> None:
            pass  # one JSON line per notification instead of the default access log

        def _send(self, status: HTTPStatus, body: Any) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(Store(MAX_NOTIFICATIONS)))  # noqa: S104
    log.info(json.dumps({"message": "alert-sink listening", "port": port}))
    server.serve_forever()


if __name__ == "__main__":
    main()
