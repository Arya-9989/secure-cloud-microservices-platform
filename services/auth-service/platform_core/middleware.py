"""Request correlation, access logging and HTTP metrics in a single middleware."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from django.http import HttpRequest, HttpResponse

from .metrics import HTTP_REQUESTS
from .request_context import REQUEST_ID_HEADER, request_id_var, resolve_request_id, user_id_var

access_log = logging.getLogger("access")

_QUIET_PATHS = frozenset({"/healthz", "/readyz"})


class RequestContextMiddleware:
    """Assigns/propagates X-Request-ID, records latency metrics and emits one access log line.

    The gateway forwards (or the client supplies) an ``X-Request-ID``; if it is
    missing or malformed a UUID is generated. The ID is echoed back on the
    response and attached to every log record emitted while handling the request.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request_id = resolve_request_id(request.headers.get(REQUEST_ID_HEADER))
        rid_token = request_id_var.set(request_id)
        uid_token = user_id_var.set(None)
        started = time.perf_counter()
        try:
            response = self.get_response(request)
            response[REQUEST_ID_HEADER] = request_id
            elapsed = time.perf_counter() - started
            self._record(request, response, elapsed)
            return response
        finally:
            user_id_var.reset(uid_token)
            request_id_var.reset(rid_token)

    @staticmethod
    def _record(request: HttpRequest, response: HttpResponse, elapsed: float) -> None:
        match = request.resolver_match
        uri = f"/{match.route}" if match is not None and match.route else "UNKNOWN"
        HTTP_REQUESTS.labels(
            method=request.method or "UNKNOWN", uri=uri, status=str(response.status_code)
        ).observe(elapsed)

        level = logging.DEBUG if request.path in _QUIET_PATHS else logging.INFO
        access_log.log(
            level,
            "%s %s %s",
            request.method,
            request.path,
            response.status_code,
            extra={
                "http_method": request.method,
                "http_path": request.path,
                "http_route": uri,
                "http_status": response.status_code,
                "duration_ms": round(elapsed * 1000, 2),
                "user_id": user_id_var.get(),
            },
        )
