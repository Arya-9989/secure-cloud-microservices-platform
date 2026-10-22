"""Prometheus metrics.

Metric and label names deliberately mirror Spring Boot / Micrometer
(`http_server_requests_seconds{method,uri,status}`) so one Grafana query works
for every service regardless of language.

Under gunicorn the metrics are aggregated across worker processes with
prometheus_client's multiprocess mode and served by the gunicorn master on a
separate, internal-only port (see gunicorn.conf.py).
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

HTTP_REQUESTS = Histogram(
    "http_server_requests_seconds",
    "HTTP server request latency.",
    labelnames=("method", "uri", "status"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

LOGIN_ATTEMPTS = Counter(
    "auth_login_attempts",
    "Password login attempts by outcome.",
    labelnames=("outcome",),
)

TOKENS_ISSUED = Counter(
    "auth_tokens_issued",
    "Access/refresh token pairs issued, by grant type.",
    labelnames=("grant_type",),
)

REFRESH_REUSE_DETECTED = Counter(
    "auth_refresh_token_reuse_detected",
    "Replayed (already rotated) refresh tokens; each one revokes the whole token family.",
)
