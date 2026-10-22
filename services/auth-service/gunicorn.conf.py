"""Gunicorn configuration.

Prometheus metrics from every worker are aggregated with prometheus_client's
multiprocess mode and exposed by the *master* process on METRICS_PORT, which
is never routed through the gateway.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

# Must be set before any worker imports prometheus_client. It is scoped to the
# server process on purpose: management commands keep the default registry.
os.environ.setdefault("PROMETHEUS_MULTIPROC_DIR", "/tmp/prometheus")  # noqa: S108

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))
worker_class = "gthread"
timeout = 30
graceful_timeout = 25
keepalive = 5
# Recycle workers periodically to bound memory growth; jitter avoids a thundering herd.
max_requests = 2000
max_requests_jitter = 200
worker_tmp_dir = "/dev/shm"  # noqa: S108 - heartbeat files, avoids disk I/O stalls
accesslog = None  # one structured access-log line per request is emitted by the app
errorlog = "-"
logconfig_dict: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"ctx": {"()": "platform_core.logging.RequestContextFilter"}},
    "formatters": {"json": {"()": "platform_core.logging.PlatformJsonFormatter"}},
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "filters": ["ctx"],
            "stream": "ext://sys.stdout",
        }
    },
    "loggers": {
        "gunicorn.error": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}

METRICS_PORT = int(os.environ.get("METRICS_PORT", "9100"))


def on_starting(server: Any) -> None:
    # Stale per-process files from a previous run would corrupt the aggregates.
    path = Path(os.environ["PROMETHEUS_MULTIPROC_DIR"])
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def when_ready(server: Any) -> None:
    from prometheus_client import CollectorRegistry, multiprocess, start_http_server

    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)  # type: ignore[no-untyped-call]
    start_http_server(METRICS_PORT, registry=registry)
    server.log.info("Prometheus metrics listening on :%s", METRICS_PORT)


def child_exit(server: Any, worker: Any) -> None:
    from prometheus_client import multiprocess

    multiprocess.mark_process_dead(worker.pid)  # type: ignore[no-untyped-call]
