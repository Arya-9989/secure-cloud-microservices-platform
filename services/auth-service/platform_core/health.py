"""Liveness and readiness probes (plain Django views: no auth, no throttling)."""

from __future__ import annotations

import logging

from django.db import connection
from django.http import HttpRequest, JsonResponse

logger = logging.getLogger(__name__)


def liveness(request: HttpRequest) -> JsonResponse:
    """The process is up and serving requests. Never touches dependencies."""
    return JsonResponse({"status": "UP"})


def readiness(request: HttpRequest) -> JsonResponse:
    """Ready to take traffic: the database answers and the signing key is loadable."""
    from accounts.keys import get_key_set  # local import: keep platform_core app-agnostic

    checks: dict[str, str] = {}
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        checks["database"] = "UP"
    except Exception:
        logger.exception("Readiness check failed: database")
        checks["database"] = "DOWN"
    try:
        get_key_set()
        checks["signing_key"] = "UP"
    except Exception:
        logger.exception("Readiness check failed: signing key")
        checks["signing_key"] = "DOWN"

    healthy = all(value == "UP" for value in checks.values())
    return JsonResponse(
        {"status": "UP" if healthy else "DOWN", "checks": checks}, status=200 if healthy else 503
    )
