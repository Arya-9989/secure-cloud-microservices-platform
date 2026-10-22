"""Render every DRF error as an RFC 9457 ``application/problem+json`` document.

The Java services use Spring's ``ProblemDetail``, so clients see one error
shape across the platform.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

from rest_framework.response import Response
from rest_framework.views import exception_handler

from .request_context import request_id_var

PROBLEM_JSON = "application/problem+json"


def problem_exception_handler(exc: Exception, context: dict[str, Any]) -> Response | None:
    response = exception_handler(exc, context)
    if response is None:
        return None  # unhandled -> Django returns a generic 500 without leaking details

    status = response.status_code
    data = response.data
    problem: dict[str, Any] = {
        "type": "about:blank",
        "title": HTTPStatus(status).phrase,
        "status": status,
    }
    if isinstance(data, dict) and set(data) == {"detail"}:
        problem["detail"] = str(data["detail"])
    elif isinstance(data, dict):
        problem["detail"] = "Request validation failed."
        problem["errors"] = data
    elif isinstance(data, list):
        problem["detail"] = "; ".join(str(item) for item in data)
    if request_id := request_id_var.get():
        problem["request_id"] = request_id

    response.data = problem
    response.content_type = PROBLEM_JSON
    return response
