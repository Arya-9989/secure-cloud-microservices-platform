"""Structured (JSON) logging that stamps every record with the request correlation ID."""

from __future__ import annotations

import logging
from typing import Any

from pythonjsonlogger.json import JsonFormatter

from .request_context import current_trace_ids, request_id_var, user_id_var


class RequestContextFilter(logging.Filter):
    """Copies correlation fields from context variables onto each log record."""

    def __init__(self, service: str = "auth-service") -> None:
        super().__init__()
        self.service = service

    def filter(self, record: logging.LogRecord) -> bool:
        record.service = self.service
        # Values passed explicitly via `extra=` win over the ambient context.
        if getattr(record, "request_id", None) is None:
            record.request_id = request_id_var.get()
        if getattr(record, "user_id", None) is None:
            record.user_id = user_id_var.get()
        if getattr(record, "trace_id", None) is None:
            record.trace_id, record.span_id = current_trace_ids()
        return True


class PlatformJsonFormatter(JsonFormatter):
    """JSON formatter using the same field names as the Java services' logstash format."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault(
            "fmt", "%(asctime)s %(levelname)s %(name)s %(message)s %(service)s %(request_id)s"
        )
        kwargs.setdefault(
            "rename_fields", {"asctime": "@timestamp", "levelname": "level", "name": "logger_name"}
        )
        kwargs.setdefault("datefmt", "%Y-%m-%dT%H:%M:%S%z")
        super().__init__(*args, **kwargs)

    def add_fields(
        self, log_data: dict[str, Any], record: logging.LogRecord, message_dict: dict[str, Any]
    ) -> None:
        super().add_fields(log_data, record, message_dict)
        # Drop empty correlation fields (e.g. log lines emitted outside a request).
        for key in ("request_id", "user_id", "trace_id", "span_id"):
            if log_data.get(key) is None:
                log_data.pop(key, None)
