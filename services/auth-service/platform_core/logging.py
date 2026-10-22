"""Structured (JSON) logging that stamps every record with the request correlation ID."""

from __future__ import annotations

import logging
from typing import Any

from pythonjsonlogger.json import JsonFormatter

from .request_context import request_id_var, user_id_var


class RequestContextFilter(logging.Filter):
    """Copies correlation fields from context variables onto each log record."""

    def __init__(self, service: str = "auth-service") -> None:
        super().__init__()
        self.service = service

    def filter(self, record: logging.LogRecord) -> bool:
        record.service = self.service
        record.request_id = request_id_var.get()
        record.user_id = user_id_var.get()
        return True


class PlatformJsonFormatter(JsonFormatter):
    """JSON formatter with stable field names shared with the Java services."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault(
            "fmt", "%(asctime)s %(levelname)s %(name)s %(message)s %(service)s %(request_id)s"
        )
        kwargs.setdefault(
            "rename_fields", {"asctime": "timestamp", "levelname": "level", "name": "logger"}
        )
        kwargs.setdefault("datefmt", "%Y-%m-%dT%H:%M:%S%z")
        super().__init__(*args, **kwargs)

    def add_fields(
        self, log_data: dict[str, Any], record: logging.LogRecord, message_dict: dict[str, Any]
    ) -> None:
        super().add_fields(log_data, record, message_dict)
        # Drop empty correlation fields (e.g. log lines emitted outside a request).
        for key in ("request_id", "user_id"):
            if log_data.get(key) is None:
                log_data.pop(key, None)
