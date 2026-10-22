from __future__ import annotations

import json
import logging

from platform_core.logging import PlatformJsonFormatter, RequestContextFilter
from platform_core.request_context import request_id_var, user_id_var


def _render(record: logging.LogRecord) -> dict[str, object]:
    RequestContextFilter().filter(record)
    rendered: dict[str, object] = json.loads(PlatformJsonFormatter().format(record))
    return rendered


def _record(**extra: object) -> logging.LogRecord:
    record = logging.LogRecord("accounts.views", logging.INFO, __file__, 1, "hello", None, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_log_lines_use_the_platform_schema() -> None:
    token = request_id_var.set("req-abc-123")
    try:
        line = _render(_record())
    finally:
        request_id_var.reset(token)

    assert line["message"] == "hello"
    assert line["level"] == "INFO"
    assert line["logger_name"] == "accounts.views"
    assert line["service"] == "auth-service"
    assert line["request_id"] == "req-abc-123"
    assert "@timestamp" in line
    assert "user_id" not in line  # empty correlation fields are omitted


def test_explicit_extra_fields_win_over_context() -> None:
    token = user_id_var.set("from-context")
    try:
        line = _render(_record(user_id="explicit"))
    finally:
        user_id_var.reset(token)

    assert line["user_id"] == "explicit"
