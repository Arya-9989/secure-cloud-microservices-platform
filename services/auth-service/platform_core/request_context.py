"""Per-request correlation context shared by middleware and the logging filter."""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar

REQUEST_ID_HEADER = "X-Request-ID"

# Accept caller-supplied IDs only if they are short and boring; anything else is
# replaced so a client cannot inject newlines or huge values into our logs.
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
user_id_var: ContextVar[str | None] = ContextVar("user_id", default=None)


def resolve_request_id(incoming: str | None) -> str:
    if incoming and _VALID_REQUEST_ID.match(incoming):
        return incoming
    return str(uuid.uuid4())
