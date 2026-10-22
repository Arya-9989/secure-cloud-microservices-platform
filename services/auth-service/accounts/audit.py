"""Record security-relevant changes as AuditEvent rows (and one structured log line each).

Callers pass ids and non-sensitive details only: never passwords, tokens, secrets or
email addresses. The request supplies the source IP (honouring TRUSTED_PROXY_COUNT, as
the throttles do) and the correlation id.
"""

from __future__ import annotations

import logging
from typing import Any

from rest_framework.request import Request
from rest_framework.throttling import BaseThrottle

from platform_core.request_context import request_id_var

from .models import AuditAction, AuditEvent

logger = logging.getLogger("audit")

SYSTEM = "system"


def record(
    action: AuditAction,
    *,
    target_type: str,
    target_id: str,
    actor_id: str = SYSTEM,
    request: Request | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    source_ip = BaseThrottle().get_ident(request) if request is not None else None
    event = AuditEvent.objects.create(
        action=action,
        actor_id=actor_id,
        target_type=target_type,
        target_id=target_id,
        source_ip=source_ip or None,
        request_id=request_id_var.get() or "",
        details=details or {},
    )
    logger.info(
        "Audit event",
        extra={
            "audit_action": action.value,
            "actor_id": actor_id,
            "target": f"{target_type}:{target_id}",
            "details": event.details,
        },
    )
    return event
