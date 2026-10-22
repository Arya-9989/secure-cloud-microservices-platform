from __future__ import annotations

from typing import Any

from rest_framework.permissions import BasePermission
from rest_framework.request import Request


class HasScope(BasePermission):
    """Grants access when the access token carries ``view.required_scope``."""

    def has_permission(self, request: Request, view: Any) -> bool:
        required: str | None = getattr(view, "required_scope", None)
        claims = request.auth
        if required is None or not isinstance(claims, dict):
            return False
        return required in str(claims.get("scope", "")).split()
