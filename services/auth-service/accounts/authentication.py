from __future__ import annotations

from typing import Any

from drf_spectacular.extensions import OpenApiAuthenticationExtension
from rest_framework import authentication, exceptions
from rest_framework.request import Request

from platform_core.request_context import user_id_var

from .models import User
from .tokens import TokenError, decode_access_token


class JWTAuthentication(authentication.BaseAuthentication):
    """Authenticates ``Authorization: Bearer <access token>`` issued by this service.

    Unlike the downstream resource servers (which trust the token until it
    expires), the issuer also checks the account is still active, so admin
    endpoints react immediately to a disabled account.
    """

    keyword = "Bearer"

    def authenticate(self, request: Request) -> tuple[User, dict[str, Any]] | None:
        header = authentication.get_authorization_header(request).decode("latin-1")
        if not header:
            return None
        scheme, _, token = header.partition(" ")
        if scheme.lower() != self.keyword.lower() or not token.strip():
            raise exceptions.AuthenticationFailed("Expected 'Authorization: Bearer <token>'")

        try:
            claims = decode_access_token(token.strip())
        except TokenError as exc:
            raise exceptions.AuthenticationFailed(str(exc)) from exc

        user = User.objects.filter(pk=claims["sub"]).first()
        if user is None or not user.is_active:
            raise exceptions.AuthenticationFailed("Account is disabled or no longer exists")

        user_id_var.set(str(user.pk))
        return user, claims

    def authenticate_header(self, request: Request) -> str:
        return f'{self.keyword} realm="secure-platform"'


class JWTAuthenticationScheme(OpenApiAuthenticationExtension):  # type: ignore[no-untyped-call]
    target_class = "accounts.authentication.JWTAuthentication"
    name = "bearerAuth"

    def get_security_definition(self, auto_schema: Any) -> dict[str, str]:
        return {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
