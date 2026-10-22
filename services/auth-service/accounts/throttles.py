"""Brute-force protection for credential endpoints.

Two independent limits apply to login: one per client IP (stops a single
source spraying many accounts) and one per target account (stops a botnet
hammering a single account from many IPs). Counters live in Django's cache,
which is the shared database cache in production so all workers and replicas
see the same counts.
"""

from __future__ import annotations

from typing import Any

from rest_framework.request import Request
from rest_framework.throttling import SimpleRateThrottle


class LoginIPThrottle(SimpleRateThrottle):
    scope = "login_ip"

    def get_cache_key(self, request: Request, view: Any) -> str:
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}


class LoginAccountThrottle(SimpleRateThrottle):
    scope = "login_account"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        email = request.data.get("email") if hasattr(request.data, "get") else None
        if not isinstance(email, str) or not email:
            return None  # validation will reject the request anyway
        return self.cache_format % {"scope": self.scope, "ident": email.strip().lower()}


class RegisterThrottle(SimpleRateThrottle):
    scope = "register"

    def get_cache_key(self, request: Request, view: Any) -> str:
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}


class RefreshThrottle(SimpleRateThrottle):
    scope = "refresh"

    def get_cache_key(self, request: Request, view: Any) -> str:
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}


class ClientTokenIPThrottle(SimpleRateThrottle):
    """Token requests per source IP, whatever client they claim to be."""

    scope = "client_token_ip"

    def get_cache_key(self, request: Request, view: Any) -> str:
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}


class ClientTokenClientThrottle(SimpleRateThrottle):
    """Token requests per claimed client id: bounds secret guessing from many IPs."""

    scope = "client_token_client"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        from .oauth import OAuthError, parse_basic_credentials

        try:
            client_id, _ = parse_basic_credentials(request.headers.get("Authorization", ""))
        except OAuthError:
            return None  # the view rejects it anyway
        return self.cache_format % {"scope": self.scope, "ident": client_id.lower()}
