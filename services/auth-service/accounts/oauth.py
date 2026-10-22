"""OAuth 2.0 client credentials grant (RFC 6749 section 4.4) with DPoP (RFC 9449).

See docs/adr/0006-client-credentials-and-dpop.md. Errors are OAuth error responses
(RFC 6749 section 5.2), not problem documents: OAuth client libraries expect them.
"""

from __future__ import annotations

import base64
import binascii
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_plus

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password

from platform_core.metrics import TOKENS_ISSUED

from . import dpop
from .models import CLIENT_SCOPES, OAuthClient
from .tokens import issue_client_access_token

logger = logging.getLogger(__name__)

GRANT_TYPE = "client_credentials"
MAX_CREDENTIAL_LENGTH = 256

# Checked when the client id is unknown, so a miss costs as much as a wrong secret
# and response times do not reveal which client ids exist.
_DUMMY_SECRET_HASH = make_password("dummy-secret-for-constant-time-checks")


@dataclass
class OAuthError(Exception):
    error: str
    description: str
    status: int = 400
    headers: dict[str, str] = field(default_factory=dict)

    def body(self) -> dict[str, str]:
        return {"error": self.error, "error_description": self.description}


@dataclass(frozen=True)
class IssuedToken:
    access_token: str
    token_type: str
    expires_in: int
    scope: str

    def as_response(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": self.scope,
        }


def _invalid_client(description: str = "Client authentication failed") -> OAuthError:
    return OAuthError(
        "invalid_client",
        description,
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="secure-platform"'},
    )


def parse_basic_credentials(header: str) -> tuple[str, str]:
    """client_secret_basic: both parts are form-urlencoded before base64 (RFC 6749 2.3.1)."""
    scheme, _, encoded = header.partition(" ")
    if scheme.lower() != "basic" or not encoded.strip():
        raise _invalid_client("Authenticate the client with HTTP Basic (client_secret_basic)")
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise _invalid_client("Malformed Basic credentials") from exc
    client_id, sep, secret = decoded.partition(":")
    client_id, secret = unquote_plus(client_id), unquote_plus(secret)
    if not sep or not client_id or not secret:
        raise _invalid_client("Malformed Basic credentials")
    if len(client_id) > MAX_CREDENTIAL_LENGTH or len(secret) > MAX_CREDENTIAL_LENGTH:
        raise _invalid_client()
    return client_id, secret


def authenticate_client(client_id: str, secret: str) -> OAuthClient:
    client = OAuthClient.objects.filter(client_id=client_id).first()
    if client is None:
        check_password(secret, _DUMMY_SECRET_HASH)
        raise _invalid_client()
    if not client.check_secret(secret) or not client.is_active:
        raise _invalid_client()
    return client


def _requested_scopes(client: OAuthClient, scope: str | None) -> list[str]:
    allowed = [s for s in client.scopes if s in CLIENT_SCOPES]
    if not scope:
        return allowed
    requested = scope.split()
    if not requested or any(s not in allowed for s in requested):
        raise OAuthError("invalid_scope", "The requested scope is not granted to this client")
    return list(dict.fromkeys(requested))


def _audience(client: OAuthClient, resources: list[str]) -> str:
    allowed = [a for a in client.audiences if a in settings.OAUTH_RESOURCES]
    if len(resources) > 1:
        raise OAuthError("invalid_target", "Request a token for one resource at a time")
    if resources:
        if resources[0] not in allowed:
            raise OAuthError("invalid_target", "This client may not access that resource")
        return str(resources[0])
    if len(allowed) != 1:
        raise OAuthError("invalid_target", "Name the resource with the `resource` parameter")
    return str(allowed[0])


def issue_token(
    *,
    authorization: str,
    form: dict[str, list[str]],
    dpop_headers: list[str],
    method: str,
    url: str,
) -> IssuedToken:
    """Validate the whole request and issue a token; raises OAuthError for any problem."""
    for name in ("grant_type", "scope"):
        if len(form.get(name, [])) > 1:
            raise OAuthError("invalid_request", f"`{name}` must appear once")
    if form.get("client_secret") or form.get("client_id"):
        raise OAuthError(
            "invalid_request", "Send client credentials in the Authorization header only"
        )
    grant_type = (form.get("grant_type") or [""])[0]
    if grant_type != GRANT_TYPE:
        raise OAuthError("unsupported_grant_type", "Only client_credentials is supported")

    client = authenticate_client(*parse_basic_credentials(authorization))
    scope = form.get("scope")
    scopes = _requested_scopes(client, scope[0] if scope else None)
    audience = _audience(client, form.get("resource", []))

    jkt: str | None = None
    if len(dpop_headers) > 1:
        raise OAuthError("invalid_dpop_proof", "Send exactly one DPoP header")
    if dpop_headers:
        try:
            jkt = dpop.validate_proof(dpop_headers[0], method=method, url=url).jkt
        except dpop.DPoPError as exc:
            raise OAuthError(exc.error, str(exc), headers={"DPoP-Nonce": dpop.new_nonce()}) from exc
    elif client.require_dpop:
        raise OAuthError(
            "invalid_dpop_proof",
            "This client must prove possession of a key (DPoP)",
            headers={"DPoP-Nonce": dpop.new_nonce()},
        )

    token = issue_client_access_token(client.client_id, scopes, audience, jkt)
    TOKENS_ISSUED.labels(grant_type=GRANT_TYPE).inc()
    logger.info(
        "Client token issued",
        extra={"client_id": client.client_id, "audience": audience, "dpop_bound": jkt is not None},
    )
    return IssuedToken(
        access_token=token,
        token_type="DPoP" if jkt else "Bearer",
        expires_in=settings.CLIENT_TOKEN_TTL_SECONDS,
        scope=" ".join(scopes),
    )
