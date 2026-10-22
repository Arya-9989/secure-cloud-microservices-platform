"""Access-token (JWT) and refresh-token lifecycle.

Access tokens are short-lived RS256 JWTs that resource servers verify offline
against the JWKS. Refresh tokens are opaque random strings, stored hashed,
rotated on every use and revocable server-side.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import jwt
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from platform_core.metrics import REFRESH_REUSE_DETECTED, TOKENS_ISSUED

from .keys import get_key_set
from .models import RefreshToken, RevocationReason, User

logger = logging.getLogger(__name__)

ALGORITHM = "RS256"
REQUIRED_CLAIMS = ("iss", "aud", "sub", "exp", "iat", "jti")


class TokenError(Exception):
    """Raised for any token that must be rejected; the message is safe to return."""


class RefreshTokenReuseError(TokenError):
    pass


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    scope: str

    def as_response(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
            "refresh_token": self.refresh_token,
            "refresh_expires_in": self.refresh_expires_in,
            "scope": self.scope,
        }


# --------------------------------------------------------------------------- access tokens


def issue_access_token(user: User, now: datetime | None = None) -> str:
    now = now or timezone.now()
    keys = get_key_set()
    claims = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "sub": str(user.pk),
        "email": user.email,
        "roles": [user.role],
        "scope": " ".join(user.scopes),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.ACCESS_TOKEN_TTL_SECONDS)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(
        claims, keys.signing.private_key, algorithm=ALGORITHM, headers={"kid": keys.signing.kid}
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """Verify signature, algorithm, issuer, audience and expiry of an access token."""
    keys = get_key_set()
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TokenError("Malformed token") from exc

    # Never trust the token's `alg` to pick the algorithm (alg=none / HS256 confusion).
    if header.get("alg") != ALGORITHM:
        raise TokenError("Unsupported token algorithm")
    public_key = keys.verification.get(str(header.get("kid")))
    if public_key is None:
        raise TokenError("Unknown signing key")

    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            leeway=settings.JWT_CLOCK_SKEW_SECONDS,
            options={"require": list(REQUIRED_CLAIMS)},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except jwt.PyJWTError as exc:
        raise TokenError("Invalid token") from exc
    return claims


# --------------------------------------------------------------------------- refresh tokens


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _new_refresh_token(
    user: User, family_id: uuid.UUID, session_expires_at: datetime, now: datetime
) -> tuple[RefreshToken, str]:
    raw = secrets.token_urlsafe(48)
    expires_at = min(
        now + timedelta(seconds=settings.REFRESH_TOKEN_TTL_SECONDS), session_expires_at
    )
    token = RefreshToken.objects.create(
        user=user,
        family_id=family_id,
        token_hash=_hash(raw),
        expires_at=expires_at,
        session_expires_at=session_expires_at,
    )
    return token, raw


def _pair(user: User, refresh: RefreshToken, raw_refresh: str, now: datetime) -> TokenPair:
    return TokenPair(
        access_token=issue_access_token(user, now),
        expires_in=settings.ACCESS_TOKEN_TTL_SECONDS,
        refresh_token=raw_refresh,
        refresh_expires_in=int((refresh.expires_at - now).total_seconds()),
        scope=" ".join(user.scopes),
    )


def issue_token_pair(user: User) -> TokenPair:
    """Start a new session (token family) for a freshly authenticated user."""
    now = timezone.now()
    session_expires_at = now + timedelta(seconds=settings.REFRESH_SESSION_MAX_SECONDS)
    refresh, raw = _new_refresh_token(user, uuid.uuid4(), session_expires_at, now)
    TOKENS_ISSUED.labels(grant_type="password").inc()
    return _pair(user, refresh, raw, now)


def _lock_family(family_id: uuid.UUID) -> None:
    """Serialise every rotation and revocation of one session family.

    Row locks on individual tokens are not enough: under READ COMMITTED a revoking
    UPDATE that waits for a concurrent rotation re-checks the locked row but never sees
    the successor token that rotation inserts, which would survive a replay. Every
    path that changes a family therefore first locks the family's oldest token, which
    always exists. (SQLite ignores FOR UPDATE but serialises writers anyway.)
    """
    root = (
        RefreshToken.objects.select_for_update()
        .filter(family_id=family_id)
        .order_by("created_at", "id")
        .values_list("pk", flat=True)
    )
    list(root[:1])


def rotate_refresh_token(raw: str) -> TokenPair:
    """Exchange a refresh token for a new pair; the presented token becomes unusable.

    Reuse of an already-rotated token revokes the whole family. The revocation is
    committed in the same transaction that holds the family lock, before the error
    is raised, so no concurrent rotation can slip a live token past it.
    """
    now = timezone.now()
    token_hash = _hash(raw)
    family_id = (
        RefreshToken.objects.filter(token_hash=token_hash)
        .values_list("family_id", flat=True)
        .first()
    )
    if family_id is None:
        raise TokenError("Invalid refresh token")

    revoked = 0
    with transaction.atomic():
        _lock_family(family_id)
        # Also locks the user row, so an admin disabling or demoting the account waits
        # for this rotation and then revokes the token it mints.
        current = (
            RefreshToken.objects.select_for_update()
            .select_related("user")
            .get(token_hash=token_hash)
        )
        if current.revoked_at is None:
            if current.expires_at <= now:
                raise TokenError("Refresh token has expired")
            if not current.user.is_active:
                raise TokenError("Account is disabled")
            replacement, new_raw = _new_refresh_token(
                current.user, current.family_id, current.session_expires_at, now
            )
            current.revoked_at = now
            current.revoked_reason = RevocationReason.ROTATED
            current.replaced_by = replacement
            current.save(update_fields=["revoked_at", "revoked_reason", "replaced_by"])
            TOKENS_ISSUED.labels(grant_type="refresh_token").inc()
            return _pair(current.user, replacement, new_raw, now)
        if current.revoked_reason != RevocationReason.ROTATED:
            raise TokenError("Refresh token has been revoked")
        # An already-rotated token was presented again: treat it as stolen.
        revoked = revoke_family(family_id, RevocationReason.REUSE_DETECTED)

    REFRESH_REUSE_DETECTED.inc()
    logger.warning(
        "Refresh token reuse detected; revoked token family",
        extra={"family_id": str(family_id), "revoked_tokens": revoked},
    )
    raise RefreshTokenReuseError("Refresh token has already been used")


def revoke_family(family_id: uuid.UUID, reason: str) -> int:
    return RefreshToken.objects.filter(family_id=family_id, revoked_at__isnull=True).update(
        revoked_at=timezone.now(), revoked_reason=reason
    )


def revoke_refresh_token(raw: str) -> None:
    """Logout: revoke the session the token belongs to. Unknown tokens are ignored."""
    family_id = (
        RefreshToken.objects.filter(token_hash=_hash(raw))
        .values_list("family_id", flat=True)
        .first()
    )
    if family_id is not None:
        with transaction.atomic():
            _lock_family(family_id)  # see _lock_family: no rotation can outlive the logout
            revoke_family(family_id, RevocationReason.LOGOUT)


def revoke_all_for_user(user: User, reason: str) -> int:
    return RefreshToken.objects.filter(user=user, revoked_at__isnull=True).update(
        revoked_at=timezone.now(), revoked_reason=reason
    )
