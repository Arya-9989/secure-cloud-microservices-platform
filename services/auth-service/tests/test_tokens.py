from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import override_settings
from django.utils import timezone

from accounts.keys import get_key_set
from accounts.models import RefreshToken, RevocationReason, User
from accounts.tokens import (
    RefreshTokenReuseError,
    TokenError,
    decode_access_token,
    issue_access_token,
    issue_token_pair,
    revoke_refresh_token,
    rotate_refresh_token,
)

from .conftest import local_private_key

pytestmark = pytest.mark.django_db


def _sign(claims: dict[str, Any], **headers: Any) -> str:
    keys = get_key_set()
    return jwt.encode(
        claims,
        local_private_key(),
        algorithm="RS256",
        headers={"kid": keys.signing.kid, **headers},
    )


def _valid_claims(user: User, **overrides: Any) -> dict[str, Any]:
    now = int(timezone.now().timestamp())
    claims = {
        "iss": "urn:secure-platform:auth-service",
        "aud": "secure-platform-api",
        "sub": str(user.pk),
        "iat": now,
        "exp": now + 300,
        "jti": "test",
    }
    claims.update(overrides)
    return claims


class TestAccessTokens:
    def test_claims_carry_identity_roles_and_scopes(self, user: User) -> None:
        token = issue_access_token(user)

        header = jwt.get_unverified_header(token)
        claims = decode_access_token(token)

        assert header["alg"] == "RS256"
        assert header["kid"] == get_key_set().signing.kid
        assert claims["sub"] == str(user.pk)
        assert claims["email"] == user.email
        assert claims["roles"] == ["USER"]
        assert claims["scope"] == "orders:read orders:write"
        assert claims["exp"] - claims["iat"] == 900

    def test_admin_receives_admin_scopes(self, admin: User) -> None:
        claims = decode_access_token(issue_access_token(admin))

        assert claims["roles"] == ["ADMIN"]
        assert {"orders:admin", "users:admin"} <= set(claims["scope"].split())

    def test_expired_token_is_rejected(self, user: User) -> None:
        token = issue_access_token(user, now=timezone.now() - timedelta(hours=1))

        with pytest.raises(TokenError, match="expired"):
            decode_access_token(token)

    @pytest.mark.parametrize(
        ("override", "value"),
        [("aud", "some-other-api"), ("iss", "https://evil.example.com")],
    )
    def test_wrong_audience_or_issuer_is_rejected(
        self, user: User, override: str, value: str
    ) -> None:
        with pytest.raises(TokenError):
            decode_access_token(_sign(_valid_claims(user, **{override: value})))

    def test_missing_required_claim_is_rejected(self, user: User) -> None:
        claims = _valid_claims(user)
        del claims["jti"]

        with pytest.raises(TokenError):
            decode_access_token(_sign(claims))

    def test_tampered_payload_is_rejected(self, user: User) -> None:
        header, payload, signature = issue_access_token(user).split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
        claims["roles"] = ["ADMIN"]
        forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()

        with pytest.raises(TokenError):
            decode_access_token(f"{header}.{forged}.{signature}")

    def test_alg_none_is_rejected(self, user: User) -> None:
        token = jwt.encode(_valid_claims(user), key="", algorithm="none")

        with pytest.raises(TokenError, match="algorithm"):
            decode_access_token(token)

    def test_hs256_key_confusion_is_rejected(self, user: User) -> None:
        # Classic attack: sign with HMAC using the *public* key as the secret.
        public_pem = (
            local_private_key()
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

        # PyJWT refuses to build this token, so forge it by hand.
        def b64(data: bytes) -> bytes:
            return base64.urlsafe_b64encode(data).rstrip(b"=")

        header = b64(
            json.dumps({"alg": "HS256", "typ": "JWT", "kid": get_key_set().signing.kid}).encode()
        )
        payload = b64(json.dumps(_valid_claims(user)).encode())
        signature = b64(hmac.new(public_pem, header + b"." + payload, hashlib.sha256).digest())
        token = b".".join((header, payload, signature)).decode()

        with pytest.raises(TokenError, match="algorithm"):
            decode_access_token(token)

    def test_token_signed_by_unknown_key_is_rejected(self, user: User) -> None:
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = jwt.encode(
            _valid_claims(user),
            attacker_key,
            algorithm="RS256",
            headers={"kid": get_key_set().signing.kid},  # even with a valid-looking kid
        )

        with pytest.raises(TokenError):
            decode_access_token(token)

    def test_unknown_kid_is_rejected(self, user: User) -> None:
        with pytest.raises(TokenError, match="Unknown signing key"):
            decode_access_token(_sign(_valid_claims(user), kid="not-a-real-kid"))

    def test_garbage_is_rejected(self) -> None:
        with pytest.raises(TokenError):
            decode_access_token("not.a.jwt")


class TestRefreshTokens:
    def test_only_a_hash_of_the_refresh_token_is_stored(self, user: User) -> None:
        pair = issue_token_pair(user)

        stored = RefreshToken.objects.get(user=user)
        assert pair.refresh_token not in stored.token_hash
        assert len(stored.token_hash) == 64

    def test_rotation_issues_new_tokens_and_retires_the_old_one(self, user: User) -> None:
        first = issue_token_pair(user)

        second = rotate_refresh_token(first.refresh_token)

        assert second.refresh_token != first.refresh_token
        assert decode_access_token(second.access_token)["sub"] == str(user.pk)
        old = RefreshToken.objects.get(replaced_by__isnull=False)
        assert old.revoked_reason == RevocationReason.ROTATED
        assert old.replaced_by is not None
        assert old.replaced_by.family_id == old.family_id

    def test_reuse_of_rotated_token_revokes_the_whole_family(self, user: User) -> None:
        stolen = issue_token_pair(user)
        legitimate = rotate_refresh_token(stolen.refresh_token)

        with pytest.raises(RefreshTokenReuseError):
            rotate_refresh_token(stolen.refresh_token)

        # The attacker's replay also kills the legitimate client's current token.
        with pytest.raises(TokenError, match="revoked"):
            rotate_refresh_token(legitimate.refresh_token)
        assert not RefreshToken.objects.filter(revoked_at__isnull=True).exists()
        assert RefreshToken.objects.filter(revoked_reason=RevocationReason.REUSE_DETECTED).exists()

    def test_reuse_only_revokes_the_affected_session(self, user: User) -> None:
        laptop = issue_token_pair(user)
        phone = issue_token_pair(user)
        rotate_refresh_token(laptop.refresh_token)

        with pytest.raises(RefreshTokenReuseError):
            rotate_refresh_token(laptop.refresh_token)

        assert rotate_refresh_token(phone.refresh_token).refresh_token

    def test_expired_refresh_token_is_rejected(self, user: User) -> None:
        pair = issue_token_pair(user)
        RefreshToken.objects.update(expires_at=timezone.now() - timedelta(seconds=1))

        with pytest.raises(TokenError, match="expired"):
            rotate_refresh_token(pair.refresh_token)

    def test_rotation_never_extends_past_the_absolute_session_lifetime(self, user: User) -> None:
        with override_settings(REFRESH_TOKEN_TTL_SECONDS=3600, REFRESH_SESSION_MAX_SECONDS=60):
            pair = issue_token_pair(user)
            rotated = rotate_refresh_token(pair.refresh_token)

        assert rotated.refresh_expires_in <= 60

    def test_disabled_account_cannot_refresh(self, user: User) -> None:
        pair = issue_token_pair(user)
        User.objects.filter(pk=user.pk).update(is_active=False)

        with pytest.raises(TokenError, match="disabled"):
            rotate_refresh_token(pair.refresh_token)

    def test_unknown_refresh_token_is_rejected(self) -> None:
        with pytest.raises(TokenError, match="Invalid"):
            rotate_refresh_token("definitely-not-issued")

    def test_logout_revokes_the_session(self, user: User) -> None:
        pair = issue_token_pair(user)
        rotated = rotate_refresh_token(pair.refresh_token)

        revoke_refresh_token(rotated.refresh_token)

        with pytest.raises(TokenError, match="revoked"):
            rotate_refresh_token(rotated.refresh_token)
        assert RefreshToken.objects.filter(revoked_reason=RevocationReason.LOGOUT).count() == 1
