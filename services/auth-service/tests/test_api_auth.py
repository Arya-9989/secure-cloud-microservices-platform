from __future__ import annotations

from collections.abc import Callable
from typing import Any

import jwt
import pytest
from prometheus_client import REGISTRY
from rest_framework.test import APIClient
from rest_framework.throttling import SimpleRateThrottle

from accounts.models import User

from .conftest import PASSWORD, login

pytestmark = pytest.mark.django_db

TOKEN_URL = "/api/v1/auth/token/"
REFRESH_URL = "/api/v1/auth/token/refresh/"


class TestRegistration:
    def test_register_creates_a_user_with_least_privilege(self, api: APIClient) -> None:
        response = api.post(
            "/api/v1/auth/register/",
            {"email": "New.Person@Example.com", "password": PASSWORD},
            format="json",
        )

        assert response.status_code == 201
        body = response.json()
        assert body["email"] == "new.person@example.com"
        assert body["role"] == "USER"
        assert "password" not in body
        assert User.objects.get(email="new.person@example.com").check_password(PASSWORD)

    def test_role_cannot_be_chosen_by_the_client(self, api: APIClient) -> None:
        response = api.post(
            "/api/v1/auth/register/",
            {"email": "sneaky@example.com", "password": PASSWORD, "role": "ADMIN"},
            format="json",
        )

        assert response.status_code == 201
        assert response.json()["role"] == "USER"

    def test_weak_password_is_rejected(self, api: APIClient) -> None:
        response = api.post(
            "/api/v1/auth/register/",
            {"email": "weak@example.com", "password": "password"},
            format="json",
        )

        assert response.status_code == 400
        assert response["Content-Type"] == "application/problem+json"
        assert not User.objects.filter(email="weak@example.com").exists()

    def test_duplicate_email_is_rejected_case_insensitively(
        self, api: APIClient, user: User
    ) -> None:
        response = api.post(
            "/api/v1/auth/register/",
            {"email": "ALICE@example.com", "password": PASSWORD},
            format="json",
        )

        assert response.status_code == 400
        assert "email" in response.json()["errors"]


class TestLogin:
    def test_valid_credentials_return_a_token_pair(self, api: APIClient, user: User) -> None:
        body = login(api, "Alice@Example.com")

        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 900
        assert body["scope"] == "orders:read orders:write"
        assert isinstance(body["refresh_token"], str)

    def test_token_responses_are_not_cacheable(self, api: APIClient, user: User) -> None:
        response = api.post(TOKEN_URL, {"email": user.email, "password": PASSWORD}, format="json")

        assert response["Cache-Control"] == "no-store"

    @pytest.mark.parametrize(
        ("email", "password"),
        [("alice@example.com", "wrong-password-123"), ("nobody@example.com", PASSWORD)],
        ids=["wrong-password", "unknown-account"],
    )
    def test_failures_are_indistinguishable(
        self, api: APIClient, user: User, email: str, password: str
    ) -> None:
        response = api.post(TOKEN_URL, {"email": email, "password": password}, format="json")

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid email or password."
        assert response["WWW-Authenticate"].startswith("Bearer")

    def test_disabled_account_cannot_log_in(self, api: APIClient, user: User) -> None:
        User.objects.filter(pk=user.pk).update(is_active=False)

        response = api.post(TOKEN_URL, {"email": user.email, "password": PASSWORD}, format="json")

        assert response.status_code == 401

    def test_malformed_body_is_a_validation_error(self, api: APIClient) -> None:
        response = api.post(TOKEN_URL, {"email": "not-an-email"}, format="json")

        assert response.status_code == 400
        assert set(response.json()["errors"]) == {"email", "password"}

    def test_failed_logins_are_counted(self, api: APIClient, user: User) -> None:
        def failures() -> float:
            value = REGISTRY.get_sample_value(
                "auth_login_attempts_total", {"outcome": "invalid_credentials"}
            )
            return value or 0.0

        before = failures()
        api.post(TOKEN_URL, {"email": user.email, "password": "nope-nope-nope"}, format="json")

        assert failures() == before + 1


class TestLoginRateLimiting:
    @pytest.fixture
    def rates(self, monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
        def _set(**rates: str) -> None:
            merged = {**SimpleRateThrottle.THROTTLE_RATES, **rates}
            monkeypatch.setattr(SimpleRateThrottle, "THROTTLE_RATES", merged)

        return _set

    def test_per_account_limit_applies_across_ip_addresses(
        self, api: APIClient, user: User, rates: Callable[..., None]
    ) -> None:
        rates(login_account="3/min", login_ip="100/min")
        for i in range(3):
            response = api.post(
                TOKEN_URL,
                {"email": user.email, "password": "wrong-password"},
                format="json",
                REMOTE_ADDR=f"10.0.0.{i}",
            )
            assert response.status_code == 401

        blocked = api.post(
            TOKEN_URL,
            {"email": user.email, "password": PASSWORD},
            format="json",
            REMOTE_ADDR="10.0.0.99",
        )

        assert blocked.status_code == 429
        assert int(blocked["Retry-After"]) > 0
        # Other accounts are unaffected.
        other = api.post(
            TOKEN_URL,
            {"email": "bob@example.com", "password": "x"},
            format="json",
            REMOTE_ADDR="10.0.0.99",
        )
        assert other.status_code == 401

    def test_per_ip_limit_applies_across_accounts(
        self, api: APIClient, rates: Callable[..., None]
    ) -> None:
        rates(login_account="100/min", login_ip="2/min")
        statuses = [
            api.post(
                TOKEN_URL, {"email": f"u{i}@example.com", "password": "x"}, format="json"
            ).status_code
            for i in range(3)
        ]

        assert statuses == [401, 401, 429]


class TestRefreshAndLogout:
    def test_refresh_rotates_and_detects_replay(self, api: APIClient, user: User) -> None:
        first = login(api, user.email)

        rotated = api.post(REFRESH_URL, {"refresh_token": first["refresh_token"]}, format="json")
        replay = api.post(REFRESH_URL, {"refresh_token": first["refresh_token"]}, format="json")
        after_replay = api.post(
            REFRESH_URL, {"refresh_token": rotated.json()["refresh_token"]}, format="json"
        )

        assert rotated.status_code == 200
        assert replay.status_code == 401
        assert replay.json()["detail"] == "Refresh token has already been used"
        assert after_replay.status_code == 401

    def test_logout_revokes_refresh_token(self, api: APIClient, user: User) -> None:
        tokens = login(api, user.email)

        logout = api.post(
            "/api/v1/auth/logout/", {"refresh_token": tokens["refresh_token"]}, format="json"
        )
        refresh = api.post(REFRESH_URL, {"refresh_token": tokens["refresh_token"]}, format="json")

        assert logout.status_code == 204
        assert refresh.status_code == 401

    def test_logout_with_unknown_token_does_not_leak_validity(self, api: APIClient) -> None:
        response = api.post("/api/v1/auth/logout/", {"refresh_token": "unknown"}, format="json")

        assert response.status_code == 204


class TestMe:
    def test_requires_a_bearer_token(self, api: APIClient) -> None:
        response = api.get("/api/v1/auth/me/")

        assert response.status_code == 401
        assert response["WWW-Authenticate"] == 'Bearer realm="secure-platform"'

    @pytest.mark.parametrize("header", ["Bearer not-a-token", "Basic YWxpY2U6c2VjcmV0", "Bearer "])
    def test_rejects_invalid_credentials(self, api: APIClient, header: str) -> None:
        response = api.get("/api/v1/auth/me/", HTTP_AUTHORIZATION=header)

        assert response.status_code == 401

    def test_returns_the_caller(
        self, api: APIClient, user: User, bearer: Callable[[User], dict[str, Any]]
    ) -> None:
        response = api.get("/api/v1/auth/me/", **bearer(user))

        assert response.status_code == 200
        assert response.json()["email"] == "alice@example.com"
        assert response.json()["scopes"] == ["orders:read", "orders:write"]

    def test_token_of_a_disabled_account_is_rejected_by_the_issuer(
        self, api: APIClient, user: User, bearer: Callable[[User], dict[str, Any]]
    ) -> None:
        headers = bearer(user)
        User.objects.filter(pk=user.pk).update(is_active=False)

        assert api.get("/api/v1/auth/me/", **headers).status_code == 401


class TestJWKS:
    def test_jwks_verifies_issued_tokens(self, api: APIClient, user: User) -> None:
        access_token = login(api, user.email)["access_token"]
        response = api.get("/.well-known/jwks.json")

        assert response.status_code == 200
        assert "max-age" in response["Cache-Control"]
        jwk_set = jwt.PyJWKSet.from_dict(response.json())
        kid = jwt.get_unverified_header(access_token)["kid"]
        key = next(k for k in jwk_set.keys if k.key_id == kid)
        claims = jwt.decode(
            access_token, key.key, algorithms=["RS256"], audience="secure-platform-api"
        )
        assert claims["sub"] == str(user.pk)

    def test_jwks_ignores_bogus_authorization_headers(self, api: APIClient) -> None:
        response = api.get("/.well-known/jwks.json", HTTP_AUTHORIZATION="Bearer garbage")

        assert response.status_code == 200


class TestRequestCorrelation:
    def test_incoming_request_id_is_echoed(self, api: APIClient) -> None:
        response = api.get("/healthz", HTTP_X_REQUEST_ID="req-1234-abcd")

        assert response["X-Request-ID"] == "req-1234-abcd"

    @pytest.mark.parametrize("bad", ["short", "has spaces in it", "x" * 200, "inject\r\nheader"])
    def test_unsafe_request_ids_are_replaced(self, api: APIClient, bad: str) -> None:
        response = api.get("/healthz", HTTP_X_REQUEST_ID=bad)

        assert response["X-Request-ID"] != bad
        assert len(response["X-Request-ID"]) == 36  # generated UUID

    def test_errors_include_the_request_id(self, api: APIClient) -> None:
        response = api.get("/api/v1/auth/me/", HTTP_X_REQUEST_ID="trace-me-please")

        assert response.json()["request_id"] == "trace-me-please"
