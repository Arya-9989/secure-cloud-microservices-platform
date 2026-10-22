"""Client credentials grant with DPoP: the happy path and every way to abuse it."""

from __future__ import annotations

import base64
import time
import uuid
from collections.abc import Callable
from io import StringIO
from typing import Any
from urllib.parse import urlencode

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.core.management import CommandError, call_command
from django.test import override_settings
from jwt.algorithms import ECAlgorithm
from rest_framework.test import APIClient

from accounts import dpop
from accounts.models import OAuthClient
from accounts.throttles import ClientTokenClientThrottle
from accounts.tokens import TokenError, decode_access_token

from .conftest import local_private_key

pytestmark = pytest.mark.django_db

TOKEN_URL = "/api/v1/auth/oauth/token"
FULL_URL = "http://testserver" + TOKEN_URL
SECRET = "s3cret-for-tests-0123456789-abcdefghij"
RESOURCE = "urn:secure-platform:orders-service"


@pytest.fixture
def client_app() -> OAuthClient:
    app = OAuthClient(
        client_id="fulfilment", scopes=["orders:fulfil"], audiences=[RESOURCE], require_dpop=True
    )
    app.set_secret(SECRET)
    app.save()
    return app


def basic(client_id: str = "fulfilment", secret: str = SECRET) -> str:
    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


class Key:
    def __init__(self) -> None:
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.jwk: dict[str, Any] = ECAlgorithm.to_jwk(self.private.public_key(), as_dict=True)

    def proof(self, **overrides: Any) -> str:
        claims: dict[str, Any] = {
            "jti": str(uuid.uuid4()),
            "htm": "POST",
            "htu": FULL_URL,
            "iat": int(time.time()),
            "nonce": dpop.new_nonce(),
        }
        headers: dict[str, Any] = {"typ": "dpop+jwt", "jwk": self.jwk}
        headers.update(overrides.pop("headers", {}))
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, self.private, algorithm="ES256", headers=headers)


@pytest.fixture
def key() -> Key:
    return Key()


FORM = "application/x-www-form-urlencoded"


def form_post(api: APIClient, data: dict[str, Any], **extra: Any) -> Any:
    return api.post(TOKEN_URL, urlencode(data, doseq=True), content_type=FORM, **extra)


@pytest.fixture
def token_request(api: APIClient) -> Callable[..., Any]:
    def _request(
        proof: str | None, data: dict[str, Any] | None = None, auth: str | None = None
    ) -> Any:
        extra: dict[str, str] = {"HTTP_AUTHORIZATION": auth or basic()}
        if proof is not None:
            extra["HTTP_DPOP"] = proof
        return form_post(api, data or {"grant_type": "client_credentials"}, **extra)

    return _request


class TestIssuance:
    def test_a_dpop_bound_token_for_the_requested_resource(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any]
    ) -> None:
        response = token_request(key.proof())

        assert response.status_code == 200, response.content
        body = response.json()
        assert body["token_type"] == "DPoP"
        assert body["scope"] == "orders:fulfil"
        assert body["expires_in"] == 300
        assert "refresh_token" not in body
        assert response["Cache-Control"] == "no-store"
        assert response["DPoP-Nonce"]
        claims = jwt.decode(
            body["access_token"],
            local_private_key().public_key(),
            algorithms=["RS256"],
            audience=RESOURCE,
        )
        assert claims["sub"] == claims["client_id"] == "fulfilment"
        assert claims["cnf"] == {"jkt": dpop.jwk_thumbprint(key.jwk)}
        assert "roles" not in claims
        assert "email" not in claims
        assert claims["exp"] - claims["iat"] == 300

    def test_the_first_attempt_without_a_nonce_is_told_which_to_use(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any]
    ) -> None:
        first = token_request(key.proof(nonce=None))

        assert first.status_code == 400
        assert first.json()["error"] == "use_dpop_nonce"
        retry = token_request(key.proof(nonce=first["DPoP-Nonce"]))
        assert retry.status_code == 200

    def test_a_client_token_cannot_call_user_apis(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any], api: APIClient
    ) -> None:
        token = token_request(key.proof()).json()["access_token"]

        with pytest.raises(TokenError):
            decode_access_token(token)  # wrong audience for the platform API
        response = api.get("/api/v1/auth/me/", HTTP_AUTHORIZATION=f"Bearer {token}")
        assert response.status_code == 401

    def test_scope_and_resource_are_validated(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any]
    ) -> None:
        def error(data: dict[str, Any]) -> str:
            response = token_request(key.proof(), {"grant_type": "client_credentials", **data})
            assert response.status_code == 400
            return str(response.json()["error"])

        assert error({"scope": "orders:admin"}) == "invalid_scope"
        assert error({"scope": "orders:fulfil users:admin"}) == "invalid_scope"
        assert error({"resource": "urn:secure-platform:billing"}) == "invalid_target"

    @override_settings(OAUTH_RESOURCES=[RESOURCE, "urn:secure-platform:other"])
    def test_a_client_with_several_audiences_must_name_one(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any]
    ) -> None:
        client_app.audiences = [RESOURCE, "urn:secure-platform:other"]
        client_app.save()

        unnamed = token_request(key.proof())
        named = token_request(
            key.proof(),
            {"grant_type": "client_credentials", "resource": "urn:secure-platform:other"},
        )

        assert unnamed.json()["error"] == "invalid_target"
        assert named.status_code == 200

    def test_bearer_tokens_only_for_clients_that_allow_them(
        self, client_app: OAuthClient, token_request: Callable[..., Any]
    ) -> None:
        refused = token_request(None)
        client_app.require_dpop = False
        client_app.save()
        allowed = token_request(None)

        assert refused.status_code == 400
        assert refused.json()["error"] == "invalid_dpop_proof"
        assert allowed.status_code == 200
        assert allowed.json()["token_type"] == "Bearer"
        assert "cnf" not in jwt.decode(
            allowed.json()["access_token"], options={"verify_signature": False}
        )


class TestClientAuthentication:
    @pytest.mark.parametrize(
        "auth",
        [
            basic(secret="wrong-secret"),
            basic(client_id="nobody"),
            "Bearer " + "x" * 20,
            "Basic not-base64!!",
            "Basic " + base64.b64encode(b"no-colon").decode(),
            "",
        ],
    )
    def test_bad_credentials_are_invalid_client(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any], auth: str
    ) -> None:
        if auth:
            response = token_request(key.proof(), auth=auth)
        else:  # no Authorization header at all
            response = form_post(
                APIClient(), {"grant_type": "client_credentials"}, HTTP_DPOP=key.proof()
            )

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"
        assert response["WWW-Authenticate"].startswith("Basic")

    def test_a_disabled_client_fails_like_a_wrong_secret(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any]
    ) -> None:
        client_app.is_active = False
        client_app.save()

        response = token_request(key.proof())

        assert response.status_code == 401
        assert response.json() == {
            "error": "invalid_client",
            "error_description": "Client authentication failed",
        }

    def test_secrets_in_the_body_are_refused(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any]
    ) -> None:
        response = token_request(
            key.proof(),
            {
                "grant_type": "client_credentials",
                "client_id": "fulfilment",
                "client_secret": SECRET,
            },
        )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_other_grants_and_json_bodies_are_refused(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any], api: APIClient
    ) -> None:
        password = token_request(key.proof(), {"grant_type": "password"})
        as_json = api.post(
            TOKEN_URL,
            {"grant_type": "client_credentials"},
            format="json",
            HTTP_AUTHORIZATION=basic(),
            HTTP_DPOP=key.proof(),
        )

        assert password.json()["error"] == "unsupported_grant_type"
        assert as_json.status_code == 415

    def test_only_a_hash_of_the_secret_is_stored(self, client_app: OAuthClient) -> None:
        assert SECRET not in client_app.secret_hash
        assert client_app.secret_hash.startswith(("argon2", "md5"))  # tests use MD5 for speed


class TestProofs:
    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"htm": "GET"}, "htm"),
            ({"htu": "http://testserver/api/v1/auth/token/"}, "htu"),
            ({"htu": "https://evil.example/api/v1/auth/oauth/token"}, "htu"),
            ({"iat": int(time.time()) - 600}, "old"),
            ({"iat": int(time.time()) + 600}, "future"),
            ({"jti": None}, "claims"),
            ({"jti": "x" * 300}, "jti"),
            ({"headers": {"typ": "JWT"}}, "typ"),
            ({"nonce": "1.forged"}, "nonce"),
        ],
    )
    def test_proofs_that_do_not_match_this_request_are_rejected(
        self,
        client_app: OAuthClient,
        key: Key,
        token_request: Callable[..., Any],
        overrides: dict[str, Any],
        message: str,
    ) -> None:
        response = token_request(key.proof(**overrides))

        assert response.status_code == 400
        assert response.json()["error"] in {"invalid_dpop_proof", "use_dpop_nonce"}
        assert message in response.json()["error_description"]

    def test_a_proof_works_once(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any]
    ) -> None:
        proof = key.proof()

        assert token_request(proof).status_code == 200
        replay = token_request(proof)

        assert replay.status_code == 400
        assert "already been used" in replay.json()["error_description"]

    def test_a_proof_signed_by_another_key_than_its_jwk_is_rejected(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any]
    ) -> None:
        impostor = Key()
        forged = jwt.encode(
            {
                "jti": "1",
                "htm": "POST",
                "htu": FULL_URL,
                "iat": int(time.time()),
                "nonce": dpop.new_nonce(),
            },
            impostor.private,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": key.jwk},  # claims to be `key`
        )

        assert token_request(forged).json()["error"] == "invalid_dpop_proof"

    def test_symmetric_unsigned_and_private_key_proofs_are_rejected(
        self, client_app: OAuthClient, key: Key, token_request: Callable[..., Any]
    ) -> None:
        claims = {"jti": "2", "htm": "POST", "htu": FULL_URL, "iat": int(time.time())}
        hmac = jwt.encode(
            claims, "a" * 32, algorithm="HS256", headers={"typ": "dpop+jwt", "jwk": key.jwk}
        )
        unsigned = jwt.encode(
            claims, "", algorithm="none", headers={"typ": "dpop+jwt", "jwk": key.jwk}
        )
        with_private = key.proof(headers={"jwk": {**key.jwk, "d": "c2VjcmV0"}})

        for proof, reason in (
            (hmac, "asymmetric"),
            (unsigned, "asymmetric"),
            (with_private, "private"),
        ):
            response = token_request(proof)
            assert response.status_code == 400
            assert reason in response.json()["error_description"]

    def test_rsa_keys_are_accepted_and_thumbprinted_per_rfc7638(self) -> None:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        from accounts.keys import public_jwk

        published = public_jwk(private.public_key())  # its kid is the RFC 7638 thumbprint

        assert dpop.jwk_thumbprint(published) == published["kid"]

    def test_nonces_expire_after_two_windows(self) -> None:
        now = 1_800_000_000.0
        nonce = dpop.new_nonce(now)

        assert dpop.nonce_is_valid(nonce, now)
        assert dpop.nonce_is_valid(nonce, now + 300)  # the next window still accepts it
        assert not dpop.nonce_is_valid(nonce, now + 601)
        assert not dpop.nonce_is_valid(nonce.replace(".", ".x"), now)
        assert not dpop.nonce_is_valid(None, now)

    def test_url_normalisation(self) -> None:
        assert (
            dpop.normalise_url("HTTPS://Api.Example.com:443/x?y=1#z") == "https://api.example.com/x"
        )
        assert dpop.normalise_url("http://h:8080/p") == "http://h:8080/p"


class TestThrottling:
    def test_guessing_a_clients_secret_is_throttled(
        self,
        client_app: OAuthClient,
        key: Key,
        token_request: Callable[..., Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(ClientTokenClientThrottle, "rate", "3/min", raising=False)

        statuses = [
            token_request(key.proof(), auth=basic(secret=f"guess-{n}")).status_code
            for n in range(4)
        ]

        assert statuses == [401, 401, 401, 429]


class TestEnsureOAuthClient:
    def test_creates_then_updates_idempotently(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CLIENT_SECRET_FOR_TEST", SECRET)
        args = [
            "fulfilment",
            "--secret-env",
            "CLIENT_SECRET_FOR_TEST",
            "--scope",
            "orders:fulfil",
            "--audience",
            RESOURCE,
        ]

        call_command("ensure_oauth_client", *args, stdout=StringIO())
        out = StringIO()
        call_command("ensure_oauth_client", *args, stdout=out)

        client = OAuthClient.objects.get()
        assert client.check_secret(SECRET)
        assert client.require_dpop
        assert "Updated" in out.getvalue()
        assert "rotated" not in out.getvalue()

    def test_rotates_the_secret_when_it_changes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        args = ["svc", "--secret-env", "S", "--scope", "orders:fulfil", "--audience", RESOURCE]
        monkeypatch.setenv("S", SECRET)
        call_command("ensure_oauth_client", *args, stdout=StringIO())
        monkeypatch.setenv("S", SECRET + "-next")
        call_command("ensure_oauth_client", *args, stdout=StringIO())

        client = OAuthClient.objects.get()
        assert client.check_secret(SECRET + "-next")
        assert not client.check_secret(SECRET)

    @pytest.mark.parametrize(
        ("secret", "audience", "message"),
        [("short", RESOURCE, "at least 32"), (SECRET, "urn:unknown", "Unknown resource")],
    )
    def test_rejects_weak_secrets_and_unknown_resources(
        self, monkeypatch: pytest.MonkeyPatch, secret: str, audience: str, message: str
    ) -> None:
        monkeypatch.setenv("S", secret)

        with pytest.raises(CommandError, match=message):
            call_command(
                "ensure_oauth_client",
                "svc",
                "--secret-env",
                "S",
                "--scope",
                "orders:fulfil",
                "--audience",
                audience,
                stdout=StringIO(),
            )
