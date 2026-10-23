"""Signing-key rotation in Vault transit, end to end (compose profile `kms`, JWT_SIGNER=vault).

Rotates the transit key in the middle of the run and checks the overlap guarantees
from docs/adr/0007: the new version is published before it signs, tokens issued
before the rotation keep working at orders-service, and new tokens switch to the new
key once it has been published long enough.
"""

from __future__ import annotations

import time

import httpx
import jwt
import pytest

from conftest import eventually, register_and_login, setting

pytestmark = pytest.mark.skipif(
    setting("JWT_SIGNER", "local") != "vault",
    reason="the signer is the file key (set COMPOSE_PROFILES=kms and JWT_SIGNER=vault)",
)

VAULT_URL = setting("VAULT_URL", "http://localhost:" + setting("VAULT_PORT", "8200"))
PUBLISH_AHEAD = int(setting("JWT_KEY_PUBLISH_AHEAD_SECONDS", "360"))
REFRESH = int(setting("JWT_KEYSET_REFRESH_SECONDS", "30"))


def kids(gateway: httpx.Client) -> list[str]:
    return [key["kid"] for key in gateway.get("/.well-known/jwks.json").json()["keys"]]


def kid_of(token: str) -> str:
    return str(jwt.get_unverified_header(token)["kid"])


def fresh_token(gateway: httpx.Client) -> str:
    # A new account each time: logging one account in repeatedly would hit its throttle.
    return register_and_login(gateway).access_token


def orders_accepts(gateway: httpx.Client, token: str) -> bool:
    response = gateway.get("/api/v1/orders", headers={"Authorization": f"Bearer {token}"})
    return response.status_code == 200


class TestKeyRotation:
    def test_rotation_publishes_first_and_breaks_no_token(self, gateway: httpx.Client) -> None:
        account = register_and_login(gateway)
        before = account.access_token
        published_before = kids(gateway)
        assert kid_of(before) == published_before[0], "the signing key is listed first"

        rotated = httpx.post(
            f"{VAULT_URL}/v1/transit/keys/auth-jwt/rotate",
            headers={"X-Vault-Token": setting("VAULT_DEV_ROOT_TOKEN")},
            timeout=10,
        )
        assert rotated.status_code in (200, 204), rotated.text

        def new_version_published() -> None:
            assert len(kids(gateway)) == len(published_before) + 1

        eventually(new_version_published, timeout=REFRESH + 30, interval=2)
        if PUBLISH_AHEAD > REFRESH + 10:
            # Not yet trusted everywhere, so it must not sign yet.
            assert kid_of(fresh_token(gateway)) == kid_of(before)
        assert orders_accepts(gateway, before)

        if PUBLISH_AHEAD > 120:
            pytest.skip(f"switch-over after {PUBLISH_AHEAD}s is too long for an e2e run")
        time.sleep(max(0, PUBLISH_AHEAD - REFRESH))
        new_kid = kid_of(before)

        def signs_with_the_new_version() -> None:
            nonlocal new_kid
            new_kid = kid_of(fresh_token(gateway))
            assert new_kid != kid_of(before)

        eventually(signs_with_the_new_version, timeout=REFRESH + 60, interval=REFRESH or 2)
        after = fresh_token(gateway)
        assert kid_of(before) in kids(gateway), "the old version stays until its tokens expire"
        assert orders_accepts(gateway, after), "orders-service fetches the new key"
        assert orders_accepts(gateway, before), "and still accepts tokens from before"
