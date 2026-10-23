"""Vault transit against a real Vault (dev mode).

Skipped unless VAULT_ADDR and VAULT_TOKEN are set:

    docker run --rm -d -p 127.0.0.1:8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=dev-root \
        hashicorp/vault:2.1.2
    VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root uv run pytest tests/test_vault.py

CI runs these in the auth-service job with a Vault service container.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from accounts.keys import get_key_set
from accounts.kms import SigningUnavailableError, VaultTransit, VaultTransitSigner, plan_rotation
from accounts.models import User
from accounts.tokens import decode_access_token, issue_access_token

ADDRESS = os.environ.get("VAULT_ADDR", "")
ROOT_TOKEN = os.environ.get("VAULT_TOKEN", "")

pytestmark = pytest.mark.skipif(
    not (ADDRESS and ROOT_TOKEN), reason="needs a Vault: set VAULT_ADDR and VAULT_TOKEN"
)


@pytest.fixture
def transit() -> Iterator[VaultTransit]:
    admin = VaultTransit(ADDRESS, lambda: ROOT_TOKEN, key_name="unused")
    mounts = admin._request("GET", "sys/mounts")
    if "transit/" not in mounts.get("data", mounts):
        admin._request("POST", "sys/mounts/transit", {"type": "transit"})
    name = f"test-{uuid.uuid4().hex[:10]}"
    admin._request("POST", f"transit/keys/{name}", {"type": "rsa-2048", "exportable": False})
    client = VaultTransit(ADDRESS, lambda: ROOT_TOKEN, key_name=name)
    yield client
    admin._request("POST", f"transit/keys/{name}/config", {"deletion_allowed": True})
    admin._request("DELETE", f"transit/keys/{name}")


def test_signatures_verify_with_the_published_public_key(transit: VaultTransit) -> None:
    (only,) = transit.key_versions()
    message = b"header.payload"

    signature = transit.sign(only.version, message)

    only.public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


def test_a_token_signed_by_vault_is_a_valid_rs256_jwt(transit: VaultTransit) -> None:
    (only,) = transit.key_versions()
    signer = VaultTransitSigner(transit, only.version, kid="k1")
    header = jwt.utils.base64url_encode(b'{"alg":"RS256","kid":"k1","typ":"JWT"}')
    payload = jwt.utils.base64url_encode(b'{"sub":"alice"}')
    signing_input = header + b"." + payload

    token = (signing_input + b"." + jwt.utils.base64url_encode(signer.sign(signing_input))).decode()

    assert jwt.decode(token, only.public_key, algorithms=["RS256"]) == {"sub": "alice"}


def test_rotation_adds_a_version_and_the_plan_overlaps_them(transit: VaultTransit) -> None:
    transit.rotate()
    versions = transit.key_versions()
    now = time.time()

    assert sorted(v.version for v in versions) == [1, 2]
    before = plan_rotation(versions, now, publish_ahead=360, retire_after=990)
    after = plan_rotation(versions, now + 360, publish_ahead=360, retire_after=990)
    assert before.signing.version == 1  # v2 is only published for now
    assert {v.version for v in before.published} == {1, 2}
    assert after.signing.version == 2
    assert {v.version for v in after.published} == {1, 2}  # v1 tokens still verify
    signature = transit.sign(2, b"m")
    versions[1 if versions[1].version == 2 else 0].public_key.verify(
        signature, b"m", padding.PKCS1v15(), hashes.SHA256()
    )


def test_a_least_privilege_token_can_sign_but_not_rotate(transit: VaultTransit) -> None:
    admin = VaultTransit(ADDRESS, lambda: ROOT_TOKEN, key_name=transit.key_name)
    policy = f"signer-{transit.key_name}"
    admin._request(
        "PUT",
        f"sys/policies/acl/{policy}",
        {
            "policy": (
                f'path "transit/keys/{transit.key_name}" {{ capabilities = ["read"] }}\n'
                f'path "transit/sign/{transit.key_name}/*" {{ capabilities = ["update"] }}\n'
            )
        },
    )
    issued = admin._request("POST", "auth/token/create", {"policies": [policy], "ttl": "5m"})
    token = issued["auth"]["client_token"]
    signer = VaultTransit(ADDRESS, lambda: token, key_name=transit.key_name)

    assert signer.sign(1, b"m")
    with pytest.raises(SigningUnavailableError) as rejected:
        signer.rotate()
    assert "HTTP 403" in rejected.value.reason


def test_an_unreachable_vault_fails_fast_and_cleanly() -> None:
    dead = VaultTransit("http://127.0.0.1:9", lambda: "t", key_name="k", timeout=0.5, retries=1)
    started = time.monotonic()

    with pytest.raises(SigningUnavailableError) as failure:
        dead.sign(1, b"m")

    assert "unreachable" in failure.value.reason
    assert "127.0.0.1" not in str(failure.value.detail), "no internals in the client message"
    assert time.monotonic() - started < 3


# --------------------------------------------------------------------------- the key set


@pytest.fixture
def vault_signing(transit: VaultTransit, tmp_path: Path, settings: Any) -> Iterator[VaultTransit]:
    token_file = tmp_path / "vault-token"
    token_file.write_text(ROOT_TOKEN, encoding="utf-8")
    settings.JWT_SIGNER = "vault"
    settings.VAULT_ADDR = ADDRESS
    settings.VAULT_TOKEN_FILE = str(token_file)
    settings.JWT_VAULT_KEY = transit.key_name
    settings.JWT_KEYSET_REFRESH_SECONDS = 0  # re-read on every call: rotations show at once
    get_key_set.cache_clear()
    yield transit
    get_key_set.cache_clear()


@pytest.mark.django_db
def test_tokens_are_signed_by_vault_and_verify_against_the_jwks(
    vault_signing: VaultTransit, user: User
) -> None:
    token = issue_access_token(user)
    (version,) = vault_signing.key_versions()

    assert decode_access_token(token)["sub"] == str(user.pk)
    assert jwt.get_unverified_header(token)["kid"] == get_key_set().jwks["keys"][0]["kid"]
    jwt.decode(token, version.public_key, algorithms=["RS256"], audience="secure-platform-api")


@pytest.mark.django_db
def test_rotation_never_breaks_a_token_issued_before_it(
    vault_signing: VaultTransit, user: User, settings: Any
) -> None:
    settings.JWT_KEY_PUBLISH_AHEAD_SECONDS = 360
    before = issue_access_token(user)
    old_kid = jwt.get_unverified_header(before)["kid"]

    vault_signing.rotate()
    published = [k["kid"] for k in get_key_set().jwks["keys"]]
    still_old = issue_access_token(user)

    assert len(published) == 2, "the new version is published at once"
    assert jwt.get_unverified_header(still_old)["kid"] == old_kid, "but signs only later"

    settings.JWT_KEY_PUBLISH_AHEAD_SECONDS = 0  # time has passed: every cache has the key
    after = issue_access_token(user)

    assert jwt.get_unverified_header(after)["kid"] != old_kid
    assert old_kid in [k["kid"] for k in get_key_set().jwks["keys"]], "old tokens still verify"
    for token in (before, still_old, after):
        assert decode_access_token(token)["sub"] == str(user.pk)


@pytest.mark.django_db
def test_a_vault_outage_keeps_the_jwks_and_answers_logins_with_503(
    vault_signing: VaultTransit, user: User, settings: Any
) -> None:
    from rest_framework.test import APIClient

    from .conftest import PASSWORD

    jwks_before = get_key_set().jwks
    Path(settings.VAULT_TOKEN_FILE).unlink()  # Vault refuses us from now on
    refresh_tokens = user.refresh_tokens.count()

    jwks = APIClient().get("/.well-known/jwks.json")
    login = APIClient().post(
        "/api/v1/auth/token/", {"email": user.email, "password": PASSWORD}, format="json"
    )

    assert jwks.status_code == 200
    assert jwks.json() == jwks_before, "verification keeps working on the last key set"
    assert login.status_code == 503
    assert login["Retry-After"]
    assert login["Content-Type"] == "application/problem+json"
    assert "vault" not in login.content.decode().lower(), "no internals in the response"
    assert user.refresh_tokens.count() == refresh_tokens, "nothing half-issued"


@pytest.mark.django_db
def test_the_rotate_command_needs_an_admin_token_and_shows_the_overlap(
    vault_signing: VaultTransit, tmp_path: Path, settings: Any
) -> None:
    from io import StringIO

    from django.core.management import CommandError, call_command

    admin_file = tmp_path / "admin-token"
    admin_file.write_text(ROOT_TOKEN, encoding="utf-8")
    with pytest.raises(CommandError, match="admin-token-file"):
        call_command("rotate_signing_key", "--admin-token-file", "", stdout=StringIO())

    out = StringIO()
    call_command("rotate_signing_key", "--admin-token-file", str(admin_file), stdout=out)
    shown = StringIO()
    call_command("rotate_signing_key", "--show", stdout=shown)

    assert "Rotated transit key" in out.getvalue()
    lines = shown.getvalue().splitlines()
    assert lines[0].startswith("v1")
    assert lines[0].endswith("signing")
    assert lines[1].startswith("v2")
    assert "published, signs from" in lines[1]
