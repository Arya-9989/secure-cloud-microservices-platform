from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from accounts.keys import generate_private_key_pem, get_key_set, public_jwk


def _b64url_to_int(value: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")


def test_kid_matches_rfc7638_test_vector() -> None:
    # Example key and expected thumbprint from RFC 7638, section 3.1.
    n = (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP"
        "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY"
        "368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f"
        "M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    )
    public_key = rsa.RSAPublicNumbers(e=65537, n=_b64url_to_int(n)).public_key()

    jwk = public_jwk(public_key)

    assert jwk["kid"] == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    assert jwk["n"] == n
    assert jwk["e"] == "AQAB"
    assert (jwk["alg"], jwk["use"], jwk["kty"]) == ("RS256", "sig", "RSA")


def test_jwks_publishes_only_public_material() -> None:
    jwks = get_key_set().jwks

    assert len(jwks["keys"]) == 1
    assert set(jwks["keys"][0]) == {"kty", "n", "e", "kid", "use", "alg"}  # no "d", "p", "q"


def test_additional_public_keys_are_published_for_rotation(tmp_path: Path) -> None:
    retired = serialization.load_pem_private_key(generate_private_key_pem(2048), password=None)
    retired_pem = retired.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    retired_path = tmp_path / "retired.pub.pem"
    retired_path.write_bytes(retired_pem)

    with override_settings(JWT_ADDITIONAL_PUBLIC_KEY_FILES=[str(retired_path)]):
        get_key_set.cache_clear()
        key_set = get_key_set()

    assert len(key_set.jwks["keys"]) == 2
    assert len(key_set.verification) == 2
    assert key_set.jwks["keys"][0]["kid"] == key_set.signing.kid


def test_missing_key_file_fails_with_actionable_error(tmp_path: Path) -> None:
    with override_settings(JWT_PRIVATE_KEY_FILE=str(tmp_path / "absent.pem")):
        get_key_set.cache_clear()
        with pytest.raises(ImproperlyConfigured, match="ensure_signing_key"):
            get_key_set()


def test_weak_keys_are_rejected(tmp_path: Path) -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    path = tmp_path / "weak.pem"
    path.write_bytes(
        weak.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with override_settings(JWT_PRIVATE_KEY_FILE=str(path)):
        get_key_set.cache_clear()
        with pytest.raises(ImproperlyConfigured, match="at least 2048"):
            get_key_set()
