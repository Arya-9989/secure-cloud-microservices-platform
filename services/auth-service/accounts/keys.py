"""RSA signing-key management and JWKS publication.

* The active private key is read from ``JWT_PRIVATE_KEY_FILE`` (PEM, PKCS#8).
  It is mounted as a secret; it is never generated implicitly at runtime, so
  every replica signs with the same key.
* ``JWT_ADDITIONAL_PUBLIC_KEY_FILES`` lists retired/next public keys that must
  stay in the JWKS during a key rotation, so tokens signed by the previous key
  remain verifiable until they expire.
* The ``kid`` is the RFC 7638 JWK thumbprint, so it is derived from the key
  material itself and can never drift out of sync with it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

MIN_RSA_KEY_BITS = 2048


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_jwk(public_key: rsa.RSAPublicKey) -> dict[str, str]:
    numbers = public_key.public_numbers()
    required = {"e": _b64url_uint(numbers.e), "kty": "RSA", "n": _b64url_uint(numbers.n)}
    # RFC 7638: SHA-256 over the lexicographically ordered required members.
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
    kid = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()
    return {**required, "kid": kid, "use": "sig", "alg": "RS256"}


@dataclass(frozen=True)
class SigningKey:
    private_key: rsa.RSAPrivateKey
    kid: str


@dataclass(frozen=True)
class KeySet:
    signing: SigningKey
    verification: dict[str, rsa.RSAPublicKey]
    jwks: dict[str, Any]


def _load_private_key(path: Path) -> rsa.RSAPrivateKey:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ImproperlyConfigured(
            f"Cannot read JWT signing key at {path}. Generate one with "
            "`python manage.py ensure_signing_key <path>`."
        ) from exc
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ImproperlyConfigured("JWT signing key must be an RSA private key")
    if key.key_size < MIN_RSA_KEY_BITS:
        raise ImproperlyConfigured(f"JWT signing key must be at least {MIN_RSA_KEY_BITS} bits")
    return key


def _load_public_key(path: Path) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ImproperlyConfigured(f"{path} is not an RSA public key")
    return key


@lru_cache(maxsize=1)
def get_key_set() -> KeySet:
    private_key = _load_private_key(Path(settings.JWT_PRIVATE_KEY_FILE))
    signing_jwk = public_jwk(private_key.public_key())
    signing = SigningKey(private_key=private_key, kid=signing_jwk["kid"])

    verification: dict[str, rsa.RSAPublicKey] = {signing.kid: private_key.public_key()}
    jwks_keys = [signing_jwk]
    for extra in settings.JWT_ADDITIONAL_PUBLIC_KEY_FILES:
        public_key = _load_public_key(Path(extra))
        jwk = public_jwk(public_key)
        if jwk["kid"] not in verification:
            verification[jwk["kid"]] = public_key
            jwks_keys.append(jwk)

    return KeySet(signing=signing, verification=verification, jwks={"keys": jwks_keys})


def generate_private_key_pem(bits: int = 3072) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
