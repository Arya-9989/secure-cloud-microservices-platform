"""Signing keys and JWKS publication.

Two signers (``JWT_SIGNER``, docs/adr/0007-kms-signing-and-rotation.md):

* ``local`` (default): the active private key is read from ``JWT_PRIVATE_KEY_FILE`` (PEM,
  PKCS#8). It is mounted as a secret; it is never generated implicitly at runtime, so
  every replica signs with the same key.
* ``vault``: the key lives in Vault transit and never leaves it. Which version signs and
  which versions are published is decided by ``kms.plan_rotation``: new versions are
  published before they sign, retired ones stay until their tokens have expired.

Either way ``JWT_ADDITIONAL_PUBLIC_KEY_FILES`` lists extra public keys that must stay in
the JWKS, e.g. the file key during a cut-over to Vault, so tokens it signed remain
verifiable until they expire. The ``kid`` is the RFC 7638 JWK thumbprint, so it is
derived from the key material itself and can never drift out of sync with it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .kms import (
    MIN_RSA_KEY_BITS,
    LocalSigner,
    RotationPlan,
    Signer,
    SigningUnavailableError,
    VaultTransit,
    VaultTransitSigner,
    plan_rotation,
)

logger = logging.getLogger(__name__)

__all__ = [
    "MIN_RSA_KEY_BITS",
    "KeySet",
    "generate_private_key_pem",
    "get_key_set",
    "public_jwk",
    "vault_transit",
]


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
class KeySet:
    signing: Signer
    verification: dict[str, rsa.RSAPublicKey]
    jwks: dict[str, Any]
    plan: RotationPlan | None = None  # Vault only: what signs, what is published, until when


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


def _assemble(
    signing: Signer, published: list[rsa.RSAPublicKey], plan: RotationPlan | None = None
) -> KeySet:
    """The signing key's JWK first, then every other published key, then the extra files."""
    verification: dict[str, rsa.RSAPublicKey] = {}
    jwks_keys: list[dict[str, str]] = []
    extras = [_load_public_key(Path(p)) for p in settings.JWT_ADDITIONAL_PUBLIC_KEY_FILES]
    for public_key in [*published, *extras]:
        jwk = public_jwk(public_key)
        if jwk["kid"] not in verification:
            verification[jwk["kid"]] = public_key
            jwks_keys.append(jwk)
    return KeySet(signing=signing, verification=verification, jwks={"keys": jwks_keys}, plan=plan)


def _local_key_set() -> KeySet:
    private_key = _load_private_key(Path(settings.JWT_PRIVATE_KEY_FILE))
    signer = LocalSigner(private_key=private_key, kid=public_jwk(private_key.public_key())["kid"])
    return _assemble(signer, [private_key.public_key()])


def _read_token(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SigningUnavailableError(f"cannot read the Vault token at {path}") from exc


def vault_transit(token_file: str | None = None) -> VaultTransit:
    file = token_file or settings.VAULT_TOKEN_FILE
    return VaultTransit(
        settings.VAULT_ADDR,
        token=lambda: _read_token(file),  # re-read: the token can be replaced on disk
        key_name=settings.JWT_VAULT_KEY,
        mount=settings.JWT_VAULT_MOUNT,
    )


def _vault_key_set() -> KeySet:
    transit = vault_transit()
    retire_after = (
        max(settings.ACCESS_TOKEN_TTL_SECONDS, settings.CLIENT_TOKEN_TTL_SECONDS)
        + settings.JWT_CLOCK_SKEW_SECONDS
        + 60
    )
    plan = plan_rotation(
        transit.key_versions(),
        time.time(),
        publish_ahead=settings.JWT_KEY_PUBLISH_AHEAD_SECONDS,
        retire_after=retire_after,
    )
    signer = VaultTransitSigner(
        transit, plan.signing.version, kid=public_jwk(plan.signing.public_key)["kid"]
    )
    published = [plan.signing.public_key] + [
        v.public_key for v in plan.published if v.version != plan.signing.version
    ]
    return _assemble(signer, published, plan)


class _KeySetCache:
    """``get_key_set()``: the file key is loaded once; a Vault key set is refreshed.

    A Vault key set is rebuilt every ``JWT_KEYSET_REFRESH_SECONDS`` so rotations show up.
    If Vault cannot be reached the last good key set stays in use (the JWKS keeps being
    served, so verification is unaffected) and the failure is logged; with no key set at
    all the error propagates.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._key_set: KeySet | None = None
        self._expires = 0.0
        self._last_renewal = 0.0

    def __call__(self) -> KeySet:
        local = settings.JWT_SIGNER == "local"
        current = self._key_set
        if current is not None and (local or time.monotonic() < self._expires):
            return current
        with self._lock:
            if self._key_set is not None and (local or time.monotonic() < self._expires):
                return self._key_set
            if local:
                self._key_set = _local_key_set()
                return self._key_set
            try:
                self._key_set = _vault_key_set()
                self._renew_token_now_and_then()
            except SigningUnavailableError as exc:
                if self._key_set is None:
                    raise
                logger.warning(
                    "Vault unavailable; keeping the last key set", extra={"reason": exc.reason}
                )
            self._expires = time.monotonic() + settings.JWT_KEYSET_REFRESH_SECONDS
            return self._key_set

    def _renew_token_now_and_then(self) -> None:
        # Periodic tokens must be renewed within their period; hourly is plenty.
        if self._last_renewal and time.monotonic() - self._last_renewal < 3600:
            return
        try:
            vault_transit().renew_token()
            self._last_renewal = time.monotonic()
        except SigningUnavailableError as exc:
            logger.warning("Could not renew the Vault token", extra={"reason": exc.reason})

    def cache_clear(self) -> None:
        with self._lock:
            self._key_set = None
            self._expires = 0.0


get_key_set = _KeySetCache()


def generate_private_key_pem(bits: int = 3072) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
