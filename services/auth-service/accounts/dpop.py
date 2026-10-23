"""DPoP proof validation (RFC 9449) for the token endpoint.

A client proves possession of a private key by sending, with each request, a short
JWT (``typ: dpop+jwt``) that it signed with that key and whose header carries the
public key. The access token issued is bound to the key's RFC 7638 thumbprint
(``cnf.jkt``), so a stolen token is useless without the private key.

Checks, in order: size, ``typ``, an asymmetric ``alg``, a public-only ``jwk``, the
signature, ``htm`` / ``htu`` against this request, ``iat`` within the allowed age,
the server nonce, and ``jti`` replay. The replay cache is Django's cache, which is
the shared database cache in production, so every worker and replica sees it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt
from django.conf import settings
from django.core.cache import cache
from django.utils.crypto import constant_time_compare, salted_hmac

ALLOWED_ALGORITHMS = ("ES256", "ES384", "PS256", "RS256", "EdDSA")
MAX_PROOF_BYTES = 8 * 1024
MAX_JTI_LENGTH = 256
# Members whose presence would mean the client published its private key.
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
# RFC 7638: the required members per key type, in lexicographic order.
THUMBPRINT_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
    "RSA": ("e", "kty", "n"),
}
_NONCE_SALT = "accounts.dpop.nonce"


class DPoPError(Exception):
    """The proof must be rejected; the message is safe to return to the client."""

    error = "invalid_dpop_proof"


class DPoPNonceRequiredError(DPoPError):
    """The proof lacks a current server nonce; the client retries with ``DPoP-Nonce``."""

    error = "use_dpop_nonce"


@dataclass(frozen=True)
class Proof:
    jkt: str
    jti: str


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    members = THUMBPRINT_MEMBERS.get(str(jwk.get("kty")))
    if members is None or any(not isinstance(jwk.get(m), str) for m in members):
        raise DPoPError("Unsupported or incomplete jwk")
    canonical = json.dumps({m: jwk[m] for m in members}, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _window(now: float) -> int:
    return int(now // settings.DPOP_NONCE_LIFETIME_SECONDS)


def _nonce_for(window: int) -> str:
    mac = salted_hmac(_NONCE_SALT, str(window), algorithm="sha256").digest()
    return f"{window}.{base64.urlsafe_b64encode(mac[:18]).decode()}"


def new_nonce(now: float | None = None) -> str:
    """A stateless nonce: valid for the current and the previous lifetime window."""
    return _nonce_for(_window(time.time() if now is None else now))


def nonce_is_valid(nonce: object, now: float) -> bool:
    if not isinstance(nonce, str) or len(nonce) > 64:
        return False
    current = _window(now)
    return any(constant_time_compare(nonce, _nonce_for(w)) for w in (current, current - 1))


def normalise_url(url: str) -> str:
    """Scheme and host lower-cased, default port dropped, no query or fragment (RFC 9449 4.3)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    default = {"http": 80, "https": 443}.get(parts.scheme.lower())
    netloc = host if parts.port in (None, default) else f"{host}:{parts.port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", "", ""))


def validate_proof(proof: str, *, method: str, url: str, now: float | None = None) -> Proof:
    now = time.time() if now is None else now
    if len(proof.encode()) > MAX_PROOF_BYTES:
        raise DPoPError("DPoP proof is too large")
    try:
        header = jwt.get_unverified_header(proof)
    except jwt.PyJWTError as exc:
        raise DPoPError("Malformed DPoP proof") from exc

    if header.get("typ") != "dpop+jwt":
        raise DPoPError("DPoP proof must have typ dpop+jwt")
    algorithm = header.get("alg")
    if algorithm not in ALLOWED_ALGORITHMS:
        raise DPoPError("DPoP proof must use an asymmetric algorithm")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise DPoPError("DPoP proof must carry the public key in its jwk header")
    if PRIVATE_JWK_MEMBERS & jwk.keys():
        raise DPoPError("The jwk header must not contain private key material")
    jkt = jwk_thumbprint(jwk)

    try:
        key = jwt.PyJWK.from_dict(jwk, algorithm=str(algorithm))
        claims: dict[str, Any] = jwt.decode(
            proof,
            key.key,
            algorithms=[str(algorithm)],
            # iat is checked below, both directions, with a precise message.
            options={
                "require": ["jti", "htm", "htu", "iat"],
                "verify_aud": False,
                "verify_iat": False,
            },
        )
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise DPoPError("DPoP proof signature or claims are invalid") from exc

    jti = claims["jti"]
    if not isinstance(jti, str) or not 0 < len(jti) <= MAX_JTI_LENGTH:
        raise DPoPError("Invalid jti")
    if claims["htm"] != method:
        raise DPoPError("htm does not match the request method")
    if not isinstance(claims["htu"], str) or normalise_url(claims["htu"]) != normalise_url(url):
        raise DPoPError("htu does not match the request URL")
    issued_at = claims["iat"]
    max_age = settings.DPOP_PROOF_MAX_AGE_SECONDS
    if not isinstance(issued_at, int | float) or abs(now - issued_at) > max_age:
        raise DPoPError("DPoP proof is too old or from the future")
    if settings.DPOP_REQUIRE_NONCE and not nonce_is_valid(claims.get("nonce"), now):
        raise DPoPNonceRequiredError("A current DPoP nonce is required")

    # Replay: the same proof (key + jti) is accepted once while it is still fresh.
    replay_key = "dpop-jti:" + hashlib.sha256(f"{jkt}:{jti}".encode()).hexdigest()
    if not cache.add(replay_key, 1, timeout=2 * settings.DPOP_PROOF_MAX_AGE_SECONDS + 5):
        raise DPoPError("DPoP proof has already been used")
    return Proof(jkt=jkt, jti=jti)
