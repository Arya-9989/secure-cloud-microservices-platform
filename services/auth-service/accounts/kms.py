"""Signing keys behind a KMS, and when each key version may sign (docs/adr/0007).

* ``Signer``: what token issuance needs, a ``kid`` and ``sign(message)``. ``LocalSigner``
  wraps a PEM private key; ``VaultTransitSigner`` asks Vault transit to sign, so the
  private key never exists in this process.
* ``plan_rotation``: from the key versions and the current time, which version signs
  and which versions are published in the JWKS. New versions are published before they
  sign; old versions stay published until every token they signed has expired.
* ``VaultTransit``: a minimal, timeout- and retry-bounded client for the transit API.
"""

from __future__ import annotations

import base64
import json
import logging
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from rest_framework.exceptions import APIException

logger = logging.getLogger(__name__)

MIN_RSA_KEY_BITS = 2048


class SigningUnavailableError(APIException):
    """The KMS could not sign right now: 503 with Retry-After, never 500.

    ``reason`` is for logs only; clients get a generic message, so Vault addresses,
    paths and errors never leak into responses.
    """

    status_code = 503
    default_detail = "Tokens cannot be issued right now. Retry shortly."
    default_code = "signing_unavailable"

    def __init__(self, reason: str) -> None:
        super().__init__()
        self.reason = reason
        logger.warning("Signing unavailable", extra={"reason": reason})


class Signer(Protocol):
    @property
    def kid(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


@dataclass(frozen=True)
class LocalSigner:
    """RS256 with a private key held in memory (read from a PEM file)."""

    private_key: rsa.RSAPrivateKey
    kid: str

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


# --------------------------------------------------------------------------- rotation plan


@dataclass(frozen=True)
class KeyVersion:
    version: int
    created_at: float  # epoch seconds
    public_key: rsa.RSAPublicKey


@dataclass(frozen=True)
class RotationPlan:
    signing: KeyVersion
    published: tuple[KeyVersion, ...]
    # When each published version that no longer signs drops out of the JWKS.
    retires_at: dict[int, float]


def plan_rotation(
    versions: Sequence[KeyVersion], now: float, *, publish_ahead: float, retire_after: float
) -> RotationPlan:
    """Decide which version signs and which are published, so rotation never breaks a token.

    * A version may sign once it has been published for ``publish_ahead`` seconds, so every
      JWKS cache has seen it before the first token signed with it arrives.
    * The newest version that may sign, signs. If none may yet (a brand-new key), the oldest
      one does, so bootstrap never stalls.
    * A version that stopped signing at time T stays published until T + ``retire_after``
      (the longest token lifetime plus clock skew), so every token it signed still verifies.
    * Versions newer than the signing one are published ahead of use.
    """
    if not versions:
        raise ValueError("no key versions")
    ordered = sorted(versions, key=lambda v: v.version)
    eligible = [v for v in ordered if v.created_at + publish_ahead <= now]
    signing = eligible[-1] if eligible else ordered[0]

    published: list[KeyVersion] = []
    retires_at: dict[int, float] = {}
    for index, version in enumerate(ordered):
        if version.version >= signing.version:
            published.append(version)
            continue
        successor = ordered[index + 1]
        stopped_signing = successor.created_at + publish_ahead
        retire = stopped_signing + retire_after
        if now < retire:
            published.append(version)
            retires_at[version.version] = retire
    return RotationPlan(signing=signing, published=tuple(published), retires_at=retires_at)


# --------------------------------------------------------------------------- Vault transit


def _parse_time(value: str) -> float:
    # Vault reports RFC 3339 with nanoseconds, e.g. 2026-10-23T01:02:03.123456789Z
    head, _, frac = value.rstrip("Z").partition(".")
    seconds = datetime.fromisoformat(head + "+00:00").timestamp()
    return seconds + (float("0." + frac[:6]) if frac else 0.0)


class VaultTransit:
    """The handful of transit endpoints auth-service needs, with timeouts and retries."""

    def __init__(
        self,
        address: str,
        token: Callable[[], str],
        key_name: str,
        mount: str = "transit",
        timeout: float = 2.0,
        retries: int = 2,
    ) -> None:
        self.address = address.rstrip("/")
        self.token = token
        self.key_name = key_name
        self.mount = mount.strip("/")
        self.timeout = timeout
        self.retries = retries

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(  # noqa: S310 - the address is configuration
                f"{self.address}/v1/{path}", data=data, method=method
            )
            request.add_header("X-Vault-Token", self.token())
            request.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                    raw = response.read()
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError as exc:
                if exc.code < 500:  # a client error will not go away by retrying
                    raise SigningUnavailableError(
                        f"Vault rejected {path}: HTTP {exc.code}"
                    ) from exc
                last = exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last = exc
            if attempt < self.retries:
                time.sleep(0.2 * (2**attempt))
        raise SigningUnavailableError(f"Vault unreachable for {path}: {last}") from last

    def key_versions(self) -> list[KeyVersion]:
        body = self._request("GET", f"{self.mount}/keys/{self.key_name}")
        data = body["data"]
        if not str(data.get("type", "")).startswith("rsa-"):
            raise SigningUnavailableError(f"transit key {self.key_name} is not an RSA key")
        versions = []
        for number, info in data["keys"].items():
            public_key = serialization.load_pem_public_key(info["public_key"].encode())
            if (
                not isinstance(public_key, rsa.RSAPublicKey)
                or public_key.key_size < MIN_RSA_KEY_BITS
            ):
                raise SigningUnavailableError("transit key versions must be RSA >= 2048 bits")
            versions.append(KeyVersion(int(number), _parse_time(info["creation_time"]), public_key))
        return versions

    def sign(self, version: int, message: bytes) -> bytes:
        body = self._request(
            "POST",
            f"{self.mount}/sign/{self.key_name}/sha2-256",
            {
                "input": base64.b64encode(message).decode(),
                "key_version": version,
                "signature_algorithm": "pkcs1v15",
            },
        )
        signature = str(body["data"]["signature"])
        prefix = f"vault:v{version}:"
        if not signature.startswith(prefix):
            raise SigningUnavailableError("Vault signed with an unexpected key version")
        return base64.b64decode(signature[len(prefix) :])

    def rotate(self) -> None:
        self._request("POST", f"{self.mount}/keys/{self.key_name}/rotate", {})

    def renew_token(self) -> None:
        self._request("POST", "auth/token/renew-self", {})


@dataclass(frozen=True)
class VaultTransitSigner:
    transit: VaultTransit
    version: int
    kid: str

    def sign(self, message: bytes) -> bytes:
        return self.transit.sign(self.version, message)
