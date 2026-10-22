"""Fixtures for black-box tests against a running stack (`docker compose up --wait`).

Configuration comes from the environment, falling back to the repository's
.env file (written by scripts/init_env.py):

    GATEWAY_URL        default http://localhost:$GATEWAY_HTTP_PORT (8080)
    GATEWAY_HTTPS_URL  default https://localhost:$GATEWAY_HTTPS_PORT (8443)
    PROMETHEUS_URL     default http://localhost:$PROMETHEUS_PORT (9090)
    GRAFANA_URL        default http://localhost:$GRAFANA_PORT (3000)
    AUTH_BOOTSTRAP_ADMIN_EMAIL / AUTH_BOOTSTRAP_ADMIN_PASSWORD
    GRAFANA_ADMIN_USER / GRAFANA_ADMIN_PASSWORD
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "e2e-Correct-Horse-Battery-9"


def _dotenv() -> dict[str, str]:
    path = REPO_ROOT / ".env"
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and not line.lstrip().startswith("#"):
            values[key.strip()] = value.strip()
    return values


_DOTENV = _dotenv()


def setting(name: str, default: str | None = None) -> str:
    value = os.environ.get(name) or _DOTENV.get(name) or default
    if value is None:
        pytest.fail(f"{name} is not configured (env or .env)")
    return value


GATEWAY_URL = setting("GATEWAY_URL", "http://localhost:" + setting("GATEWAY_HTTP_PORT", "8080"))
GATEWAY_HTTPS_URL = setting(
    "GATEWAY_HTTPS_URL", "https://localhost:" + setting("GATEWAY_HTTPS_PORT", "8443")
)
PROMETHEUS_URL = setting("PROMETHEUS_URL", "http://localhost:" + setting("PROMETHEUS_PORT", "9090"))
GRAFANA_URL = setting("GRAFANA_URL", "http://localhost:" + setting("GRAFANA_PORT", "3000"))


@dataclass
class Account:
    email: str
    password: str
    access_token: str
    refresh_token: str
    user_id: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}


def eventually(check: Callable[[], None], timeout: float = 60, interval: float = 2) -> None:
    """Retry an assertion until it passes (metrics need a scrape interval to appear)."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            check()
            return
        except AssertionError:
            if time.monotonic() > deadline:
                raise
            time.sleep(interval)


@pytest.fixture(scope="session")
def gateway() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=GATEWAY_URL, timeout=15) as client:
        eventually(lambda: _assert_ready(client), timeout=120)
        yield client


def _assert_ready(client: httpx.Client) -> None:
    try:
        jwks = client.get("/.well-known/jwks.json").status_code
        products = client.get("/api/v1/products").status_code  # 401 means routed + up
    except httpx.TransportError as exc:
        raise AssertionError(str(exc)) from exc
    assert (jwks, products) == (200, 401)


def login(client: httpx.Client, email: str, password: str) -> httpx.Response:
    return client.post("/api/v1/auth/token/", json={"email": email, "password": password})


def register_and_login(client: httpx.Client) -> Account:
    email = f"e2e-{uuid.uuid4().hex[:12]}@example.com"
    registered = client.post("/api/v1/auth/register/", json={"email": email, "password": PASSWORD})
    assert registered.status_code == 201, registered.text
    tokens = login(client, email, PASSWORD)
    assert tokens.status_code == 200, tokens.text
    body = tokens.json()
    return Account(
        email, PASSWORD, body["access_token"], body["refresh_token"], registered.json()["id"]
    )


@pytest.fixture(scope="session")
def alice(gateway: httpx.Client) -> Account:
    return register_and_login(gateway)


@pytest.fixture(scope="session")
def bob(gateway: httpx.Client) -> Account:
    return register_and_login(gateway)


@pytest.fixture(scope="session")
def admin(gateway: httpx.Client) -> Account:
    email = setting("AUTH_BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
    password = setting("AUTH_BOOTSTRAP_ADMIN_PASSWORD")
    response = login(gateway, email, password)
    assert response.status_code == 200, response.text
    body = response.json()
    me = gateway.get(
        "/api/v1/auth/me/", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    return Account(email, password, body["access_token"], body["refresh_token"], me.json()["id"])
