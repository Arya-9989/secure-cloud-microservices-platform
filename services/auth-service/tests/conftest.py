from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.cache import cache
from rest_framework.test import APIClient

from accounts.keys import get_key_set
from accounts.kms import LocalSigner
from accounts.models import Role, User

PASSWORD = "correct-horse-battery-staple"


def local_private_key() -> rsa.RSAPrivateKey:
    """The test suite signs with a file key; tests that forge tokens need it."""
    signer = get_key_set().signing
    assert isinstance(signer, LocalSigner)
    return signer.private_key


@pytest.fixture(autouse=True)
def _isolate_state() -> Iterator[None]:
    """Throttle counters live in the cache and keys are memoised; reset both per test."""
    cache.clear()
    get_key_set.cache_clear()
    yield
    get_key_set.cache_clear()


@pytest.fixture
def api() -> APIClient:
    return APIClient()


@pytest.fixture
def make_user(db: None) -> Callable[..., User]:
    counter = iter(range(1, 10_000))

    def _make(role: str = Role.USER, email: str | None = None, **extra: object) -> User:
        return User.objects.create_user(
            email=email or f"user{next(counter)}@example.com", password=PASSWORD, role=role, **extra
        )

    return _make


@pytest.fixture
def user(make_user: Callable[..., User]) -> User:
    return make_user(email="alice@example.com")


@pytest.fixture
def admin(make_user: Callable[..., User]) -> User:
    return make_user(role=Role.ADMIN, email="admin@example.com")


def login(api: APIClient, email: str, password: str = PASSWORD) -> dict[str, Any]:
    response = api.post(
        "/api/v1/auth/token/", {"email": email, "password": password}, format="json"
    )
    assert response.status_code == 200, response.content
    body: dict[str, Any] = response.json()
    return body


@pytest.fixture
def bearer(api: APIClient) -> Callable[[User], dict[str, Any]]:
    def _bearer(account: User) -> dict[str, Any]:
        tokens = login(api, account.email)
        return {"HTTP_AUTHORIZATION": f"Bearer {tokens['access_token']}"}

    return _bearer
