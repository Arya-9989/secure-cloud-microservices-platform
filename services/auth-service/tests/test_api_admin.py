from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from rest_framework.test import APIClient

from accounts.models import RefreshToken, Role, User

from .conftest import login

pytestmark = pytest.mark.django_db

Bearer = Callable[[User], dict[str, Any]]


def test_admin_endpoints_require_authentication(api: APIClient) -> None:
    assert api.get("/api/v1/admin/users/").status_code == 401


def test_regular_users_are_forbidden(api: APIClient, user: User, bearer: Bearer) -> None:
    headers = bearer(user)

    assert api.get("/api/v1/admin/users/", **headers).status_code == 403
    assert (
        api.patch(
            f"/api/v1/admin/users/{user.pk}/", {"role": "ADMIN"}, format="json", **headers
        ).status_code
        == 403
    )
    assert User.objects.get(pk=user.pk).role == Role.USER


def test_admin_can_list_users(api: APIClient, admin: User, user: User, bearer: Bearer) -> None:
    response = api.get("/api/v1/admin/users/", **bearer(admin))

    assert response.status_code == 200
    assert response.json()["count"] == 2
    assert {u["email"] for u in response.json()["results"]} == {admin.email, user.email}


def test_disabling_a_user_revokes_their_sessions(
    api: APIClient, admin: User, user: User, bearer: Bearer
) -> None:
    session = login(api, user.email)

    response = api.patch(
        f"/api/v1/admin/users/{user.pk}/", {"is_active": False}, format="json", **bearer(admin)
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is False
    assert not RefreshToken.objects.filter(user=user, revoked_at__isnull=True).exists()
    refresh = api.post(
        "/api/v1/auth/token/refresh/", {"refresh_token": session["refresh_token"]}, format="json"
    )
    assert refresh.status_code == 401


def test_promoting_a_user_takes_effect_on_next_login(
    api: APIClient, admin: User, user: User, bearer: Bearer
) -> None:
    response = api.patch(
        f"/api/v1/admin/users/{user.pk}/", {"role": "ADMIN"}, format="json", **bearer(admin)
    )

    assert response.status_code == 200
    assert "users:admin" in login(api, user.email)["scope"]


def test_admin_cannot_lock_themselves_out(api: APIClient, admin: User, bearer: Bearer) -> None:
    response = api.patch(
        f"/api/v1/admin/users/{admin.pk}/", {"is_active": False}, format="json", **bearer(admin)
    )

    assert response.status_code == 400
    assert User.objects.get(pk=admin.pk).is_active


def test_invalid_role_is_rejected(api: APIClient, admin: User, user: User, bearer: Bearer) -> None:
    response = api.patch(
        f"/api/v1/admin/users/{user.pk}/", {"role": "ROOT"}, format="json", **bearer(admin)
    )

    assert response.status_code == 400


def test_unknown_user_is_404(api: APIClient, admin: User, bearer: Bearer) -> None:
    response = api.get(f"/api/v1/admin/users/{uuid.uuid4()}/", **bearer(admin))

    assert response.status_code == 404
    assert response["Content-Type"] == "application/problem+json"
