"""Password change, account deletion, admin user search and the audit trail."""

from __future__ import annotations

import json
from collections.abc import Callable
from io import StringIO
from typing import Any

import pytest
from django.core.management import call_command
from rest_framework.test import APIClient

from accounts.models import AuditAction, AuditEvent, OAuthClient, RefreshToken, Role, User
from accounts.throttles import AccountChangeThrottle

from .conftest import PASSWORD, login

pytestmark = pytest.mark.django_db

Bearer = Callable[[User], dict[str, Any]]
NEW_PASSWORD = "a-brand-new-long-passphrase-42"


def change(api: APIClient, headers: dict[str, Any], current: str, new: str) -> Any:
    return api.post(
        "/api/v1/auth/password/",
        {"current_password": current, "new_password": new},
        format="json",
        **headers,
    )


class TestPasswordChange:
    def test_changes_the_password_and_signs_out_every_session(
        self, api: APIClient, user: User, bearer: Bearer
    ) -> None:
        laptop = login(api, user.email)
        headers = bearer(user)  # a second session

        response = change(api, headers, PASSWORD, NEW_PASSWORD)

        assert response.status_code == 204
        assert not RefreshToken.objects.filter(user=user, revoked_at__isnull=True).exists()
        refresh = api.post(
            "/api/v1/auth/token/refresh/", {"refresh_token": laptop["refresh_token"]}, format="json"
        )
        assert refresh.status_code == 401
        old = api.post(
            "/api/v1/auth/token/", {"email": user.email, "password": PASSWORD}, format="json"
        )
        assert old.status_code == 401
        assert login(api, user.email, NEW_PASSWORD)["access_token"]

    def test_the_current_password_is_required(
        self, api: APIClient, user: User, bearer: Bearer
    ) -> None:
        response = change(api, bearer(user), "not-my-password-123", NEW_PASSWORD)

        assert response.status_code == 400
        assert "current_password" in response.json()["errors"]
        user.refresh_from_db()
        assert user.check_password(PASSWORD)

    @pytest.mark.parametrize("weak", ["short", "123456789012", PASSWORD, "password1234"])
    def test_weak_or_unchanged_passwords_are_refused(
        self, api: APIClient, user: User, bearer: Bearer, weak: str
    ) -> None:
        response = change(api, bearer(user), PASSWORD, weak)

        assert response.status_code == 400
        assert "new_password" in json.dumps(response.json())

    def test_anonymous_callers_cannot_change_a_password(self, api: APIClient) -> None:
        assert change(api, {}, PASSWORD, NEW_PASSWORD).status_code == 401

    def test_guessing_the_current_password_is_throttled(
        self, api: APIClient, user: User, bearer: Bearer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(AccountChangeThrottle, "rate", "3/hour", raising=False)
        headers = bearer(user)

        statuses = [
            change(api, headers, f"guess-number-{n}-xx", NEW_PASSWORD).status_code for n in range(4)
        ]

        assert statuses == [400, 400, 400, 429]

    def test_is_audited_without_secrets(self, api: APIClient, user: User, bearer: Bearer) -> None:
        change(api, bearer(user), PASSWORD, NEW_PASSWORD)

        event = AuditEvent.objects.get(action=AuditAction.PASSWORD_CHANGED)
        assert event.target_id == event.actor_id == str(user.pk)
        assert event.details["sessions_revoked"] >= 1
        assert event.source_ip == "127.0.0.1"
        serialized = json.dumps(event.details)
        assert PASSWORD not in serialized
        assert NEW_PASSWORD not in serialized


def delete_account(api: APIClient, headers: dict[str, Any], password: str) -> Any:
    return api.delete("/api/v1/auth/me/", {"password": password}, format="json", **headers)


class TestAccountDeletion:
    def test_deletes_the_account_and_its_sessions(
        self, api: APIClient, user: User, bearer: Bearer
    ) -> None:
        session = login(api, user.email)
        headers = bearer(user)
        user_id = str(user.pk)

        response = delete_account(api, headers, PASSWORD)

        assert response.status_code == 204
        assert not User.objects.filter(pk=user_id).exists()
        assert not RefreshToken.objects.filter(user_id=user_id).exists()
        assert api.get("/api/v1/auth/me/", **headers).status_code == 401  # token, no account
        refresh = api.post(
            "/api/v1/auth/token/refresh/",
            {"refresh_token": session["refresh_token"]},
            format="json",
        )
        assert refresh.status_code == 401
        event = AuditEvent.objects.get(action=AuditAction.ACCOUNT_DELETED)
        assert event.target_id == user_id
        assert user.email not in json.dumps(event.details), "no personal data kept"

    def test_the_password_must_confirm_the_deletion(
        self, api: APIClient, user: User, bearer: Bearer
    ) -> None:
        response = delete_account(api, bearer(user), "wrong-password-1234")

        assert response.status_code == 400
        assert User.objects.filter(pk=user.pk).exists()

    def test_the_last_administrator_cannot_delete_themselves(
        self, api: APIClient, admin: User, bearer: Bearer, make_user: Callable[..., User]
    ) -> None:
        refused = delete_account(api, bearer(admin), PASSWORD)
        assert refused.status_code == 400
        assert User.objects.filter(pk=admin.pk).exists()

        make_user(role=Role.ADMIN, email="second-admin@example.com")
        assert delete_account(api, bearer(admin), PASSWORD).status_code == 204

    def test_reading_the_profile_is_not_throttled(
        self, api: APIClient, user: User, bearer: Bearer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(AccountChangeThrottle, "rate", "1/hour", raising=False)
        headers = bearer(user)

        assert [api.get("/api/v1/auth/me/", **headers).status_code for _ in range(3)] == [200] * 3


class TestAdminUserSearch:
    @pytest.fixture
    def people(self, make_user: Callable[..., User]) -> None:
        make_user(email="ada@example.com")
        make_user(email="grace@example.com", role=Role.ADMIN)
        make_user(email="linus@example.org", is_active=False)

    def emails(self, api: APIClient, headers: dict[str, Any], query: str) -> set[str]:
        response = api.get(f"/api/v1/admin/users/?{query}", **headers)
        assert response.status_code == 200, response.content
        return {u["email"] for u in response.json()["results"]}

    def test_filters_by_email_role_and_status(
        self, api: APIClient, admin: User, bearer: Bearer, people: None
    ) -> None:
        headers = bearer(admin)

        assert self.emails(api, headers, "email=EXAMPLE.ORG") == {"linus@example.org"}
        assert self.emails(api, headers, "role=ADMIN") == {"grace@example.com", admin.email}
        assert self.emails(api, headers, "is_active=false") == {"linus@example.org"}
        assert self.emails(api, headers, "email=ada&role=USER&is_active=true") == {
            "ada@example.com"
        }

    @pytest.mark.parametrize("query", ["role=ROOT", "is_active=yes", "email=" + "x" * 255])
    def test_invalid_filters_are_rejected(
        self, api: APIClient, admin: User, bearer: Bearer, query: str
    ) -> None:
        assert api.get(f"/api/v1/admin/users/?{query}", **bearer(admin)).status_code == 400

    def test_regular_users_cannot_search(self, api: APIClient, user: User, bearer: Bearer) -> None:
        assert api.get("/api/v1/admin/users/?email=a", **bearer(user)).status_code == 403


class TestAuditTrail:
    def test_admin_changes_are_recorded_with_before_and_after(
        self, api: APIClient, admin: User, user: User, bearer: Bearer
    ) -> None:
        headers = bearer(admin)
        api.patch(f"/api/v1/admin/users/{user.pk}/", {"role": "ADMIN"}, format="json", **headers)
        api.patch(f"/api/v1/admin/users/{user.pk}/", {"role": "ADMIN"}, format="json", **headers)

        events = api.get(
            f"/api/v1/admin/audit-events/?action=ADMIN_USER_UPDATED&target_id={user.pk}", **headers
        ).json()["results"]

        assert len(events) == 1, "a no-op update is not an event"
        assert events[0]["actor_id"] == str(admin.pk)
        assert events[0]["details"] == {"role": {"from": "USER", "to": "ADMIN"}}
        assert events[0]["request_id"]

    def test_only_administrators_can_read_it_and_nobody_can_change_it(
        self, api: APIClient, admin: User, user: User, bearer: Bearer
    ) -> None:
        assert api.get("/api/v1/admin/audit-events/", **bearer(user)).status_code == 403
        assert api.get("/api/v1/admin/audit-events/").status_code == 401
        headers = bearer(admin)
        assert (
            api.post("/api/v1/admin/audit-events/", {}, format="json", **headers).status_code == 405
        )
        assert api.get("/api/v1/admin/audit-events/?action=NOPE", **headers).status_code == 400

    def test_client_provisioning_is_recorded_only_when_something_changes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("S", "s3cret-for-tests-0123456789-abcdefghij")
        args = [
            "svc",
            "--secret-env",
            "S",
            "--scope",
            "orders:fulfil",
            "--audience",
            "urn:secure-platform:orders-service",
        ]

        for _ in range(3):
            call_command("ensure_oauth_client", *args, stdout=StringIO())

        events = AuditEvent.objects.filter(action=AuditAction.OAUTH_CLIENT_PROVISIONED)
        assert events.count() == 1
        assert events.get().details["created"] is True
        assert "s3cret" not in json.dumps(events.get().details)
        assert OAuthClient.objects.get().client_id == "svc"
