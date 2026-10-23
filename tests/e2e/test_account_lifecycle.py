"""Account lifecycle through the gateway: password change, deletion, admin search, audit trail."""

from __future__ import annotations

import httpx

from conftest import PASSWORD, Account, login, register_and_login

NEW_PASSWORD = "e2e-Another-Long-Passphrase-77"


def audit_events(gateway: httpx.Client, admin: Account, **params: str) -> list[dict[str, object]]:
    response = gateway.get("/api/v1/admin/audit-events/", params=params, headers=admin.headers)
    assert response.status_code == 200, response.text
    results: list[dict[str, object]] = response.json()["results"]
    return results


class TestAccountLifecycle:
    def test_changing_the_password_signs_out_every_session(
        self, gateway: httpx.Client, admin: Account
    ) -> None:
        account = register_and_login(gateway)

        changed = gateway.post(
            "/api/v1/auth/password/",
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            headers=account.headers,
        )
        refresh = gateway.post(
            "/api/v1/auth/token/refresh/", json={"refresh_token": account.refresh_token}
        )

        assert changed.status_code == 204, changed.text
        assert refresh.status_code == 401
        assert login(gateway, account.email, PASSWORD).status_code == 401
        assert login(gateway, account.email, NEW_PASSWORD).status_code == 200
        events = audit_events(gateway, admin, action="PASSWORD_CHANGED", target_id=account.user_id)
        assert len(events) == 1

    def test_deleting_an_account_erases_it_and_leaves_an_audit_record(
        self, gateway: httpx.Client, admin: Account
    ) -> None:
        account = register_and_login(gateway)

        deleted = gateway.request(
            "DELETE", "/api/v1/auth/me/", json={"password": PASSWORD}, headers=account.headers
        )

        assert deleted.status_code == 204, deleted.text
        assert login(gateway, account.email, PASSWORD).status_code == 401
        found = gateway.get(
            "/api/v1/admin/users/", params={"email": account.email}, headers=admin.headers
        )
        assert found.json()["count"] == 0
        (event,) = audit_events(gateway, admin, action="ACCOUNT_DELETED", target_id=account.user_id)
        assert account.email not in str(event)

    def test_administrators_can_find_users(self, gateway: httpx.Client, admin: Account) -> None:
        account = register_and_login(gateway)

        response = gateway.get(
            "/api/v1/admin/users/",
            params={"email": account.email.upper(), "role": "USER", "is_active": "true"},
            headers=admin.headers,
        )

        assert response.status_code == 200
        assert [u["id"] for u in response.json()["results"]] == [account.user_id]

    def test_customers_cannot_read_the_audit_trail(
        self, gateway: httpx.Client, alice: Account
    ) -> None:
        response = gateway.get("/api/v1/admin/audit-events/", headers=alice.headers)

        assert response.status_code == 403
