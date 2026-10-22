"""Idempotency-Key on POST /api/v1/orders, through the gateway (docs/adr/0003)."""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx

from conftest import GATEWAY_URL, Account, register_and_login

ORDER = {"lines": [{"sku": "MS-002", "quantity": 1}]}


def place(account: Account, key: str, body: object = ORDER) -> httpx.Response:
    with httpx.Client(base_url=GATEWAY_URL, timeout=15) as client:
        return client.post(
            "/api/v1/orders", json=body, headers={**account.headers, "Idempotency-Key": key}
        )


class TestIdempotency:
    def test_a_retried_order_is_placed_once(self, gateway: httpx.Client) -> None:
        account = register_and_login(gateway)
        key = str(uuid.uuid4())

        first = place(account, key)
        retry = place(account, key)

        assert first.status_code == retry.status_code == 201
        assert retry.headers["Idempotent-Replayed"] == "true"
        assert retry.json() == first.json()
        assert retry.headers["Location"] == first.headers["Location"]
        listed = gateway.get("/api/v1/orders", headers=account.headers).json()
        assert listed["totalItems"] == 1

    def test_concurrent_duplicates_place_one_order(self, gateway: httpx.Client) -> None:
        account = register_and_login(gateway)
        key = str(uuid.uuid4())

        with ThreadPoolExecutor(max_workers=6) as pool:
            responses = list(pool.map(lambda _: place(account, key), range(6)))

        assert [r.status_code for r in responses] == [201] * 6
        assert len({r.json()["id"] for r in responses}) == 1
        assert sum("Idempotent-Replayed" in r.headers for r in responses) == 5
        listed = gateway.get("/api/v1/orders", headers=account.headers).json()
        assert listed["totalItems"] == 1

    def test_the_same_key_for_another_request_is_rejected(self, gateway: httpx.Client) -> None:
        account = register_and_login(gateway)
        key = str(uuid.uuid4())
        place(account, key)

        other = place(account, key, {"lines": [{"sku": "MS-002", "quantity": 2}]})

        assert other.status_code == 422
        assert other.headers["Content-Type"].startswith("application/problem+json")

    def test_keys_belong_to_one_customer(
        self, gateway: httpx.Client, alice: Account, bob: Account
    ) -> None:
        key = str(uuid.uuid4())

        alices = place(alice, key)
        bobs = place(bob, key)

        assert bobs.status_code == 201
        assert "Idempotent-Replayed" not in bobs.headers
        assert bobs.json()["id"] != alices.json()["id"]

    def test_a_malformed_key_is_a_bad_request(self, alice: Account) -> None:
        assert place(alice, "short").status_code == 400
