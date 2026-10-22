"""Service to service through the gateway: client credentials + DPoP (docs/adr/0006).

The test plays the warehouse: it holds an EC key, obtains a DPoP-bound token from
auth-service with its client secret, and ships an order at orders-service, doing
the RFC 9449 nonce handshake with both servers.
"""

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from conftest import GATEWAY_URL, Account, setting

TOKEN_PATH = "/api/v1/auth/oauth/token"
QUEUE_PATH = "/api/v1/fulfilment/orders"
ORDER = {"lines": [{"sku": "CB-HDMI-2", "quantity": 1}]}


class DPoPClient:
    """A minimal DPoP client: signs one proof per request, follows DPoP-Nonce."""

    def __init__(self, client: httpx.Client) -> None:
        self.http = client
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.jwk: dict[str, Any] = ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        self.nonce: str | None = None

    def proof(self, method: str, path: str, token: str | None = None, **claims: Any) -> str:
        body: dict[str, Any] = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": GATEWAY_URL + path,
            "iat": int(time.time()),
        }
        if self.nonce:
            body["nonce"] = self.nonce
        if token:
            digest = hashlib.sha256(token.encode()).digest()
            body["ath"] = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        body.update(claims)
        return jwt.encode(
            body, self.key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": self.jwk}
        )

    def send(
        self, method: str, path: str, *, token: str | None = None, retry: bool = True, **kwargs: Any
    ) -> httpx.Response:
        """One request, retried once if the server asks for a (new) nonce."""
        headers = {"DPoP": self.proof(method, path, token)}
        if token:
            headers["Authorization"] = f"DPoP {token}"
        response = self.http.request(method, path, headers=headers, **kwargs)
        self.nonce = response.headers.get("DPoP-Nonce", self.nonce)
        challenge = response.text + response.headers.get("WWW-Authenticate", "")
        if retry and "use_dpop_nonce" in challenge:
            return self.send(method, path, token=token, retry=False, **kwargs)
        return response

    def token(self) -> str:
        secret = setting("FULFILMENT_CLIENT_SECRET")
        response = self.send(
            "POST",
            TOKEN_PATH,
            data={"grant_type": "client_credentials"},
            auth=("fulfilment", secret),
        )
        assert response.status_code == 200, response.text
        assert response.json()["token_type"] == "DPoP"
        return str(response.json()["access_token"])


@pytest.fixture
def warehouse(gateway: httpx.Client) -> DPoPClient:
    return DPoPClient(gateway)


def confirmed_order(gateway: httpx.Client, customer: Account, admin: Account) -> str:
    order_id = str(
        gateway.post("/api/v1/orders", json=ORDER, headers=customer.headers).json()["id"]
    )
    confirm = gateway.patch(
        f"/api/v1/admin/orders/{order_id}/status",
        json={"status": "CONFIRMED"},
        headers=admin.headers,
    )
    assert confirm.status_code == 200, confirm.text
    return order_id


class TestServiceToService:
    def test_the_warehouse_ships_an_order_with_a_dpop_bound_token(
        self, gateway: httpx.Client, warehouse: DPoPClient, alice: Account, admin: Account
    ) -> None:
        order_id = confirmed_order(gateway, alice, admin)
        token = warehouse.token()

        queue = warehouse.send("GET", QUEUE_PATH, token=token)
        shipped = warehouse.send(
            "PATCH", f"{QUEUE_PATH}/{order_id}/status", token=token, json={"status": "SHIPPED"}
        )

        assert queue.status_code == 200, queue.text
        assert order_id in [item["id"] for item in queue.json()["items"]]
        assert shipped.status_code == 200, shipped.text
        assert shipped.json()["status"] == "SHIPPED"
        seen_by_customer = gateway.get(f"/api/v1/orders/{order_id}", headers=alice.headers)
        assert seen_by_customer.json()["status"] == "SHIPPED"

    def test_a_stolen_token_is_useless_without_the_key(
        self, gateway: httpx.Client, warehouse: DPoPClient
    ) -> None:
        token = warehouse.token()
        thief = DPoPClient(gateway)  # has the token, not the key
        thief.nonce = warehouse.nonce

        as_bearer = gateway.get(QUEUE_PATH, headers={"Authorization": f"Bearer {token}"})
        with_own_key = thief.send("GET", QUEUE_PATH, token=token)

        assert as_bearer.status_code == 401
        assert 'error="invalid_token"' in as_bearer.headers["WWW-Authenticate"]
        assert with_own_key.status_code == 401

    def test_a_captured_proof_cannot_be_replayed(
        self, gateway: httpx.Client, warehouse: DPoPClient
    ) -> None:
        token = warehouse.token()
        warehouse.send("GET", QUEUE_PATH, token=token)  # learn the resource server's nonce
        proof = warehouse.proof("GET", QUEUE_PATH, token)
        headers = {"Authorization": f"DPoP {token}", "DPoP": proof}

        first = gateway.get(QUEUE_PATH, headers=headers)
        replay = gateway.get(QUEUE_PATH, headers=headers)

        assert first.status_code == 200, first.text
        assert replay.status_code == 401

    def test_the_client_token_cannot_act_as_a_customer_or_an_admin(
        self, gateway: httpx.Client, warehouse: DPoPClient
    ) -> None:
        token = warehouse.token()

        for path in ("/api/v1/orders", "/api/v1/admin/orders", "/api/v1/auth/me/"):
            response = warehouse.send("GET", path, token=token)
            assert response.status_code in (401, 403), (path, response.status_code)

    def test_wrong_client_secret_and_people_tokens_are_refused(
        self, gateway: httpx.Client, warehouse: DPoPClient, admin: Account
    ) -> None:
        wrong = gateway.post(
            TOKEN_PATH,
            data={"grant_type": "client_credentials"},
            auth=("fulfilment", "not-the-secret-not-the-secret-000"),
            headers={"DPoP": warehouse.proof("POST", TOKEN_PATH)},
        )
        admin_at_fulfilment = gateway.get(QUEUE_PATH, headers=admin.headers)

        assert wrong.status_code == 401
        assert wrong.json()["error"] == "invalid_client"
        assert admin_at_fulfilment.status_code == 403
