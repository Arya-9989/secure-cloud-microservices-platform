"""End-to-end tests: every request goes through the Traefik gateway to real services."""

from __future__ import annotations

import base64
import json
import re
import socket
import ssl
import uuid
from urllib.parse import urlparse

import httpx
import jwt
import pytest

from conftest import (
    GATEWAY_HTTPS_URL,
    GRAFANA_URL,
    PROMETHEUS_URL,
    REPO_ROOT,
    Account,
    eventually,
    login,
    register_and_login,
    setting,
)

ORDER = {"lines": [{"sku": "KB-001", "quantity": 2}, {"sku": "MS-002", "quantity": 1}]}


class TestGateway:
    def test_unknown_routes_never_reach_a_service(self, gateway: httpx.Client) -> None:
        paths = ("/admin/", "/actuator/prometheus", "/metrics", "/readyz", "/healthz", "/assets/")
        for path in paths:
            assert gateway.get(path).status_code == 404, path

    def test_landing_page_is_served_under_a_strict_csp(self, gateway: httpx.Client) -> None:
        response = gateway.get("/")
        csp = response.headers["Content-Security-Policy"]

        assert response.status_code == 200
        assert response.headers["Content-Type"].startswith("text/html")
        assert "<h1" in response.text
        assert re.search(r"<script(?![^>]*\bsrc=)", response.text) is None, "no inline <script>"
        assert "default-src 'none'" in csp
        assert "script-src 'self'" in csp
        assert "require-trusted-types-for 'script'" in csp
        assert "unsafe" not in csp
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Server" not in response.headers
        assert gateway.post("/").status_code == 405  # static site: GET and HEAD only
        assets = (
            "/assets/landing.css",
            "/assets/landing.js",
            "/assets/live.js",
            "/assets/docs.css",
        )
        for asset in assets:
            assert gateway.get(asset).status_code == 200, asset

    def test_api_docs_share_the_platform_theme_under_csp(self, gateway: httpx.Client) -> None:
        auth = gateway.get("/docs/auth/")
        orders = gateway.get("/docs/orders/swagger-ui.html", follow_redirects=True)

        for page in (auth, orders):
            csp = page.headers["Content-Security-Policy"]
            assert page.status_code == 200
            assert 'href="/assets/docs.css"' in page.text
            # Title and lead are server-rendered inside the <main> landmark.
            pattern = r"<main[ >].*<h1[^>]*>\w+ API reference[.]</h1>.*</main>"
            assert re.search(pattern, page.text, re.S)
            assert "script-src 'self'" in csp
            assert "unsafe" not in csp

    def test_api_docs_are_served_through_the_gateway(self, gateway: httpx.Client) -> None:
        auth_docs = gateway.get("/docs/auth/")
        orders_docs = gateway.get("/docs/orders/swagger-ui.html", follow_redirects=True)
        bundle = "/docs/auth/static/drf_spectacular_sidecar/swagger-ui-dist/swagger-ui-bundle.js"

        assert auth_docs.status_code == 200
        assert orders_docs.status_code == 200
        assert gateway.get(bundle).status_code == 200  # >1 MiB: exercises gateway buffering
        assert gateway.get("/docs/auth/openapi.json").status_code == 200
        assert gateway.get("/docs/orders/openapi.json").status_code == 200

    def test_security_headers_are_applied(self, gateway: httpx.Client) -> None:
        response = gateway.get("/.well-known/jwks.json")

        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "Server" not in response.headers

    def test_https_entrypoint_serves_hsts(self) -> None:
        # The local stack serves Traefik's self-signed default certificate.
        with httpx.Client(base_url=GATEWAY_HTTPS_URL, verify=False, timeout=10) as client:  # noqa: S501
            response = client.get("/.well-known/jwks.json")

        assert response.status_code == 200
        assert "max-age=31536000" in response.headers["Strict-Transport-Security"]

    @pytest.mark.parametrize(
        ("cipher", "accepted"),
        [("ECDHE-RSA-AES128-GCM-SHA256", True), ("ECDHE-RSA-AES128-SHA", False)],
    )
    def test_tls12_allows_only_aead_ciphers(self, cipher: str, accepted: bool) -> None:
        url = urlparse(GATEWAY_HTTPS_URL)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # local self-signed certificate
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(f"{cipher}:@SECLEVEL=0")

        def handshake() -> str | None:
            with (
                socket.create_connection((url.hostname, url.port or 443), timeout=10) as raw,
                context.wrap_socket(raw, server_hostname=url.hostname) as tls,
            ):
                negotiated = tls.cipher()
                return negotiated[0] if negotiated else None

        if accepted:
            assert handshake() == cipher
        else:
            with pytest.raises(ssl.SSLError):
                handshake()


class TestTokens:
    def test_access_token_verifies_offline_against_jwks(
        self, gateway: httpx.Client, alice: Account
    ) -> None:
        jwks = jwt.PyJWKSet.from_dict(gateway.get("/.well-known/jwks.json").json())
        kid = jwt.get_unverified_header(alice.access_token)["kid"]
        key = next(k for k in jwks.keys if k.key_id == kid)

        claims = jwt.decode(
            alice.access_token,
            key.key,
            algorithms=["RS256"],
            audience=setting("JWT_AUDIENCE", "secure-platform-api"),
            issuer=setting("JWT_ISSUER", "urn:secure-platform:auth-service"),
        )

        assert claims["sub"] == alice.user_id
        assert claims["roles"] == ["USER"]
        assert set(claims["scope"].split()) == {"orders:read", "orders:write"}

    def test_refresh_rotation_and_replay_detection(self, gateway: httpx.Client) -> None:
        account = register_and_login(gateway)
        url = "/api/v1/auth/token/refresh/"

        rotated = gateway.post(url, json={"refresh_token": account.refresh_token})
        replay = gateway.post(url, json={"refresh_token": account.refresh_token})
        after_replay = gateway.post(url, json={"refresh_token": rotated.json()["refresh_token"]})

        assert rotated.status_code == 200
        assert replay.status_code == 401
        assert after_replay.status_code == 401, "replay must revoke the whole session"

    def test_logout_revokes_the_session(self, gateway: httpx.Client) -> None:
        account = register_and_login(gateway)

        logout = gateway.post("/api/v1/auth/logout/", json={"refresh_token": account.refresh_token})
        refresh = gateway.post(
            "/api/v1/auth/token/refresh/", json={"refresh_token": account.refresh_token}
        )

        assert logout.status_code == 204
        assert refresh.status_code == 401

    def test_orders_service_rejects_forged_tokens(
        self, gateway: httpx.Client, alice: Account
    ) -> None:
        header, payload, signature = alice.access_token.split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims["roles"] = ["ADMIN"]
        claims["scope"] += " orders:admin"
        forged_payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        forged = f"{header}.{forged_payload}.{signature}"

        response = gateway.get(
            "/api/v1/admin/orders", headers={"Authorization": f"Bearer {forged}"}
        )

        assert response.status_code == 401
        assert response.headers["Content-Type"].startswith("application/problem+json")

    def test_login_is_rate_limited_per_account(self, gateway: httpx.Client) -> None:
        account = register_and_login(gateway)  # 1 successful login counts towards the limit
        statuses = [
            login(gateway, account.email, "wrong-password-123").status_code for _ in range(5)
        ]

        assert statuses[:4] == [401] * 4
        assert statuses[-1] == 429
        blocked = login(gateway, account.email, account.password)
        assert blocked.status_code == 429, "even the right password is refused while throttled"
        assert int(blocked.headers["Retry-After"]) > 0

    def test_resource_server_advertises_rfc9728_metadata(self, gateway: httpx.Client) -> None:
        challenge = gateway.get("/api/v1/orders").headers["WWW-Authenticate"]
        metadata_url = challenge.split('resource_metadata="', 1)[1].rstrip('"')

        metadata = gateway.get(metadata_url)

        assert metadata.status_code == 200
        assert metadata.json()["bearer_methods_supported"] == ["header"]


class TestOrders:
    def test_customer_order_lifecycle(self, gateway: httpx.Client, alice: Account) -> None:
        created = gateway.post("/api/v1/orders", json=ORDER, headers=alice.headers)
        assert created.status_code == 201, created.text
        order = created.json()
        assert order["totalAmount"] == 207.5  # priced server-side: 2 x 89.00 + 29.50
        assert order["customerId"] == alice.user_id
        assert created.headers["Location"].endswith(f"/api/v1/orders/{order['id']}")

        listed = gateway.get("/api/v1/orders", headers=alice.headers).json()
        assert order["id"] in [item["id"] for item in listed["items"]]

        cancelled = gateway.post(f"/api/v1/orders/{order['id']}/cancel", headers=alice.headers)
        assert cancelled.json()["status"] == "CANCELLED"

    def test_orders_are_private_to_their_owner(
        self, gateway: httpx.Client, alice: Account, bob: Account
    ) -> None:
        order_id = gateway.post("/api/v1/orders", json=ORDER, headers=alice.headers).json()["id"]

        assert gateway.get(f"/api/v1/orders/{order_id}", headers=bob.headers).status_code == 404
        assert gateway.get(f"/api/v1/orders/{order_id}", headers=alice.headers).status_code == 200

    def test_customers_cannot_use_admin_apis(self, gateway: httpx.Client, alice: Account) -> None:
        assert gateway.get("/api/v1/admin/orders", headers=alice.headers).status_code == 403
        assert gateway.get("/api/v1/admin/users/", headers=alice.headers).status_code == 403

    def test_requests_without_a_token_are_rejected(self, gateway: httpx.Client) -> None:
        response = gateway.get("/api/v1/orders")

        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"].startswith("Bearer")


class TestAdministration:
    def test_admin_fulfils_an_order(
        self, gateway: httpx.Client, alice: Account, admin: Account
    ) -> None:
        order_id = gateway.post("/api/v1/orders", json=ORDER, headers=alice.headers).json()["id"]
        path = f"/api/v1/admin/orders/{order_id}/status"

        for status in ("CONFIRMED", "SHIPPED", "DELIVERED"):
            response = gateway.patch(path, json={"status": status}, headers=admin.headers)
            assert response.status_code == 200, response.text
        invalid = gateway.patch(path, json={"status": "PENDING"}, headers=admin.headers)

        assert invalid.status_code == 409
        assert gateway.get(f"/api/v1/orders/{order_id}", headers=alice.headers).json()[
            "status"
        ] == ("DELIVERED")

    def test_disabling_an_account_revokes_its_sessions(
        self, gateway: httpx.Client, admin: Account
    ) -> None:
        victim = register_and_login(gateway)

        disabled = gateway.patch(
            f"/api/v1/admin/users/{victim.user_id}/",
            json={"is_active": False},
            headers=admin.headers,
        )
        refresh = gateway.post(
            "/api/v1/auth/token/refresh/", json={"refresh_token": victim.refresh_token}
        )

        assert disabled.status_code == 200
        assert refresh.status_code == 401
        assert login(gateway, victim.email, victim.password).status_code == 401


class TestCorrelation:
    def test_request_id_flows_through_gateway_and_services(
        self, gateway: httpx.Client, alice: Account
    ) -> None:
        request_id = f"e2e-{uuid.uuid4()}"
        headers = {**alice.headers, "X-Request-ID": request_id}

        orders = gateway.get("/api/v1/orders", headers=headers)
        auth = gateway.get("/api/v1/auth/me/", headers=headers)
        error = gateway.get(f"/api/v1/orders/{uuid.uuid4()}", headers=headers)

        assert orders.headers["X-Request-ID"] == request_id
        assert auth.headers["X-Request-ID"] == request_id
        assert error.status_code == 404
        assert error.json()["request_id"] == request_id


class TestObservability:
    def test_prometheus_scrapes_every_component(self) -> None:
        def all_up() -> None:
            targets = httpx.get(f"{PROMETHEUS_URL}/api/v1/targets", timeout=10).json()
            health = {t["labels"]["job"]: t["health"] for t in targets["data"]["activeTargets"]}
            assert health == {
                "auth-service": "up",
                "orders-service": "up",
                "gateway": "up",
                "prometheus": "up",
            }

        eventually(all_up)

    @pytest.mark.parametrize(
        "expr",
        [
            'auth_login_attempts_total{outcome="success"}',
            "auth_tokens_issued_total",
            "orders_placed_total",
            'http_server_requests_seconds_count{job="auth-service"}',
            'http_server_requests_seconds_count{job="orders-service"}',
            "traefik_service_requests_total",
        ],
    )
    def test_dashboard_metrics_are_populated(self, expr: str) -> None:
        def has_series() -> None:
            response = httpx.get(
                f"{PROMETHEUS_URL}/api/v1/query", params={"query": expr}, timeout=10
            )
            assert response.json()["data"]["result"], f"no series for {expr}"

        eventually(has_series)

    def test_every_dashboard_query_returns_data(self) -> None:
        dashboard = json.loads(
            (REPO_ROOT / "observability/grafana/dashboards/platform-overview.json").read_text(
                encoding="utf-8"
            )
        )
        queries = {
            f"{panel['title']} [{target['refId']}]": target["expr"]
            .replace("$__rate_interval", "1m")
            .replace("$__interval", "1m")
            for panel in dashboard["panels"]
            for target in panel.get("targets", [])
        }
        assert len(queries) >= 20

        def all_return_data() -> None:
            empty = [
                name
                for name, expr in queries.items()
                if not httpx.get(
                    f"{PROMETHEUS_URL}/api/v1/query", params={"query": expr}, timeout=10
                ).json()["data"]["result"]
            ]
            assert not empty, f"panels without data (wrong metric or label?): {empty}"

        eventually(all_return_data, timeout=90)

    def test_grafana_dashboard_is_provisioned(self) -> None:
        auth = (setting("GRAFANA_ADMIN_USER", "admin"), setting("GRAFANA_ADMIN_PASSWORD"))
        response = httpx.get(
            f"{GRAFANA_URL}/api/dashboards/uid/secure-platform-overview", auth=auth, timeout=10
        )

        assert response.status_code == 200
        assert response.json()["dashboard"]["title"] == "Secure Platform — Overview"


class TestEdgeRateLimit:
    """Runs last: deliberately exhausts the gateway's per-IP budget for auth routes."""

    def test_gateway_sheds_bursts_with_429(self, gateway: httpx.Client) -> None:
        statuses = [gateway.get("/.well-known/jwks.json").status_code for _ in range(60)]

        assert 429 in statuses
        assert statuses[0] == 200
