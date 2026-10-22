#!/usr/bin/env python3
"""Generate realistic traffic through the gateway so the Grafana dashboard has data.

Standard library only. Registers a few customers, logs in, browses the catalog,
places and cancels orders, lets an admin fulfil some, and mixes in failure
cases (bad passwords, missing tokens, a refresh-token replay).

    python scripts/demo_traffic.py --duration 120
"""

from __future__ import annotations

import argparse
import json
import os
import random
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "demo-Correct-Horse-Battery-7"  # noqa: S105 - throwaway demo accounts
SKUS = ["KB-001", "MS-002", "MN-27-4K", "HD-USB-C", "CB-HDMI-2"]


def dotenv() -> dict[str, str]:
    path = ROOT / ".env"
    if not path.exists():
        return {}
    pairs = (line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)
    return {k.strip(): v.strip() for k, v in pairs if not k.lstrip().startswith("#")}


class Client:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def call(
        self, method: str, path: str, body: Any = None, token: str | None = None
    ) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base_url + path, data=data, method=method)  # noqa: S310
        request.add_header("Content-Type", "application/json")
        request.add_header("X-Request-ID", f"demo-{uuid.uuid4()}")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                return error.code, json.loads(raw) if raw else None
            except json.JSONDecodeError:
                return error.code, None
        except (urllib.error.URLError, TimeoutError):
            # A slow or briefly unavailable stack must not end the whole run.
            return 0, None


def main() -> None:
    env = dotenv()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    # Same precedence as docker compose: the shell environment, then .env.
    port = os.environ.get("GATEWAY_HTTP_PORT") or env.get("GATEWAY_HTTP_PORT", "8080")
    parser.add_argument("--url", default=f"http://localhost:{port}")
    parser.add_argument("--duration", type=int, default=90, help="seconds to run")
    parser.add_argument("--customers", type=int, default=8)
    args = parser.parse_args()

    api = Client(args.url)
    rng = random.Random(42)  # noqa: S311 - not security sensitive

    status, admin = api.call(
        "POST",
        "/api/v1/auth/token/",
        {
            "email": os.environ.get("AUTH_BOOTSTRAP_ADMIN_EMAIL")
            or env.get("AUTH_BOOTSTRAP_ADMIN_EMAIL"),
            "password": os.environ.get("AUTH_BOOTSTRAP_ADMIN_PASSWORD")
            or env.get("AUTH_BOOTSTRAP_ADMIN_PASSWORD"),
        },
    )
    admin_token = admin["access_token"] if status == 200 else None

    customers = []
    for _ in range(args.customers):
        email = f"demo-{uuid.uuid4().hex[:8]}@example.com"
        api.call("POST", "/api/v1/auth/register/", {"email": email, "password": PASSWORD})
        status, tokens = api.call(
            "POST", "/api/v1/auth/token/", {"email": email, "password": PASSWORD}
        )
        if status == 200:
            customers.append({"email": email, **tokens})

    if not customers:
        raise SystemExit("Could not register any demo customers (is the stack up? rate limited?)")

    deadline = time.monotonic() + args.duration
    counts: dict[str, int] = {}
    while time.monotonic() < deadline:
        customer = rng.choice(customers)
        token = customer["access_token"]
        roll = rng.random()
        if roll < 0.30:
            status, _ = api.call("GET", "/api/v1/products", token=token)
        elif roll < 0.55:
            lines = [
                {"sku": sku, "quantity": rng.randint(1, 3)}
                for sku in rng.sample(SKUS, rng.randint(1, 3))
            ]
            status, order = api.call("POST", "/api/v1/orders", {"lines": lines}, token)
            if status == 201 and admin_token and rng.random() < 0.6:
                api.call(
                    "PATCH",
                    f"/api/v1/admin/orders/{order['id']}/status",
                    {"status": "CONFIRMED"},
                    admin_token,
                )
            elif status == 201 and rng.random() < 0.2:
                api.call("POST", f"/api/v1/orders/{order['id']}/cancel", token=token)
        elif roll < 0.75:
            status, _ = api.call("GET", "/api/v1/orders?size=10", token=token)
        elif roll < 0.85:
            status, _ = api.call("GET", "/api/v1/auth/me/", token=token)
        elif roll < 0.88:
            status, _ = api.call(
                "POST",
                "/api/v1/auth/token/",
                {"email": customer["email"], "password": "wrong-password-1"},
            )
        elif roll < 0.92:
            status, _ = api.call("GET", "/api/v1/orders")  # no token -> 401
        elif roll < 0.95:
            status, _ = api.call("GET", "/api/v1/admin/orders", token=token)  # customer -> 403
        else:
            # Rotate the refresh token. Occasionally replay the old one, which the
            # auth service treats as theft and answers by revoking the session.
            old = customer["refresh_token"]
            status, rotated = api.call(
                "POST", "/api/v1/auth/token/refresh/", {"refresh_token": old}
            )
            if status == 200:
                customer.update(rotated)
                if rng.random() < 0.2:
                    api.call("POST", "/api/v1/auth/token/refresh/", {"refresh_token": old})
                    _, fresh = api.call(
                        "POST",
                        "/api/v1/auth/token/",
                        {"email": customer["email"], "password": PASSWORD},
                    )
                    if fresh and "access_token" in fresh:
                        customer.update(fresh)
        counts[str(status)] = counts.get(str(status), 0) + 1
        time.sleep(rng.uniform(0.05, 0.25))

    print("responses by status:", dict(sorted(counts.items())))


if __name__ == "__main__":
    main()
