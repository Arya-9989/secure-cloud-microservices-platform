"""Distributed tracing through the real stack (compose profile `tracing`, TRACING_ENABLED=true).

Each test acts as the caller's own instrumentation: it sends a W3C ``traceparent``
with a fresh trace id, then reads that trace back from Jaeger and checks that it is
one connected tree across the gateway, the services and PostgreSQL.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import GRAFANA_URL, Account, eventually, setting

pytestmark = pytest.mark.skipif(
    setting("TRACING_ENABLED", "false") != "true",
    reason="tracing is off (set COMPOSE_PROFILES=tracing and TRACING_ENABLED=true)",
)

JAEGER_URL = setting("JAEGER_URL", "http://localhost:" + setting("JAEGER_PORT", "16686"))
CLIENT_SPAN_ID = "00f067aa0ba902b7"
ORDER = {"lines": [{"sku": "KB-001", "quantity": 1}]}


@dataclass(frozen=True)
class Span:
    span_id: str
    parent_id: str | None
    service: str
    name: str
    tags: dict[str, Any]


def new_trace() -> tuple[str, dict[str, str]]:
    trace_id = secrets.token_hex(16)
    return trace_id, {"traceparent": f"00-{trace_id}-{CLIENT_SPAN_ID}-01"}


def fetch_trace(trace_id: str) -> list[Span]:
    response = httpx.get(f"{JAEGER_URL}/api/traces/{trace_id}", timeout=10)
    assert response.status_code == 200, f"trace {trace_id} not in Jaeger yet"
    (trace,) = response.json()["data"]
    services = {key: process["serviceName"] for key, process in trace["processes"].items()}
    spans = []
    for raw in trace["spans"]:
        parents = [r["spanID"] for r in raw["references"] if r["refType"] == "CHILD_OF"]
        spans.append(
            Span(
                span_id=raw["spanID"],
                parent_id=parents[0] if parents else None,
                service=services[raw["processID"]],
                name=raw["operationName"],
                tags={tag["key"]: tag["value"] for tag in raw["tags"]},
            )
        )
    return spans


def wait_for_trace(trace_id: str, *services: str) -> list[Span]:
    """Spans arrive in batches from each process; wait until every service has reported."""
    found: list[Span] = []

    def complete() -> None:
        nonlocal found
        found = fetch_trace(trace_id)
        reported = {span.service for span in found}
        assert set(services) <= reported, f"{trace_id}: have {reported}, want {services}"

    eventually(complete, timeout=45)
    return found


def assert_connected(spans: list[Span]) -> Span:
    """Exactly one span is parented on the caller's span; every other span has its parent here."""
    ids = {span.span_id for span in spans}
    roots = [span for span in spans if span.parent_id == CLIENT_SPAN_ID]
    orphans = [s for s in spans if s.parent_id not in ids and s.parent_id != CLIENT_SPAN_ID]
    assert len(roots) == 1, f"one entry span expected, got {[r.name for r in roots]}"
    assert not orphans, f"spans whose parent is missing: {[(o.service, o.name) for o in orphans]}"
    assert roots[0].service == "gateway"
    return roots[0]


def ancestors(spans: list[Span], span: Span) -> list[Span]:
    by_id = {s.span_id: s for s in spans}
    chain = []
    current = by_id.get(span.parent_id or "")
    while current is not None:
        chain.append(current)
        current = by_id.get(current.parent_id or "")
    return chain


SQL_SYSTEM_TAGS = ("db.system", "db.system.name")


def is_sql(span: Span) -> bool:
    """psycopg spans set db.system; datasource-micrometer records jdbc.query[0]."""
    if "jdbc.query[0]" in span.tags:
        return True
    return any(str(span.tags.get(key, "")).lower() == "postgresql" for key in SQL_SYSTEM_TAGS)


class TestTracing:
    def test_placing_an_order_is_one_trace_from_the_gateway_to_postgres(
        self, gateway: httpx.Client, alice: Account
    ) -> None:
        trace_id, headers = new_trace()

        created = gateway.post("/api/v1/orders", json=ORDER, headers={**alice.headers, **headers})

        assert created.status_code == 201, created.text
        spans = wait_for_trace(trace_id, "gateway", "orders-service")
        assert_connected(spans)
        server = next(
            s for s in spans if s.service == "orders-service" and s.name.startswith("http post")
        )
        assert ancestors(spans, server)[-1].service == "gateway"
        queries = [s for s in spans if s.service == "orders-service" and is_sql(s)]
        assert queries, "INSERTs into orders/order_lines are spans"
        assert all(server in ancestors(spans, q) for q in queries)
        assert all("KB-001" not in str(q.tags) for q in queries), "no parameter values"

    def test_a_jwks_refetch_carries_the_trace_into_auth_service(
        self, gateway: httpx.Client
    ) -> None:
        # An unknown kid makes orders-service refetch the key set (at most twice per 10 s).
        attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        def refetch_is_traced() -> None:
            trace_id, headers = new_trace()
            forged = jwt.encode(
                {"sub": "mallory", "exp": 4102444800},
                attacker,
                algorithm="RS256",
                headers={"kid": f"forged-{uuid.uuid4()}"},
            )
            response = gateway.get(
                "/api/v1/orders", headers={"Authorization": f"Bearer {forged}", **headers}
            )
            assert response.status_code == 401
            spans = wait_for_trace(trace_id, "gateway", "orders-service")
            fetch = [s for s in spans if s.name == "GET /.well-known/jwks.json"]
            assert fetch, "refetch budget spent by an earlier request; try again"
            jwks_server = wait_for_trace(trace_id, "auth-service")
            assert_connected(jwks_server)
            auth = next(s for s in jwks_server if s.service == "auth-service")
            assert auth.parent_id == fetch[0].span_id, "auth-service continues the fetch span"

        eventually(refetch_is_traced, timeout=60, interval=6)

    def test_logging_in_traces_auth_service_and_its_database(
        self, gateway: httpx.Client, alice: Account
    ) -> None:
        trace_id, headers = new_trace()

        response = gateway.post(
            "/api/v1/auth/token/",
            json={"email": alice.email, "password": alice.password},
            headers=headers,
        )

        assert response.status_code == 200
        spans = wait_for_trace(trace_id, "gateway", "auth-service")
        assert_connected(spans)
        assert [s for s in spans if s.service == "auth-service" and is_sql(s)]
        recorded = str([s.tags for s in spans])
        assert alice.password not in recorded
        assert response.json()["access_token"] not in recorded

    def test_grafana_reads_traces_from_jaeger(self) -> None:
        auth = (setting("GRAFANA_ADMIN_USER", "admin"), setting("GRAFANA_ADMIN_PASSWORD"))

        health = httpx.get(
            f"{GRAFANA_URL}/api/datasources/uid/jaeger/health", auth=auth, timeout=10
        )
        assert health.json()["status"] == "OK", health.text

        def search_finds_traces() -> None:
            query = {
                "queries": [
                    {
                        "refId": "A",
                        "datasource": {"uid": "jaeger", "type": "jaeger"},
                        "queryType": "search",
                        "service": "orders-service",
                        "limit": 5,
                    }
                ],
                "from": "now-1h",
                "to": "now",
            }
            response = httpx.post(f"{GRAFANA_URL}/api/ds/query", json=query, auth=auth, timeout=10)
            assert response.status_code == 200, response.text
            frames = response.json()["results"]["A"]["frames"]
            assert frames, "Grafana returned no frames"
            assert frames[0]["data"]["values"], "Grafana found no orders-service traces"

        eventually(search_finds_traces)
