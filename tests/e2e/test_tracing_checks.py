"""Exercise the Grafana e2e assertions without a running stack."""

from __future__ import annotations

import time

import httpx
import pytest

import test_tracing


@pytest.fixture(autouse=True)
def fast_polling(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 0.0

    def advance(seconds: float) -> None:
        nonlocal now
        now += seconds

    monkeypatch.setattr(time, "monotonic", lambda: now)
    monkeypatch.setattr(time, "sleep", advance)
    monkeypatch.setenv("GRAFANA_ADMIN_PASSWORD", "test-password")


@pytest.mark.parametrize(
    "initial_health",
    [
        httpx.Response(404, json={"messageId": "plugin.notRegistered"}),
        httpx.Response(503, text="starting"),
        httpx.Response(200, json={}),
        httpx.Response(400, json={"status": "ERROR", "message": "Jaeger unavailable"}),
        httpx.ConnectError("connection refused"),
    ],
)
def test_grafana_waits_for_datasource_readiness(
    monkeypatch: pytest.MonkeyPatch, initial_health: httpx.Response | httpx.TransportError
) -> None:
    health_calls = 0
    query_calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal health_calls, query_calls
        if request.url.path.endswith("/health"):
            health_calls += 1
            if health_calls == 1:
                if isinstance(initial_health, httpx.TransportError):
                    raise initial_health
                return initial_health
            return httpx.Response(200, json={"status": "OK"})
        assert request.url.path == "/api/ds/query"
        query_calls += 1
        return httpx.Response(
            200, json={"results": {"A": {"frames": [{"data": {"values": [["trace-id"]]}}]}}}
        )

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        monkeypatch.setattr(httpx, "get", client.get)
        monkeypatch.setattr(httpx, "post", client.post)
        test_tracing.TestTracing().test_grafana_reads_traces_from_jaeger()

    assert health_calls == 2
    assert query_calls == 1


@pytest.mark.parametrize(
    ("stage", "failure", "diagnostic"),
    [
        (
            "health",
            httpx.Response(404, json={"messageId": "plugin.notRegistered"}),
            "404.*plugin.notRegistered",
        ),
        ("health", httpx.Response(200, json={"status": "ERROR"}), "ERROR"),
        ("health", httpx.Response(200, json={}), r"\{\}"),
        ("health", httpx.ConnectError("connection refused"), "connection refused"),
        ("query", httpx.Response(502, text="Jaeger unavailable"), "Jaeger unavailable"),
        (
            "query",
            httpx.Response(200, json={"results": {"A": {"frames": []}}}),
            "Grafana returned no frames",
        ),
        (
            "query",
            httpx.Response(
                200, json={"results": {"A": {"frames": [{"data": {"values": [[], []]}}]}}}
            ),
            "Grafana found no orders-service traces",
        ),
    ],
)
def test_grafana_fails_with_diagnostics_after_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    failure: httpx.Response | httpx.TransportError,
    diagnostic: str,
) -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if stage == "query" and request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "OK"})
        if isinstance(failure, httpx.TransportError):
            raise failure
        return failure

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        monkeypatch.setattr(httpx, "get", client.get)
        monkeypatch.setattr(httpx, "post", client.post)
        with pytest.raises(AssertionError, match=diagnostic):
            test_tracing.TestTracing().test_grafana_reads_traces_from_jaeger()

    assert 1 < calls <= 33, "persistent failures must exhaust the bounded retry"
