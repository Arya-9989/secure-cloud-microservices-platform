"""Tracing: W3C context from the gateway is continued, DB calls are children, nothing leaks."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator

import pytest
from django.db import connection
from opentelemetry import trace
from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
from opentelemetry.propagate import get_global_textmap, set_global_textmap
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from rest_framework.test import APIClient

from accounts.models import User
from platform_core import tracing
from platform_core.logging import PlatformJsonFormatter, RequestContextFilter
from platform_core.request_context import current_trace_ids

from .conftest import PASSWORD

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT_SPAN_ID = "00f067aa0ba902b7"


def traceparent(sampled: bool = True) -> str:
    return f"00-{TRACE_ID}-{PARENT_SPAN_ID}-{'01' if sampled else '00'}"


@pytest.fixture
def spans(request: pytest.FixtureRequest) -> Iterator[InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = tracing.build_tracer_provider(exporter, batch=False)
    tracing.instrument(provider)
    # In production the instrumentation is installed before the first connection; the test
    # database connection already exists, so instrument it explicitly.
    raw = None
    if connection.vendor == "postgresql" and "django_db" in request.keywords:
        connection.ensure_connection()
        raw = connection.connection
        PsycopgInstrumentor.instrument_connection(raw, tracer_provider=provider)
    try:
        yield exporter
    finally:
        if raw is not None:
            PsycopgInstrumentor.uninstrument_connection(raw)
        tracing.uninstrument()
        provider.shutdown()


@pytest.mark.django_db
class TestServerSpans:
    def test_login_continues_the_gateways_trace(
        self, spans: InMemorySpanExporter, user: User
    ) -> None:
        response = APIClient().post(
            "/api/v1/auth/token/",
            {"email": user.email, "password": PASSWORD},
            format="json",
            HTTP_TRACEPARENT=traceparent(),
        )

        assert response.status_code == 200
        finished = spans.get_finished_spans()
        server = next(s for s in finished if s.kind is SpanKind.SERVER)
        assert format(server.context.trace_id, "032x") == TRACE_ID
        assert server.parent is not None
        assert format(server.parent.span_id, "016x") == PARENT_SPAN_ID
        assert server.name == "POST api/v1/auth/token/"
        assert server.resource.attributes["service.name"] == "auth-service"
        if connection.vendor == "postgresql":
            queries = [s for s in finished if s.kind is SpanKind.CLIENT]
            assert queries, "every SQL statement is a child span"
            assert all(s.context.trace_id == server.context.trace_id for s in queries)
            assert all(s.parent and s.parent.span_id == server.context.span_id for s in queries)

    def test_spans_carry_no_credentials(self, spans: InMemorySpanExporter, user: User) -> None:
        APIClient().post(
            "/api/v1/auth/token/",
            {"email": user.email, "password": PASSWORD},
            format="json",
            HTTP_TRACEPARENT=traceparent(),
            HTTP_AUTHORIZATION="Bearer should-never-be-recorded",
        )

        recorded = json.dumps(
            [dict(s.attributes or {}) for s in spans.get_finished_spans()], default=str
        )
        assert spans.get_finished_spans()
        assert PASSWORD not in recorded
        assert "should-never-be-recorded" not in recorded
        assert user.email not in recorded

    def test_requests_the_gateway_did_not_sample_are_not_recorded(
        self, spans: InMemorySpanExporter, api: APIClient
    ) -> None:
        api.get("/.well-known/jwks.json", HTTP_TRACEPARENT=traceparent(sampled=False))
        api.get("/.well-known/jwks.json")  # no traceparent at all: a root span

        assert spans.get_finished_spans() == ()

    def test_probes_are_never_traced(self, spans: InMemorySpanExporter, api: APIClient) -> None:
        api.get("/healthz", HTTP_TRACEPARENT=traceparent())
        api.get("/readyz", HTTP_TRACEPARENT=traceparent())

        assert spans.get_finished_spans() == ()


def test_log_lines_carry_the_trace_and_span_id() -> None:
    exporter = InMemorySpanExporter()
    provider = tracing.build_tracer_provider(exporter, batch=False)
    tracer = provider.get_tracer("test")
    parent = TraceContextTextMapPropagator().extract({"traceparent": traceparent()})

    with tracer.start_as_current_span("work", context=parent) as span:
        record = logging.LogRecord("accounts.views", logging.INFO, __file__, 1, "hi", None, None)
        RequestContextFilter().filter(record)
        line = json.loads(PlatformJsonFormatter().format(record))
        expected_span = format(span.get_span_context().span_id, "016x")

    assert line["trace_id"] == TRACE_ID
    assert line["span_id"] == expected_span
    assert current_trace_ids() == (None, None)  # outside the span again


def test_tracing_is_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRACING_ENABLED", raising=False)
    monkeypatch.setattr(tracing, "_configured", False)

    assert tracing.configure_tracing() is False
    assert not isinstance(trace.get_tracer_provider(), TracerProvider)


def test_enabling_installs_w3c_only_propagation_and_edge_sampling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed: list[object] = []
    previous_textmap = get_global_textmap()
    monkeypatch.setenv("TRACING_ENABLED", "true")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9")
    monkeypatch.delenv("OTEL_TRACES_SAMPLER", raising=False)
    monkeypatch.setattr(tracing, "_configured", False)
    monkeypatch.setattr(trace, "set_tracer_provider", installed.append)
    monkeypatch.setattr(tracing, "instrument", installed.append)
    try:
        assert tracing.configure_tracing() is True
        assert tracing.configure_tracing() is True  # idempotent: nothing installed twice

        assert isinstance(get_global_textmap(), TraceContextTextMapPropagator)  # no baggage
        provider = installed[0]
        assert isinstance(provider, TracerProvider)
        assert installed == [provider, provider]
        description = provider.sampler.get_description()
        assert description.startswith("ParentBased{root:TraceIdRatioBased{0.0}")
        provider.shutdown()
    finally:
        set_global_textmap(previous_textmap)
