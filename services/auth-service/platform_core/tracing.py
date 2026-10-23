"""Distributed tracing with OpenTelemetry (off unless ``TRACING_ENABLED`` is true).

When enabled, every request handled by Django gets a server span that continues
the W3C ``traceparent`` sent by the gateway, and every PostgreSQL statement gets a
child span. Spans are exported over OTLP/HTTP; the endpoint, service name and
timeouts come from the standard ``OTEL_*`` environment variables.

Choices that matter for security and cost (see docs/adr/0001-distributed-tracing.md):

* Sampling is decided at the edge. The sampler is parent-based with a root ratio of
  0 unless ``OTEL_TRACES_SAMPLER`` says otherwise, so only requests the gateway
  sampled are recorded; health checks and direct calls never start a trace.
* Only W3C Trace Context is propagated. Baggage is ignored, so clients cannot push
  arbitrary key/value pairs through every hop.
* No request headers are captured, and SQL is recorded with placeholders only.

``configure_tracing`` must run in each gunicorn worker before the WSGI application
is built (``auth_service/wsgi.py`` does this): the batch exporter owns a thread,
and the Django instrumentation inserts its middleware into the settings.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from opentelemetry import trace
from opentelemetry.instrumentation.django import DjangoInstrumentor
from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
from opentelemetry.propagate import set_global_textmap
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.sampling import ParentBased, Sampler, TraceIdRatioBased
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from .env import env_bool

logger = logging.getLogger(__name__)

DEFAULT_SERVICE_NAME = "auth-service"
# Probes are polled every few seconds; tracing them would bury the real traffic.
EXCLUDED_URLS = "healthz,readyz"

_configured = False


def tracing_enabled() -> bool:
    return env_bool("TRACING_ENABLED", default=False)


def _sampler() -> Sampler | None:
    """Parent-based, ratio 0 for root spans, unless the standard env vars choose one."""
    if os.environ.get("OTEL_TRACES_SAMPLER"):
        return None  # the SDK reads OTEL_TRACES_SAMPLER / OTEL_TRACES_SAMPLER_ARG itself
    return ParentBased(root=TraceIdRatioBased(0.0))


def build_tracer_provider(exporter: SpanExporter, *, batch: bool = True) -> TracerProvider:
    attributes: dict[str, Any] = {}
    if not os.environ.get("OTEL_SERVICE_NAME"):
        attributes[SERVICE_NAME] = DEFAULT_SERVICE_NAME
    provider = TracerProvider(resource=Resource.create(attributes), sampler=_sampler())
    if batch:
        provider.add_span_processor(BatchSpanProcessor(exporter))
    else:  # tests: spans are visible as soon as they end
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider


def instrument(provider: TracerProvider) -> None:
    DjangoInstrumentor().instrument(tracer_provider=provider, excluded_urls=EXCLUDED_URLS)
    # The SQL commenter would append trace ids to statements; parameters are never captured.
    PsycopgInstrumentor().instrument(tracer_provider=provider, enable_commenter=False)


def uninstrument() -> None:
    DjangoInstrumentor().uninstrument()
    PsycopgInstrumentor().uninstrument()


def configure_tracing() -> bool:
    """Install the tracer provider and instrumentations once; return whether tracing is on."""
    global _configured
    if _configured or not tracing_enabled():
        return _configured
    # Imported lazily: the exporter pulls in an HTTP client that is useless when tracing is off.
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    set_global_textmap(TraceContextTextMapPropagator())
    provider = build_tracer_provider(OTLPSpanExporter())
    trace.set_tracer_provider(provider)
    instrument(provider)
    _configured = True
    logger.info("Tracing enabled", extra={"otlp_endpoint": _endpoint()})
    return True


def _endpoint() -> str:
    return os.environ.get(
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    )
