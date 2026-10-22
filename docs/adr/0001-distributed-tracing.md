# 0001. Distributed tracing with OpenTelemetry and Jaeger

- Status: accepted
- Date: 2026-10-23

## Context

A request crosses the Traefik gateway, one of two services written in different languages, PostgreSQL and, when orders-service sees an unknown key id, a JWKS fetch from auth-service. Request IDs already correlate log lines, but they don't show where the time goes or which hop failed. We want one trace per request that spans every hop, without changing the platform's security properties and without making the default stack heavier.

Constraints:

- The default `docker compose up` stack and the e2e suite must not need a tracing backend.
- Traefik's static configuration can't be switched with environment variables: a file, CLI flags and environment variables are mutually exclusive configuration sources.
- Trace context arriving from the internet is untrusted input.

## Options considered

1. **OpenTelemetry Java agent** for orders-service. It instruments everything with no code, but adds a 20+ MB jar to the distroless image, slows startup, and instruments Spring Framework 7 / Boot 4 from outside, version by version.
2. **Spring Boot 4's own OpenTelemetry starter** (Micrometer Observation bridged to the OTel SDK). Server spans and log correlation come with the framework the service already uses for metrics. JDBC needs `datasource-micrometer`; the JWKS client needs a small wrapper.
3. **Backend: Tempo or Jaeger.** Tempo needs object storage or a local volume, and Grafana to view traces. Jaeger v2's all-in-one image is a single OTel Collector-based process with an in-memory store and its own UI, and Grafana has a native Jaeger datasource.
4. **Toggling the gateway:** two static Traefik files (drift), a shell entrypoint that concatenates fragments, or the router-level `observability.tracing` switch in the dynamic file-provider configuration, which Traefik renders as a Go template.

## Decision

- **Python:** the OpenTelemetry SDK with the Django and psycopg instrumentations, set up in `platform_core/tracing.py` when the WSGI app loads in each gunicorn worker (after the fork, so the exporter's thread belongs to the worker).
- **Java:** `spring-boot-starter-opentelemetry` plus `datasource-micrometer-spring-boot` for JDBC. The OTLP *metrics* registry and the OkHttp sender (with its Kotlin runtime) are excluded: metrics stay on Prometheus, and spans go out over the JDK HTTP client. The JWKS fetch runs through `ObservedJwksRetriever`, which wraps the same Nimbus retriever (same timeouts and size limit) in a client observation and injects `traceparent`.
- **Gateway:** `tracing` is declared once in `traefik.yml`. Each router's `observability.tracing` is rendered from `TRACING_ENABLED`, so with tracing off Traefik creates no spans at all, exports nothing and passes `traceparent` through unchanged. This was checked against Traefik 3.7.16 before it was adopted.
- **Backend:** Jaeger v2 (in-memory, bounded) in the compose profile `tracing`, with a provisioned Grafana datasource. Everything speaks OTLP over HTTP, so swapping in Tempo or a collector changes one endpoint.
- **Switch:** `TRACING_ENABLED=true` together with `COMPOSE_PROFILES=tracing`. Off by default.
- **Sampling is decided once, at the edge.** The services use a parent-based sampler whose root ratio is 0. They record a request only when the gateway sampled it. Health checks and other calls that bypass the gateway are never traced, and a client can't make a service start its own traces.
- **Propagation is W3C Trace Context only.** Baggage isn't propagated, so a client can't push arbitrary key/value pairs into every hop.
- **Nothing sensitive goes into spans.** No request headers apart from `X-Request-Id`, and SQL statements with placeholders but no parameter values. The `Authorization` header is never captured.
- **Logs carry `trace_id` and `span_id`**, on both services, next to `request_id`.

## Consequences

- One request produces a single trace from the gateway through the service to PostgreSQL. A JWKS refetch shows up as a child of the request that caused it, followed by auth-service's own server span. The e2e suite asserts both.
- The gateway's `routes.yml` is a template now (one expression per router). Traefik validates it on load, and the e2e suite exercises it in both modes.
- In production the gateway's `sampleRate` (1.0 locally) is the only knob, and clients can still mark their own traceparent as sampled. If that matters, put a collector with tail sampling or rate limiting between the gateway and the backend.
- Spring Security's per-filter observations are switched off, because they add about ten spans per request and say little.
