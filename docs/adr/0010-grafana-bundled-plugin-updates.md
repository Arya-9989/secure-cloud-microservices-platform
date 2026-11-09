# 0010. Keep Grafana's bundled plugins at the image versions

- Status: proposed
- Date: 2026-11-09

## Context

PR #32's CI run 42637004359 used Grafana 13.2.4 and Jaeger 2.20.0. At
14:53:40, Grafana attempted to update its bundled Jaeger plugin from 13.0.5
to 13.0.8, stopped the plugin process, then failed with
`unlinkat /usr/share/grafana/data/plugins-bundled/jaeger: read-only file system`.
At 14:55:35, the datasource health request returned HTTP 404 with
`plugin.notRegistered`. The three preceding tracing tests passed against Jaeger.

Grafana 13.2 ships Jaeger as a standalone plugin and updates it independently
of the Grafana image. Disabling analytics update checks does not disable these
plugin updates. The datasource health test assumed every response contained
`status`, so a `KeyError` hid the HTTP error and its body.

## Decision

- Set `GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false` in Compose. Keep the container
  read-only and retain the Jaeger plugin shipped in the versioned Grafana image.
  Retain Jaeger 2.20.0's query API compatibility documented in ADR 0001.
- Check the health response's HTTP status before requiring JSON `status=OK`.
  Poll with the existing 60-second retry helper and a 10-second request timeout,
  preserving the last error's response body. Retries allow startup readiness;
  they do not repair a plugin unregistered by a failed update.
- Still require a successful Grafana `/api/ds/query` search with actual trace
  rows from Jaeger. A healthy Grafana server alone does not satisfy this check.

## Consequences

Bundled plugin fixes arrive through deliberate Grafana image upgrades. The
health API and query must both succeed; persistent errors fail the test after
the retry deadline (plus at most an in-flight request and polling interval).

References: [CI job log](https://github.com/Arya-9989/secure-cloud-microservices-platform/actions/runs/42637004359/job/129234098058),
[Grafana's Jaeger plugin update behavior](https://grafana.com/docs/grafana/latest/datasources/jaeger/#plugin-updates).
