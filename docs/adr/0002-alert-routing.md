# 0002. Alert routing with Alertmanager

- Status: accepted
- Date: 2026-10-23

## Context

Six Prometheus rules (`observability/prometheus/alerts.yml`) fired into the Prometheus UI and nowhere else. Nobody gets woken up for a dead service, and a replayed refresh token (possible token theft) looks no different from a slow endpoint. Routing has to be testable without a PagerDuty or Slack account, and checked in CI like the rules themselves.

## Options considered

1. **Grafana alerting.** It can evaluate and route, but then the rules would live in two places, and the `promtool` unit tests would no longer cover what actually pages.
2. **Alertmanager** next to Prometheus, configured as code. It handles routing, grouping, inhibition and silences; `amtool` validates the config and can unit-test the routing tree.
3. **Receivers for local and CI testing:** a hosted request bin (needs an account and leaks alert content), a generic echo image (can't be queried afterwards), or a ~100-line standard-library sink in the repo that records what it receives.

## Decision

- Alertmanager v0.34 in the compose stack, single instance, with its state in tmpfs.
- **Routing by intent, first match wins:**
  1. `category=security` goes to `security`, whatever the severity: fast `group_wait` (10 s), grouped by alert name.
  2. `severity=critical` goes to `pager`.
  3. Everything else goes to `platform` (team chat). The default route catches unlabelled alerts too, so nothing is dropped.

  `RefreshTokenReuse` and `LoginBruteForce` gain a `category: security` label. Their `promtool` tests were updated for it.
- **Inhibition:**
  - `TargetDown` silences the same job's error-rate and latency warnings.
  - A critical alert silences that job's other warnings, except security alerts.

  Both sides of the second rule must *have* a `job` label. Alertmanager treats a label missing on both alerts as equal, so without this a `GatewayErrorRate` (which has `router`, not `job`) would silence every job-less warning, including `LoginBruteForce`. The e2e suite checks exactly that case.
- **Grouping:** by `alertname, job, router` by default (one notification per problem and service), and by `alertname` for security alerts (one notification per attack, however many instances report it).
- **Receivers:** locally, webhooks into `alert-sink` (`observability/alert-sink/sink.py`). It keeps a bounded in-memory log, validates the payload shape, caps bodies at 1 MiB, and can be queried at `GET /notifications`. In production each receiver becomes a PagerDuty or Slack config whose secret is read from a mounted file (`routing_key_file`, `api_url_file`), so no credential enters the repository.
- **CI:** `amtool check-config`, plus `routes.test.sh`. That script runs `amtool config routes test --verify.receivers` once per rule, using the labels each rule's expression keeps. It's checked to fail against a config that routes differently. The sink has its own unit tests, and the e2e suite proves delivery from end to end.

## Consequences

- A real `RefreshTokenReuse` notification reaches the security receiver about 30 seconds after the replay: one scrape, one rule evaluation and the 10-second `group_wait`.
- Notification state (what was already sent, silences) resets when the container restarts. A production deployment would run two or more Alertmanagers in a gossip cluster with persistent storage.
- A new alert rule has to say where it goes: add `category` if it's a security signal, and a case in `routes.test.sh`.
