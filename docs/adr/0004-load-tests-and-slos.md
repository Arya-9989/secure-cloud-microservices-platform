# 0004. Load tests with latency SLOs in CI

- Status: accepted
- Date: 2026-10-23

## Context

Nothing stopped a change from making the API ten times slower: the e2e suite checks behaviour, not latency. We want a load test with realistic traffic whose latency and error targets fail CI when they're missed, and those targets must be ones a shared CI runner meets reliably. A threshold that flakes gets ignored, and one set too loose catches nothing.

## Options considered

1. **Locust or Gatling.** Locust needs a Python runtime and harness, and Gatling a JVM build. Both work, but SLOs need extra glue to become an exit code.
2. **k6.** One static binary or a pinned image, JavaScript scenarios, open-model executors, and thresholds that set the exit code natively.
3. **Where to run it:** a separate CI job would rebuild every image (about 5 minutes). The e2e job already has the full stack up and healthy.

## Decision

- **k6** (`tests/load/platform.js`), run in the e2e job right after the black-box suite, from `grafana/k6:2.3.0` pinned by digest. The summary JSON is uploaded as an artifact.
- **Open model** (`constant-arrival-rate`): if the platform slows down, k6 opens more concurrent requests instead of quietly sending fewer.
  - `browse` 10/s: the catalog and "my orders" (two GETs per iteration).
  - `place_order` 4/s: `POST /api/v1/orders` with an `Idempotency-Key`. One in ten is retried with the same key and must replay the same order.
  - `login` 1/s: Argon2id password login, rotating over 30 accounts registered in `setup()`.
  - A 30 s warm-up comes first and is excluded from the latency SLOs (JIT compilation and connection pools aren't steady state). Its errors still count.
- **Within the platform's own limits.** Every request comes from one client IP, so the rates sit under the per-IP limits: 50 req/s API and 10 req/s auth at the gateway, 120 logins/min per IP and 5/min per account at auth-service. A 429 counts as a failure.
- **SLOs (thresholds):** error rate < 1 %, checks > 99 %, and the latency limits below.

## Measurements and headroom

Measured with k6 2.3.0 against the compose stack with tracing on (as in CI), on the development machine while other workloads were running. Each run starts from a freshly started stack. Latency is per scenario, in ms.

| Scenario | Run A p95 / p99 | Run B p95 / p99 | Threshold p95 / p99 | Headroom vs the worse run |
|---|---|---|---|---|
| browse | 12.1 / 30.9 | 6.2 / 7.9 | 100 / 250 | 8× / 8× |
| place_order | 28.8 / 79.0 | 13.7 / 19.2 | 150 / 400 | 5× / 5× |
| login (Argon2id) | 637 / 854 | 239 / 255 | 1000 / 2000 | 1.6× / 2.3× |

Both runs: 0 failed requests out of about 3,500, and all checks passed. A run before the warm-up existed showed cold-JIT outliers (`place_order` p99 442 ms), which is why the warm-up is there.

- The API limits allow 5–8× over the worse local run. That absorbs a slower, shared 4-vCPU runner and the noise of a 2-minute sample, while still failing a real regression such as an N+1 query or a lost index. Those typically cost 10× or more at these sizes.
- Login is slow on purpose: Argon2id with Django's defaults uses about 100 MiB and two passes per hash, so its latency follows CPU contention. It gets less headroom in relative terms but a hard, user-meaningful bound: 95 % of logins finish within 1 s.
- These numbers aren't capacity figures. The single-IP limits cap the offered load at about 21 req/s. Load-testing capacity would mean lifting the edge limits in a dedicated environment.

## Consequences

- The e2e job takes about 2.5 minutes longer.
- If CI shows the thresholds flaking, profile before loosening them, and update the table above with the CI numbers from the uploaded summary.
