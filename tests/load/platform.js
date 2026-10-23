// Load test with latency SLOs, run against the compose stack through the gateway.
//
//   k6 run tests/load/platform.js                         # BASE_URL defaults to localhost:8080
//   BASE_URL=http://localhost:5441 k6 run tests/load/platform.js
//
// A 30 s warm-up (JIT compilation, connection pools) runs first and is excluded
// from the latency SLOs, though its errors still count. Then three open-model
// scenarios (constant arrival rate, so a slow system gets more concurrent
// requests rather than fewer, as with real users):
//   browse       10/s  catalog + "my orders" (two GETs per iteration)
//   place_order   4/s  POST /api/v1/orders with an Idempotency-Key; 1 in 10 is
//                      retried with the same key, as a client would after a timeout
//   login         1/s  password login (Argon2id) rotating over the test accounts
//
// Every request comes from one client IP, so the rates stay inside the platform's
// own per-IP limits: 50 req/s for the API and 10 req/s for auth routes at the
// gateway, 120 logins/min per IP and 5/min per account at auth-service. A 429
// counts as a failed request, so the test fails if it ever trips them.
//
// SLOs (thresholds) and the headroom behind them: docs/adr/0004-load-tests-and-slos.md.

import http from "k6/http";
import { check, fail, sleep } from "k6";
import exec from "k6/execution";

const BASE_URL = (__ENV.BASE_URL || "http://localhost:8080").replace(/\/$/, "");
const DURATION = __ENV.LOAD_DURATION || "2m";
const WARMUP = __ENV.LOAD_WARMUP || "30s";
const USERS = Number(__ENV.LOAD_USERS || 30);
const PASSWORD = "k6-Correct-Horse-Battery-5";
const SKUS = ["KB-001", "MS-002", "MN-27-4K", "HD-USB-C", "CB-HDMI-2"];
const JSON_HEADERS = { "Content-Type": "application/json" };

function scenario(rate, exec, maxVUs, startTime = WARMUP, duration = DURATION) {
  return {
    executor: "constant-arrival-rate",
    rate,
    timeUnit: "1s",
    startTime,
    duration,
    preAllocatedVUs: Math.max(2, rate * 2),
    maxVUs,
    exec,
  };
}

export const options = {
  scenarios: {
    warmup: scenario(5, "warmup", 20, "0s", WARMUP),
    browse: scenario(10, "browse", 40),
    place_order: scenario(4, "placeOrder", 20),
    login: scenario(1, "login", 10),
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    checks: ["rate>0.99"],
    "http_req_duration{scenario:browse}": ["p(95)<100", "p(99)<250"],
    "http_req_duration{scenario:place_order}": ["p(95)<150", "p(99)<400"],
    "http_req_duration{scenario:login}": ["p(95)<1000", "p(99)<2000"],
  },
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
};

function bearer(token, extra = {}) {
  return { headers: { Authorization: `Bearer ${token}`, ...JSON_HEADERS, ...extra } };
}

function passwordLogin(email, tags) {
  return http.post(
    `${BASE_URL}/api/v1/auth/token/`,
    JSON.stringify({ email, password: PASSWORD }),
    { headers: JSON_HEADERS, tags },
  );
}

// Registers the test accounts, paced under the gateway's 10 req/s auth limit.
export function setup() {
  const run = `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
  const accounts = [];
  for (let i = 0; i < USERS; i++) {
    const email = `k6-${run}-${i}@example.com`;
    const registered = http.post(
      `${BASE_URL}/api/v1/auth/register/`,
      JSON.stringify({ email, password: PASSWORD }),
      { headers: JSON_HEADERS, tags: { name: "setup register" } },
    );
    if (registered.status !== 201) {
      fail(`registering ${email}: ${registered.status} ${registered.body}`);
    }
    const tokens = passwordLogin(email, { name: "setup login" });
    if (tokens.status !== 200) {
      fail(`logging in ${email}: ${tokens.status} ${tokens.body}`);
    }
    accounts.push({ email, token: tokens.json("access_token") });
    sleep(0.25);
  }
  return { accounts };
}

function account(data) {
  return data.accounts[exec.scenario.iterationInTest % data.accounts.length];
}

export function browse(data) {
  const { token } = account(data);
  const products = http.get(`${BASE_URL}/api/v1/products`, {
    ...bearer(token),
    tags: { name: "GET /api/v1/products" },
  });
  const orders = http.get(`${BASE_URL}/api/v1/orders?page=0&size=20`, {
    ...bearer(token),
    tags: { name: "GET /api/v1/orders" },
  });
  check(products, { "catalog 200": (r) => r.status === 200 && r.json().length > 0 });
  check(orders, { "orders 200": (r) => r.status === 200 && r.json("items") !== undefined });
}

export function placeOrder(data) {
  const { token } = account(data);
  const key = crypto.randomUUID();
  const lines = [{ sku: SKUS[exec.scenario.iterationInTest % SKUS.length], quantity: 1 + (exec.scenario.iterationInTest % 3) }];
  const body = JSON.stringify({ lines });
  const params = { ...bearer(token, { "Idempotency-Key": key }), tags: { name: "POST /api/v1/orders" } };

  const created = http.post(`${BASE_URL}/api/v1/orders`, body, params);
  check(created, { "order 201": (r) => r.status === 201 });

  if (exec.scenario.iterationInTest % 10 === 0) {
    const retried = http.post(`${BASE_URL}/api/v1/orders`, body, params);
    check(retried, {
      "retry replays the same order": (r) =>
        r.status === 201 &&
        r.headers["Idempotent-Replayed"] === "true" &&
        r.json("id") === created.json("id"),
    });
  }
}

export function warmup(data) {
  browse(data);
  if (exec.scenario.iterationInTest % 2 === 0) {
    placeOrder(data);
  }
}

export function login(data) {
  const { email } = account(data);
  const response = passwordLogin(email, { name: "POST /api/v1/auth/token/" });
  check(response, {
    "login 200": (r) => r.status === 200 && typeof r.json("access_token") === "string",
  });
}
