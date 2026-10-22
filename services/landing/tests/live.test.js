// Unit tests for the live console logic: node --test tests/
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  INTERVAL_MS,
  MAX_INTERVAL_MS,
  Poller,
  SPARK_FLOOR_MS,
  SPARK_SLOTS,
  SPARK_WIDTH,
  TIMEOUT_MS,
  cadenceLabel,
  describe,
  nextDelay,
  sparkGeometry,
} from "../site/assets/live.js";

const AUTH = { name: "auth-service", okLabel: "Operational", expected: "a key set" };

/** Deterministic timers: nothing runs until the test fires it. */
function fakeTimers() {
  const pending = new Map();
  let id = 0;
  return {
    pending,
    setTimer: (fn, delay) => {
      id += 1;
      pending.set(id, { fn, delay });
      return id;
    },
    clearTimer: (handle) => pending.delete(handle),
    async fire() {
      assert.equal(pending.size, 1, "exactly one timer must be pending");
      const [[handle, { fn }]] = pending;
      pending.delete(handle);
      await fn();
    },
  };
}

/** A round whose completion the test controls. */
function controlledRound() {
  const calls = [];
  const round = () =>
    new Promise((resolve) => {
      calls.push(resolve);
    });
  return { round, calls };
}

test("cadence backs off while rounds fail and recovers at once", () => {
  assert.deepEqual([0, 1, 2, 3, 4, 10].map(nextDelay), [5000, 10000, 20000, 30000, 30000, 30000]);
  assert.equal(nextDelay(0), INTERVAL_MS);
  assert.equal(nextDelay(99), MAX_INTERVAL_MS);
});

test("a healthy answer shows the probe's own detail", () => {
  const view = describe({ kind: "response", status: 200, detail: "RS256 · 1 key" }, AUTH);
  assert.deepEqual(view, { up: true, status: "Operational", detail: "RS256 · 1 key" });
});

test("gateway errors say which service is down and why, in plain words", () => {
  const view = describe({ kind: "response", status: 503, detail: null }, AUTH);
  assert.equal(view.up, false);
  assert.equal(view.status, "Unavailable");
  assert.match(view.detail, /^HTTP 503: auth-service is down, .*no healthy instance/);
});

test("a failure replaces the last good detail instead of leaving it on screen", () => {
  const up = describe({ kind: "response", status: 200, detail: "kid abc · 1 key" }, AUTH);
  const down = describe({ kind: "response", status: 502, detail: null }, AUTH);
  assert.notEqual(down.detail, up.detail);
  assert.doesNotMatch(down.detail, /kid/);
});

test("timeouts, network errors and unexpected answers are distinguished", () => {
  assert.equal(describe({ kind: "timeout" }, AUTH).status, "Timed out");
  assert.match(describe({ kind: "timeout" }, AUTH).detail, new RegExp(`${TIMEOUT_MS / 1000} seconds`));
  assert.equal(describe({ kind: "network" }, AUTH).status, "Unreachable");
  const odd = describe({ kind: "response", status: 404, detail: null }, AUTH);
  assert.equal(odd.status, "Unexpected answer");
  assert.match(odd.detail, /HTTP 404 where a key set was expected/);
});

test("rounds never overlap, however often the visitor toggles", async () => {
  const timers = fakeTimers();
  const { round, calls } = controlledRound();
  const poller = new Poller({ round, ...timers });

  poller.start();
  poller.pause();
  poller.resume();
  poller.setHidden(true);
  poller.setHidden(false);
  poller.resume();

  assert.equal(calls.length, 1, "only the first round may be in flight");
  calls[0]({ failed: false });
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(timers.pending.size, 1, "exactly one next round is scheduled");
  assert.equal([...timers.pending.values()][0].delay, INTERVAL_MS);
});

test("pausing cancels the next round and sends nothing until resumed", async () => {
  const timers = fakeTimers();
  let rounds = 0;
  const poller = new Poller({
    round: async () => {
      rounds += 1;
      return { failed: false };
    },
    ...timers,
  });

  await poller.start();
  poller.pause();
  assert.equal(timers.pending.size, 0);
  assert.equal(rounds, 1);

  await poller.resume();
  assert.equal(rounds, 2, "resuming refreshes straight away");
  assert.equal(timers.pending.size, 1);
});

test("a hidden tab keeps no timer and catches up when shown", async () => {
  const timers = fakeTimers();
  let rounds = 0;
  const poller = new Poller({
    round: async () => {
      rounds += 1;
      return { failed: false };
    },
    ...timers,
  });

  await poller.start();
  poller.setHidden(true);
  assert.equal(timers.pending.size, 0);
  await poller.setHidden(false);
  assert.equal(rounds, 2);
});

test("failing rounds slow the schedule down, a good round restores it", async () => {
  const timers = fakeTimers();
  const results = [true, true, true, false];
  const poller = new Poller({ round: async () => ({ failed: results.shift() }), ...timers });

  await poller.start();
  const delays = [];
  for (let i = 0; i < 3; i += 1) {
    delays.push([...timers.pending.values()][0].delay);
    await timers.fire();
  }
  delays.push([...timers.pending.values()][0].delay);
  assert.deepEqual(delays, [10000, 20000, 30000, 5000]);
});

test("the cadence line tells the visitor what the console is doing", () => {
  assert.match(cadenceLabel({ paused: true, hidden: false, delay: 5000 }), /^Paused/);
  assert.match(cadenceLabel({ paused: false, hidden: true, delay: 5000 }), /background/);
  assert.equal(cadenceLabel({ paused: false, hidden: false, delay: 5000 }), "Checking every 5 seconds.");
  assert.match(cadenceLabel({ paused: false, hidden: false, delay: 20000 }), /next in 20 seconds/);
});

test("default timers are called as plain functions, not as methods of the poller", async () => {
  // Browsers reject window.setTimeout called with another `this` ("Illegal
  // invocation"); Node does not, so emulate the browser's check.
  const realSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = function strictSetTimeout(fn, delay) {
    if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation");
    return realSetTimeout(fn, delay);
  };
  try {
    const poller = new Poller({ round: async () => ({ failed: false }) });
    await poller.start();
    assert.notEqual(poller.timer, null);
    poller.pause();
  } finally {
    globalThis.setTimeout = realSetTimeout;
  }
});

/** The x coordinates of every command in a path's d attribute. */
const xs = (d) => [...d.matchAll(/[ML](-?[\d.]+)/g)].map((m) => Number(m[1]));

test("the newest sample always sits on the sparkline's right edge", () => {
  for (const n of [1, 2, 7, SPARK_SLOTS, SPARK_SLOTS + 10]) {
    const { line } = sparkGeometry(Array.from({ length: n }, (_, i) => 10 + i));
    assert.equal(xs(line).at(-1), SPARK_WIDTH, `with ${n} samples`);
  }
});

test("one hidden sample waits left of the edge, so sliding never pops a point", () => {
  const history = Array.from({ length: 40 }, () => 12);
  const { line, step } = sparkGeometry(history);
  const x = xs(line);
  assert.equal(x.length, SPARK_SLOTS + 1);
  assert.ok(Math.abs(x[0] + step) < 0.01, "oldest kept point is one step off-screen");
  assert.ok(Math.abs(step - SPARK_WIDTH / (SPARK_SLOTS - 1)) < 1e-9);
});

test("the scale has a floor and headroom, and points are kept in raw milliseconds", () => {
  assert.ok(Math.abs(sparkGeometry([1, 2]).max - SPARK_FLOOR_MS * 1.15) < 1e-9);
  const geo = sparkGeometry([100, 40]);
  assert.ok(Math.abs(geo.max - 115) < 1e-9);
  assert.match(geo.line, /^M[\d.]+ -100L120 -40$/);
});

test("a failure breaks the line and leaves a full-height tick", () => {
  const { line, fails } = sparkGeometry([5, 6, null, 7, 8]);
  assert.equal((line.match(/M/g) || []).length, 2, "two separate runs");
  assert.equal((fails.match(/M/g) || []).length, 1);
  assert.match(fails, /^M[\d.]+ 3V25$/);
});

test("an isolated sample still shows as a dot, and an outage alone draws no line", () => {
  assert.match(sparkGeometry([null, 9, null]).line, /h0\.01$/);
  const down = sparkGeometry([null, null]);
  assert.equal(down.line, "");
  assert.equal((down.fails.match(/M/g) || []).length, 2);
});
