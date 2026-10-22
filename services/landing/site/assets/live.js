// Pure logic behind the landing page's live gateway console: no DOM, so it is
// unit-tested with `node --test` (services/landing/tests/live.test.js).

/** Normal cadence of a probe round. */
export const INTERVAL_MS = 5000;
/** Slowest cadence while something keeps failing. */
export const MAX_INTERVAL_MS = 30000;
/** A probe that has not answered by now counts as timed out. */
export const TIMEOUT_MS = 4000;

/**
 * Delay before the next round. Doubles after each round in which a probe failed
 * (5, 10, 20, 30 s), so a tab left open on a broken stack does not keep polling
 * at full rate, and returns to 5 s as soon as everything answers again.
 */
export function nextDelay(failedRounds) {
  return Math.min(MAX_INTERVAL_MS, INTERVAL_MS * 2 ** Math.max(0, failedRounds));
}

const GATEWAY_ERRORS = {
  502: "it did not answer the gateway properly",
  503: "the gateway has no healthy instance of it",
  504: "the gateway gave up waiting for it",
};

/**
 * Turns the outcome of one probe into what the console shows.
 *
 * @param {{kind: "response", status: number, detail: string | null}
 *        | {kind: "timeout"} | {kind: "network"}} outcome
 * @param {{name: string, okLabel: string, expected: string}} probe
 * @returns {{up: boolean, status: string, detail: string}}
 */
export function describe(outcome, probe) {
  if (outcome.kind === "network") {
    return { up: false, status: "Unreachable", detail: "No response from the gateway at all." };
  }
  if (outcome.kind === "timeout") {
    return {
      up: false,
      status: "Timed out",
      detail: `No answer within ${TIMEOUT_MS / 1000} seconds.`,
    };
  }
  if (outcome.detail !== null) {
    return { up: true, status: probe.okLabel, detail: outcome.detail };
  }
  const reason = GATEWAY_ERRORS[outcome.status];
  if (reason) {
    return {
      up: false,
      status: "Unavailable",
      detail: `HTTP ${outcome.status}: ${probe.name} is down, ${reason}.`,
    };
  }
  return {
    up: false,
    status: "Unexpected answer",
    detail: `HTTP ${outcome.status} where ${probe.expected} was expected.`,
  };
}

/** Width of a sparkline in SVG user units (its viewBox is 0 0 120 28). */
export const SPARK_WIDTH = 120;
/** Samples visible at once; the newest always sits on the right edge. */
export const SPARK_SLOTS = 24;
/** Lowest top of the scale, so a fast, flat series does not look jumpy. */
export const SPARK_FLOOR_MS = 20;

/**
 * Geometry of one sparkline. `history` holds round-trip times in ms, or null
 * for a probe that failed. Uses the last SPARK_SLOTS + 1 samples: the oldest
 * sits one step left of the visible area, so when the line slides left by
 * `step` to make room for a new sample, nothing pops out at the left edge.
 *
 * The line is drawn in raw milliseconds (y = -ms), so a change of scale is one
 * transform (scaleY = 24 / max) that can be animated instead of every point
 * jumping. A failure breaks the line and becomes a full-height tick, so an
 * outage stays visible in the history after the service recovers.
 *
 * @param {Array<number | null>} history oldest first
 * @returns {{line: string, fails: string, max: number, step: number}}
 */
export function sparkGeometry(history) {
  const step = SPARK_WIDTH / (SPARK_SLOTS - 1);
  const samples = history.slice(-(SPARK_SLOTS + 1));
  const n = samples.length;
  const x = (i) => Number((SPARK_WIDTH - (n - 1 - i) * step).toFixed(2));
  const valid = samples.filter((ms) => ms !== null);
  const max = Math.max(SPARK_FLOOR_MS, ...valid) * 1.15;

  const line = [];
  const fails = [];
  let open = false;
  samples.forEach((ms, i) => {
    if (ms === null) {
      fails.push(`M${x(i)} 3V25`);
      open = false;
      return;
    }
    const y = -Number(ms.toFixed(2));
    if (open) {
      line.push(`L${x(i)} ${y}`);
      return;
    }
    // A run of one sample still shows, as a dot: a tiny segment with round caps.
    const next = samples[i + 1];
    line.push(next === undefined || next === null ? `M${x(i)} ${y}h0.01` : `M${x(i)} ${y}`);
    open = true;
  });
  return { line: line.join(""), fails: fails.join(""), max, step };
}

/** Human cadence line for the console header. */
export function cadenceLabel({ paused, hidden, delay }) {
  if (paused) return "Paused. Nothing is sent until you resume.";
  if (hidden) return "Paused while this tab is in the background.";
  if (delay <= INTERVAL_MS) return `Checking every ${INTERVAL_MS / 1000} seconds.`;
  return `Something is failing, so checks back off: next in ${delay / 1000} seconds.`;
}

/**
 * Runs probe rounds one at a time. Never overlaps two rounds, never keeps a
 * timer while paused or hidden, and backs off while rounds fail.
 *
 * `round()` must resolve to `{ failed: boolean }`. Timers are injected so the
 * scheduling can be tested without waiting.
 */
export class Poller {
  constructor({
    round,
    onCadence = () => {},
    // Wrapped: browsers throw "Illegal invocation" when setTimeout is called as a
    // method of another object (this.setTimer(...)).
    setTimer = (fn, delay) => setTimeout(fn, delay),
    clearTimer = (handle) => clearTimeout(handle),
  }) {
    this.round = round;
    this.onCadence = onCadence;
    this.setTimer = setTimer;
    this.clearTimer = clearTimer;
    this.paused = false;
    this.hidden = false;
    this.inFlight = false;
    this.failedRounds = 0;
    this.timer = null;
  }

  start() {
    return this.tick();
  }

  async tick() {
    this.timer = null;
    if (this.inFlight || this.paused || this.hidden) return;
    this.inFlight = true;
    try {
      const { failed } = await this.round();
      this.failedRounds = failed ? this.failedRounds + 1 : 0;
    } finally {
      this.inFlight = false;
    }
    this.schedule();
  }

  schedule() {
    if (this.paused || this.hidden || this.timer !== null || this.inFlight) {
      this.report();
      return;
    }
    const delay = nextDelay(this.failedRounds);
    this.timer = this.setTimer(() => this.tick(), delay);
    this.report(delay);
  }

  report(delay = nextDelay(this.failedRounds)) {
    this.onCadence(cadenceLabel({ paused: this.paused, hidden: this.hidden, delay }));
  }

  stop() {
    if (this.timer !== null) this.clearTimer(this.timer);
    this.timer = null;
  }

  pause() {
    this.paused = true;
    this.stop();
    this.report();
  }

  resume() {
    this.paused = false;
    // A round still in flight schedules the next one when it finishes.
    return this.inFlight ? this.report() : this.tick();
  }

  setHidden(hidden) {
    this.hidden = hidden;
    if (hidden) {
      this.stop();
      this.report();
      return undefined;
    }
    return this.paused || this.inFlight ? this.report() : this.tick();
  }
}
