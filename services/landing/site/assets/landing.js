// Landing page behaviour: live endpoint probes, section-aware nav, scroll reveals.
// Everything here is progressive enhancement: with JavaScript off the page reads
// completely. DOM writes use textContent and attributes only, so the page runs
// under `require-trusted-types-for 'script'`.
import { Poller, SPARK_SLOTS, TIMEOUT_MS, describe, sparkGeometry } from "./live.js";

// One sample more than the sparkline shows, so the slide never pops a point.
const HISTORY = SPARK_SLOTS + 1;
const SPARK_MS = 600;
const EASE = "cubic-bezier(0.4, 0, 0.6, 1)";
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

// ---------------------------------------------------------------- live probes

const shortKid = (kid) => (kid.length > 10 ? `${kid.slice(0, 10)}…` : kid);

// `evaluate` returns the detail line for a healthy answer, or null.
const PROBES = {
  gateway: {
    url: "/",
    method: "HEAD",
    name: "the gateway",
    okLabel: "Operational",
    expected: "this page",
    async evaluate(response) {
      return response.ok ? `HTTP ${response.status} · served through Traefik` : null;
    },
  },
  auth: {
    url: "/.well-known/jwks.json",
    name: "auth-service",
    okLabel: "Operational",
    expected: "a JSON Web Key Set",
    async evaluate(response) {
      if (!response.ok) return null;
      const keys = (await response.json()).keys || [];
      if (!keys.length) return null;
      const count = `${keys.length} ${keys.length === 1 ? "key" : "keys"} published`;
      return `${keys[0].alg} · kid ${shortKid(String(keys[0].kid))} · ${count}`;
    },
  },
  orders: {
    url: "/.well-known/oauth-protected-resource",
    name: "orders-service",
    okLabel: "Operational",
    expected: "RFC 9728 metadata",
    async evaluate(response) {
      if (!response.ok) return null;
      const scopes = (await response.json()).scopes_supported || [];
      return `Scopes: ${scopes.join(" ")}`;
    },
  },
  policy: {
    url: "/api/v1/orders",
    name: "orders-service",
    okLabel: "Enforced",
    expected: "401 with a Bearer challenge",
    async evaluate(response) {
      const challenge = response.headers.get("WWW-Authenticate") || "";
      if (response.status !== 401 || !challenge.startsWith("Bearer")) return null;
      return "401 Unauthorized · Bearer challenge";
    },
  },
};

async function probeOnce(probe) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), TIMEOUT_MS);
  const started = performance.now();
  try {
    const response = await fetch(probe.url, {
      method: probe.method || "GET",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    const ms = performance.now() - started;
    const detail = await probe.evaluate(response.clone()).catch(() => null);
    // Always drain the body so the connection is released straight away.
    await response.arrayBuffer().catch(() => null);
    return { ms, outcome: { kind: "response", status: response.status, detail } };
  } catch (error) {
    const kind = error && error.name === "AbortError" ? "timeout" : "network";
    return { ms: null, outcome: { kind } };
  } finally {
    window.clearTimeout(timeout);
  }
}

function setupProbes() {
  const rows = [...document.querySelectorAll("[data-probe]")];
  if (!rows.length || !window.fetch || !window.AbortController) return;
  // Rows marked data-manual run only when the visitor asks (the 401 probe would
  // otherwise log a console error on every round).
  const polled = rows.filter((row) => !row.hasAttribute("data-manual"));
  const toggle = document.querySelector("[data-live-toggle]");
  const toggleLabel = document.querySelector("[data-live-label]");
  const cadence = document.querySelector("[data-cadence]");
  const announcer = document.querySelector("[data-announce]");
  const state = new Map(rows.map((row) => [row, { history: [], last: null, ping: 1 }]));
  let firstRound = true;

  // The sparkline slides left by one step as each sample arrives and eases to a
  // new scale, instead of being redrawn in place. Only attributes and transforms
  // are written (no layout reads), and with reduced motion it simply updates.
  const drawSpark = (row, s) => {
    const line = row.querySelector("[data-spark]");
    const fails = row.querySelector("[data-spark-fail]");
    const slide = row.querySelector("[data-spark-slide]");
    const scale = row.querySelector("[data-spark-scale]");
    if (!line || !fails || !slide || !scale) return;
    const geo = sparkGeometry(s.history);
    const to = `translate(0px, 26px) scale(1, ${(24 / geo.max).toFixed(5)})`;
    const from = s.scale || to;
    line.setAttribute("d", geo.line);
    fails.setAttribute("d", geo.fails);
    scale.style.transform = to;
    s.scale = to;
    if (reduceMotion.matches || typeof slide.animate !== "function" || s.history.length < 2) {
      return;
    }
    const timing = { duration: SPARK_MS, easing: EASE };
    slide.animate(
      [{ transform: `translateX(${geo.step.toFixed(3)}px)` }, { transform: "translateX(0px)" }],
      timing,
    );
    if (from !== to) scale.animate([{ transform: from }, { transform: to }], timing);
  };

  const render = (row, { ms, outcome }) => {
    const s = state.get(row);
    const probe = PROBES[row.dataset.probe];
    const view = describe(outcome, probe);
    const status = row.querySelector("[data-status]");
    row.dataset.state = view.up ? "up" : "down";
    status.textContent = view.status;
    status.hidden = false;
    row.querySelector("[data-detail]").textContent = view.detail;
    // Only a healthy answer measures the service; an error page or a timeout does not.
    row.querySelector("[data-rtt]").textContent = view.up
      ? String(Math.max(1, Math.round(ms)))
      : "–";
    // A failure is recorded too: it breaks the line and leaves a red tick.
    s.history.push(view.up ? ms : null);
    if (s.history.length > HISTORY) s.history.shift();
    drawSpark(row, s);
    if (view.up) {
      if (!reduceMotion.matches) {
        s.ping = s.ping === 1 ? 2 : 1;
        row.dataset.ping = String(s.ping);
      }
    }
    if (!firstRound && s.last !== null && s.last !== view.up && announcer) {
      const name = row.querySelector(".probe-name").textContent.trim();
      announcer.textContent = view.up ? `${name} is answering again.` : `${name}: ${view.status}.`;
    }
    s.last = view.up;
    return view.up;
  };

  const poller = new Poller({
    round: async () => {
      const results = await Promise.all(
        polled.map((row) => probeOnce(PROBES[row.dataset.probe])),
      );
      const healthy = polled.map((row, i) => render(row, results[i]));
      firstRound = false;
      return { failed: healthy.includes(false) };
    },
    onCadence: (text) => {
      if (cadence) cadence.textContent = text;
    },
  });

  if (toggle && toggleLabel) {
    toggle.hidden = false;
    toggle.addEventListener("click", () => {
      const pausing = !poller.paused;
      toggle.setAttribute("aria-pressed", String(pausing));
      toggleLabel.textContent = pausing ? "Resume live updates" : "Pause live updates";
      if (pausing) poller.pause();
      else poller.resume();
    });
  }

  for (const row of rows.filter((r) => r.hasAttribute("data-manual"))) {
    const button = row.querySelector("[data-try]");
    if (!button) continue;
    button.hidden = false;
    row.querySelector("[data-status]").hidden = true;
    button.addEventListener("click", async () => {
      button.disabled = true;
      render(row, await probeOnce(PROBES[row.dataset.probe]));
      if (announcer) {
        const status = row.querySelector("[data-status]").textContent;
        const detail = row.querySelector("[data-detail]").textContent;
        announcer.textContent = `${status}. ${detail}`;
      }
      button.textContent = "Send again";
      button.disabled = false;
    });
  }

  document.addEventListener("visibilitychange", () => poller.setHidden(document.hidden));
  poller.hidden = document.hidden;
  poller.start();
}

// ---------------------------------------------------------------- local nav

function setupNav() {
  const nav = document.querySelector(".localnav-links");
  const links = [...document.querySelectorAll(".localnav-links a[href^='#']")];
  if (!nav || !links.length || !("IntersectionObserver" in window)) return;
  const byId = new Map(links.map((a) => [a.getAttribute("href").slice(1), a]));

  // One underline that slides to the active link (a transform only), instead of
  // one per link blinking on and off. Created here, so without JavaScript there
  // is nothing to slide and nothing is missing.
  const ink = document.createElement("span");
  ink.className = "nav-ink";
  ink.setAttribute("aria-hidden", "true");
  nav.append(ink);
  nav.classList.add("has-ink");
  let active = null;
  let frame = 0;
  const placeInk = () => {
    frame = 0;
    if (!active || !active.offsetWidth) {
      ink.classList.remove("is-on");
      return;
    }
    ink.style.transform = `translateX(${active.offsetLeft}px) scaleX(${active.offsetWidth})`;
    ink.classList.add("is-on");
  };
  const queueInk = () => {
    if (!frame) frame = requestAnimationFrame(placeInk);
  };
  if ("ResizeObserver" in window) new ResizeObserver(queueInk).observe(nav);

  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        for (const a of links) a.removeAttribute("aria-current");
        // Sections without a nav link (the hero, the closing call to action)
        // clear the highlight instead of leaving the last one lit.
        active = byId.get(entry.target.id) || null;
        active?.setAttribute("aria-current", "true");
        queueInk();
      }
    },
    { rootMargin: "-45% 0px -50% 0px" },
  );
  for (const section of document.querySelectorAll("main > section")) observer.observe(section);
}

// ---------------------------------------------------------------- reveals

// Content is never hidden at rest: it is laid out, visible and readable in
// screenshots, in print and with JavaScript off. A block below the fold plays a
// short fade-and-lift once, the first time it scrolls into view (.reveal-in).
function setupReveals() {
  if (reduceMotion.matches || !("IntersectionObserver" in window)) return;
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add("reveal-in");
      observer.unobserve(entry.target);
    }
  });
  const fold = window.innerHeight;
  for (const el of document.querySelectorAll(".reveal")) {
    if (el.getBoundingClientRect().top < fold) continue; // already on screen: no motion
    observer.observe(el);
  }
}

setupReveals();
setupNav();
setupProbes();
