// Landing page behaviour: live endpoint probes, section-aware nav, scroll reveals.
// Everything here is progressive enhancement. DOM writes use textContent and
// attributes only, so the page runs under `require-trusted-types-for 'script'`.
(() => {
  "use strict";

  const INTERVAL_MS = 5000;
  const HISTORY = 24;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  // ---------------------------------------------------------------- live probes

  const shortKid = (kid) => (kid.length > 10 ? `${kid.slice(0, 10)}…` : kid);

  const PROBES = {
    gateway: {
      url: "/",
      method: "HEAD",
      okLabel: "Operational",
      async evaluate(response) {
        if (!response.ok) return null;
        return `HTTP ${response.status} · served through Traefik`;
      },
    },
    auth: {
      url: "/.well-known/jwks.json",
      okLabel: "Operational",
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
      okLabel: "Operational",
      async evaluate(response) {
        if (!response.ok) return null;
        const scopes = (await response.json()).scopes_supported || [];
        return `Scopes: ${scopes.join(" ")}`;
      },
    },
    policy: {
      url: "/api/v1/orders",
      okLabel: "Enforced",
      async evaluate(response) {
        const challenge = response.headers.get("WWW-Authenticate") || "";
        if (response.status !== 401 || !challenge.startsWith("Bearer")) return null;
        return "401 Unauthorized · Bearer challenge";
      },
    },
  };

  function setupProbes() {
    const rows = [...document.querySelectorAll("[data-probe]")];
    if (!rows.length || !window.fetch) return;
    // Rows marked data-manual run only when the visitor asks (the 401 probe would
    // otherwise log a console error on every round).
    const polled = rows.filter((row) => !row.hasAttribute("data-manual"));

    const toggle = document.querySelector("[data-live-toggle]");
    const toggleLabel = document.querySelector("[data-live-label]");
    const announcer = document.querySelector("[data-announce]");
    const state = new Map(rows.map((row) => [row, { history: [], last: null, ping: 1 }]));
    let paused = false;
    let timer = 0;
    let firstRound = true;

    const drawSpark = (row, history) => {
      const line = row.querySelector("[data-spark]");
      if (!line || history.length < 2) return;
      const max = Math.max(20, ...history) * 1.15;
      const step = 120 / (history.length - 1);
      const points = history.map(
        (ms, i) => `${(i * step).toFixed(1)},${(26 - (ms / max) * 24).toFixed(1)}`,
      );
      line.setAttribute("points", points.join(" "));
    };

    const render = (row, result) => {
      const s = state.get(row);
      const probe = PROBES[row.dataset.probe];
      const name = row.querySelector(".probe-name").textContent.trim();
      const up = result.detail !== null;
      row.dataset.state = up ? "up" : "down";
      row.querySelector("[data-status]").textContent = up ? probe.okLabel : result.problem;
      row.querySelector("[data-status]").hidden = false;
      if (up) row.querySelector("[data-detail]").textContent = result.detail;
      row.querySelector("[data-rtt]").textContent =
        result.ms === null ? "–" : String(Math.max(1, Math.round(result.ms)));
      if (result.ms !== null) {
        s.history.push(result.ms);
        if (s.history.length > HISTORY) s.history.shift();
        drawSpark(row, s.history);
      }
      if (up && !reduceMotion.matches) {
        s.ping = s.ping === 1 ? 2 : 1;
        row.dataset.ping = String(s.ping);
      }
      if (!firstRound && s.last !== null && s.last !== up && announcer) {
        announcer.textContent = up ? `${name} is answering again.` : `${name}: ${result.problem}.`;
      }
      s.last = up;
    };

    const probeOnce = async (row) => {
      const probe = PROBES[row.dataset.probe];
      const started = performance.now();
      try {
        const response = await fetch(probe.url, {
          method: probe.method || "GET",
          cache: "no-store",
          credentials: "omit",
          redirect: "error",
          headers: { Accept: "application/json" },
        });
        const ms = performance.now() - started;
        const detail = await probe.evaluate(response.clone()).catch(() => null);
        // Always drain the body so the connection is released straight away.
        await response.arrayBuffer().catch(() => null);
        return { ms, detail, problem: detail === null ? `Unexpected HTTP ${response.status}` : "" };
      } catch {
        return { ms: null, detail: null, problem: "Unreachable" };
      }
    };

    const round = async () => {
      timer = 0;
      const results = await Promise.all(polled.map(probeOnce));
      polled.forEach((row, i) => render(row, results[i]));
      firstRound = false;
      schedule();
    };

    const schedule = () => {
      if (!paused && !document.hidden && !timer) timer = window.setTimeout(round, INTERVAL_MS);
    };

    const stop = () => {
      window.clearTimeout(timer);
      timer = 0;
    };

    if (toggle && toggleLabel) {
      toggle.hidden = false;
      toggle.addEventListener("click", () => {
        paused = !paused;
        toggle.setAttribute("aria-pressed", String(paused));
        toggleLabel.textContent = paused ? "Resume live updates" : "Pause live updates";
        if (paused) stop();
        else round();
      });
    }

    for (const row of rows.filter((r) => r.hasAttribute("data-manual"))) {
      const button = row.querySelector("[data-try]");
      if (!button) continue;
      button.hidden = false;
      row.querySelector("[data-status]").hidden = true;
      button.addEventListener("click", async () => {
        button.disabled = true;
        render(row, await probeOnce(row));
        if (announcer) {
          const status = row.querySelector("[data-status]").textContent;
          const detail = row.querySelector("[data-detail]").textContent;
          announcer.textContent = `${status}. ${detail}.`;
        }
        button.textContent = "Send again";
        button.disabled = false;
      });
    }

    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stop();
      else if (!paused) round();
    });

    round();
  }

  // ---------------------------------------------------------------- local nav

  function setupNav() {
    const links = [...document.querySelectorAll(".localnav-links a[href^='#']")];
    if (!links.length || !("IntersectionObserver" in window)) return;
    const byId = new Map(links.map((a) => [a.getAttribute("href").slice(1), a]));
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          for (const a of links) a.removeAttribute("aria-current");
          byId.get(entry.target.id)?.setAttribute("aria-current", "true");
        }
      },
      { rootMargin: "-45% 0px -50% 0px" },
    );
    for (const id of byId.keys()) {
      const section = document.getElementById(id);
      if (section) observer.observe(section);
    }
  }

  // ---------------------------------------------------------------- reveals

  function setupReveals() {
    if (reduceMotion.matches || !("IntersectionObserver" in window)) return;
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          entry.target.classList.add("reveal-in");
          entry.target.classList.remove("reveal-pending");
          observer.unobserve(entry.target);
        }
      },
      { rootMargin: "0px 0px -6% 0px" },
    );
    const fold = window.innerHeight;
    for (const el of document.querySelectorAll(".reveal")) {
      // Content already on screen never animates in; only what is below the fold does.
      if (el.getBoundingClientRect().top < fold) continue;
      el.classList.add("reveal-pending");
      observer.observe(el);
    }
  }

  setupReveals();
  setupNav();
  setupProbes();
})();
