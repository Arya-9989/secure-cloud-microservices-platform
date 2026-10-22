// Static checks of the landing page itself: CSP compatibility, the motion rules
// (progressive enhancement, reduced motion, compositor-friendly properties) and
// content that must be in the HTML with JavaScript off. node --test tests/
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

const site = new URL("../site/", import.meta.url);
const html = readFileSync(new URL("index.html", site), "utf8");
const css = readFileSync(new URL("assets/landing.css", site), "utf8");

/**
 * Flattens a stylesheet into rules, each with the at-rule preludes it is nested
 * in. Keyframe blocks come back as one rule each (selector "@keyframes name").
 */
function parseCss(source) {
  const text = source.replace(/\/\*[\s\S]*?\*\//g, "");
  const rules = [];
  const stack = [];
  let buffer = "";
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "{") {
      const prelude = buffer.trim();
      buffer = "";
      if (prelude.startsWith("@keyframes")) {
        let depth = 1;
        let j = i + 1;
        while (depth > 0) {
          if (text[j] === "{") depth += 1;
          if (text[j] === "}") depth -= 1;
          j += 1;
        }
        rules.push({ selector: prelude, body: text.slice(i + 1, j - 1), within: [...stack] });
        i = j - 1;
      } else if (prelude.startsWith("@")) {
        stack.push(prelude);
      } else {
        const end = text.indexOf("}", i);
        rules.push({ selector: prelude, body: text.slice(i + 1, end), within: [...stack] });
        i = end;
      }
    } else if (ch === "}") {
      stack.pop();
      buffer = "";
    } else if (ch === ";" && !stack.length && buffer.trim().startsWith("@")) {
      buffer = "";
    } else {
      buffer += ch;
    }
  }
  return rules;
}

const rules = parseCss(css);
const styleRules = rules.filter((r) => !r.selector.startsWith("@keyframes"));
const motionAllowed = (r) => r.within.some((at) => /prefers-reduced-motion:\s*no-preference/.test(at));
const scrollDriven = (r) => r.within.some((at) => /@supports\s*\(animation-timeline:\s*view\(\)\)/.test(at));

test("the page needs no inline script or style, so the strict CSP holds", () => {
  assert.doesNotMatch(html, /<style[\s>]/i, "no <style> element");
  assert.doesNotMatch(html, /\sstyle\s*=/i, "no style attribute");
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i, "no inline event handler");
  assert.doesNotMatch(html, /javascript:/i);
  for (const tag of html.match(/<script\b[^>]*>/gi)) {
    assert.match(tag, /\ssrc="\/assets\/[\w.-]+\.js"/, `external script only: ${tag}`);
  }
});

test("every script and stylesheet the page loads exists", () => {
  const refs = [...html.matchAll(/(?:src|href)="\/assets\/([\w./-]+)"/g)].map((m) => m[1]);
  assert.ok(refs.includes("motion.js") && refs.includes("landing.js"));
  for (const ref of refs) assert.ok(existsSync(new URL(`assets/${ref}`, site)), ref);
});

test("keyframes animate only opacity, transforms and SVG stroke offsets", () => {
  const allowed = new Set(["opacity", "transform", "stroke-dashoffset", "clip-path"]);
  const keyframes = rules.filter((r) => r.selector.startsWith("@keyframes"));
  assert.ok(keyframes.length >= 10);
  for (const block of keyframes) {
    for (const [, prop] of block.body.matchAll(/([a-z-]+)\s*:/g)) {
      assert.ok(allowed.has(prop), `${block.selector} animates ${prop}`);
    }
  }
});

test("every animation is skipped under reduced motion", () => {
  for (const rule of styleRules) {
    const plays =
      /animation(-name)?\s*:\s*(?!none\b)\S/.test(rule.body) || /animation-timeline/.test(rule.body);
    if (plays) assert.ok(motionAllowed(rule), `${rule.selector} animates without a reduced-motion guard`);
  }
});

test("scroll timelines and the pinned story exist only where the browser supports them", () => {
  for (const rule of styleRules) {
    const scrubs = /view-timeline|animation-timeline|position:\s*sticky/.test(rule.body);
    if (scrubs && /\.fl\b|\.flow/.test(rule.selector)) {
      assert.ok(scrollDriven(rule), `${rule.selector} needs @supports (animation-timeline: view())`);
    }
  }
  const pinned = styleRules.find((r) => r.selector === ".flow" && /height:\s*400vh/.test(r.body));
  assert.ok(pinned && motionAllowed(pinned) && scrollDriven(pinned));
});

test("nothing starts hidden unless motion is allowed and armed", () => {
  // Decorative pieces that never carry text: the probe ping ring and the nav
  // underline (created by JavaScript).
  const decorative = new Set([".dot::after", ".nav-ink"]);
  for (const rule of styleRules) {
    if (!/(^|;)\s*opacity:\s*0\s*(;|$)/.test(rule.body.trim())) continue;
    assert.ok(motionAllowed(rule) || decorative.has(rule.selector), `${rule.selector} hides content at rest`);
  }
  // The JavaScript fallback hides wires only after motion.js has armed the flow.
  for (const rule of styleRules.filter((r) => r.selector.includes("flow-armed"))) {
    assert.ok(motionAllowed(rule), rule.selector);
  }
});

test("every flow timing class used in the page is defined with matching values", () => {
  const used = new Set([...html.matchAll(/\bk-(\d\d)-(\d\d\d?)\b/g)].map((m) => m[0]));
  assert.ok(used.size >= 30);
  for (const name of used) {
    const [, a, b] = name.match(/k-(\d+)-(\d+)/);
    const rule = styleRules.find((r) => r.selector === `.${name}`);
    assert.ok(rule, `.${name} is not defined`);
    assert.equal(Number(rule.body.match(/--a:\s*([\d.]+)/)[1]), Number(a) / 100, name);
    assert.equal(Number(rule.body.match(/--b:\s*([\d.]+)/)[1]), Number(b) / 100, name);
  }
});

test("the request flow reads completely from the HTML, with JavaScript off", () => {
  const list = html.match(/<ol class="flow-steps"[\s\S]*?<\/ol>/);
  assert.ok(list, "the steps are in the page, not generated");
  const titles = [...list[0].matchAll(/<h4 class="flow-step-title">([^<]+)<\/h4>/g)].map((m) => m[1]);
  assert.deepEqual(titles, [
    "Log in.",
    "RS256 token issued.",
    "JWKS fetched.",
    "Verified at orders.",
    "No token, 401.",
  ]);
  for (const call of ["POST /api/v1/auth/token/", "GET /.well-known/jwks.json", "GET /api/v1/orders · 401"]) {
    assert.ok(list[0].includes(call), call);
  }
  // Both diagrams describe the numbered flow for screen readers.
  assert.equal((html.match(/Numbered markers follow one request/g) || []).length, 2);
});
