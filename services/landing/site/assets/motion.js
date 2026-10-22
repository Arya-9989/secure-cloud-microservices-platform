// Request-flow fallback for browsers without CSS scroll-driven animations.
//
// Where `animation-timeline: view()` is supported, landing.css scrubs the flow
// with the scroll position and this file does nothing. Elsewhere it arms the
// diagram (only now that JavaScript has run may anything start hidden) and plays
// the same five steps once, when the diagram comes into view. With reduced
// motion, or without IntersectionObserver, the diagram stays in its drawn,
// static state.
const flow = document.querySelector(".flow");
const scrubbed = window.CSS && CSS.supports("animation-timeline: view()");
const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

if (flow && !scrubbed && !reduce && "IntersectionObserver" in window) {
  const figure = flow.querySelector(".diagram");
  const observer = new IntersectionObserver(
    (entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) return;
      flow.classList.add("flow-play");
      observer.disconnect();
    },
    { threshold: 0.45 },
  );
  // Already on screen when the page loads: leave it drawn rather than blank it.
  const box = figure.getBoundingClientRect();
  if (box.top > window.innerHeight) {
    flow.classList.add("flow-armed");
    observer.observe(figure);
  }
}
