// Shared by both API reference pages. Loaded synchronously in <head> so the
// first paint already uses the right theme: follows the OS colour scheme and
// keeps Swagger UI's own `dark-mode` class in step with our design tokens.
(() => {
  "use strict";
  const root = document.documentElement;
  const query = window.matchMedia("(prefers-color-scheme: dark)");
  const apply = () => {
    root.dataset.theme = query.matches ? "dark" : "light";
    root.classList.toggle("dark-mode", query.matches);
  };
  apply();
  query.addEventListener("change", apply);

  // Accessibility patches for markup Swagger UI renders:
  // - the server picker has no label;
  // - tag headings are <h3> and "Schemas" is <h4> directly under the <h1> title,
  //   so expose them as level 2 to keep the heading outline unbroken.
  const patch = () => {
    const select = document.getElementById("servers");
    if (select && !select.hasAttribute("aria-label")) select.setAttribute("aria-label", "Server");
    for (const heading of document.querySelectorAll(
      "#swagger-ui .opblock-tag:not([aria-level]), #swagger-ui section.models > h4:not([aria-level])",
    )) {
      heading.setAttribute("aria-level", "2");
    }
  };
  new MutationObserver(patch).observe(root, { childList: true, subtree: true });
})();
