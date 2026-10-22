// Swagger UI bootstrap for the orders-service API reference. It lives in a file, not
// inline, so the page runs under a CSP without 'unsafe-inline'.
//
// The page's title and introduction are plain HTML. Swagger UI's stylesheet and
// 1.5 MB bundle are requested only after that has painted, so they never delay
// it, and Swagger renders once both have arrived.
(() => {
  "use strict";
  const node = document.getElementById("swagger-ui");

  const load = (element) =>
    new Promise((resolve, reject) => {
      element.addEventListener("load", resolve, { once: true });
      element.addEventListener("error", reject, { once: true });
    });

  const start = () => {
    const stylesheet = document.createElement("link");
    stylesheet.rel = "stylesheet";
    stylesheet.href = node.dataset.stylesheet;
    // Before the platform theme, so the theme keeps overriding Swagger's styles.
    const theme = document.querySelector('link[href="/assets/tokens.css"]');
    document.head.insertBefore(stylesheet, theme);

    const bundle = document.createElement("script");
    bundle.src = node.dataset.bundle;
    const ready = Promise.all([load(stylesheet), load(bundle)]);
    document.body.append(bundle);

    ready.then(
      () => {
        window.ui = window.SwaggerUIBundle({
          url: node.dataset.openapiUrl,
          dom_id: "#swagger-ui",
          layout: "BaseLayout", // the page brings its own header; no standalone top bar
          presets: [window.SwaggerUIBundle.presets.apis],
          // Deep links render an <a> inside each operation's toggle button, which nests
          // interactive controls (axe: nested-interactive). Accessibility wins.
          deepLinking: false,
          tryItOutEnabled: true,
          defaultModelsExpandDepth: 0,
          // Bearer tokens stay in memory: nothing is written to localStorage on the
          // gateway origin the landing page shares.
          persistAuthorization: false,
          validatorUrl: null,
        });
      },
      () => {
        const message = document.createElement("p");
        message.className = "docs-noscript";
        message.textContent =
          "The interactive reference could not be loaded. The OpenAPI document above describes every operation.";
        node.replaceChildren(message);
      },
    );
  };

  // Start once the browser reports the first paint (the title and introduction),
  // and never later than 3 s, e.g. in a background tab that does not paint.
  let started = false;
  const once = () => {
    if (!started) {
      started = true;
      start();
    }
  };
  if (window.PerformanceObserver && PerformanceObserver.supportedEntryTypes?.includes("paint")) {
    new PerformanceObserver((list, observer) => {
      observer.disconnect();
      setTimeout(once, 0);
    }).observe({ type: "paint", buffered: true });
  } else {
    requestAnimationFrame(() => setTimeout(once, 0));
  }
  setTimeout(once, 3000);
})();
