// Swagger UI bootstrap for the orders-service API reference. It lives in a file,
// not inline, so the page runs under a CSP without 'unsafe-inline', and it starts
// as soon as the bundle is parsed instead of waiting for the load event.
(() => {
  "use strict";
  const node = document.getElementById("swagger-ui");
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
})();
