// Swagger UI bootstrap for the auth-service API reference. It lives in a file,
// not inline, so the page runs under a CSP without 'unsafe-inline'.
(() => {
  "use strict";
  const node = document.getElementById("swagger-ui");
  window.ui = window.SwaggerUIBundle({
    url: node.dataset.openapiUrl,
    dom_id: "#swagger-ui",
    layout: "BaseLayout",
    presets: [window.SwaggerUIBundle.presets.apis],
    // Deep links render an <a> inside each operation's toggle button, which nests
    // interactive controls (axe: nested-interactive). Accessibility wins.
    deepLinking: false,
    tryItOutEnabled: true,
    defaultModelsExpandDepth: 0,
    validatorUrl: null,
  });
})();
