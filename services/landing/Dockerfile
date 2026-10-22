# syntax=docker/dockerfile:1.7

# Static landing page and the shared API-docs theme. No build step: the site is
# hand-written HTML, CSS and a small script, served by unprivileged nginx.
FROM nginxinc/nginx-unprivileged:1.30.6-alpine3.24-slim

LABEL org.opencontainers.image.title="landing" \
      org.opencontainers.image.description="Platform landing page and API docs theme, served behind the gateway" \
      org.opencontainers.image.source="https://github.com/Arya-9989/secure-cloud-microservices-platform" \
      org.opencontainers.image.licenses="MIT"

# Replace the stock configuration entirely (no default server, no entrypoint
# scripts that try to rewrite config on a read-only filesystem).
USER root
RUN rm -rf /etc/nginx/conf.d /docker-entrypoint.d /usr/share/nginx/html/*
COPY nginx.conf /etc/nginx/nginx.conf
COPY security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --chmod=0644 site/ /usr/share/nginx/html/
RUN find /usr/share/nginx/html -type d -exec chmod 0755 {} + \
 && nginx -t -c /etc/nginx/nginx.conf
USER 101:101

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]

ENTRYPOINT ["nginx", "-g", "daemon off;"]
