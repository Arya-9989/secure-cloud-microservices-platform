# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.12.15-slim-trixie

# ---------------------------------------------------------------------------- build
FROM ghcr.io/astral-sh/uv:0.13.5 AS uv

FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src

# Dependencies first so the layer is cached until the lockfile changes.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project

COPY manage.py gunicorn.conf.py ./
COPY auth_service ./auth_service
COPY accounts ./accounts
COPY platform_core ./platform_core

# Collect Swagger UI assets. Settings need *some* values to import; these are
# build-time placeholders and are not present in the final image environment.
RUN DJANGO_SECRET_KEY=build-only-placeholder-not-a-real-secret-000000 \
    DATABASE_URL=sqlite://:memory: \
    /opt/venv/bin/python manage.py collectstatic --noinput --verbosity 0

# ---------------------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="auth-service" \
      org.opencontainers.image.description="Issues RS256 JWTs, rotating refresh tokens and a JWKS endpoint" \
      org.opencontainers.image.source="https://github.com/Arya-9989/secure-cloud-microservices-platform" \
      org.opencontainers.image.licenses="MIT"

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && install -d -o app -g app -m 0700 /keys

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    JWT_PRIVATE_KEY_FILE=/keys/jwt-private-key.pem

COPY --from=build /opt/venv /opt/venv
# Application code is owned by root and read-only for the runtime user.
COPY --from=build /src /app
WORKDIR /app

USER 10001:10001
EXPOSE 8000 9100

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

CMD ["gunicorn", "--config", "gunicorn.conf.py", "auth_service.wsgi:application"]
