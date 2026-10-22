"""Settings for the auth service.

All configuration comes from environment variables (12-factor). Defaults are
secure: DEBUG is off, secrets have no fallback outside DEBUG, and the service
refuses to start without a database URL or a signing key path.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured
from django.utils.csp import CSP

from platform_core.env import env_bool, env_int, env_list, env_str

BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = env_bool("DJANGO_DEBUG", default=False)

if DEBUG:
    # Local development only: an ephemeral key is fine because nothing we sign
    # with SECRET_KEY needs to survive a restart (JWTs use the RSA key).
    SECRET_KEY = env_str("DJANGO_SECRET_KEY", secrets.token_urlsafe(50))
else:
    SECRET_KEY = env_str("DJANGO_SECRET_KEY")
    if len(SECRET_KEY) < 32:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be at least 32 characters")

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_spectacular",
    "drf_spectacular_sidecar",
    "accounts",
]

MIDDLEWARE = [
    "platform_core.middleware.RequestContextMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "auth_service.urls"
WSGI_APPLICATION = "auth_service.wsgi.application"
APPEND_SLASH = False

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": ["django.template.context_processors.request"]},
    },
]

# --------------------------------------------------------------------------- database & cache
_database_url = env_str(
    "DATABASE_URL", "sqlite:///" + str(BASE_DIR / "db.sqlite3") if DEBUG else None
)
DATABASES = {
    "default": dj_database_url.parse(_database_url, conn_max_age=60, conn_health_checks=True)
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Throttle counters must be shared by every worker and replica, so production
# uses the database cache (no extra infrastructure). `locmem` is for tests.
_cache_backend = env_str("CACHE_BACKEND", "database")
CACHES = {
    "default": (
        {"BACKEND": "django.core.cache.backends.db.DatabaseCache", "LOCATION": "auth_cache"}
        if _cache_backend == "database"
        else {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    )
}

# --------------------------------------------------------------------------- authentication
AUTH_USER_MODEL = "accounts.User"
AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",  # verify-only fallback for legacy hashes
]
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

JWT_ISSUER = env_str("JWT_ISSUER", "urn:secure-platform:auth-service")
JWT_AUDIENCE = env_str("JWT_AUDIENCE", "secure-platform-api")
JWT_PRIVATE_KEY_FILE = env_str("JWT_PRIVATE_KEY_FILE", "/run/secrets/jwt-private-key.pem")
JWT_ADDITIONAL_PUBLIC_KEY_FILES = env_list("JWT_ADDITIONAL_PUBLIC_KEY_FILES")
JWT_CLOCK_SKEW_SECONDS = env_int("JWT_CLOCK_SKEW_SECONDS", 30)
ACCESS_TOKEN_TTL_SECONDS = env_int("ACCESS_TOKEN_TTL_SECONDS", 900)
REFRESH_TOKEN_TTL_SECONDS = env_int("REFRESH_TOKEN_TTL_SECONDS", 7 * 24 * 3600)
REFRESH_SESSION_MAX_SECONDS = env_int("REFRESH_SESSION_MAX_SECONDS", 30 * 24 * 3600)

# --------------------------------------------------------------------------- REST framework
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["accounts.authentication.JWTAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 50,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "platform_core.exceptions.problem_exception_handler",
    "UNAUTHENTICATED_USER": None,
    # Number of trusted reverse proxies in front of the service. Only then is
    # X-Forwarded-For used to identify the client for rate limiting.
    "NUM_PROXIES": env_int("TRUSTED_PROXY_COUNT", 0) or None,
    "DEFAULT_THROTTLE_RATES": {
        "login_ip": env_str("LOGIN_RATE_PER_IP", "20/min"),
        "login_account": env_str("LOGIN_RATE_PER_ACCOUNT", "5/min"),
        "register": env_str("REGISTER_RATE_PER_IP", "10/hour"),
        "refresh": env_str("REFRESH_RATE_PER_IP", "60/min"),
    },
}

API_DOCS_ENABLED = env_bool("API_DOCS_ENABLED", default=True)
SPECTACULAR_SETTINGS = {
    "TITLE": "Auth Service API",
    "DESCRIPTION": (
        "Issues RS256 access tokens and rotating refresh tokens for the Secure "
        "Cloud Microservices Platform. Verify tokens with the JWKS at "
        "`/.well-known/jwks.json`."
    ),
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SERVE_PERMISSIONS": ["rest_framework.permissions.AllowAny"],
    "SERVE_AUTHENTICATION": [],
    "SCHEMA_PATH_PREFIX": "/api/v1",
    "COMPONENT_SPLIT_REQUEST": True,
}

# --------------------------------------------------------------------------- HTTP security
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
X_FRAME_OPTIONS = "DENY"
# One policy for every response. The API docs page is the only HTML: Swagger UI
# and its bootstrap are same-origin files, and its icons are data: URIs.
SECURE_CSP = {
    "default-src": [CSP.NONE],
    "script-src": [CSP.SELF],
    "style-src": [CSP.SELF],
    "img-src": [CSP.SELF, "data:"],
    "font-src": [CSP.SELF],
    "connect-src": [CSP.SELF],
    "base-uri": [CSP.NONE],
    "form-action": [CSP.NONE],
    "frame-ancestors": [CSP.NONE],
}
if env_bool("TRUST_PROXY_PROTO_HEADER", default=False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# --------------------------------------------------------------------------- static (API docs)
STATIC_URL = "/docs/auth/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# --------------------------------------------------------------------------- i18n
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

# --------------------------------------------------------------------------- logging
LOG_LEVEL = env_str("LOG_LEVEL", "INFO")
LOG_FORMAT = env_str("LOG_FORMAT", "json")
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"request_context": {"()": "platform_core.logging.RequestContextFilter"}},
    "formatters": {
        "json": {"()": "platform_core.logging.PlatformJsonFormatter"},
        "console": {"format": "%(asctime)s %(levelname)-7s [%(request_id)s] %(name)s: %(message)s"},
    },
    "handlers": {
        "stdout": {
            "class": "logging.StreamHandler",
            "filters": ["request_context"],
            "formatter": "json" if LOG_FORMAT == "json" else "console",
        }
    },
    "root": {"handlers": ["stdout"], "level": LOG_LEVEL},
    "loggers": {
        # Requests are logged once by RequestContextMiddleware.
        "django.request": {"level": "ERROR"},
        "django.server": {"level": "WARNING"},
    },
}
