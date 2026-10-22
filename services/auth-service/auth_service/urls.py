from django.conf import settings
from django.urls import include, path
from django.views.generic import TemplateView
from drf_spectacular.views import SpectacularAPIView

from accounts.urls import admin_urlpatterns, auth_urlpatterns
from accounts.views import JWKSView
from platform_core.health import liveness, readiness

urlpatterns = [
    path("api/v1/auth/", include(auth_urlpatterns)),
    path("api/v1/admin/", include(admin_urlpatterns)),
    path(".well-known/jwks.json", JWKSView.as_view(), name="jwks"),
    path("healthz", liveness, name="liveness"),
    path("readyz", readiness, name="readiness"),
]

if settings.API_DOCS_ENABLED:
    urlpatterns += [
        path("docs/auth/openapi.json", SpectacularAPIView.as_view(), name="openapi-schema"),
        # Swagger UI with the platform theme; scripts are files so the CSP needs no 'unsafe-inline'.
        path(
            "docs/auth/",
            TemplateView.as_view(template_name="accounts/api_docs.html"),
            name="docs",
        ),
    ]
