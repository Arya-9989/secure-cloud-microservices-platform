from django.conf import settings
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

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
        path("docs/auth/", SpectacularSwaggerView.as_view(url_name="openapi-schema"), name="docs"),
    ]
