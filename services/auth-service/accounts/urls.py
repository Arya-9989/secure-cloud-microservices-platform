from django.urls import path

from . import views

auth_urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="register"),
    path("token/", views.TokenView.as_view(), name="token"),
    path("token/refresh/", views.TokenRefreshView.as_view(), name="token-refresh"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("me/", views.MeView.as_view(), name="me"),
    path("password/", views.PasswordChangeView.as_view(), name="password-change"),
    path("oauth/token", views.OAuthTokenView.as_view(), name="oauth-token"),
]

admin_urlpatterns = [
    path("users/", views.AdminUserListView.as_view(), name="admin-users"),
    path("users/<uuid:pk>/", views.AdminUserDetailView.as_view(), name="admin-user-detail"),
    path("audit-events/", views.AdminAuditEventListView.as_view(), name="admin-audit-events"),
]
