from django.urls import path
from .views import (
    InternalHealthCheckView,
    LoginView,
    AdminOnlyView,
    UserOnlyView,
    ServiceOnlyView,
    AdminOrServiceView
)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),

    path('admin-only/', AdminOnlyView.as_view()),
    path('user-only/', UserOnlyView.as_view()),
    path('service-only/', ServiceOnlyView.as_view()),
    path('admin-service/', AdminOrServiceView.as_view()),
    path('internal/health/', InternalHealthCheckView.as_view()),

]
