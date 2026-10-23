import os

from django.core.wsgi import get_wsgi_application

from platform_core.tracing import configure_tracing

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "auth_service.settings")

# Before the application is built: the Django instrumentation adds its middleware to
# the settings, and gunicorn imports this module in each worker after forking.
configure_tracing()

application = get_wsgi_application()
