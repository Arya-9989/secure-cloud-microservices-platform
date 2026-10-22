from __future__ import annotations

import os
from typing import Any

from django.contrib.auth.password_validation import validate_password
from django.core.management.base import BaseCommand, CommandError

from accounts.managers import UserManager
from accounts.models import Role, User


class Command(BaseCommand):
    help = (
        "Create the initial administrator from AUTH_BOOTSTRAP_ADMIN_EMAIL and "
        "AUTH_BOOTSTRAP_ADMIN_PASSWORD. Idempotent: an existing account is left unchanged."
    )

    def handle(self, *args: Any, **options: Any) -> None:
        email = os.environ.get("AUTH_BOOTSTRAP_ADMIN_EMAIL", "").strip()
        password = os.environ.get("AUTH_BOOTSTRAP_ADMIN_PASSWORD", "")
        if not email:
            self.stdout.write("AUTH_BOOTSTRAP_ADMIN_EMAIL not set; skipping admin bootstrap.")
            return
        if User.objects.filter(email=UserManager.normalize(email)).exists():
            self.stdout.write(f"Admin {email} already exists; nothing to do.")
            return
        if not password:
            raise CommandError("AUTH_BOOTSTRAP_ADMIN_PASSWORD must be set to create the admin")
        validate_password(password)
        User.objects.create_user(email=email, password=password, role=Role.ADMIN)
        self.stdout.write(self.style.SUCCESS(f"Created administrator {email}"))
