from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib.auth.base_user import BaseUserManager

if TYPE_CHECKING:
    from .models import User


class UserManager(BaseUserManager["User"]):
    use_in_migrations = True

    @staticmethod
    def normalize(email: str) -> str:
        # Emails are compared case-insensitively everywhere; store them lower-cased.
        return email.strip().lower()

    def create_user(
        self, email: str, password: str | None = None, role: str = "USER", **extra: Any
    ) -> User:
        if not email:
            raise ValueError("An email address is required")
        user = self.model(email=self.normalize(email), role=role, **extra)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.full_clean(exclude=["password"])
        user.save(using=self._db)
        return user

    def get_by_natural_key(self, username: str | None) -> User:
        return self.get(email=self.normalize(username or ""))
