from __future__ import annotations

import uuid
from typing import ClassVar

from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models

from .managers import UserManager


class Role(models.TextChoices):
    USER = "USER", "User"
    ADMIN = "ADMIN", "Administrator"


# OAuth2-style scopes granted to each role. Resource servers authorize on these
# (plus the `roles` claim for coarse admin checks), so adding a new API means
# adding a scope here rather than teaching every service about roles.
ROLE_SCOPES: dict[str, tuple[str, ...]] = {
    Role.USER: ("orders:read", "orders:write"),
    Role.ADMIN: ("orders:read", "orders:write", "orders:admin", "users:admin"),
}


class User(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=254, unique=True)
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.USER)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = []

    objects = UserManager()

    class Meta:
        ordering = ("created_at",)

    def __str__(self) -> str:
        return self.email

    @property
    def scopes(self) -> tuple[str, ...]:
        return ROLE_SCOPES.get(self.role, ())


class RevocationReason(models.TextChoices):
    ROTATED = "ROTATED", "Rotated (exchanged for a new token)"
    LOGOUT = "LOGOUT", "Logged out"
    REUSE_DETECTED = "REUSE_DETECTED", "Family revoked after token reuse"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED", "Account disabled or role changed"


class RefreshToken(models.Model):
    """An opaque, single-use refresh token.

    Only a SHA-256 digest of the token is stored, so a database leak does not
    yield usable tokens. Every token belongs to a *family* (one login session);
    presenting a token that was already rotated is treated as theft and revokes
    the entire family (OAuth 2.0 Security BCP, refresh token rotation).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="refresh_tokens")
    family_id = models.UUIDField(db_index=True)
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    # Absolute lifetime of the whole family: rotation slides `expires_at` but
    # can never extend a session beyond this point.
    session_expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(
        max_length=32, choices=RevocationReason.choices, blank=True, default=""
    )
    replaced_by = models.OneToOneField(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="replaces"
    )

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["user", "revoked_at"], name="refresh_user_active_idx"),
        ]

    def __str__(self) -> str:
        return f"RefreshToken({self.id}, family={self.family_id})"
