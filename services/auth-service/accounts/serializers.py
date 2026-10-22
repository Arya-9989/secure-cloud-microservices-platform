from __future__ import annotations

from typing import Any

from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from .managers import UserManager
from .models import Role, User


class UserSerializer(serializers.ModelSerializer[User]):
    scopes = serializers.ListField(child=serializers.CharField(), read_only=True)

    class Meta:
        model = User
        fields = ("id", "email", "role", "is_active", "scopes", "created_at")
        read_only_fields = fields


class RegisterSerializer(serializers.Serializer[User]):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(write_only=True, trim_whitespace=False, max_length=128)

    def validate_email(self, value: str) -> str:
        email = UserManager.normalize(value)
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("An account with this email already exists.")
        return email

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        validate_password(attrs["password"], user=User(email=attrs["email"]))
        return attrs

    def create(self, validated_data: dict[str, Any]) -> User:
        return User.objects.create_user(
            email=validated_data["email"], password=validated_data["password"], role=Role.USER
        )


class LoginSerializer(serializers.Serializer[None]):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(write_only=True, trim_whitespace=False, max_length=128)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        # ModelBackend hashes a dummy password for unknown users, so response
        # time does not reveal whether an account exists, and it rejects
        # inactive users. Both failures produce the same generic message.
        user = authenticate(
            self.context.get("request"), username=attrs["email"], password=attrs["password"]
        )
        if user is None:
            raise serializers.ValidationError("Invalid email or password.", code="invalid_login")
        attrs["user"] = user
        return attrs


class RefreshSerializer(serializers.Serializer[None]):
    refresh_token = serializers.CharField(max_length=512)


class TokenResponseSerializer(serializers.Serializer[None]):
    access_token = serializers.CharField()
    token_type = serializers.CharField()
    expires_in = serializers.IntegerField()
    refresh_token = serializers.CharField()
    refresh_expires_in = serializers.IntegerField()
    scope = serializers.CharField()


class AdminUserUpdateSerializer(serializers.ModelSerializer[User]):
    class Meta:
        model = User
        fields = ("role", "is_active")
