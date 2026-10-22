from __future__ import annotations

import logging
from typing import Any, NoReturn, cast

from django.db import transaction
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import exceptions, generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from platform_core.metrics import LOGIN_ATTEMPTS

from .keys import get_key_set
from .models import RevocationReason, User
from .permissions import HasScope
from .serializers import (
    AdminUserUpdateSerializer,
    LoginSerializer,
    RefreshSerializer,
    RegisterSerializer,
    TokenResponseSerializer,
    UserSerializer,
)
from .throttles import LoginAccountThrottle, LoginIPThrottle, RefreshThrottle, RegisterThrottle
from .tokens import (
    TokenError,
    issue_token_pair,
    revoke_all_for_user,
    revoke_refresh_token,
    rotate_refresh_token,
)

logger = logging.getLogger(__name__)


class PublicEndpoint(APIView):
    # Credential endpoints ignore any Authorization header the client sends. (A comment,
    # not a docstring: drf-spectacular would publish a docstring as every subclass's
    # operation description.)

    authentication_classes = ()
    permission_classes = (AllowAny,)

    def get_authenticate_header(self, request: Request) -> str:
        # Without an authenticator DRF would downgrade 401 to 403; credential
        # failures here are genuinely "unauthenticated".
        return 'Bearer realm="secure-platform"'


@extend_schema(
    tags=["auth"],
    summary="Create a customer account (role USER; rate limited per IP)",
    description=(
        "Passwords need at least 12 characters and must not be common or all digits. "
        "The new account always has the role USER."
    ),
    request=RegisterSerializer,
    responses={201: UserSerializer},
)
class RegisterView(PublicEndpoint):
    throttle_classes = (RegisterThrottle,)

    def post(self, request: Request) -> Response:
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        logger.info("User registered", extra={"user_id": str(user.pk)})
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)


@extend_schema(
    tags=["auth"],
    summary="Log in with email and password (rate limited per IP and per account)",
    description=(
        "Returns an RS256 access token (15 minutes by default) and an opaque, single-use "
        "refresh token. "
        "Wrong email and wrong password fail identically. While an account is throttled, "
        "even the right password is refused with 429."
    ),
    request=LoginSerializer,
    responses={
        200: TokenResponseSerializer,
        401: OpenApiResponse(description="Invalid credentials"),
        429: OpenApiResponse(description="Too many attempts"),
    },
)
class TokenView(PublicEndpoint):
    throttle_classes = (LoginIPThrottle, LoginAccountThrottle)

    def throttled(self, request: Request, wait: float) -> NoReturn:
        LOGIN_ATTEMPTS.labels(outcome="throttled").inc()
        logger.warning("Login throttled")
        super().throttled(request, wait)

    def post(self, request: Request) -> Response:
        serializer = LoginSerializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            if "non_field_errors" in serializer.errors:
                LOGIN_ATTEMPTS.labels(outcome="invalid_credentials").inc()
                logger.info("Login failed: invalid credentials")
                raise exceptions.AuthenticationFailed("Invalid email or password.")
            raise exceptions.ValidationError(serializer.errors)

        user: User = serializer.validated_data["user"]
        pair = issue_token_pair(user)
        LOGIN_ATTEMPTS.labels(outcome="success").inc()
        logger.info("Login succeeded", extra={"user_id": str(user.pk)})
        return Response(pair.as_response(), headers={"Cache-Control": "no-store"})


@extend_schema(
    tags=["auth"],
    summary="Rotate a refresh token; reusing an old token revokes the whole session",
    description=(
        "Each refresh token works once and is exchanged for a new pair. Presenting a token "
        "that was already rotated is treated as theft: every token of that session is "
        "revoked and the caller gets 401."
    ),
    request=RefreshSerializer,
    responses={200: TokenResponseSerializer, 401: OpenApiResponse(description="Invalid token")},
)
class TokenRefreshView(PublicEndpoint):
    throttle_classes = (RefreshThrottle,)

    def post(self, request: Request) -> Response:
        serializer = RefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            pair = rotate_refresh_token(serializer.validated_data["refresh_token"])
        except TokenError as exc:
            raise exceptions.AuthenticationFailed(str(exc)) from exc
        return Response(pair.as_response(), headers={"Cache-Control": "no-store"})


@extend_schema(
    tags=["auth"],
    summary="Revoke the session that owns the given refresh token",
    description="Always 204, so the response does not reveal whether the token was valid.",
    request=RefreshSerializer,
    responses={204: None},
)
class LogoutView(PublicEndpoint):
    throttle_classes = (RefreshThrottle,)

    def post(self, request: Request) -> Response:
        serializer = RefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        revoke_refresh_token(serializer.validated_data["refresh_token"])
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(tags=["auth"], summary="The authenticated caller", responses={200: UserSerializer})
class MeView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request: Request) -> Response:
        return Response(UserSerializer(cast(User, request.user)).data)


@extend_schema(
    tags=["jwks"],
    summary="JSON Web Key Set used by resource servers to verify access tokens",
    description=(
        "Public RS256 keys as an RFC 7517 JWK Set. Each kid is the key's RFC 7638 "
        "thumbprint. Cacheable for 5 minutes."
    ),
    responses={200: OpenApiResponse(description="RFC 7517 JWK Set")},
)
class JWKSView(PublicEndpoint):
    def get(self, request: Request) -> Response:
        return Response(get_key_set().jwks, headers={"Cache-Control": "public, max-age=300"})


ADMIN_PERMISSIONS = (IsAuthenticated, HasScope)


@extend_schema(tags=["admin"], summary="List users (scope users:admin)")
class AdminUserListView(generics.ListAPIView[User]):
    permission_classes = ADMIN_PERMISSIONS
    required_scope = "users:admin"
    queryset = User.objects.all()
    serializer_class = UserSerializer


@extend_schema(tags=["admin"], summary="Get or update a user (scope users:admin)")
class AdminUserDetailView(generics.RetrieveUpdateAPIView[User]):
    permission_classes = ADMIN_PERMISSIONS
    required_scope = "users:admin"
    queryset = User.objects.all()
    http_method_names = ("get", "patch", "head", "options")

    def get_serializer_class(self) -> Any:
        return AdminUserUpdateSerializer if self.request.method == "PATCH" else UserSerializer

    @extend_schema(
        summary="Change role or disable an account; revokes the user's sessions",
        request=AdminUserUpdateSerializer,
        responses={200: UserSerializer},
    )
    def patch(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        target = self.get_object()
        serializer = AdminUserUpdateSerializer(target, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        if target.pk == request.user.pk:
            raise exceptions.ValidationError("Administrators cannot change their own account.")

        privileges_changed = any(
            field in serializer.validated_data
            and serializer.validated_data[field] != getattr(target, field)
            for field in ("role", "is_active")
        )
        with transaction.atomic():
            user = serializer.save()
            if privileges_changed:
                # Existing sessions must not keep minting tokens with stale privileges.
                revoke_all_for_user(user, RevocationReason.ACCOUNT_DISABLED)
        logger.info(
            "User updated by admin",
            extra={"target_user_id": str(user.pk), "changes": serializer.validated_data},
        )
        return Response(UserSerializer(user).data)
