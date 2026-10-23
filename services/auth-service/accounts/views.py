from __future__ import annotations

import logging
from typing import Any, NoReturn, cast

from django.db import transaction
from django.http import QueryDict
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import exceptions, generics, status
from rest_framework.parsers import FormParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from platform_core.metrics import LOGIN_ATTEMPTS

from . import audit, dpop
from .keys import get_key_set
from .models import AuditAction, AuditEvent, RevocationReason, Role, User
from .oauth import OAuthError, issue_token
from .permissions import HasScope
from .serializers import (
    AccountDeletionSerializer,
    AdminUserUpdateSerializer,
    AuditEventSerializer,
    LoginSerializer,
    PasswordChangeSerializer,
    RefreshSerializer,
    RegisterSerializer,
    TokenResponseSerializer,
    UserSerializer,
)
from .throttles import (
    AccountChangeThrottle,
    ClientTokenClientThrottle,
    ClientTokenIPThrottle,
    LoginAccountThrottle,
    LoginIPThrottle,
    RefreshThrottle,
    RegisterThrottle,
)
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


NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@extend_schema(
    tags=["oauth"],
    summary="Client credentials grant for services (RFC 6749 4.4), DPoP-bound (RFC 9449)",
    description=(
        "Form-encoded `grant_type=client_credentials`, optional `scope` and `resource` "
        "(RFC 8707). Authenticate the client with HTTP Basic. Send a `DPoP` proof for "
        "`POST` to this URL; the first attempt returns `use_dpop_nonce` with a "
        "`DPoP-Nonce` header to include in the proof. Errors follow RFC 6749 5.2."
    ),
    request={"application/x-www-form-urlencoded": dict},
    responses={
        200: OpenApiResponse(description="access_token, token_type (DPoP), expires_in, scope"),
        400: OpenApiResponse(description="OAuth error (invalid_request, invalid_dpop_proof, ...)"),
        401: OpenApiResponse(description="invalid_client"),
    },
)
class OAuthTokenView(PublicEndpoint):
    parser_classes = (FormParser,)
    throttle_classes = (ClientTokenIPThrottle, ClientTokenClientThrottle)

    def post(self, request: Request) -> Response:
        try:
            issued = issue_token(
                authorization=request.headers.get("Authorization", ""),
                form=_form_lists(request),
                dpop_headers=_header_values(request, "HTTP_DPOP"),
                method=request.method or "POST",
                url=request.build_absolute_uri(request.path),
            )
        except OAuthError as exc:
            return Response(exc.body(), status=exc.status, headers={**NO_STORE, **exc.headers})
        # A fresh nonce on every response lets the client sign its next proof with it.
        return Response(issued.as_response(), headers={**NO_STORE, "DPoP-Nonce": dpop.new_nonce()})


def _form_lists(request: Request) -> dict[str, list[str]]:
    data = request.data
    if not isinstance(data, QueryDict):  # FormParser always yields a QueryDict
        return {}
    return {key: data.getlist(key) for key in data}


def _header_values(request: Request, meta_key: str) -> list[str]:
    value = request.META.get(meta_key)
    # WSGI folds repeated headers into one comma-separated value; a JWT has no commas.
    return [] if value is None else [v.strip() for v in str(value).split(",")]


@extend_schema(tags=["auth"], summary="The authenticated caller", responses={200: UserSerializer})
class MeView(APIView):
    permission_classes = (IsAuthenticated,)
    throttle_classes = (AccountChangeThrottle,)

    def get_throttles(self) -> list[Any]:
        # Reading your own profile is not rate limited; deleting the account is.
        return super().get_throttles() if self.request.method == "DELETE" else []

    def get(self, request: Request) -> Response:
        return Response(UserSerializer(cast(User, request.user)).data)

    @extend_schema(
        summary="Delete your account (confirm with your password)",
        description=(
            "Erases the account and every session immediately. Orders stay with the orders "
            "service under the account's opaque id, which no longer maps to a person. The "
            "last active administrator cannot delete their account (400)."
        ),
        request=AccountDeletionSerializer,
        responses={204: None, 400: OpenApiResponse(description="Wrong password, or last admin")},
    )
    def delete(self, request: Request) -> Response:
        user = cast(User, request.user)
        serializer = AccountDeletionSerializer(data=request.data, context={"user": user})
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            # Locks the remaining admins, so two admins cannot delete themselves at once.
            others = (
                User.objects.select_for_update()
                .filter(role=Role.ADMIN, is_active=True)
                .exclude(pk=user.pk)
            )
            if user.role == Role.ADMIN and not list(others):
                raise exceptions.ValidationError(
                    "The last active administrator cannot delete their account."
                    " Promote another administrator first.",
                    code="last_admin",
                )
            user_id, role = str(user.pk), user.role
            user.delete()  # refresh tokens cascade
            audit.record(
                AuditAction.ACCOUNT_DELETED,
                actor_id=user_id,
                target_type="user",
                target_id=user_id,
                request=request,
                details={"role": role},
            )
        logger.info("Account deleted by its holder", extra={"user_id": user_id})
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    tags=["auth"],
    summary="Change your password; every session is signed out",
    description=(
        "Needs the current password. All refresh tokens (every device, this one included) "
        "are revoked, so log in again with the new password. Access tokens already issued "
        "expire on their own within 15 minutes. Rate limited per account."
    ),
    request=PasswordChangeSerializer,
    responses={204: None, 400: OpenApiResponse(description="Wrong or weak password")},
)
class PasswordChangeView(APIView):
    permission_classes = (IsAuthenticated,)
    throttle_classes = (AccountChangeThrottle,)

    def post(self, request: Request) -> Response:
        user = cast(User, request.user)
        serializer = PasswordChangeSerializer(data=request.data, context={"user": user})
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            user.set_password(serializer.validated_data["new_password"])
            user.save(update_fields=["password", "updated_at"])
            revoked = revoke_all_for_user(user, RevocationReason.PASSWORD_CHANGED)
            audit.record(
                AuditAction.PASSWORD_CHANGED,
                actor_id=str(user.pk),
                target_type="user",
                target_id=str(user.pk),
                request=request,
                details={"sessions_revoked": revoked},
            )
        return Response(status=status.HTTP_204_NO_CONTENT)


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


@extend_schema(
    tags=["admin"],
    summary="List and search users (scope users:admin)",
    parameters=[
        OpenApiParameter("email", str, description="Case-insensitive substring of the email"),
        OpenApiParameter("role", str, enum=[r.value for r in Role]),
        OpenApiParameter("is_active", bool),
    ],
)
class AdminUserListView(generics.ListAPIView[User]):
    permission_classes = ADMIN_PERMISSIONS
    required_scope = "users:admin"
    serializer_class = UserSerializer

    def get_queryset(self) -> Any:
        users = User.objects.all()
        params = self.request.query_params
        if email := params.get("email", "").strip():
            if len(email) > 254:
                raise exceptions.ValidationError({"email": "Too long."})
            users = users.filter(email__icontains=email.lower())
        if role := params.get("role"):
            if role not in Role.values:
                raise exceptions.ValidationError({"role": f"One of {', '.join(Role.values)}."})
            users = users.filter(role=role)
        if (active := params.get("is_active")) is not None:
            if active not in ("true", "false"):
                raise exceptions.ValidationError({"is_active": "true or false."})
            users = users.filter(is_active=active == "true")
        return users


@extend_schema(
    tags=["admin"],
    summary="Audit trail of security-relevant changes (scope users:admin)",
    parameters=[
        OpenApiParameter("action", str, enum=[a.value for a in AuditAction]),
        OpenApiParameter("target_id", str),
    ],
)
class AdminAuditEventListView(generics.ListAPIView[AuditEvent]):
    permission_classes = ADMIN_PERMISSIONS
    required_scope = "users:admin"
    serializer_class = AuditEventSerializer

    def get_queryset(self) -> Any:
        events = AuditEvent.objects.all()
        params = self.request.query_params
        if action := params.get("action"):
            if action not in AuditAction.values:
                raise exceptions.ValidationError({"action": "Unknown action."})
            events = events.filter(action=action)
        if target := params.get("target_id"):
            events = events.filter(target_id=target[:64])
        return events


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
        before = {field: getattr(target, field) for field in ("role", "is_active")}
        with transaction.atomic():
            user = serializer.save()
            if privileges_changed:
                # Existing sessions must not keep minting tokens with stale privileges.
                revoke_all_for_user(user, RevocationReason.ACCOUNT_DISABLED)
            changes = {
                field: {"from": before[field], "to": getattr(user, field)}
                for field in before
                if before[field] != getattr(user, field)
            }
            if changes:
                audit.record(
                    AuditAction.ADMIN_USER_UPDATED,
                    actor_id=str(request.user.pk),
                    target_type="user",
                    target_id=str(user.pk),
                    request=request,
                    details=changes,
                )
        logger.info(
            "User updated by admin",
            extra={"target_user_id": str(user.pk), "changes": serializer.validated_data},
        )
        return Response(UserSerializer(user).data)
