"""Health probes, management commands, settings hardening and migrations."""

from __future__ import annotations

import os
import re
import stat
import sys
from io import StringIO
from pathlib import Path

import pytest
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import override_settings
from rest_framework.test import APIClient

from accounts.keys import get_key_set
from accounts.models import Role, User

pytestmark = pytest.mark.django_db


class TestHealth:
    def test_liveness(self, api: APIClient) -> None:
        response = api.get("/healthz")

        assert response.status_code == 200
        assert response.json() == {"status": "UP"}

    def test_readiness_checks_dependencies(self, api: APIClient) -> None:
        response = api.get("/readyz")

        assert response.status_code == 200
        assert response.json()["checks"] == {"database": "UP", "signing_key": "UP"}

    def test_readiness_fails_without_signing_key(self, api: APIClient, tmp_path: Path) -> None:
        with override_settings(JWT_PRIVATE_KEY_FILE=str(tmp_path / "missing.pem")):
            get_key_set.cache_clear()
            response = api.get("/readyz")

        assert response.status_code == 503
        assert response.json()["checks"]["signing_key"] == "DOWN"


class TestEnsureSigningKey:
    def test_creates_a_private_key_once(self, tmp_path: Path) -> None:
        path = tmp_path / "keys" / "jwt.pem"

        call_command("ensure_signing_key", str(path), "--bits", "2048", stdout=StringIO())
        first = path.read_bytes()
        call_command("ensure_signing_key", str(path), stdout=StringIO())

        assert first.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert path.read_bytes() == first  # never overwritten

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_key_file_is_owner_readable_only(self, tmp_path: Path) -> None:
        path = tmp_path / "jwt.pem"

        call_command("ensure_signing_key", str(path), "--bits", "2048", stdout=StringIO())

        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


class TestBootstrapAdmin:
    def test_creates_admin_idempotently(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUTH_BOOTSTRAP_ADMIN_EMAIL", "Root@Example.com")
        monkeypatch.setenv("AUTH_BOOTSTRAP_ADMIN_PASSWORD", "a-long-and-unique-passphrase")

        call_command("bootstrap_admin", stdout=StringIO())
        call_command("bootstrap_admin", stdout=StringIO())

        admin = User.objects.get()
        assert admin.email == "root@example.com"
        assert admin.role == Role.ADMIN

    def test_rejects_weak_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUTH_BOOTSTRAP_ADMIN_EMAIL", "root@example.com")
        monkeypatch.setenv("AUTH_BOOTSTRAP_ADMIN_PASSWORD", "admin")

        with pytest.raises(ValidationError):
            call_command("bootstrap_admin", stdout=StringIO())
        assert not User.objects.exists()

    def test_noop_without_configuration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AUTH_BOOTSTRAP_ADMIN_EMAIL", raising=False)

        call_command("bootstrap_admin", stdout=StringIO())

        assert not User.objects.exists()


def test_production_settings_hash_passwords_with_argon2() -> None:
    import auth_service.settings as production

    assert production.PASSWORD_HASHERS[0].endswith("Argon2PasswordHasher")
    assert production.DEBUG is False


def test_models_and_migrations_are_in_sync() -> None:
    call_command("makemigrations", "--check", "--dry-run", stdout=StringIO())


def test_openapi_schema_is_served(api: APIClient) -> None:
    response = api.get("/docs/auth/openapi.json")

    assert response.status_code == 200
    assert b"/api/v1/auth/token/" in response.content


def test_api_docs_page_is_themed_and_runs_without_inline_script(api: APIClient) -> None:
    response = api.get("/docs/auth/")
    html = response.content.decode()
    csp = response["Content-Security-Policy"]

    assert response.status_code == 200
    assert 'href="/assets/docs.css"' in html  # platform theme, served by the landing service
    assert "swagger-ui-dist/swagger-ui-bundle.js" in html  # self-hosted, never a CDN
    assert re.search(r"<script(?![^>]*\bsrc=)", html) is None, "no inline <script>"
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe" not in csp


def test_api_docs_page_renders_its_title_without_javascript(api: APIClient) -> None:
    # The heading and lead are in the HTML, so they paint before the 1.5 MB Swagger
    # bundle runs (they are the page's LCP element), and the whole reference sits in a
    # <main> landmark (axe: region).
    html = api.get("/docs/auth/").content.decode()

    main = re.search(r"<main\b[^>]*>(.*)</main>", html, re.S)
    assert main is not None, "the reference must live in a <main> landmark"
    assert re.search(r"<h1\b[^>]*>Auth API reference\.</h1>", main.group(1))
    assert 'id="swagger-ui"' in main.group(1)
    assert 'href="/docs/auth/openapi.json"' in main.group(1)


def test_openapi_operations_describe_themselves(api: APIClient) -> None:
    schema = api.get("/docs/auth/openapi.json", {"format": "json"}).json()

    operations = [op for path in schema["paths"].values() for op in path.values()]
    descriptions = {op["operationId"]: op.get("description", "") for op in operations}
    assert all("Credential endpoints" not in text for text in descriptions.values()), (
        "an implementation comment leaked into the public API reference"
    )
    jwks = next(op for op in operations if op["operationId"].startswith(".well_known_jwks"))
    assert "JWK" in jwks["description"]


def test_every_response_carries_the_content_security_policy(api: APIClient) -> None:
    response = api.get("/healthz")

    assert response["Content-Security-Policy"].startswith("default-src 'none'")
