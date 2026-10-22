from __future__ import annotations

import os
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError, CommandParser

from accounts import audit
from accounts.models import CLIENT_SCOPES, AuditAction, OAuthClient

MIN_SECRET_LENGTH = 32


class Command(BaseCommand):
    help = (
        "Create or update a service client for the client credentials grant (idempotent). "
        "The secret is read from an environment variable and only its hash is stored."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("client_id")
        parser.add_argument(
            "--secret-env", required=True, help="environment variable with the secret"
        )
        parser.add_argument(
            "--scope", action="append", required=True, choices=sorted(CLIENT_SCOPES)
        )
        parser.add_argument("--audience", action="append", required=True)
        parser.add_argument("--name", default="")
        parser.add_argument(
            "--allow-bearer",
            action="store_true",
            help="also issue plain bearer tokens (default: every token must be DPoP-bound)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        secret = os.environ.get(options["secret_env"], "")
        if len(secret) < MIN_SECRET_LENGTH:
            raise CommandError(
                f"{options['secret_env']} must hold a secret of at least "
                f"{MIN_SECRET_LENGTH} characters"
            )
        unknown = [a for a in options["audience"] if a not in settings.OAUTH_RESOURCES]
        if unknown:
            raise CommandError(
                f"Unknown resource(s) {unknown}; OAUTH_RESOURCES lists the valid ones"
            )

        client = OAuthClient.objects.filter(client_id=options["client_id"]).first()
        created = client is None
        if client is None:
            client = OAuthClient(client_id=options["client_id"])
        before = (client.scopes, client.audiences, client.require_dpop) if not created else None
        client.name = options["name"] or client.name
        client.scopes = sorted(set(options["scope"]))
        client.audiences = sorted(set(options["audience"]))
        client.require_dpop = not options["allow_bearer"]
        rotated = created or not client.check_secret(secret)
        if rotated:
            client.set_secret(secret)
        try:
            client.full_clean()
        except ValidationError as exc:
            raise CommandError(f"Invalid client: {exc}") from exc
        client.save()
        if created or rotated or before != (client.scopes, client.audiences, client.require_dpop):
            audit.record(
                AuditAction.OAUTH_CLIENT_PROVISIONED,
                target_type="oauth_client",
                target_id=client.client_id,
                details={
                    "created": created,
                    "secret_rotated": rotated,
                    "scopes": client.scopes,
                    "audiences": client.audiences,
                    "require_dpop": client.require_dpop,
                },
            )
        action = "Created" if created else ("Updated (secret rotated)" if rotated else "Updated")
        self.stdout.write(self.style.SUCCESS(f"{action} OAuth client {client.client_id}"))
