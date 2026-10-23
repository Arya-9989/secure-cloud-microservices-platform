from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser

from accounts.keys import get_key_set, public_jwk, vault_transit
from accounts.kms import SigningUnavailableError


def _when(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%d %H:%M:%SZ")


class Command(BaseCommand):
    help = (
        "Rotate the token signing key in Vault transit (JWT_SIGNER=vault), or with --show "
        "print which key version signs and which are published. The new version is "
        "published at once and signs after JWT_KEY_PUBLISH_AHEAD_SECONDS; the old one stays "
        "published until its tokens have expired (docs/adr/0007-kms-signing-and-rotation.md)."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--show", action="store_true", help="only print the current plan")
        parser.add_argument(
            "--admin-token-file",
            default=os.environ.get("VAULT_ADMIN_TOKEN_FILE", ""),
            help="token allowed to rotate (the service's own token cannot)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if settings.JWT_SIGNER != "vault":
            raise CommandError(
                "JWT_SIGNER is 'local': rotate a file key by generating a new one, adding the "
                "old public key to JWT_ADDITIONAL_PUBLIC_KEY_FILES and removing it after the "
                "access-token lifetime."
            )
        try:
            if not options["show"]:
                if not options["admin_token_file"]:
                    raise CommandError("--admin-token-file (or VAULT_ADMIN_TOKEN_FILE) is required")
                vault_transit(options["admin_token_file"]).rotate()
                self.stdout.write(
                    self.style.SUCCESS(f"Rotated transit key {settings.JWT_VAULT_KEY}")
                )
                get_key_set.cache_clear()
            plan = get_key_set().plan
        except SigningUnavailableError as exc:
            raise CommandError(f"Vault: {exc.reason}") from exc
        if plan is None:  # only a file key has no plan, and that was refused above
            raise CommandError("No rotation plan: is JWT_SIGNER=vault?")
        for version in plan.published:
            kid = public_jwk(version.public_key)["kid"]
            if version.version == plan.signing.version:
                state = "signing"
            elif version.version > plan.signing.version:
                state = "published, signs from " + _when(
                    version.created_at + settings.JWT_KEY_PUBLISH_AHEAD_SECONDS
                )
            else:
                state = "published until " + _when(plan.retires_at[version.version])
            self.stdout.write(
                f"v{version.version}  {kid}  created {_when(version.created_at)}  {state}"
            )
