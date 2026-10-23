from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from django.core.management.base import BaseCommand, CommandError, CommandParser


class Command(BaseCommand):
    help = (
        "Write the public half of a PEM private key (idempotent). Listed in "
        "JWT_ADDITIONAL_PUBLIC_KEY_FILES, it keeps tokens signed by that key verifiable "
        "after the signer changes, e.g. when moving to Vault."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("private_key", type=Path)
        parser.add_argument("public_key", type=Path)

    def handle(self, *args: Any, **options: Any) -> None:
        try:
            key = serialization.load_pem_private_key(options["private_key"].read_bytes(), None)
        except (OSError, ValueError) as exc:
            raise CommandError(f"Cannot read {options['private_key']}: {exc}") from exc
        pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        target: Path = options["public_key"]
        if target.exists() and target.read_bytes() == pem:
            self.stdout.write(f"{target} is up to date.")
            return
        tmp = target.with_suffix(target.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
        tmp.replace(target)  # atomic: readers never see a partial key
        self.stdout.write(self.style.SUCCESS(f"Wrote {target}"))
