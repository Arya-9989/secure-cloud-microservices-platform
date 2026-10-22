from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandParser

from accounts.keys import generate_private_key_pem


class Command(BaseCommand):
    help = (
        "Create an RSA signing key at PATH if none exists (idempotent). Intended for local "
        "and CI environments; production keys should come from a secret manager."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("path", type=Path)
        parser.add_argument("--bits", type=int, default=3072, choices=(2048, 3072, 4096))

    def handle(self, *args: Any, **options: Any) -> None:
        path: Path = options["path"]
        if path.exists():
            self.stdout.write(f"Signing key already present at {path}; leaving it untouched.")
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        # O_EXCL: never clobber a key another process created concurrently;
        # 0o600: only the service user may read the private key.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(generate_private_key_pem(options["bits"]))
        self.stdout.write(self.style.SUCCESS(f"Generated {options['bits']}-bit RSA key at {path}"))
