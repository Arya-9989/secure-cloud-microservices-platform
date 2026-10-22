#!/usr/bin/env python3
"""Create .env from .env.example, filling every ``<generate>`` value with a random secret.

Standard library only, so it runs anywhere Python 3.9+ is available:

    python scripts/init_env.py            # refuses to overwrite an existing .env
    python scripts/init_env.py --force    # regenerate (invalidates existing volumes' passwords)
"""

from __future__ import annotations

import argparse
import contextlib
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER = "<generate>"


def render(template: str) -> str:
    lines = []
    for line in template.splitlines():
        key, sep, value = line.partition("=")
        if sep and value.strip() == PLACEHOLDER and not line.lstrip().startswith("#"):
            # URL-safe so the value can be embedded in connection strings unescaped.
            line = f"{key}={secrets.token_urlsafe(32)}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="overwrite an existing .env")
    args = parser.parse_args()

    target = ROOT / ".env"
    if target.exists() and not args.force:
        print(f"{target} already exists; leaving it untouched (use --force to regenerate).")
        return 0

    content = render((ROOT / ".env.example").read_text(encoding="utf-8"))
    with target.open("w", encoding="utf-8", newline="\n") as handle:  # LF even on Windows
        handle.write(content)
    with contextlib.suppress(OSError):  # e.g. filesystems without POSIX permissions
        target.chmod(0o600)
    print(f"Wrote {target} with freshly generated secrets.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
