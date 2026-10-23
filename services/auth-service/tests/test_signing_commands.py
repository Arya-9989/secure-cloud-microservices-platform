"""File-key operations: the cut-over export and the refusal to 'rotate' a file key."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from django.core.management import CommandError, call_command
from django.test import override_settings

from accounts.keys import generate_private_key_pem, get_key_set


def test_export_public_key_writes_the_public_half_idempotently(tmp_path: Path) -> None:
    private = tmp_path / "jwt.pem"
    private.write_bytes(generate_private_key_pem(2048))
    public = tmp_path / "jwt.pub.pem"

    call_command("export_public_key", str(private), str(public), stdout=StringIO())
    again = StringIO()
    call_command("export_public_key", str(private), str(public), stdout=again)

    key = serialization.load_pem_public_key(public.read_bytes())
    expected = serialization.load_pem_private_key(private.read_bytes(), None).public_key()
    assert key.public_numbers() == expected.public_numbers()  # type: ignore[union-attr]
    assert b"PRIVATE" not in public.read_bytes()
    assert "up to date" in again.getvalue()


def test_export_public_key_reports_unreadable_input(tmp_path: Path) -> None:
    with pytest.raises(CommandError, match="Cannot read"):
        call_command("export_public_key", str(tmp_path / "missing.pem"), str(tmp_path / "x"))


def test_the_exported_key_keeps_old_tokens_verifiable_after_a_switch(tmp_path: Path) -> None:
    """The cut-over: the old file key's public half listed as an additional key."""
    old = tmp_path / "old.pem"
    old.write_bytes(generate_private_key_pem(2048))
    old_public = tmp_path / "old.pub.pem"
    call_command("export_public_key", str(old), str(old_public), stdout=StringIO())
    old_kid = get_key_set().jwks["keys"][0]["kid"]  # the test suite's current key

    with override_settings(
        JWT_PRIVATE_KEY_FILE=str(old), JWT_ADDITIONAL_PUBLIC_KEY_FILES=[str(old_public)]
    ):
        get_key_set.cache_clear()
        kids = [k["kid"] for k in get_key_set().jwks["keys"]]

    assert len(kids) == 1, "a key listed twice is published once"
    assert kids[0] != old_kid


def test_rotate_refuses_a_file_key_and_explains_the_procedure() -> None:
    with pytest.raises(CommandError, match="JWT_ADDITIONAL_PUBLIC_KEY_FILES"):
        call_command("rotate_signing_key", stdout=StringIO())
