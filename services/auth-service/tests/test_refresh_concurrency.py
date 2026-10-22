"""Refresh-token reuse detection under concurrency (PostgreSQL only).

A replayed refresh token must revoke *every* token of its session family, including
one minted by a rotation that is in flight at the same moment. Row locks alone do
not guarantee that: under READ COMMITTED, the revoking UPDATE waits for the
rotation's lock but never sees the row that rotation inserts.

SQLite has no row locks and serialises writers, so the race cannot occur there and
the test is skipped; CI runs the suite against PostgreSQL.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from django.db import connection, connections

import accounts.tokens as tokens
from accounts.models import RefreshToken, User
from accounts.tokens import RefreshTokenReuseError, TokenError, issue_token_pair

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.skipif(
        connection.vendor != "postgresql", reason="needs PostgreSQL row-level locking"
    ),
]


def _waiting_on_a_lock() -> int:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM pg_stat_activity "
            "WHERE datname = current_database() AND wait_event_type = 'Lock'"
        )
        row = cursor.fetchone()
    return int(row[0]) if row else 0


def _in_thread(
    target: Callable[[], Any], results: dict[str, Any], key: str, name: str | None = None
) -> threading.Thread:
    def run() -> None:
        try:
            results[key] = target()
        except Exception as exc:  # recorded and asserted on by the test
            results[key] = exc
        finally:
            connections.close_all()

    thread = threading.Thread(target=run, name=name or key, daemon=True)
    thread.start()
    return thread


def test_replay_revokes_a_token_minted_by_a_concurrent_rotation(
    make_user: Callable[..., User], monkeypatch: pytest.MonkeyPatch
) -> None:
    user = make_user()
    stolen = issue_token_pair(user)  # R1: the attacker keeps a copy
    current = tokens.rotate_refresh_token(stolen.refresh_token)  # R2: the legitimate client

    # Pause the legitimate rotation of R2 after it has taken its locks but before it
    # inserts R3, so the replay of R1 is guaranteed to run concurrently with it.
    rotation_holds_locks = threading.Event()
    release_rotation = threading.Event()
    real_new_refresh_token = tokens._new_refresh_token

    def paused_new_refresh_token(*args: Any, **kwargs: Any) -> Any:
        if threading.current_thread().name == "legitimate-rotation":
            rotation_holds_locks.set()
            assert release_rotation.wait(timeout=30)
        return real_new_refresh_token(*args, **kwargs)

    monkeypatch.setattr(tokens, "_new_refresh_token", paused_new_refresh_token)
    results: dict[str, Any] = {}

    rotation = _in_thread(
        lambda: tokens.rotate_refresh_token(current.refresh_token),
        results,
        "rotation",
        name="legitimate-rotation",
    )
    assert rotation_holds_locks.wait(timeout=30)

    replay = _in_thread(
        lambda: tokens.rotate_refresh_token(stolen.refresh_token), results, "replay"
    )
    deadline = time.monotonic() + 30
    while _waiting_on_a_lock() == 0:  # the replay is now blocked behind the rotation
        assert time.monotonic() < deadline, "replay never waited for the rotation's lock"
        time.sleep(0.05)
    release_rotation.set()
    rotation.join(timeout=30)
    replay.join(timeout=30)

    assert isinstance(results["replay"], RefreshTokenReuseError)
    minted = results["rotation"]
    if isinstance(minted, Exception):
        return  # the rotation lost the race and was refused: nothing survived
    with pytest.raises(TokenError):
        tokens.rotate_refresh_token(minted.refresh_token)
    assert not RefreshToken.objects.filter(revoked_at__isnull=True).exists(), (
        "a replay must leave no live token in the family"
    )


@pytest.mark.parametrize("revocation", ["replay", "logout"])
def test_family_revocation_also_revokes_a_rotation_racing_it(
    revocation: str, make_user: Callable[..., User], monkeypatch: pytest.MonkeyPatch
) -> None:
    user = make_user()
    stolen = issue_token_pair(user)  # R1: the attacker keeps a copy
    current = tokens.rotate_refresh_token(stolen.refresh_token)  # R2: the legitimate client

    # The family revocation (replay of R1, or a logout) starts first. Before its UPDATE
    # runs, the legitimate client starts rotating R2 and pauses just before minting R3.
    replay_detected = threading.Event()
    rotation_holds_locks = threading.Event()
    release_rotation = threading.Event()
    real_revoke_family = tokens.revoke_family
    real_new_refresh_token = tokens._new_refresh_token

    def gated_revoke_family(*args: Any, **kwargs: Any) -> Any:
        if threading.current_thread().name == "revoker":
            replay_detected.set()
            # Give the rotation a chance to take its locks first. If the implementation
            # serialises the two (as it must), the rotation is blocked and this times out.
            rotation_holds_locks.wait(timeout=3)
        return real_revoke_family(*args, **kwargs)

    def paused_new_refresh_token(*args: Any, **kwargs: Any) -> Any:
        if threading.current_thread().name == "legitimate-rotation":
            rotation_holds_locks.set()
            assert release_rotation.wait(timeout=30)
        return real_new_refresh_token(*args, **kwargs)

    monkeypatch.setattr(tokens, "revoke_family", gated_revoke_family)
    monkeypatch.setattr(tokens, "_new_refresh_token", paused_new_refresh_token)
    results: dict[str, Any] = {}

    def revoke() -> Any:
        if revocation == "replay":
            return tokens.rotate_refresh_token(stolen.refresh_token)
        return tokens.revoke_refresh_token(stolen.refresh_token)

    replay = _in_thread(revoke, results, "revoker")
    assert replay_detected.wait(timeout=30)
    rotation = _in_thread(
        lambda: tokens.rotate_refresh_token(current.refresh_token),
        results,
        "rotation",
        name="legitimate-rotation",
    )
    deadline = time.monotonic() + 30
    while _waiting_on_a_lock() == 0:  # one of the two now waits for the other's lock
        assert time.monotonic() < deadline, "the replay and the rotation never contended"
        time.sleep(0.05)
    release_rotation.set()
    replay.join(timeout=30)
    rotation.join(timeout=30)

    if revocation == "replay":
        assert isinstance(results["revoker"], RefreshTokenReuseError)
    else:
        assert results["revoker"] is None
    minted = results["rotation"]
    if not isinstance(minted, Exception):
        with pytest.raises(TokenError):
            tokens.rotate_refresh_token(minted.refresh_token)
    assert not RefreshToken.objects.filter(revoked_at__isnull=True).exists(), (
        "a replay must leave no live token in the family"
    )
