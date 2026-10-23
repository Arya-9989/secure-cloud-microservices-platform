"""The rotation planner: publish before use, retire after expiry, never break a token."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from accounts.kms import KeyVersion, _parse_time, plan_rotation

PUBLISH_AHEAD = 360.0  # JWT_KEY_PUBLISH_AHEAD_SECONDS default
RETIRE_AFTER = 900.0 + 30.0 + 60.0  # longest token TTL + clock skew + margin
T0 = 1_800_000_000.0


@pytest.fixture(scope="module")
def keys() -> list[rsa.RSAPublicKey]:
    return [rsa.generate_private_key(65537, 2048).public_key() for _ in range(3)]


def version(n: int, created: float, keys: list[rsa.RSAPublicKey]) -> KeyVersion:
    return KeyVersion(n, created, keys[n - 1])


def plan(versions: list[KeyVersion], now: float):  # type: ignore[no-untyped-def]
    return plan_rotation(versions, now, publish_ahead=PUBLISH_AHEAD, retire_after=RETIRE_AFTER)


def test_a_brand_new_key_signs_immediately(keys: list[rsa.RSAPublicKey]) -> None:
    result = plan([version(1, T0, keys)], T0 + 1)

    assert result.signing.version == 1
    assert [v.version for v in result.published] == [1]


def test_a_new_version_is_published_before_it_signs(keys: list[rsa.RSAPublicKey]) -> None:
    versions = [version(1, T0, keys), version(2, T0 + 86_400, keys)]
    just_rotated = T0 + 86_400 + 1

    result = plan(versions, just_rotated)

    assert result.signing.version == 1, "v2 is not trusted everywhere yet"
    assert [v.version for v in result.published] == [1, 2], "but it is already published"


def test_the_new_version_signs_once_every_cache_has_seen_it(
    keys: list[rsa.RSAPublicKey],
) -> None:
    rotated = T0 + 86_400
    versions = [version(1, T0, keys), version(2, rotated, keys)]

    result = plan(versions, rotated + PUBLISH_AHEAD)

    assert result.signing.version == 2
    assert [v.version for v in result.published] == [1, 2], "v1 tokens are still in flight"
    assert result.retires_at[1] == rotated + PUBLISH_AHEAD + RETIRE_AFTER


def test_the_old_version_is_retired_after_its_last_token_expired(
    keys: list[rsa.RSAPublicKey],
) -> None:
    rotated = T0 + 86_400
    versions = [version(1, T0, keys), version(2, rotated, keys)]
    switch = rotated + PUBLISH_AHEAD

    still = plan(versions, switch + RETIRE_AFTER - 1)
    gone = plan(versions, switch + RETIRE_AFTER)

    assert [v.version for v in still.published] == [1, 2]
    assert [v.version for v in gone.published] == [2]


def test_no_token_issued_before_a_rotation_fails_after_it(
    keys: list[rsa.RSAPublicKey],
) -> None:
    """Walk a timeline second by second-ish: whatever signed at t is published until t + TTL."""
    token_ttl = 900.0
    rotations = [T0, T0 + 3_000, T0 + 3_100]  # two rotations close together, the hard case
    versions = [version(i + 1, at, keys) for i, at in enumerate(rotations)]

    for issued_at in range(int(T0), int(T0 + 6_000), 7):
        signer = plan(versions, issued_at).signing.version
        for verified_at in (issued_at + 1, issued_at + token_ttl / 2, issued_at + token_ttl):
            published = {v.version for v in plan(versions, verified_at).published}
            assert signer in published, (issued_at, verified_at, signer, published)


def test_versions_out_of_order_and_empty_input(keys: list[rsa.RSAPublicKey]) -> None:
    shuffled = [version(2, T0 + 5_000, keys), version(1, T0, keys)]

    assert plan(shuffled, T0 + 5_000 + PUBLISH_AHEAD).signing.version == 2
    with pytest.raises(ValueError, match="no key versions"):
        plan([], T0)


def test_vault_timestamps_with_nanoseconds_are_parsed() -> None:
    assert _parse_time("2026-10-23T01:02:03.123456789Z") == pytest.approx(
        _parse_time("2026-10-23T01:02:03Z") + 0.123456
    )
