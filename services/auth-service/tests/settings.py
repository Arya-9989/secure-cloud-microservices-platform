"""Test settings: production settings plus a throwaway signing key and in-memory backends.

DATABASE_URL may be set (CI runs the suite against PostgreSQL); otherwise an
in-memory SQLite database is used.
"""

import os
import tempfile
from pathlib import Path

from accounts.keys import generate_private_key_pem

_key_dir = Path(tempfile.mkdtemp(prefix="auth-test-keys-"))
_key_path = _key_dir / "signing.pem"
_key_path.write_bytes(generate_private_key_pem(2048))

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-secret-key-not-used-anywhere-else-0123456789")
os.environ.setdefault("DATABASE_URL", "sqlite://:memory:")
os.environ["JWT_PRIVATE_KEY_FILE"] = str(_key_path)
os.environ["CACHE_BACKEND"] = "locmem"
os.environ.setdefault("LOG_FORMAT", "console")

from auth_service.settings import *  # noqa: E402, F403

# Fast hashing in tests; production uses Argon2 (asserted in test_operations.py).
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
STATIC_ROOT = _key_dir / "static"
STATIC_ROOT.mkdir()
