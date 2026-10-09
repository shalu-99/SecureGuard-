
import hashlib

from argon2 import PasswordHasher
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
)

ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Create a secure Argon2 password hash."""
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify Argon2 and legacy SHA-256 password hashes."""

    if password_hash.startswith("$argon2"):
        try:
            return ph.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError):
            return False

    # Support existing SHA-256 password hashes
    legacy_hash = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()

    return legacy_hash == password_hash


def needs_rehash(password_hash: str) -> bool:
    """Identify old hashes that need upgrading."""
    return not password_hash.startswith("$argon2")
