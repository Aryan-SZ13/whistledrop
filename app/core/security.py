import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import argon2
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
import jwt

from app.core.config import settings

# OWASP recommended parameters for Argon2id
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def generate_case_code() -> str:
    """Generate a cryptographically secure, high-entropy bearer token for case tracking.

    Uses secrets.token_urlsafe(24), providing 192 bits of CSPRNG entropy.
    Prefixed with 'wdc_' (WhistleDrop Case) for token recognizability.
    """
    token = secrets.token_urlsafe(24)
    return f"wdc_{token}"


def derive_case_code_digest(case_code: str) -> str:
    """Derive a one-way HMAC-SHA256 hex digest for a case code.

    Uses CASE_CODE_SECRET exclusively.
    The resulting digest is stored in PostgreSQL; the plaintext case_code is never persisted.
    """
    if not case_code:
        raise ValueError("Case code must not be empty.")
    digest = hmac.new(
        settings.CASE_CODE_SECRET.encode("utf-8"),
        case_code.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest


def normalize_username(username: str) -> str:
    """Normalize username to canonical lowercase form with whitespace stripped.

    Ensures that usernames such as 'Admin', 'admin', and ' ADMIN ' resolve to the
    same identity without case or whitespace collision vulnerabilities.
    """
    if not username or not username.strip():
        raise ValueError("Username must not be empty.")
    return username.strip().lower()


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id with OWASP-recommended parameters."""
    if not password:
        raise ValueError("Password must not be empty.")
    return _password_hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against an Argon2id hash.

    Returns False safely on verification failure, hash corruption, or mismatch.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return _password_hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def create_access_token(
    subject: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed, short-lived JWT access token for moderator authentication.

    Uses JWT_SECRET exclusively (never CASE_CODE_SECRET).
    Includes subject (moderator ID), role, issued-at ('iat'), and expiration ('exp').
    """
    now = datetime.now(timezone.utc)
    if expires_delta is not None:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "role": str(role),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token using JWT_SECRET and the configured algorithm.

    Raises jwt.PyJWTError subclasses (ExpiredSignatureError, InvalidTokenError, etc.)
    if the token is invalid, expired, or uses an unauthorized algorithm.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["sub", "role", "iat", "exp"]},
    )

