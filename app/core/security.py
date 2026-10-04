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

# Argon2id parameters chosen above OWASP's current minimum baseline
# as an intentional engineering tradeoff (memory: 64 MiB, time: 3 iterations, parallelism: 4 lanes)
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

# Fixed dummy Argon2id password hash generated once at process initialization.
# Computed from an unguessable 256-bit random string so it contains no real password.
# Used during authentication of nonexistent users to perform comparable cryptographic
# work and mitigate username-enumeration timing side channels.
DUMMY_ARGON2_HASH: str = _password_hasher.hash(secrets.token_hex(32))


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

    Username canonicalization prevents casing and surrounding-whitespace ambiguity.
    It is not a Unicode confusable/homograph defense.
    """
    if not username or not username.strip():
        raise ValueError("Username must not be empty.")
    return username.strip().lower()


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id configured above OWASP minimum baseline."""
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


import base64
import struct
import time
from typing import List


def create_access_token(
    subject: str,
    sid: Optional[str] = None,
    jti: Optional[str] = None,
    token_version: int = 1,
    auth_level: str = "pwd",
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed, short-lived JWT access token for moderator authentication.

    Uses JWT_SECRET exclusively.
    Payload contains: 'sub', 'sid', 'jti', 'token_version', 'auth_level', 'iat', 'exp', 'iss', 'aud'.
    The database remains the authoritative source of truth for user roles and lifecycle.
    """
    now = datetime.now(timezone.utc)
    if expires_delta is not None:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "sid": str(sid or secrets.token_hex(16)),
        "jti": str(jti or secrets.token_hex(16)),
        "token_version": int(token_version),
        "auth_level": str(auth_level),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token against configured issuer, audience, and algorithm.

    Raises jwt.PyJWTError subclasses if the token is invalid, expired, or unverified.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        issuer=settings.JWT_ISSUER,
        audience=settings.JWT_AUDIENCE,
        options={
            "require": ["sub", "iat", "exp", "iss", "aud"],
            "verify_iss": True,
            "verify_aud": True,
            "verify_exp": True,
        },
    )


def generate_totp_secret() -> str:
    """Generate a 160-bit cryptographically secure base32 TOTP secret (RFC 6238)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8")


def get_totp_code(secret: str, time_step: int = 30, for_time: Optional[float] = None) -> str:
    """Calculate the 6-digit numeric TOTP code for a secret and timestamp (RFC 6238 standard)."""
    if for_time is None:
        for_time = time.time()
    counter = int(for_time // time_step)
    key = base64.b32decode(secret, casefold=True)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code_int % 1000000:06d}"


def verify_totp_code(secret: str, code: str, time_step: int = 30, window: int = 1) -> bool:
    """Verify a user-provided TOTP code against the secret within a drift window."""
    if not code or len(code.strip()) != 6 or not code.strip().isdigit():
        return False
    current_time = time.time()
    for drift in range(-window, window + 1):
        target_time = current_time + (drift * time_step)
        expected = get_totp_code(secret, time_step=time_step, for_time=target_time)
        if hmac.compare_digest(expected, code.strip()):
            return True
    return False


def generate_recovery_codes(count: int = 10) -> List[str]:
    """Generate single-use alphanumeric backup recovery codes (16 chars with hyphen)."""
    codes: List[str] = []
    for _ in range(count):
        raw = secrets.token_hex(8)  # 16 hex chars
        formatted = f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:]}"
        codes.append(formatted)
    return codes


def hash_recovery_code(code: str) -> str:
    """Hash a single recovery code using Argon2id."""
    clean_code = code.replace("-", "").strip().lower()
    return hash_password(clean_code)


def verify_recovery_code(code: str, hashed_code: str) -> bool:
    """Verify a single recovery code against its Argon2id hash."""
    clean_code = code.replace("-", "").strip().lower()
    return verify_password(clean_code, hashed_code)


def hash_refresh_token(token: str) -> str:
    """Derive one-way HMAC-SHA256 hash for storing refresh token."""
    return hmac.new(
        settings.REFRESH_SECRET.encode("utf-8"),
        token.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
