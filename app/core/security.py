import hashlib
import hmac
import secrets

from app.core.config import settings


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
