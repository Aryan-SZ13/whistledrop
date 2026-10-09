import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_development_settings_defaults():
    """Verify default development configuration."""
    cfg = Settings()
    assert cfg.ENV == "development"
    assert cfg.DEBUG is True
    assert len(cfg.BACKEND_CORS_ORIGINS) > 0
    assert "http://localhost:3000" in cfg.BACKEND_CORS_ORIGINS
    assert cfg.JWT_SECRET != cfg.CASE_CODE_SECRET
    assert cfg.async_database_url.startswith("postgresql+asyncpg://")


def test_cors_origins_parsing():
    """Verify comma-separated string parsing for CORS origins."""
    cfg = Settings(
        BACKEND_CORS_ORIGINS="https://app.whistledrop.org, https://admin.whistledrop.org"
    )
    assert cfg.BACKEND_CORS_ORIGINS == [
        "https://app.whistledrop.org",
        "https://admin.whistledrop.org",
    ]


def test_cors_json_array_parsing():
    """Verify JSON array format parsing for CORS origins."""
    cfg = Settings(
        BACKEND_CORS_ORIGINS='["https://app.whistledrop.org", "https://admin.whistledrop.org"]'
    )
    assert cfg.BACKEND_CORS_ORIGINS == [
        "https://app.whistledrop.org",
        "https://admin.whistledrop.org",
    ]


def test_secret_reuse_rejection():
    """Verify that reusing secrets between JWT, case codes, and rate limiting is strictly rejected."""
    # JWT and CASE_CODE secret reuse
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            JWT_SECRET="shared-secret-that-must-never-be-reused-between-contexts",
            CASE_CODE_SECRET="shared-secret-that-must-never-be-reused-between-contexts",
            RATE_LIMIT_KEY_SECRET="unique-rate-limit-secret-key-min32-characters",
        )
    assert "distinct secrets" in str(exc_info.value)

    # JWT and RATE_LIMIT secret reuse
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            JWT_SECRET="shared-secret-that-must-never-be-reused-between-contexts",
            CASE_CODE_SECRET="unique-case-code-secret-key-min32-characters",
            RATE_LIMIT_KEY_SECRET="shared-secret-that-must-never-be-reused-between-contexts",
        )
    assert "distinct secrets" in str(exc_info.value)

    # CASE_CODE and RATE_LIMIT secret reuse
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            JWT_SECRET="unique-jwt-secret-key-min32-characters",
            CASE_CODE_SECRET="shared-secret-that-must-never-be-reused-between-contexts",
            RATE_LIMIT_KEY_SECRET="shared-secret-that-must-never-be-reused-between-contexts",
        )
    assert "distinct secrets" in str(exc_info.value)



def test_production_rejects_debug_true():
    """Verify that production mode disallows DEBUG=True."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENV="production",
            DEBUG=True,
            JWT_SECRET="a-very-secure-unique-production-jwt-secret-min32-chars",
            CASE_CODE_SECRET="a-very-secure-unique-production-case-code-secret-min32-chars",
        )
    assert "DEBUG mode cannot be enabled" in str(exc_info.value)


def test_production_rejects_weak_or_default_secrets():
    """Verify that production rejects default dev placeholders and weak keys."""
    # Default dev secret rejection
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENV="production",
            DEBUG=False,
            # using default dev secrets
        )
    assert "Production requires a strong" in str(exc_info.value)

    # Short secret rejection
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENV="production",
            DEBUG=False,
            JWT_SECRET="short-secret-key",
            CASE_CODE_SECRET="another-short-secret-key",
        )
    assert "at least 32 characters" in str(exc_info.value)


def test_production_valid_defaults():
    """Verify production behavior with valid secrets: DEBUG=False and restrictive CORS by default."""
    cfg = Settings(
        ENV="production",
        JWT_SECRET="a-very-secure-unique-production-jwt-secret-min32-chars",
        CASE_CODE_SECRET="a-very-secure-unique-production-case-code-secret-min32-chars",
        RATE_LIMIT_KEY_SECRET="a-very-secure-unique-production-rate-limit-secret-min32",
        CURSOR_SECRET="a-very-secure-unique-production-cursor-secret-min32-chars",
        AUDIT_CHAIN_SECRET="a-very-secure-unique-production-audit-chain-secret-min32",
        EVIDENCE_KEK_SECRET="a-very-secure-unique-production-evidence-kek-secret-min32",
        MFA_KEK_SECRET="a-very-secure-unique-production-mfa-kek-secret-min32-chars",
        REFRESH_SECRET="a-very-secure-unique-production-refresh-secret-min32-chars",
        WEBHOOK_KEK_SECRET="a-very-secure-unique-production-webhook-kek-secret-min32",
        WEBHOOK_SALT="a-very-secure-unique-production-webhook-salt-min32-chars",
        TRANSPARENCY_SALT="a-very-secure-unique-production-transparency-salt-min32",
        PAYLOAD_KEK_KEYRING={"1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        EXPORT_SIGNING_KEY_ED25519_PRIVATE="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        CANARY_SIGNING_KEY_ED25519_PRIVATE="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    )
    assert cfg.ENV == "production"
    assert cfg.DEBUG is False
    # Restrictive CORS: empty by default in production unless explicitly set
    assert cfg.BACKEND_CORS_ORIGINS == []


@pytest.mark.parametrize(
    "field,invalid_val",
    [
        ("SUBMISSION_RATE_LIMIT", 0),
        ("SUBMISSION_RATE_LIMIT", -1),
        ("SUBMISSION_RATE_WINDOW_SECONDS", 0),
        ("SUBMISSION_RATE_WINDOW_SECONDS", -10),
        ("LOOKUP_RATE_LIMIT", 0),
        ("LOOKUP_RATE_LIMIT", -5),
        ("LOOKUP_RATE_WINDOW_SECONDS", 0),
        ("LOOKUP_RATE_WINDOW_SECONDS", -60),
        ("LOOKUP_GLOBAL_RATE_LIMIT", 0),
        ("LOOKUP_GLOBAL_RATE_LIMIT", -100),
        ("LOOKUP_GLOBAL_RATE_WINDOW_SECONDS", 0),
        ("LOOKUP_GLOBAL_RATE_WINDOW_SECONDS", -30),
        ("LOGIN_RATE_LIMIT", 0),
        ("LOGIN_RATE_LIMIT", -1),
        ("LOGIN_RATE_WINDOW_SECONDS", 0),
        ("LOGIN_RATE_WINDOW_SECONDS", -300),
    ],
)
def test_rate_limit_bounds_rejected(field: str, invalid_val: int):
    """Verify that zero or negative values for rate limit fields are rejected."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(**{field: invalid_val})
    assert "at least 1" in str(exc_info.value)


def test_rate_limit_valid_bounds_accepted():
    """Verify that positive values (>= 1) for all rate limit fields are accepted."""
    cfg = Settings(
        SUBMISSION_RATE_LIMIT=1,
        SUBMISSION_RATE_WINDOW_SECONDS=1,
        LOOKUP_RATE_LIMIT=1,
        LOOKUP_RATE_WINDOW_SECONDS=1,
        LOOKUP_GLOBAL_RATE_LIMIT=1,
        LOOKUP_GLOBAL_RATE_WINDOW_SECONDS=1,
        LOGIN_RATE_LIMIT=1,
        LOGIN_RATE_WINDOW_SECONDS=1,
    )
    assert cfg.SUBMISSION_RATE_LIMIT == 1
    assert cfg.SUBMISSION_RATE_WINDOW_SECONDS == 1
    assert cfg.LOOKUP_RATE_LIMIT == 1
    assert cfg.LOOKUP_RATE_WINDOW_SECONDS == 1
    assert cfg.LOOKUP_GLOBAL_RATE_LIMIT == 1
    assert cfg.LOOKUP_GLOBAL_RATE_WINDOW_SECONDS == 1
    assert cfg.LOGIN_RATE_LIMIT == 1
    assert cfg.LOGIN_RATE_WINDOW_SECONDS == 1


