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
    """Verify that reusing the same secret for JWT and case codes is strictly rejected."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            JWT_SECRET="shared-secret-that-must-never-be-reused-between-contexts",
            CASE_CODE_SECRET="shared-secret-that-must-never-be-reused-between-contexts",
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
    )
    assert cfg.ENV == "production"
    assert cfg.DEBUG is False
    # Restrictive CORS: empty by default in production unless explicitly set
    assert cfg.BACKEND_CORS_ORIGINS == []
