from typing import List, Optional, Union
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_INSECURE_JWT_SECRET = "dev-insecure-jwt-secret-key-change-in-production-min32bytes"
DEV_INSECURE_CASE_CODE_SECRET = "dev-insecure-case-code-secret-key-change-in-production-min32bytes"
DEV_INSECURE_RATE_LIMIT_KEY_SECRET = "dev-insecure-rate-limit-key-secret-change-in-production-min32"
ENV_EXAMPLE_PLACEHOLDER_JWT = "replace-with-a-secure-random-secret-for-jwt-tokens-minimum-32-chars"
ENV_EXAMPLE_PLACEHOLDER_CASE = "replace-with-a-secure-random-secret-for-case-codes-minimum-32-chars"
ENV_EXAMPLE_PLACEHOLDER_RATE_LIMIT = "replace-with-a-secure-random-secret-for-rate-limit-keys-min-32"

DEFAULT_DEV_CORS_ORIGINS: List[str] = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8000",
]


class Settings(BaseSettings):
    PROJECT_NAME: str = "WhistleDrop"
    ENV: str = "development"
    DEBUG: Optional[bool] = None
    API_V1_PREFIX: str = "/api/v1"

    # Distinct Cryptographic Secrets & JWT Configuration
    JWT_SECRET: str = DEV_INSECURE_JWT_SECRET
    CASE_CODE_SECRET: str = DEV_INSECURE_CASE_CODE_SECRET
    RATE_LIMIT_KEY_SECRET: str = DEV_INSECURE_RATE_LIMIT_KEY_SECRET
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "whistledrop-api"
    JWT_AUDIENCE: str = "whistledrop-moderators"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Redis Configuration (Ephemeral Rate Limiting & Abuse Resistance)
    REDIS_URL: str = "redis://localhost:6379/0"

    # Trusted Proxy Configuration
    TRUSTED_PROXY_CIDRS: str = ""
    TRUSTED_PROXY_COUNT: int = 0

    # Rate Limiting Policies (Configurable limits and window durations in seconds)
    SUBMISSION_RATE_LIMIT: int = 5
    SUBMISSION_RATE_WINDOW_SECONDS: int = 300

    LOOKUP_RATE_LIMIT: int = 10
    LOOKUP_RATE_WINDOW_SECONDS: int = 60

    LOOKUP_GLOBAL_RATE_LIMIT: int = 100
    LOOKUP_GLOBAL_RATE_WINDOW_SECONDS: int = 60

    LOGIN_RATE_LIMIT: int = 5
    LOGIN_RATE_WINDOW_SECONDS: int = 300

    # Evidence Attachment Storage & Antivirus Scanning (Phase 8)
    MAX_ATTACHMENT_SIZE_MB: int = 10
    MAX_ATTACHMENTS_PER_REPORT: int = 5
    MAX_TOTAL_ATTACHMENT_BYTES: int = 26214400  # 25 MiB (25 * 1024 * 1024)
    MIN_FREE_STORAGE_MB: int = 1024  # 1 GiB minimum free space safety threshold
    EVIDENCE_STORAGE_PATH: str = "./evidence_storage"
    CLAMAV_HOST: str = "localhost"
    CLAMAV_PORT: int = 3310
    CLAMAV_SCAN_TIMEOUT: int = 30
    PENDING_SCAN_MAX_AGE_HOURS: int = 24
    QUARANTINE_RETENTION_HOURS: int = 72
    RECONCILIATION_INTERVAL_MINUTES: int = 60
    ATTACHMENT_UPLOAD_RATE_LIMIT: int = 10
    ATTACHMENT_UPLOAD_RATE_WINDOW_SECONDS: int = 300

    # Configurable CORS Origins
    BACKEND_CORS_ORIGINS: Union[List[str], str] = []

    # Database Configuration (Development PostgreSQL)
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "whistledrop"
    POSTGRES_PASSWORD: str = "whistledrop_dev_password"
    POSTGRES_DB: str = "whistledrop_db"
    DATABASE_URL: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                # Handle raw JSON array string if provided in env
                import json

                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return [str(origin).strip() for origin in parsed if str(origin).strip()]
                except Exception:
                    pass
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            return [str(origin).strip() for origin in v if str(origin).strip()]
        return []

    @field_validator(
        "SUBMISSION_RATE_LIMIT",
        "SUBMISSION_RATE_WINDOW_SECONDS",
        "LOOKUP_RATE_LIMIT",
        "LOOKUP_RATE_WINDOW_SECONDS",
        "LOOKUP_GLOBAL_RATE_LIMIT",
        "LOOKUP_GLOBAL_RATE_WINDOW_SECONDS",
        "LOGIN_RATE_LIMIT",
        "LOGIN_RATE_WINDOW_SECONDS",
        "ATTACHMENT_UPLOAD_RATE_LIMIT",
        "ATTACHMENT_UPLOAD_RATE_WINDOW_SECONDS",
    )
    @classmethod
    def validate_rate_limit_bounds(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Rate limit requests and window durations must be at least 1.")
        return v

    @field_validator(
        "MAX_ATTACHMENT_SIZE_MB",
        "MAX_ATTACHMENTS_PER_REPORT",
        "PENDING_SCAN_MAX_AGE_HOURS",
        "QUARANTINE_RETENTION_HOURS",
        "RECONCILIATION_INTERVAL_MINUTES",
        "CLAMAV_SCAN_TIMEOUT",
        "MIN_FREE_STORAGE_MB",
    )
    @classmethod
    def validate_positive_bounds(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Configuration bounds must be at least 1.")
        return v

    @field_validator("MAX_TOTAL_ATTACHMENT_BYTES")
    @classmethod
    def validate_total_attachment_bytes(cls, v: int) -> int:
        if v < 1048576:
            raise ValueError("MAX_TOTAL_ATTACHMENT_BYTES must be at least 1048576 (1 MiB).")
        return v

    @field_validator("CLAMAV_PORT")
    @classmethod
    def validate_clamav_port(cls, v: int) -> int:
        if v < 1 or v > 65535:
            raise ValueError("CLAMAV_PORT must be between 1 and 65535.")
        return v


    @model_validator(mode="after")
    def validate_environment_and_secrets(self) -> "Settings":
        env_normalized = self.ENV.strip().lower()
        is_production = env_normalized in ("production", "prod")

        # 1. Environment-aware DEBUG behavior
        if is_production:
            if self.DEBUG is True:
                raise ValueError("DEBUG mode cannot be enabled when ENV is set to production.")
            self.DEBUG = False
        else:
            if self.DEBUG is None:
                self.DEBUG = True

        # 2. Secret Separation & Non-Reuse Verification
        secrets_set = {self.JWT_SECRET, self.CASE_CODE_SECRET, self.RATE_LIMIT_KEY_SECRET}
        if len(secrets_set) < 3:
            raise ValueError(
                "JWT_SECRET, CASE_CODE_SECRET, and RATE_LIMIT_KEY_SECRET must be distinct secrets. "
                "Do NOT reuse the same secret across different security contexts."
            )

        # 3. Production Secret Hardening
        if is_production:
            insecure_placeholders = {
                DEV_INSECURE_JWT_SECRET,
                DEV_INSECURE_CASE_CODE_SECRET,
                DEV_INSECURE_RATE_LIMIT_KEY_SECRET,
                ENV_EXAMPLE_PLACEHOLDER_JWT,
                ENV_EXAMPLE_PLACEHOLDER_CASE,
                ENV_EXAMPLE_PLACEHOLDER_RATE_LIMIT,
            }
            if self.JWT_SECRET in insecure_placeholders or len(self.JWT_SECRET) < 32:
                raise ValueError(
                    "Production requires a strong, unique JWT_SECRET of at least 32 characters."
                )
            if self.CASE_CODE_SECRET in insecure_placeholders or len(self.CASE_CODE_SECRET) < 32:
                raise ValueError(
                    "Production requires a strong, unique CASE_CODE_SECRET of at least 32 characters."
                )
            if self.RATE_LIMIT_KEY_SECRET in insecure_placeholders or len(self.RATE_LIMIT_KEY_SECRET) < 32:
                raise ValueError(
                    "Production requires a strong, unique RATE_LIMIT_KEY_SECRET of at least 32 characters."
                )

        # 4. CORS Behavior
        # In development: default to common local frontend addresses if not specified
        # In production: default to empty list (restrictive by default) unless explicitly set
        if not self.BACKEND_CORS_ORIGINS and not is_production:
            self.BACKEND_CORS_ORIGINS = DEFAULT_DEV_CORS_ORIGINS

        # 5. Attachment Bounds Validation
        if self.MAX_ATTACHMENT_SIZE_MB * 1024 * 1024 > self.MAX_TOTAL_ATTACHMENT_BYTES:
            raise ValueError(
                "MAX_ATTACHMENT_SIZE_MB in bytes cannot exceed MAX_TOTAL_ATTACHMENT_BYTES."
            )

        return self

    @property
    def async_database_url(self) -> str:
        """Standardized async database connection URL for SQLAlchemy + asyncpg."""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def sync_database_url(self) -> str:
        """Synchronous connection URL fallback (useful for synchronous migration runners)."""
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


settings = Settings()
