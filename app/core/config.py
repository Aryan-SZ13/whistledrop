from typing import List, Optional, Union
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_INSECURE_JWT_SECRET = "dev-insecure-jwt-secret-key-change-in-production-min32bytes"
DEV_INSECURE_CASE_CODE_SECRET = "dev-insecure-case-code-secret-key-change-in-production-min32bytes"
DEV_INSECURE_RATE_LIMIT_KEY_SECRET = "dev-insecure-rate-limit-key-secret-change-in-production-min32"
DEV_INSECURE_CURSOR_SECRET = "dev-insecure-cursor-secret-key-change-in-production-min32bytes"
DEV_INSECURE_AUDIT_CHAIN_SECRET = "dev-insecure-audit-chain-secret-key-change-in-production-min32"
DEV_INSECURE_EVIDENCE_KEK_SECRET = "dev-insecure-evidence-kek-secret-key-change-in-production-min32"
DEV_INSECURE_EXPORT_SIGNING_KEY_ED25519_PRIVATE = "a1" * 32
DEV_INSECURE_MFA_KEK_SECRET = "dev-insecure-mfa-kek-secret-key-change-in-production-min32byt"
DEV_INSECURE_REFRESH_SECRET = "dev-insecure-refresh-secret-key-change-in-production-min32"
DEV_INSECURE_WEBHOOK_KEK_SECRET = "dev-insecure-webhook-kek-secret-change-in-production-min32"
DEV_INSECURE_WEBHOOK_SALT = "dev-insecure-webhook-salt-change-in-production-min32bytes"
DEV_INSECURE_PAYLOAD_KEK_1 = "dev-insecure-payload-kek-secret-change-in-production-min32byt"
DEV_INSECURE_TRANSPARENCY_SALT = "dev-insecure-transparency-salt-change-in-production-min32"
DEV_INSECURE_CANARY_SIGNING_KEY_ED25519_PRIVATE = "b2" * 32
ENV_EXAMPLE_PLACEHOLDER_JWT = "replace-with-a-secure-random-secret-for-jwt-tokens-minimum-32-chars"
ENV_EXAMPLE_PLACEHOLDER_CASE = "replace-with-a-secure-random-secret-for-case-codes-minimum-32-chars"
ENV_EXAMPLE_PLACEHOLDER_RATE_LIMIT = "replace-with-a-secure-random-secret-for-rate-limit-keys-min-32"
ENV_EXAMPLE_PLACEHOLDER_CURSOR = "replace-with-a-secure-random-secret-for-cursor-signing-minimum-32"
ENV_EXAMPLE_PLACEHOLDER_AUDIT_CHAIN = "replace-with-a-secure-random-secret-for-audit-chain-min-32-chars"
ENV_EXAMPLE_PLACEHOLDER_EVIDENCE_KEK = "replace-with-a-secure-random-secret-for-evidence-kek-min-32-char"
ENV_EXAMPLE_PLACEHOLDER_MFA_KEK = "replace-with-a-secure-random-secret-for-mfa-kek-min-32-chars"
ENV_EXAMPLE_PLACEHOLDER_REFRESH = "replace-with-a-secure-random-secret-for-refresh-token-min-32-chars"
ENV_EXAMPLE_PLACEHOLDER_WEBHOOK_KEK = "replace-with-a-secure-random-secret-for-webhook-kek-min-32-chars"
ENV_EXAMPLE_PLACEHOLDER_WEBHOOK_SALT = "replace-with-a-secure-random-secret-for-webhook-salt-min-32-char"
ENV_EXAMPLE_PLACEHOLDER_PAYLOAD_KEK = "replace-with-a-secure-random-secret-for-payload-kek-min-32-chars"
ENV_EXAMPLE_PLACEHOLDER_TRANSPARENCY_SALT = "replace-with-a-secure-random-secret-for-transparency-salt-min-32"

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
    LOG_LEVEL: str = "INFO"
    API_V1_PREFIX: str = "/api/v1"

    # Distinct Cryptographic Secrets & JWT Configuration
    JWT_SECRET: str = DEV_INSECURE_JWT_SECRET
    CASE_CODE_SECRET: str = DEV_INSECURE_CASE_CODE_SECRET
    RATE_LIMIT_KEY_SECRET: str = DEV_INSECURE_RATE_LIMIT_KEY_SECRET
    CURSOR_SECRET: str = DEV_INSECURE_CURSOR_SECRET
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

    # Anonymous Communication & Notification Policies (Phase 11 & 12)
    MAX_MESSAGE_LENGTH: int = 5000
    MAX_MESSAGE_REQUEST_BODY: int = 65536  # 64 KiB transport-level ceiling
    MESSAGE_RATE_LIMIT: int = 15
    MESSAGE_RATE_WINDOW_SECONDS: int = 60
    NOTIFICATION_RATE_LIMIT: int = 30
    NOTIFICATION_RATE_WINDOW_SECONDS: int = 60
    IDEMPOTENCY_TTL_SECONDS: int = 86400  # 24 hours
    IDEMPOTENCY_IN_PROGRESS_TTL_SECONDS: int = 60

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

    # Tamper-Evident Audit Chain & Asymmetric Export Signing (Phase 13)
    AUDIT_CHAIN_SECRET: str = DEV_INSECURE_AUDIT_CHAIN_SECRET
    EXPORT_SIGNING_KEY_ED25519_PRIVATE: str = DEV_INSECURE_EXPORT_SIGNING_KEY_ED25519_PRIVATE
    EXPORT_SIGNING_KEY_ID: str = "ed25519:2026-v1"
    TRUSTED_SIGNING_KEY_FINGERPRINTS: Union[List[str], str] = []
    EXPORT_TEMP_DIR: str = "./evidence_storage/temp_exports"
    EXPORT_MAX_ARCHIVE_BYTES: int = 104857600  # 100 MiB
    EXPORT_RATE_LIMIT: int = 10
    EXPORT_RATE_WINDOW_SECONDS: int = 60
    AUDIT_VERIFY_RATE_LIMIT: int = 30
    AUDIT_VERIFY_RATE_WINDOW_SECONDS: int = 60

    # Evidence Envelope Encryption, Retention & Withdrawal (Phase 14)
    EVIDENCE_KEK_SECRET: str = DEV_INSECURE_EVIDENCE_KEK_SECRET
    EVIDENCE_KEK_KEY_ID: str = "kek-2026-v1"
    RETENTION_RESOLVED_DAYS: int = 30
    RETENTION_DISMISSED_DAYS: int = 14
    RETENTION_WITHDRAWN_DAYS: int = 7
    RETENTION_BATCH_SIZE: int = 50
    RETENTION_LOCK_TTL_SECONDS: int = 300
    WITHDRAWAL_RATE_LIMIT: int = 5
    WITHDRAWAL_RATE_WINDOW_SECONDS: int = 60
    VERIFICATION_RECEIPT_RATE_LIMIT: int = 30
    VERIFICATION_RECEIPT_RATE_WINDOW_SECONDS: int = 60

    # Phase 15: Moderator MFA & Session Revocation
    MFA_KEK_SECRET: str = DEV_INSECURE_MFA_KEK_SECRET
    REFRESH_SECRET: str = DEV_INSECURE_REFRESH_SECRET
    MFA_SETUP_TICKET_EXPIRE_SECONDS: int = 300
    MFA_CHALLENGE_TICKET_EXPIRE_SECONDS: int = 300
    MFA_PENDING_SECRET_EXPIRE_SECONDS: int = 600
    MFA_MAX_FAILED_ATTEMPTS: int = 5
    MFA_LOCKOUT_SECONDS: int = 900
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Phase 16: Transactional Outbox & Signed Webhooks
    WEBHOOK_KEK_SECRET: str = DEV_INSECURE_WEBHOOK_KEK_SECRET
    WEBHOOK_SALT: str = DEV_INSECURE_WEBHOOK_SALT
    ALLOW_HTTP_WEBHOOKS: bool = False
    OUTBOX_LEASE_TTL_SECONDS: int = 60
    OUTBOX_BATCH_SIZE: int = 50
    OUTBOX_MAX_RETRIES: int = 5
    WEBHOOK_DISPATCH_TIMEOUT_SECONDS: float = 10.0

    # Phase 17: Dual-Control Quorum Governance
    QUORUM_DEFAULT_TTL_MINUTES: int = 60
    QUORUM_ENFORCE_RETENTION: bool = False
    QUORUM_ENFORCE_CASE_REOPEN: bool = False
    QUORUM_ENFORCE_MODERATOR_CHANGES: bool = False
    QUORUM_ENFORCE_WEBHOOK_DELETE: bool = False

    # Phase 18: Application-Level Payload Encryption (ALEE) & Keyring
    PAYLOAD_KEK_ACTIVE_VERSION: int = 1
    PAYLOAD_KEK_KEYRING: Union[dict[str, str], str] = {
        "1": DEV_INSECURE_PAYLOAD_KEK_1
    }

    # Phase 19: Append-Only Merkle Transparency Log
    TRANSPARENCY_SALT: str = DEV_INSECURE_TRANSPARENCY_SALT
    TRANSPARENCY_STH_SIGNING_KEY_ID: str = "whistledrop-transparency-2026-v1"
    TRANSPARENCY_RATE_LIMIT: int = 60
    TRANSPARENCY_RATE_WINDOW_SECONDS: int = 60

    # Phase 20: Cryptographic Warrant Canary & Emergency Sealing
    CANARY_SIGNING_KEY_ED25519_PRIVATE: str = DEV_INSECURE_CANARY_SIGNING_KEY_ED25519_PRIVATE
    CANARY_SIGNING_KEY_ID: str = "whistledrop-canary-2026-v1"
    CANARY_VALIDITY_DAYS: int = 7
    DEAD_MAN_INTERVAL_DAYS: int = 14
    DEAD_MAN_WARNING_HOURS: int = 48

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

    @field_validator("TRUSTED_SIGNING_KEY_FINGERPRINTS", mode="before")
    @classmethod
    def assemble_fingerprints(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json

                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return [str(fp).strip() for fp in parsed if str(fp).strip()]
                except Exception:
                    pass
            return [fp.strip() for fp in v.split(",") if fp.strip()]
        elif isinstance(v, list):
            return [str(fp).strip() for fp in v if str(fp).strip()]
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
        "MESSAGE_RATE_LIMIT",
        "MESSAGE_RATE_WINDOW_SECONDS",
        "NOTIFICATION_RATE_LIMIT",
        "NOTIFICATION_RATE_WINDOW_SECONDS",
        "IDEMPOTENCY_TTL_SECONDS",
        "IDEMPOTENCY_IN_PROGRESS_TTL_SECONDS",
        "EXPORT_RATE_LIMIT",
        "EXPORT_RATE_WINDOW_SECONDS",
        "AUDIT_VERIFY_RATE_LIMIT",
        "AUDIT_VERIFY_RATE_WINDOW_SECONDS",
        "WITHDRAWAL_RATE_LIMIT",
        "WITHDRAWAL_RATE_WINDOW_SECONDS",
        "VERIFICATION_RECEIPT_RATE_LIMIT",
        "VERIFICATION_RECEIPT_RATE_WINDOW_SECONDS",
        "RETENTION_RESOLVED_DAYS",
        "RETENTION_DISMISSED_DAYS",
        "RETENTION_WITHDRAWN_DAYS",
        "RETENTION_BATCH_SIZE",
        "RETENTION_LOCK_TTL_SECONDS",
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
        "MAX_MESSAGE_LENGTH",
        "MAX_MESSAGE_REQUEST_BODY",
        "EXPORT_MAX_ARCHIVE_BYTES",
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

        # 2. Derive domain-separated secrets if left as dev placeholder in production
        if is_production and self.CURSOR_SECRET in (DEV_INSECURE_CURSOR_SECRET, ENV_EXAMPLE_PLACEHOLDER_CURSOR):
            import hmac
            import hashlib
            self.CURSOR_SECRET = hmac.new(
                self.CASE_CODE_SECRET.encode("utf-8"),
                b"whistledrop-cursor-secret-domain-separation",
                hashlib.sha256,
            ).hexdigest()

        if is_production and self.AUDIT_CHAIN_SECRET in (DEV_INSECURE_AUDIT_CHAIN_SECRET, ENV_EXAMPLE_PLACEHOLDER_AUDIT_CHAIN):
            import hmac
            import hashlib
            self.AUDIT_CHAIN_SECRET = hmac.new(
                self.CASE_CODE_SECRET.encode("utf-8"),
                b"whistledrop-audit-chain-secret-domain-separation",
                hashlib.sha256,
            ).hexdigest()

        if is_production and self.EVIDENCE_KEK_SECRET in (DEV_INSECURE_EVIDENCE_KEK_SECRET, ENV_EXAMPLE_PLACEHOLDER_EVIDENCE_KEK):
            import hmac
            import hashlib
            self.EVIDENCE_KEK_SECRET = hmac.new(
                self.CASE_CODE_SECRET.encode("utf-8"),
                b"whistledrop-evidence-kek-secret-domain-separation",
                hashlib.sha256,
            ).hexdigest()

        if is_production and self.MFA_KEK_SECRET in (DEV_INSECURE_MFA_KEK_SECRET, ENV_EXAMPLE_PLACEHOLDER_MFA_KEK):
            import hmac
            import hashlib
            self.MFA_KEK_SECRET = hmac.new(
                self.CASE_CODE_SECRET.encode("utf-8"),
                b"whistledrop-mfa-kek-secret-domain-separation",
                hashlib.sha256,
            ).hexdigest()

        if is_production and self.REFRESH_SECRET in (DEV_INSECURE_REFRESH_SECRET, ENV_EXAMPLE_PLACEHOLDER_REFRESH):
            import hmac
            import hashlib
            self.REFRESH_SECRET = hmac.new(
                self.CASE_CODE_SECRET.encode("utf-8"),
                b"whistledrop-refresh-secret-domain-separation",
                hashlib.sha256,
            ).hexdigest()

        if is_production and self.WEBHOOK_KEK_SECRET in (DEV_INSECURE_WEBHOOK_KEK_SECRET, ENV_EXAMPLE_PLACEHOLDER_WEBHOOK_KEK):
            import hmac
            import hashlib
            self.WEBHOOK_KEK_SECRET = hmac.new(
                self.CASE_CODE_SECRET.encode("utf-8"),
                b"whistledrop-webhook-kek-secret-domain-separation",
                hashlib.sha256,
            ).hexdigest()

        if is_production and self.WEBHOOK_SALT in (DEV_INSECURE_WEBHOOK_SALT, ENV_EXAMPLE_PLACEHOLDER_WEBHOOK_SALT):
            import hmac
            import hashlib
            self.WEBHOOK_SALT = hmac.new(
                self.CASE_CODE_SECRET.encode("utf-8"),
                b"whistledrop-webhook-salt-domain-separation",
                hashlib.sha256,
            ).hexdigest()

        if is_production and self.TRANSPARENCY_SALT in (DEV_INSECURE_TRANSPARENCY_SALT, ENV_EXAMPLE_PLACEHOLDER_TRANSPARENCY_SALT):
            import hmac
            import hashlib
            self.TRANSPARENCY_SALT = hmac.new(
                self.CASE_CODE_SECRET.encode("utf-8"),
                b"whistledrop-transparency-salt-domain-separation",
                hashlib.sha256,
            ).hexdigest()

        # Keyring Parsing & Validation
        if isinstance(self.PAYLOAD_KEK_KEYRING, str):
            import json
            try:
                self.PAYLOAD_KEK_KEYRING = json.loads(self.PAYLOAD_KEK_KEYRING)
            except Exception:
                raise ValueError("PAYLOAD_KEK_KEYRING must be a valid JSON mapping of version to secret string.")

        active_ver_str = str(self.PAYLOAD_KEK_ACTIVE_VERSION)
        if active_ver_str not in self.PAYLOAD_KEK_KEYRING:
            raise ValueError(f"PAYLOAD_KEK_ACTIVE_VERSION '{active_ver_str}' not found in PAYLOAD_KEK_KEYRING.")
        active_payload_kek = self.PAYLOAD_KEK_KEYRING[active_ver_str]

        # 3. Secret Separation & Non-Reuse Verification
        secrets_set = {
            self.JWT_SECRET,
            self.CASE_CODE_SECRET,
            self.RATE_LIMIT_KEY_SECRET,
            self.CURSOR_SECRET,
            self.AUDIT_CHAIN_SECRET,
            self.EVIDENCE_KEK_SECRET,
            self.MFA_KEK_SECRET,
            self.REFRESH_SECRET,
            self.WEBHOOK_KEK_SECRET,
            self.WEBHOOK_SALT,
            active_payload_kek,
            self.TRANSPARENCY_SALT,
        }
        if len(secrets_set) < 12:
            raise ValueError(
                "Cryptographic secrets must be distinct secrets. "
                "Do NOT reuse the same secret across different security contexts."
            )

        # 4. Production Secret Hardening
        if is_production:
            insecure_placeholders = {
                DEV_INSECURE_JWT_SECRET,
                DEV_INSECURE_CASE_CODE_SECRET,
                DEV_INSECURE_RATE_LIMIT_KEY_SECRET,
                DEV_INSECURE_CURSOR_SECRET,
                DEV_INSECURE_AUDIT_CHAIN_SECRET,
                DEV_INSECURE_EVIDENCE_KEK_SECRET,
                ENV_EXAMPLE_PLACEHOLDER_JWT,
                ENV_EXAMPLE_PLACEHOLDER_CASE,
                ENV_EXAMPLE_PLACEHOLDER_RATE_LIMIT,
                ENV_EXAMPLE_PLACEHOLDER_CURSOR,
                ENV_EXAMPLE_PLACEHOLDER_AUDIT_CHAIN,
                ENV_EXAMPLE_PLACEHOLDER_EVIDENCE_KEK,
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
            if self.CURSOR_SECRET in insecure_placeholders or len(self.CURSOR_SECRET) < 32:
                raise ValueError(
                    "Production requires a strong, unique CURSOR_SECRET of at least 32 characters."
                )
            if self.AUDIT_CHAIN_SECRET in insecure_placeholders or len(self.AUDIT_CHAIN_SECRET) < 32:
                raise ValueError(
                    "Production requires a strong, unique AUDIT_CHAIN_SECRET of at least 32 characters."
                )
            if self.EVIDENCE_KEK_SECRET in insecure_placeholders or len(self.EVIDENCE_KEK_SECRET) < 32:
                raise ValueError(
                    "Production requires a strong, unique EVIDENCE_KEK_SECRET of at least 32 characters."
                )

        # 5. Trusted Ed25519 Fingerprints derivation / verification
        try:
            import hashlib
            from cryptography.hazmat.primitives.asymmetric import ed25519
            seed_bytes = bytes.fromhex(self.EXPORT_SIGNING_KEY_ED25519_PRIVATE)
            if len(seed_bytes) == 32:
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed_bytes)
                pub_raw = priv.public_key().public_bytes_raw()
                fp = f"SHA256:{hashlib.sha256(pub_raw).hexdigest()}"
                if not self.TRUSTED_SIGNING_KEY_FINGERPRINTS:
                    self.TRUSTED_SIGNING_KEY_FINGERPRINTS = [fp]
        except Exception:
            pass

        # 6. CORS Behavior
        # In development: default to common local frontend addresses if not specified
        # In production: default to empty list (restrictive by default) unless explicitly set
        if not self.BACKEND_CORS_ORIGINS and not is_production:
            self.BACKEND_CORS_ORIGINS = DEFAULT_DEV_CORS_ORIGINS

        # 7. Attachment Bounds Validation
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
