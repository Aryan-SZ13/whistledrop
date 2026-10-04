import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class MfaSetupTokenRequest(BaseModel):
    password: str = Field(..., min_length=8, description="Current account password for re-authentication")

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class MfaSetupTokenResponse(BaseModel):
    setup_ticket: str = Field(..., description="Short-lived single-use ticket for MFA setup")
    expires_in: int = Field(default=300, description="Ticket validity in seconds (5 minutes)")

    model_config = ConfigDict(extra="forbid")


class MfaSetupResponse(BaseModel):
    secret: str = Field(..., description="Base32-encoded 160-bit TOTP secret")
    otpauth_uri: str = Field(..., description="Standard otpauth:// URI for authenticator setup")
    expires_in: int = Field(default=600, description="Setup expiration window in seconds (10 minutes)")

    model_config = ConfigDict(extra="forbid")


class MfaVerifySetupRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$", description="6-digit numeric TOTP code")

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class MfaVerifySetupResponse(BaseModel):
    status: str = Field(default="mfa_enabled")
    enrolled_at: datetime
    backup_codes: List[str] = Field(..., description="10 single-use recovery codes (shown once)")

    model_config = ConfigDict(extra="forbid")


class MfaChallengeRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=20, description="6-digit TOTP code or recovery code")

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class MfaChallengeResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(default=1800, description="Access token expiration in seconds")

    model_config = ConfigDict(extra="forbid")


class TokenRefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=20, description="Bearer refresh token")

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class TokenRefreshResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(default=1800, description="Access token expiration in seconds")

    model_config = ConfigDict(extra="forbid")


class LogoutResponse(BaseModel):
    status: str = Field(default="logged_out")

    model_config = ConfigDict(extra="forbid")


class RevokeAllSessionsResponse(BaseModel):
    revoked_sessions_count: int = Field(..., description="Count of sessions revoked")

    model_config = ConfigDict(extra="forbid")
