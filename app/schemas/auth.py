from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator



class LoginRequest(BaseModel):
    """Credentials required for moderator login."""

    username: str = Field(..., min_length=1, max_length=64, description="Moderator username")
    password: str = Field(..., min_length=1, max_length=128, description="Moderator password")
    totp_code: Optional[str] = Field(default=None, min_length=6, max_length=20, description="Optional TOTP code")

    model_config = ConfigDict(extra="forbid")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Username cannot be empty or solely whitespace.")
        return stripped


class TokenResponse(BaseModel):
    """Short-lived JWT bearer token response."""

    access_token: str = Field(default="", description="Signed JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(default=1800, description="Token lifespan in seconds")
    refresh_token: Optional[str] = Field(default=None, description="Persistent refresh token")
    mfa_required: bool = Field(default=False, description="True if MFA challenge is required")
    mfa_ticket: Optional[str] = Field(default=None, description="One-time MFA challenge ticket")

    model_config = ConfigDict(extra="forbid")
