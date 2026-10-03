from pydantic import BaseModel, ConfigDict, Field, field_validator


class LoginRequest(BaseModel):
    """Credentials required for moderator login."""

    username: str = Field(..., min_length=1, max_length=64, description="Moderator username")
    password: str = Field(..., min_length=1, max_length=128, description="Moderator password")

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

    access_token: str = Field(..., description="Signed JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token lifespan in seconds")

    model_config = ConfigDict(extra="forbid")
