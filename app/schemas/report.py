from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import ReportCategory, ReportStatus


class ReportCreate(BaseModel):
    """Payload for submitting an anonymous whistleblower report.

    Strictly forbids unexpected fields (such as identity or tracking parameters).
    """
    category: ReportCategory = Field(
        ...,
        description="Category describing the nature of the report",
    )
    description: str = Field(
        ...,
        min_length=10,
        max_length=10000,
        description="Detailed description of the incident (10 - 10,000 characters)",
    )
    evidence_url: Optional[str] = Field(
        default=None,
        max_length=2048,
        description="Optional metadata URL pointing to external evidence. The server does not fetch this URL.",
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    @field_validator("evidence_url")
    @classmethod
    def validate_evidence_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("evidence_url must be a valid HTTP or HTTPS URL.")
        return v


class ReportCreateResponse(BaseModel):
    """Response returned upon successful report submission.

    Contains the newly generated case code, which acts as a bearer credential.
    This case code is returned only once and cannot be recovered if lost.
    """
    id: UUID = Field(..., description="Unique report identifier")
    case_code: str = Field(
        ...,
        description="Cryptographically secure bearer credential for tracking report status. Shown only once.",
    )
    status: ReportStatus = Field(..., description="Initial lifecycle status (SUBMITTED)")
    created_at: datetime = Field(..., description="Timezone-aware creation timestamp")

    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore",
    )
