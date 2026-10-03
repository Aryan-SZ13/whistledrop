from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from app.models.enums import ReportCategory, ReportStatus


class ReportCreate(BaseModel):
    """Payload for submitting an anonymous whistleblower report.

    Strictly forbids unexpected fields (such as identity or tracking parameters).
    The server stores evidence_url strictly as metadata and never fetches submitted URLs.
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
    evidence_url: Optional[HttpUrl] = Field(
        default=None,
        description="Optional metadata URL pointing to external evidence. The server never fetches this URL.",
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


class ReportCreateResponse(BaseModel):
    """Response returned upon successful report submission.

    Exposes only the minimal public tracking information.
    Internal database IDs (UUID) are strictly omitted.
    The case code is returned only once and cannot be recovered if lost.
    """
    case_code: str = Field(
        ...,
        description="Cryptographically secure bearer credential for tracking report status. Shown only once.",
    )
    status: ReportStatus = Field(..., description="Initial lifecycle status (SUBMITTED)")
    created_at: datetime = Field(
        ...,
        description=(
            "Timezone-aware creation timestamp. "
            "Note: Public timestamp precision is a deliberate current design; "
            "future privacy hardening may coarse-grain timestamps to reduce traffic correlation."
        ),
    )

    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore",
    )
