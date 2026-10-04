from datetime import datetime
from typing import List, Optional
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


from app.schemas.transparency import MerkleReceipt


class ReportCreateResponse(BaseModel):
    """Response returned upon successful report submission.

    Exposes only the minimal public tracking information.
    Internal database IDs (UUID) are strictly omitted.
    The case code is generated once and returned/shown once at submission;
    it serves as a reusable bearer credential for tracking report status.
    """
    case_code: str = Field(
        ...,
        description="Cryptographically secure bearer credential for tracking report status. Shown once upon submission.",
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
        extra="forbid",
    )


class ReportUpdatePublic(BaseModel):
    """Public representation of an update posted to a report.

    Excludes moderator identifiers, usernames, internal UUIDs, and audit logs.
    """
    message: str = Field(..., description="Status update message from the review team")
    created_at: datetime = Field(..., description="Timezone-aware timestamp of the update")

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )


class ReportTrackingResponse(BaseModel):
    """Public tracking state for a report retrieved using its case code.

    Contains only the minimal fields necessary for anonymous case tracking:
    the current status and any public updates.
    Internal database IDs, description, evidence_url, case_code_digest, and moderator
    information are strictly excluded.
    """
    status: ReportStatus = Field(..., description="Current report lifecycle status")
    updates: List[ReportUpdatePublic] = Field(
        default_factory=list,
        description="Chronological public updates posted to this report",
    )

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )
