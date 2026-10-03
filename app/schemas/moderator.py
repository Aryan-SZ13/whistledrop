from datetime import datetime
from typing import List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ReportCategory, ReportStatus, ReportUpdateType


class ReportStatusUpdateRequest(BaseModel):
    """Payload for updating a report lifecycle status."""

    status: ReportStatus = Field(..., description="Target lifecycle status")

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


class ModeratorUpdateCreate(BaseModel):
    """Payload for posting a public update or internal note to a report."""

    message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="Update or internal note content (1 - 5,000 characters)",
    )
    type: ReportUpdateType = Field(
        ...,
        description="Update visibility type: PUBLIC_UPDATE or INTERNAL_NOTE",
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


class ModeratorUpdateResponse(BaseModel):
    """Moderator view of an update or note posted to a report."""

    id: uuid.UUID = Field(..., description="Internal update UUID")
    message: str = Field(..., description="Update or note content")
    type: ReportUpdateType = Field(..., description="Visibility type")
    created_at: datetime = Field(..., description="Creation timestamp")
    created_by: Optional[uuid.UUID] = Field(None, description="UUID of moderator who authored the update")

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )


class ModeratorReportResponse(BaseModel):
    """Privileged moderator representation of an anonymous report.

    Strictly omits case_code_digest, plaintext case code, reporter identity,
    and audit log internals.
    """

    id: uuid.UUID = Field(..., description="Internal report UUID")
    category: ReportCategory = Field(..., description="Report category")
    description: str = Field(..., description="Report incident description")
    evidence_url: Optional[str] = Field(None, description="Metadata evidence URL if submitted")
    status: ReportStatus = Field(..., description="Current report lifecycle status")
    created_at: datetime = Field(..., description="Timestamp of report submission")
    updated_at: datetime = Field(..., description="Timestamp of last status or update modification")

    model_config = ConfigDict(extra="forbid")


class ModeratorReportDetailResponse(ModeratorReportResponse):
    """Detailed moderator representation of an anonymous report with chronological updates."""

    updates: List[ModeratorUpdateResponse] = Field(
        default_factory=list,
        description="Chronological public updates and internal notes posted to this report",
    )

    model_config = ConfigDict(extra="forbid")


class ModeratorReportListResponse(BaseModel):
    """Paginated collection of reports for the moderator control plane."""

    items: List[ModeratorReportResponse] = Field(..., description="List of report records")
    total: int = Field(..., ge=0, description="Total matching report count")
    limit: int = Field(..., ge=1, le=100, description="Page size limit")
    offset: int = Field(..., ge=0, description="Offset index")

    model_config = ConfigDict(extra="forbid")

