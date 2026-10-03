from datetime import datetime
from typing import List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ReportCategory, ReportStatus


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


class ModeratorReportListResponse(BaseModel):
    """Paginated collection of reports for the moderator control plane."""

    items: List[ModeratorReportResponse] = Field(..., description="List of report records")
    total: int = Field(..., ge=0, description="Total matching report count")
    limit: int = Field(..., ge=1, le=100, description="Page size limit")
    offset: int = Field(..., ge=0, description="Offset index")

    model_config = ConfigDict(extra="forbid")
