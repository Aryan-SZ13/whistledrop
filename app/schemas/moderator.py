from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ReportCategory, ReportPriority, ReportStatus, ReportUpdateType


class ReportStatusUpdateRequest(BaseModel):
    """Payload for updating a report lifecycle status."""

    status: ReportStatus = Field(..., description="Target lifecycle status")
    expected_version: int = Field(..., ge=1, description="Expected report version_id for OCC")
    reopen_reason: Optional[str] = Field(
        None,
        min_length=10,
        max_length=1000,
        description="Mandatory justification when reopening a closed or dismissed report (min 10 chars)",
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


class ReportPriorityUpdateRequest(BaseModel):
    """Payload for updating a report priority level."""

    priority: ReportPriority = Field(..., description="Target priority level")
    expected_version: int = Field(..., ge=1, description="Expected report version_id for OCC")

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


class ReportAssignmentUpdateRequest(BaseModel):
    """Payload for assigning or unassigning a report."""

    moderator_id: Optional[uuid.UUID] = Field(
        None,
        description="UUID of moderator to assign, or null to unassign",
    )
    expected_version: int = Field(..., ge=1, description="Expected report version_id for OCC")

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
    expected_version: int = Field(..., ge=1, description="Expected report version_id for OCC")

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
    priority: ReportPriority = Field(..., description="Case priority level")
    assigned_to: Optional[uuid.UUID] = Field(None, description="Assigned moderator UUID")
    version_id: int = Field(..., description="Current OCC version ID")
    created_at: datetime = Field(..., description="Timestamp of report submission")
    updated_at: datetime = Field(..., description="Timestamp of last status or update modification")

    model_config = ConfigDict(extra="forbid", from_attributes=True)


class ModeratorReportDetailResponse(ModeratorReportResponse):
    """Detailed moderator representation of an anonymous report with chronological updates."""

    updates: List[ModeratorUpdateResponse] = Field(
        default_factory=list,
        description="Chronological public updates and internal notes posted to this report",
    )

    model_config = ConfigDict(extra="forbid", from_attributes=True)


class ModeratorReportListResponse(BaseModel):
    """Paginated collection of reports for the moderator control plane."""

    items: List[ModeratorReportResponse] = Field(..., description="List of report records")
    total: int = Field(..., ge=0, description="Total matching report count")
    limit: int = Field(..., ge=1, le=100, description="Page size limit")
    offset: int = Field(..., ge=0, description="Offset index")

    model_config = ConfigDict(extra="forbid")


class TimelineEventResponse(BaseModel):
    """Privileged timeline event item."""

    id: uuid.UUID = Field(..., description="Unique event or entity UUID")
    timestamp: datetime = Field(..., description="Event timestamp (ISO 8601)")
    event_type: str = Field(..., description="Normalized event type (e.g. STATUS_CHANGED, NOTE_ADDED)")
    actor_role: Optional[str] = Field(None, description="Role of the actor (MODERATOR, ADMIN, SYSTEM)")
    actor_username: Optional[str] = Field(None, description="Username of the actor if applicable")
    summary: str = Field(..., description="Human-readable event summary")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Safe event metadata")

    model_config = ConfigDict(extra="forbid")


class TimelineListResponse(BaseModel):
    """Cursor-paginated unified case activity timeline response."""

    items: List[TimelineEventResponse] = Field(..., description="Chronological timeline events in reverse order")
    next_cursor: Optional[str] = Field(None, description="Opaque Base64URL pagination cursor for next page")
    total: int = Field(..., ge=0, description="Total events in timeline for this report")

    model_config = ConfigDict(extra="forbid")


class DashboardStatsResponse(BaseModel):
    """Consolidated case management dashboard aggregate metrics."""

    count_submitted: int = Field(..., ge=0, description="Reports in SUBMITTED state")
    count_under_review: int = Field(..., ge=0, description="Reports in UNDER_REVIEW state")
    count_resolved: int = Field(..., ge=0, description="Reports in RESOLVED state")
    count_dismissed: int = Field(..., ge=0, description="Reports in DISMISSED state")

    priority_low: int = Field(..., ge=0, description="Reports with LOW priority")
    priority_medium: int = Field(..., ge=0, description="Reports with MEDIUM priority")
    priority_high: int = Field(..., ge=0, description="Reports with HIGH priority")
    priority_critical: int = Field(..., ge=0, description="Reports with CRITICAL priority")

    unassigned_active: int = Field(..., ge=0, description="Active reports (SUBMITTED/UNDER_REVIEW) unassigned")
    my_active_cases: int = Field(..., ge=0, description="Active reports assigned to calling moderator")
    assigned_to_inactive_count: int = Field(..., ge=0, description="Active reports assigned to deactivated moderators")

    model_config = ConfigDict(extra="forbid")

