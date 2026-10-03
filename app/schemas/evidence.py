from datetime import datetime
from typing import List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import EvidenceScanStatus


class EvidenceUploadResponse(BaseModel):
    """Response returned upon successful anonymous evidence attachment upload.

    Contains strictly the count and byte size of accepted files.
    Internal database IDs, storage keys, filenames, and scan internals are strictly omitted.
    """
    status: str = Field(default="ACCEPTED", description="Upload acceptance status")
    attachments_accepted: int = Field(..., ge=1, description="Number of files accepted into quarantine")
    total_bytes: int = Field(..., ge=1, description="Total size in bytes accepted across all files")

    model_config = ConfigDict(
        extra="forbid",
    )


class EvidenceModeratorResponse(BaseModel):
    """Privileged moderator representation of an evidence attachment.

    Original client filename, raw storage paths, and reporter identity are strictly omitted.
    """
    id: uuid.UUID = Field(..., description="Internal attachment UUID")
    detected_mime: str = Field(..., description="Verified MIME type detected via server libmagic")
    file_size: int = Field(..., ge=0, description="Exact file size in bytes")
    scan_status: EvidenceScanStatus = Field(..., description="Current AV scan lifecycle status")
    created_at: datetime = Field(..., description="Upload timestamp")
    display_name: str = Field(..., description="Deterministic synthetic display filename (e.g. evidence-1.pdf)")

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )


class EvidenceModeratorListResponse(BaseModel):
    """List of evidence attachments for a specific report for authorized moderators."""
    items: List[EvidenceModeratorResponse] = Field(default_factory=list, description="List of evidence records")
    total: int = Field(..., ge=0, description="Total attachments associated with the report")

    model_config = ConfigDict(
        extra="forbid",
    )
