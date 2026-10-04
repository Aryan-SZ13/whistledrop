import uuid
from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field


class QuorumCreateRequest(BaseModel):
    action_type: str = Field(
        ...,
        pattern=r"^(MANUAL_RETENTION_SWEEP|ADMIN_CASE_REOPEN|MODERATOR_ROLE_CHANGE|MODERATOR_DEACTIVATE|WEBHOOK_ENDPOINT_DELETE)$",
        description="Allowlisted critical administrative action type",
    )
    target_id: Optional[str] = Field(default=None, max_length=64, description="Target entity ID if applicable")
    parameters: Dict[str, Any] = Field(..., description="Action parameters (e.g. expected_version, reason)")
    reason: str = Field(..., min_length=10, max_length=1000, description="Justification for proposal")

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class QuorumResponse(BaseModel):
    id: uuid.UUID
    action_type: str
    target_id: Optional[str] = None
    proposal_hash: str
    status: str
    parameters: Dict[str, Any]
    reason: str
    expires_at: datetime
    created_at: datetime
    executed_at: Optional[datetime] = None
    proposed_by_id: uuid.UUID
    approved_by_id: Optional[uuid.UUID] = None
    approval_reason: Optional[str] = None

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class QuorumApproveRequest(BaseModel):
    approval_reason: str = Field(..., min_length=10, max_length=1000, description="Approving administrator justification")
    totp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$", description="Live fresh 6-digit TOTP proof")

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class QuorumApproveResponse(BaseModel):
    status: str = Field(default="EXECUTED")
    executed_at: datetime
    action_type: str
    result: Dict[str, Any]

    model_config = ConfigDict(extra="forbid")


class QuorumRejectRequest(BaseModel):
    rejection_reason: str = Field(..., min_length=10, max_length=1000, description="Rejection reason")

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class QuorumRejectResponse(BaseModel):
    status: str = Field(default="REJECTED")
    rejected_at: datetime

    model_config = ConfigDict(extra="forbid")
